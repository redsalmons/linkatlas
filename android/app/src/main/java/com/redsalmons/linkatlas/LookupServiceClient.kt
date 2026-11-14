package com.redsalmons.linkatlas

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.Socket
import java.net.URL
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.net.ssl.HttpsURLConnection
import java.net.HttpURLConnection
import java.security.cert.CertificateFactory
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509KeyManager

/** Used lazily when accessing a server feature; never registers on app launch. */
class LookupServiceClient(
    context: Context,
    baseUrl: String,
    private val cloudProjectNumber: Long,
    private val development: Boolean = false,
) {
    class ApiError(val code: Int, message: String) : Exception("$code: $message")
    companion object {
        @Volatile private var shared: LookupServiceClient? = null
        fun configured(context: Context): LookupServiceClient? {
            if (BuildConfig.LOOKUP_BASE_URL.isBlank()) return null
            return shared ?: synchronized(this) {
                shared ?: runCatching {
                    LookupServiceClient(context, BuildConfig.LOOKUP_BASE_URL,
                        BuildConfig.PLAY_CLOUD_PROJECT, BuildConfig.LOOKUP_DEVELOPMENT)
                }.onFailure { android.util.Log.e("LookupSvc", "configured failed", it) }
                    .getOrNull().also { shared = it }
            }
        }
    }
    private val context = context.applicationContext
    private val base = URL(baseUrl.trimEnd('/'))
    private val mutex = Mutex()
    private val storageId = sha256("$base|$development|v3".toByteArray()).joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
    private val alias = "lookup.session.$storageId"
    private val sessionFile = File(this.context.noBackupFilesDir, "$alias.enc")
    private var provider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

    // Per-device client certificate: the EC private key lives in AndroidKeyStore
    // (TEE/StrongBox, non-exportable) and the server-issued certificate is stored
    // under the same alias. Until registration delivers a cert, connections use
    // the bundled bootstrap identity — the server restricts it to
    // challenge/register/refresh and the whitelist.
    // The dev environment (testapp.*) has its own CA and bootstrap identity so
    // the production CA key never leaves the production host.
    private val devEnv = base.host != "app.freedomsalmon.com"
    private val deviceKeyAlias = "linkatlas.devicekey"
    private val bootstrapAlias = "linkatlas.bootstrap"
    private val bootstrapPassword = if (devEnv) "f0985d239d0910c1fd775c432ee60968" else "597434c48fb0c8986619004be331979c"
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    // Bundled bootstrap identity (register-only). Loaded once; its cert is a
    // plain PKCS12 resource, so its private key is extractable by design —
    // it buys handshake access to bootstrap endpoints only.
    private val bootstrapStore = KeyStore.getInstance("PKCS12").apply {
        runCatching {
            load(context.resources.openRawResource(
                if (devEnv) R.raw.linkatlas_bootstrap_dev else R.raw.linkatlas_bootstrap),
                bootstrapPassword.toCharArray())
        }
    }

    private val caCert: X509Certificate? = runCatching {
        CertificateFactory.getInstance("X.509").generateCertificate(
            context.resources.openRawResource(
                if (devEnv) R.raw.linkatlas_ca_dev else R.raw.linkatlas_ca)) as X509Certificate
    }.getOrNull()

    // A server-issued device cert is present and unexpired. Sessions held over
    // from before per-device certs have a valid token but no cert — without
    // this check they would call APIs with the bootstrap identity (rejected).
    private fun deviceCertUsable(): Boolean = runCatching {
        val leaf = keyStore.getCertificateChain(deviceKeyAlias)
            ?.firstOrNull() as? X509Certificate
        leaf != null && leaf.notAfter.after(java.util.Date()) &&
            leaf.issuerX500Principal == caCert?.subjectX500Principal
    }.getOrDefault(false)

    private inner class DeviceKeyManager : X509KeyManager {
        private fun certified(): Boolean = deviceCertUsable()

        private fun bootstrapPresent(): Boolean = runCatching {
            bootstrapStore.aliases().asSequence().any {
                bootstrapStore.isKeyEntry(it) && bootstrapStore.getCertificate(it) != null
            }
        }.getOrDefault(false)

        private fun bootstrapEntryAlias(): String? = runCatching {
            bootstrapStore.aliases().asSequence().firstOrNull {
                bootstrapStore.isKeyEntry(it) && bootstrapStore.getCertificate(it) != null
            }
        }.getOrNull()

        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?,
                                       socket: Socket?) =
            if (certified()) deviceKeyAlias else bootstrapEntryAlias()?.let { bootstrapAlias }
        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) =
            if (certified()) arrayOf(deviceKeyAlias)
            else bootstrapEntryAlias()?.let { arrayOf(bootstrapAlias) }
        override fun getPrivateKey(alias: String?) = when (alias) {
            deviceKeyAlias -> keyStore.getKey(deviceKeyAlias, null) as? PrivateKey
            bootstrapAlias -> bootstrapEntryAlias()
                ?.let { bootstrapStore.getKey(it, bootstrapPassword.toCharArray()) as? PrivateKey }
            else -> null
        }
        override fun getCertificateChain(alias: String?): Array<X509Certificate>? = when (alias) {
            deviceKeyAlias -> keyStore.getCertificateChain(deviceKeyAlias)
                ?.filterIsInstance<X509Certificate>()?.toTypedArray()
            bootstrapAlias -> bootstrapEntryAlias()
                ?.let { bootstrapStore.getCertificateChain(it) }
                ?.filterIsInstance<X509Certificate>()?.toTypedArray()
            else -> null
        }
        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?,
                                       socket: Socket?): String? = null
    }

    private val mtls: SSLContext? = run {
        if (base.protocol != "https") return@run null
        runCatching {
            val caStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("ca", caCert)
            }
            val trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(caStore) }
            SSLContext.getInstance("TLS").apply {
                init(arrayOf<KeyManager>(DeviceKeyManager()), trustManagers.trustManagers, null)
                // Every request needs a full handshake so the server can send a
                // CertificateRequest; a resumed session would skip client auth.
                clientSessionContext.sessionCacheSize = 0
                clientSessionContext.sessionTimeout = 0
            }
        }.getOrNull()
    }

    init {
        val localDebug = BuildConfig.DEBUG && development &&
            base.protocol == "http" && base.host in listOf("127.0.0.1", "localhost", "10.0.2.2")
        require((base.protocol == "https" || localDebug) && base.host.isNotBlank() &&
            base.userInfo == null && base.query == null && base.ref == null &&
            (base.path.isEmpty() || base.path == "/"))
        require(!development || BuildConfig.DEBUG) { "Development proofs require a debug build" }
        require(development || cloudProjectNumber > 0) { "Google Cloud project number required" }
        require(base.protocol != "https" || mtls != null) { "mTLS materials missing for https endpoint" }
    }

    suspend fun deviceToken(): String = mutex.withLock {
        withContext(Dispatchers.IO) {
            ensureDeviceKey()
            readSession()?.let {
                if (it.getLong("expires_at") > System.currentTimeMillis() / 1000 + 60
                    && deviceCertUsable()) {
                    return@withContext it.getString("device_token")
                }
                runCatching { return@withContext refresh(it) }
            }
            // Prepare before issuing the short-lived challenge.
            if (!development && provider == null) {
                provider = IntegrityManagerFactory.createStandard(context)
                    .prepareIntegrityToken(
                        StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
                            .setCloudProjectNumber(cloudProjectNumber).build()
                    ).await()
            }
            val challenge = post("/v1/device/challenge", JSONObject()
                .put("platform", "android").put("schema", 3))
            val version = BuildConfig.VERSION_NAME
            val fields = listOf("linkatlas-register-v3", challenge.getString("challenge_id"),
                challenge.getString("challenge"), "android", "", version)
            val hash = Base64.encodeToString(sha256(fields.joinToString("\n").toByteArray(Charsets.UTF_8)),
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            val proof = if (development) {
                "development-only"
            } else {
                try {
                    provider!!.request(
                        StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
                            .setRequestHash(hash).build()
                    ).await().token()
                } catch (e: Exception) {
                    provider = null // re-prepare on next attempt; never downgrade to a mock
                    throw e
                }
            }
            val registerBody = JSONObject()
                .put("platform", "android").put("schema", 3).put("app_version", version)
                .put("challenge_id", challenge.getString("challenge_id"))
                .put("key_id", "").put("attestation", proof)
            deviceProof(challenge.getString("challenge_id"))?.let { (pub, sig) ->
                registerBody.put("client_pubkey", pub).put("client_pubkey_sig", sig)
            }
            val response = post("/v1/device/register", registerBody)
            saveSession(response)
            installClientCert(response)
            response.getString("device_token")
        }
    }

    private fun refresh(session: JSONObject): String {
        val body = JSONObject()
            .put("refresh_token", session.getString("refresh_token")).put("schema", 3)
        deviceProof(session.getString("refresh_token"))?.let { (pub, sig) ->
            body.put("client_pubkey", pub).put("client_pubkey_sig", sig)
        }
        val response = post("/v1/device/refresh", body)
        saveSession(response)
        installClientCert(response)
        return response.getString("device_token")
    }

    /** AndroidKeyStore P-256 key; private key never leaves the device. */
    private fun ensureDeviceKey() {
        val existing = keyStore.getKey(deviceKeyAlias, null) as? PrivateKey
        if (existing != null) {
            // TLS client auth signs via Digest.NONE (Conscrypt pre-hashes the
            // CertificateVerify transcript). Keys minted before that digest
            // was authorized are unusable — regenerate. Unreadable keys are
            // treated the same way.
            val info = runCatching {
                java.security.KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                    .getKeySpec(existing, android.security.keystore.KeyInfo::class.java)
            }.getOrNull()
            if (info != null && info.digests.contains(KeyProperties.DIGEST_NONE)) return
            keyStore.deleteEntry(deviceKeyAlias)
        }
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            deviceKeyAlias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
            .setIsStrongBoxBacked(strongBox).build()
        try {
            generator.initialize(spec(true))
        } catch (_: Exception) {
            generator.initialize(spec(false))
        }
        generator.generateKeyPair()
    }

    /** PKIX SubjectPublicKeyInfo + possession proof for context (challenge_id or refresh_token). */
    private fun deviceProof(context: String): Pair<String, String>? = runCatching {
        ensureDeviceKey()
        val pub = Base64.encodeToString(
            keyStore.getCertificate(deviceKeyAlias).publicKey.encoded, Base64.NO_WRAP)
        val message = "linkatlas-cert-v1\n$context\n$pub"
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyStore.getKey(deviceKeyAlias, null) as PrivateKey)
            update(message.toByteArray(Charsets.UTF_8))
            sign()
        }
        pub to Base64.encodeToString(signature, Base64.NO_WRAP)
    }.getOrNull()

    private fun installClientCert(response: JSONObject) {
        val pem = response.optString("client_cert")
        if (pem.isEmpty()) {
            android.util.Log.e("LookupSvc", "installClientCert: empty client_cert")
            return
        }
        runCatching {
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(pem.byteInputStream(Charsets.UTF_8))
            val key = keyStore.getKey(deviceKeyAlias, null) as PrivateKey
            keyStore.setKeyEntry(deviceKeyAlias, key, null, arrayOf(cert))
            android.util.Log.i("LookupSvc", "client cert installed, chain=" +
                (keyStore.getCertificateChain(deviceKeyAlias)?.size ?: -1))
        }.onFailure { android.util.Log.e("LookupSvc", "installClientCert failed", it) }
    }

    suspend fun ownerID(): String {
        deviceToken()
        return withContext(Dispatchers.IO) { readSession()!!.getString("owner_id") }
    }

    suspend fun request(path: String, body: JSONObject): JSONObject {
        val token = deviceToken()
        return withContext(Dispatchers.IO) {
            try { post(path, body, token) }
            catch (error: ApiError) {
                if (error.code != 1002) throw error
                val fresh = mutex.withLock {
                    val session = readSession() ?: throw error
                    if (session.getString("device_token") != token) session.getString("device_token")
                    else runCatching { refresh(session) }.getOrNull()
                } ?: run {
                    // Stale session (server-side state reset) — drop it and
                    // register afresh instead of retrying the dead token.
                    mutex.withLock {
                        if (readSession()?.getString("device_token") == token) sessionFile.delete()
                    }
                    deviceToken()
                }
                post(path, body, fresh)
            }
        }
    }

    suspend fun verify(product: String, receipt: String, transaction: String): JSONObject =
        request("/v1/entitlement/verify", JSONObject().put("platform", "android")
            .put("product_id", product).put("receipt", receipt).put("transaction_id", transaction).put("schema", 3))

    /** Public endpoint; no device registration is needed or performed here. */
    suspend fun fetchWhitelist(): ServiceWhitelist? = withContext(Dispatchers.IO) {
        runCatching {
            val connection = URL(base, "/v1/lookupaddress/whitelist").openConnection() as HttpURLConnection
            (connection as? HttpsURLConnection)?.sslSocketFactory = mtls?.socketFactory
            try {
                connection.requestMethod = "GET"
                connection.instanceFollowRedirects = false
                connection.connectTimeout = 15_000
                connection.readTimeout = 15_000
                connection.setRequestProperty("X-Schema", "3")
                val raw = (if (connection.responseCode == 200) connection.inputStream else connection.errorStream)
                    ?.bufferedReader()?.use { it.readText() }.orEmpty()
                val envelope = JSONObject(raw)
                if (!envelope.getBoolean("status")) {
                    android.util.Log.w("Whitelist", "fetch rejected code=${envelope.optInt("code")}")
                    return@runCatching null
                }
                envelope.optJSONObject("data")?.toString()
            } finally {
                connection.disconnect()
            }
        }.onFailure { android.util.Log.w("Whitelist", "fetch failed", it) }
            .getOrNull()?.let { ServiceWhitelist.fromJson(it) }
    }

    private fun post(path: String, body: JSONObject, token: String? = null): JSONObject {
        val connection = URL(base, path).openConnection() as HttpURLConnection
        (connection as? HttpsURLConnection)?.sslSocketFactory = mtls?.socketFactory
        try {
            connection.requestMethod = "POST"
            try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 15_000
            connection.readTimeout = 75_000
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Connection", "close")
            connection.setRequestProperty("X-Schema", "3")
            if (token != null) connection.setRequestProperty("Authorization", "Bearer $token")
            connection.setRequestProperty("X-Ts", (System.currentTimeMillis() / 1000).toString())
            connection.setRequestProperty("X-Nonce", UUID.randomUUID().toString())
            connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            val raw = (if (connection.responseCode == 200) connection.inputStream else connection.errorStream)
                ?.bufferedReader()?.use { it.readText() }.orEmpty()
            val envelope = JSONObject(raw)
            if (!envelope.getBoolean("status")) {
                throw ApiError(envelope.getInt("code"), envelope.optString("message"))
            }
            return envelope.optJSONObject("data") ?: JSONObject()
            } catch (e: Exception) {
                android.util.Log.w("LookupSvc", "post $path failed: ${e.javaClass.simpleName}: ${e.message}")
                throw e
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun storageKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }

    private fun readSession(): JSONObject? {
        if (!sessionFile.exists()) return null
        val bytes = sessionFile.readBytes()
        require(bytes.size > 12) { "Invalid stored session" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, storageKey(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        return JSONObject(String(cipher.doFinal(bytes.copyOfRange(12, bytes.size)), Charsets.UTF_8))
    }

    private fun saveSession(session: JSONObject) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, storageKey())
        val encrypted = cipher.iv + cipher.doFinal(session.toString().toByteArray(Charsets.UTF_8))
        val file = android.util.AtomicFile(sessionFile)
        val stream = file.startWrite()
        try {
            stream.write(encrypted)
            file.finishWrite(stream)
        } catch (e: Exception) {
            file.failWrite(stream)
            throw e
        }
    }

    private fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)
}
