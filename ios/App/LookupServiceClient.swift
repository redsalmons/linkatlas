import Foundation
import CryptoKit
import DeviceCheck
import Security

/// Call deviceToken() when a server feature is used, not on application launch.
/// A single instance coalesces concurrent registration attempts.
actor LookupServiceClient {
    enum Mode: String { case platform, development }
    enum Failure: Error {
        case invalidConfiguration, unsupportedDevice, invalidResponse
        case server(Int), keychain(OSStatus)
    }

    /// Shared instance configured from Info.plist key "LookupServiceURL".
    /// Falls back to development mode on simulator.
    static let shared: LookupServiceClient? = {
        guard let urlString = Bundle.main.object(forInfoDictionaryKey: "LookupServiceURL") as? String,
              let url = URL(string: urlString) else {
            #if targetEnvironment(simulator)
            return try? LookupServiceClient(baseURL: URL(string: "http://localhost:8080")!, mode: .development)
            #else
            return nil
            #endif
        }
        #if DEBUG
        return try? LookupServiceClient(baseURL: url, mode: .development)
        #else
        return try? LookupServiceClient(baseURL: url, mode: .platform)
        #endif
    }()

    private struct Session: Codable {
        let deviceToken: String
        let expiresAt: Int64
        let keyID: String
        let refreshToken: String
        let ownerID: String
    }
    struct ApiFailure: Error { let code: Int }
    private struct Envelope<T: Decodable>: Decodable {
        let status: Bool; let code: Int; let data: T?
    }
    private struct Challenge: Decodable {
        let challenge_id: String
        let challenge: String
    }
    private struct Registration: Decodable {
        let device_token: String
        let expires_at: Int64
        let refresh_token: String
        let owner_id: String
        let client_cert: String?
        let cert_expires: Int64?
    }

    private let baseURL: URL
    private let mode: Mode
    private let storageAccount: String
    private let network: PinnedHTTPClient
    private var pending: Task<String, Error>?

    init(baseURL: URL, mode: Mode = .platform) throws {
        let schemeOK = baseURL.scheme == "https"
            || (mode == .development && baseURL.scheme == "http" && Self.isLocalHost(baseURL.host))
        guard schemeOK, baseURL.host != nil,
              baseURL.user == nil, baseURL.password == nil,
              baseURL.query == nil, baseURL.fragment == nil,
              baseURL.path.isEmpty || baseURL.path == "/" else {
            throw Failure.invalidConfiguration
        }
        #if !DEBUG
        guard mode == .platform else { throw Failure.invalidConfiguration }
        #endif
        self.baseURL = baseURL
        self.mode = mode
        self.storageAccount = "\(baseURL.absoluteString)|\(mode.rawValue)"
        self.network = try PinnedHTTPClient()
        if let identity = Self.loadStoredIdentity() {
            dbgLog("[Lookup] using device identity")
            self.network.setIdentity(identity)
        } else if let identity = Self.loadBootstrapIdentity() {
            dbgLog("[Lookup] using bootstrap identity")
            self.network.setIdentity(identity)
        } else {
            dbgLog("[Lookup] NO identity available — handshake will fail")
        }
    }

    // MARK: - Device key / client certificate

    private static let deviceKeyTag = "com.redsalmons.linkatlas.devicekey"
    private static let deviceCertLabel = "com.redsalmons.linkatlas.devicecert"
    private static let bootstrapP12Password = "597434c48fb0c8986619004be331979c"
    private static let bootstrapCertLabel = "com.redsalmons.linkatlas.bootstrapcert"
    private static let bootstrapKeyLabel = "com.redsalmons.linkatlas.bootstrapkey"

    /// Bundled bootstrap identity: used before registration issues a device
    /// certificate. The server restricts it to challenge/register/refresh and
    /// the whitelist — it cannot call any API endpoint.
    ///
    /// The identity MUST be keychain-backed: an in-memory identity from
    /// SecPKCS12Import cannot sign the TLS CertificateVerify (securityd needs
    /// a persistent key), so the client silently aborts the handshake.
    private static func loadBootstrapIdentity() -> SecIdentity? {
        if let identity = bootstrapKeychainIdentity() { return identity }
        guard let url = Bundle.main.url(forResource: "LinkAtlas-bootstrap", withExtension: "p12"),
              let data = try? Data(contentsOf: url) else {
            dbgLog("[Lookup] bootstrap p12 missing from bundle"); return nil }
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData,
                                     [kSecImportExportPassphrase as String: bootstrapP12Password] as CFDictionary,
                                     &items)
        guard status == errSecSuccess,
              let dict = (items as? [[String: Any]])?.first,
              let identity = dict[kSecImportItemIdentity as String] as! SecIdentity? else {
            dbgLog("[Lookup] bootstrap p12 import failed: \(status)"); return nil }
        var cert: SecCertificate?
        var key: SecKey?
        guard SecIdentityCopyCertificate(identity, &cert) == errSecSuccess,
              SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess,
              let cert, let key else {
            dbgLog("[Lookup] bootstrap p12 missing cert/key"); return nil }
        for (cls, label, value) in [(kSecClassCertificate, bootstrapCertLabel, cert as CFTypeRef),
                                    (kSecClassKey, bootstrapKeyLabel, key as CFTypeRef)] {
            SecItemDelete([kSecClass: cls, kSecAttrLabel: label] as CFDictionary)
            let addStatus = SecItemAdd([kSecClass: cls, kSecAttrLabel: label,
                                        kSecValueRef: value] as CFDictionary, nil)
            if addStatus != errSecSuccess && addStatus != errSecDuplicateItem {
                dbgLog("[Lookup] bootstrap keychain add failed: \(addStatus)")
            }
        }
        guard let stored = bootstrapKeychainIdentity() else {
            dbgLog("[Lookup] bootstrap identity not in keychain after add")
            return nil
        }
        dbgLog("[Lookup] bootstrap identity loaded")
        return stored
    }

    private static func bootstrapKeychainIdentity() -> SecIdentity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: bootstrapCertLabel,
            kSecReturnRef as String: true]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let item else { return nil }
        return (item as! SecIdentity)
    }

    /// Hardware-bound P-256 key: Secure Enclave on real devices, plain keychain
    /// in the simulator. The private key never leaves the device.
    private static func devicePrivateKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: deviceKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item {
            return (item as! SecKey)
        }
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: deviceKeyTag]]
        #if !targetEnvironment(simulator)
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        #endif
        var error: Unmanaged<CFError>?
        if let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
            return key
        }
        // Secure Enclave unavailable (e.g. very old hardware): fall back to a
        // normal keychain key rather than failing registration outright.
        attributes.removeValue(forKey: kSecAttrTokenID as String)
        return SecKeyCreateRandomKey(attributes as CFDictionary, nil)
    }

    /// ANSI X9.63 uncompressed point — matches the server's fingerprint hash.
    private static func devicePubkeyBase64(_ privateKey: SecKey) -> String? {
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let raw = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else { return nil }
        return raw.base64EncodedString()
    }

    private static func deviceProof(_ privateKey: SecKey, context: String, pubkey: String) -> String? {
        let message = "linkatlas-cert-v1\n\(context)\n\(pubkey)"
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256,
                                              Data(message.utf8) as CFData, &error) as Data? else { return nil }
        return sig.base64EncodedString()
    }

    /// Install the server-issued client cert next to the device key so iOS can
    /// pair them into a SecIdentity for the TLS layer.
    /// Installed device cert expiry (unix seconds). Once it lapses the server
    /// refuses the handshake, so the client must drop back to the bundled
    /// bootstrap identity to reach register/refresh.
    private static let certExpiryKey = "com.redsalmons.linkatlas.certexpiry"

    private static var deviceCertUsable: Bool {
        (UserDefaults.standard.object(forKey: certExpiryKey) as? Int64 ?? 0)
            > Int64(Date().timeIntervalSince1970)
    }

    private func installClientCert(_ pem: String, expires: Int64? = nil) {
        let der = pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
        guard let derData = Data(base64Encoded: der),
              let cert = SecCertificateCreateWithData(nil, derData as CFData) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: Self.deviceCertLabel]
        SecItemDelete(query as CFDictionary)
        var attrs = query
        attrs[kSecValueRef as String] = cert
        guard SecItemAdd(attrs as CFDictionary, nil) == errSecSuccess else { return }
        // Persist the expiry BEFORE loading the identity — loadStoredIdentity
        // gates on deviceCertUsable, which reads this key. A freshly issued
        // cert is usable by definition, so also load it unconditionally.
        if let expires { UserDefaults.standard.set(expires, forKey: Self.certExpiryKey) }
        if let identity = Self.keychainIdentity() {
            network.setIdentity(identity)
            dbgLog("[Lookup] device cert installed, expires=\(expires ?? 0)")
        } else {
            dbgLog("[Lookup] device cert installed but identity load failed")
        }
    }

    private static func keychainIdentity() -> SecIdentity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: deviceCertLabel,
            kSecReturnRef as String: true]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let item else { return nil }
        return (item as! SecIdentity)
    }

    private static func loadStoredIdentity() -> SecIdentity? {
        deviceCertUsable ? keychainIdentity() : nil
    }

    /// Local-network hosts allowed to use plain http in development mode:
    /// loopback, private/ link-local IPv4, .local names and IPv6 ULA/loopback.
    private static func isLocalHost(_ host: String?) -> Bool {
        guard let host = host?.lowercased(), !host.isEmpty else { return false }
        if host == "localhost" || host.hasSuffix(".localhost") || host.hasSuffix(".local")
            || host == "::1" { return true }
        let v4 = host.split(separator: ".").compactMap { UInt8($0) }
        if v4.count == 4 {
            switch (v4[0], v4[1]) {
            case (10, _), (127, _), (192, 168), (169, 254): return true
            case (172, 16...31): return true
            default: return false
            }
        }
        if host.hasPrefix("fc") || host.hasPrefix("fd") || host.hasPrefix("fe80") { return true }
        return false
    }

    func deviceToken() async throws -> String {
        // A token is only useful with a device certificate: sessions carried
        // over from before per-device certs have a valid token but no cert,
        // and the API layer rejects the bootstrap identity. Force a refresh —
        // it reissues the cert — until a usable device cert exists.
        if let session = try readSession(),
           session.expiresAt > Int64(Date().timeIntervalSince1970) + 60,
           Self.deviceCertUsable {
            return session.deviceToken
        }
        if let pending { return try await pending.value }
        let task = Task { try await self.registerOrRefresh() }
        pending = task
        defer { pending = nil }
        return try await task.value
    }

    private func registerOrRefresh() async throws -> String {
        // An expired device cert fails the TLS handshake — drop to the bundled
        // bootstrap identity, which is allowed to reach register/refresh.
        if !Self.deviceCertUsable, let bootstrap = Self.loadBootstrapIdentity() {
            network.setIdentity(bootstrap)
        }
        if let session = try readSession(),
           !session.refreshToken.isEmpty {
            do { return try await refresh(session) } catch { }
        }
        return try await register()
    }

    private func refresh(_ session: Session) async throws -> String {
        struct RefreshResponse: Decodable {
            let device_token: String
            let expires_at: Int64
            let refresh_token: String
            let owner_id: String
            let client_cert: String?
            let cert_expires: Int64?
        }
        var body: [String: Any] = ["refresh_token": session.refreshToken, "schema": 3]
        if let key = Self.devicePrivateKey(),
           let pub = Self.devicePubkeyBase64(key),
           let sig = Self.deviceProof(key, context: session.refreshToken, pubkey: pub) {
            body["client_pubkey"] = pub
            body["client_pubkey_sig"] = sig
        }
        let response: RefreshResponse = try await post("/v1/device/refresh", body)
        let updated = Session(deviceToken: response.device_token,
                              expiresAt: response.expires_at,
                              keyID: session.keyID,
                              refreshToken: response.refresh_token,
                              ownerID: response.owner_id)
        try saveSession(updated)
        if let pem = response.client_cert { installClientCert(pem, expires: response.cert_expires) }
        return response.device_token
    }

    private func register() async throws -> String {
        let service = DCAppAttestService.shared
        if mode == .platform && !service.isSupported { throw Failure.unsupportedDevice }
        // Each new registration has a new attestation key. Never attest the same
        // key twice. Token renewal / purchase restoration is a separate protocol.
        let keyID = mode == .platform ? try await service.generateKey() : ""
        let challenge: Challenge = try await post("/v1/device/challenge", [
            "platform": "ios", "schema": 3
        ])
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
        let fields = ["linkatlas-register-v3", challenge.challenge_id,
                      challenge.challenge, "ios", keyID, version]
        let hash = Data(SHA256.hash(data: Data(fields.joined(separator: "\n").utf8)))
        let proof: String
        if mode == .platform {
            proof = try await service.attestKey(keyID, clientDataHash: hash).base64EncodedString()
        } else {
            #if DEBUG
            proof = "development-only"
            #else
            throw Failure.invalidConfiguration
            #endif
        }
        var body: [String: Any] = [
            "platform": "ios", "schema": 3, "app_version": version,
            "key_id": keyID, "challenge_id": challenge.challenge_id, "attestation": proof]
        if let key = Self.devicePrivateKey(),
           let pub = Self.devicePubkeyBase64(key),
           let sig = Self.deviceProof(key, context: challenge.challenge_id, pubkey: pub) {
            body["client_pubkey"] = pub
            body["client_pubkey_sig"] = sig
        }
        let response: Registration = try await post("/v1/device/register", body)
        try saveSession(Session(deviceToken: response.device_token,
                                expiresAt: response.expires_at, keyID: keyID,
                                refreshToken: response.refresh_token, ownerID: response.owner_id))
        if let pem = response.client_cert { installClientCert(pem, expires: response.cert_expires) }
        return response.device_token
    }

    // MARK: - Authenticated API

    /// Authenticated POST that returns the `data` dictionary from the envelope.
    /// Handles 401 by refreshing the token and retrying once.
    func request(path: String, body: [String: Any]) async throws -> [String: Any] {
        dbgLog("[Lookup] request \(path)")
        let token = try await deviceToken()
        do {
            return try await postAuthenticated(path, body, token)
        } catch let error as ApiFailure where error.code == 1002 {
            // Server rejected the token (expired, or server-side state reset).
            // Drop the cached session — otherwise deviceToken() would return
            // the same stale token forever.
            try discardSession()
            let fresh = try await deviceToken()
            if fresh == token { throw error }
            return try await postAuthenticated(path, body, fresh)
        }
    }

    private func postAuthenticated(_ path: String, _ body: [String: Any],
                                   _ token: String) async throws -> [String: Any] {
        var request = URLRequest(url: baseURL.appendingPathComponent(String(path.dropFirst())))
        // LLM-backed queries can take close to the server's 60s budget.
        request.timeoutInterval = 120
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("3", forHTTPHeaderField: "X-Schema")
        request.setValue(String(Int64(Date().timeIntervalSince1970)), forHTTPHeaderField: "X-Ts")
        request.setValue(UUID().uuidString, forHTTPHeaderField: "X-Nonce")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await network.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw Failure.invalidResponse }
        // Parse envelope manually to handle [String: Any] data.
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Failure.invalidResponse
        }
        let status = json["status"] as? Bool ?? false
        let code = json["code"] as? Int ?? 0
        if !status {
            dbgLog("[Lookup] \(path) api error code=\(code)")
            throw ApiFailure(code: code)
        }
        guard http.statusCode == 200 else { throw Failure.server(http.statusCode) }
        return (json["data"] as? [String: Any]) ?? [:]
    }

    func verify(product: String, receipt: String, transaction: String) async throws -> [String: Any] {
        try await request(path: "/v1/entitlement/verify", body: [
            "platform": "ios", "product_id": product,
            "receipt": receipt, "transaction_id": transaction, "schema": 3
        ])
    }

    func config() async throws -> [String: Any] {
        try await request(path: "/v1/lookupaddress/config", body: ["schema": 3])
    }

    /// Public endpoint; no device registration is needed or performed here.
    func fetchWhitelist() async -> ServiceWhitelist? {
        var request = URLRequest(url: baseURL.appendingPathComponent("v1/lookupaddress/whitelist"))
        request.timeoutInterval = 120
        request.setValue("3", forHTTPHeaderField: "X-Schema")
        do {
            let (data, _) = try await network.data(for: request)
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  json["status"] as? Bool == true,
                  let d = json["data"] as? [String: Any] else {
                NSLog("Whitelist fetch rejected or malformed")
                return nil
            }
            return ServiceWhitelist(
                domains: (d["domains"] as? [String] ?? []).map { $0.lowercased() },
                ips: d["ips"] as? [String] ?? [])
        } catch {
            NSLog("Whitelist fetch failed: \(error.localizedDescription)")
            return nil
        }
    }

    func ownerID() async throws -> String {
        _ = try await deviceToken()
        guard let session = try readSession() else { throw Failure.invalidResponse }
        return session.ownerID
    }

    private func post<T: Decodable>(_ path: String, _ body: [String: Any]) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(String(path.dropFirst())))
        // LLM-backed queries can take close to the server's 60s budget.
        request.timeoutInterval = 120
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("3", forHTTPHeaderField: "X-Schema")
        request.setValue(String(Int64(Date().timeIntervalSince1970)), forHTTPHeaderField: "X-Ts")
        request.setValue(UUID().uuidString, forHTTPHeaderField: "X-Nonce")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await network.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw Failure.invalidResponse }
        guard http.statusCode == 200 else { throw Failure.server(http.statusCode) }
        // Envelope: {status, code, message, data}
        let envelope = try JSONDecoder().decode(Envelope<T>.self, from: data)
        if !envelope.status { throw ApiFailure(code: envelope.code) }
        guard let payload = envelope.data else { throw Failure.invalidResponse }
        return payload
    }

    private var keychainQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "com.redsalmons.lookup.session",
         kSecAttrAccount as String: storageAccount]
    }

    private func readSession() throws -> Session? {
        var query = keychainQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw Failure.keychain(status) }
        guard let data = result as? Data else { throw Failure.invalidResponse }
        return try JSONDecoder().decode(Session.self, from: data)
    }

    private func discardSession() throws {
        let status = SecItemDelete(keychainQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure.keychain(status)
        }
    }

    private func saveSession(_ session: Session) throws {
        let data = try JSONEncoder().encode(session)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        var status = SecItemUpdate(keychainQuery as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(keychainQuery.merging(attributes) { _, new in new } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw Failure.keychain(status) }
    }
}
