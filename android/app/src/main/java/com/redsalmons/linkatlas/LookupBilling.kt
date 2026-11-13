package com.redsalmons.linkatlas

import android.app.Activity
import android.content.Context
import com.android.billingclient.api.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Application-scoped: verification survives leaving the detail screen. Store
 * owned-purchase queries recover payments after process death. */
class LookupBilling private constructor(context: Context, private val api: LookupServiceClient) {
    data class Update(val state: String = "idle", val sequence: Long = 0)
    val update = MutableStateFlow(Update())
    val products = MutableStateFlow<Map<String, ProductDetails>>(emptyMap())
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val connectionLock = Mutex()
    private val verificationLock = Mutex()
    private val prefs = context.getSharedPreferences("lookup-development-purchase", Context.MODE_PRIVATE)
    private val billing = BillingClient.newBuilder(context.applicationContext)
        .setListener { result, purchases ->
            when (result.responseCode) {
                BillingClient.BillingResponseCode.OK -> purchases.orEmpty().forEach { process(it) }
                BillingClient.BillingResponseCode.USER_CANCELED -> update.value = Update("cancelled")
                BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED -> restore()
                else -> update.value = Update("failed")
            }
        }
        .enablePendingPurchases(PendingPurchasesParams.newBuilder().enableOneTimeProducts().build())
        .enableAutoServiceReconnection()
        .build()

    companion object {
        const val SINGLE = "lookupaddress.single"
        const val PRO = "lookupaddress.pro"
        const val PRO_YEAR = "lookupaddress.pro.year"
        private val SUBS = mapOf(PRO to "P1M", PRO_YEAR to "P1Y")
        @Volatile private var instance: LookupBilling? = null
        fun configured(context: Context): LookupBilling? {
            val api = LookupServiceClient.configured(context) ?: return null
            return instance ?: synchronized(this) {
                instance ?: LookupBilling(context.applicationContext, api).also { instance = it }
            }
        }
    }

    private suspend fun connect() = connectionLock.withLock {
        if (!billing.isReady) suspendCancellableCoroutine<Unit> { continuation ->
            billing.startConnection(object : BillingClientStateListener {
                override fun onBillingSetupFinished(result: BillingResult) {
                    if (!continuation.isActive) return
                    if (result.responseCode == BillingClient.BillingResponseCode.OK) continuation.resume(Unit)
                    else continuation.resumeWithException(IllegalStateException("billing unavailable"))
                }
                override fun onBillingServiceDisconnected() { }
            })
        }
    }

    suspend fun loadProducts() {
        if (BuildConfig.LOOKUP_DEVELOPMENT && !BuildConfig.LOOKUP_REAL_BILLING) return
        connect()
        val found = mutableMapOf<String, ProductDetails>()
        for ((id, type) in listOf(SINGLE to BillingClient.ProductType.INAPP)
            + SUBS.keys.map { it to BillingClient.ProductType.SUBS }) {
            val details = suspendCancellableCoroutine<List<ProductDetails>> { continuation ->
                val params = QueryProductDetailsParams.newBuilder().setProductList(
                    listOf(QueryProductDetailsParams.Product.newBuilder().setProductId(id).setProductType(type).build())
                ).build()
                billing.queryProductDetailsAsync(params) { result, response ->
                    if (!continuation.isActive) return@queryProductDetailsAsync
                    if (result.responseCode == BillingClient.BillingResponseCode.OK) continuation.resume(response.productDetailsList)
                    else continuation.resumeWithException(IllegalStateException("product unavailable"))
                }
            }
            details.firstOrNull()?.let { found[id] = it }
        }
        products.value = found
    }

    fun price(id: String): String? = products.value[id]?.let {
        if (id == SINGLE) it.oneTimePurchaseOfferDetails?.formattedPrice
        else it.subscriptionOfferDetails?.firstOrNull { offer ->
            offer.offerId == null && offer.pricingPhases.pricingPhaseList.any { phase ->
                phase.billingPeriod == SUBS[id]
            }
        }?.pricingPhases?.pricingPhaseList?.lastOrNull()?.formattedPrice
    }

    fun buy(activity: Activity, id: String) {
        if (update.value.state in listOf("paying", "verifying", "pending")) return
        update.value = Update("paying")
        scope.launch {
            try {
                // Recheck availability immediately before opening payment UI.
                val config = api.request("/v1/lookupaddress/config", org.json.JSONObject().put("schema", 3))
                check(config.getBoolean("purchases_enabled") && config.getBoolean("store_ready"))
                if (BuildConfig.LOOKUP_DEVELOPMENT && !BuildConfig.LOOKUP_REAL_BILLING) {
                    check(BuildConfig.DEBUG)
                    // Mock purchase token embeds owner ID so the server's mock
                    // Google Play API returns matching obfuscatedExternalAccountId.
                    val ownerId = api.ownerID()
                    val transaction = prefs.getString("transaction", null) ?: java.util.UUID.randomUUID().toString()
                    val product = prefs.getString("product", null) ?: id
                    val mockToken = "mock-$ownerId~$transaction"
                    check(prefs.edit().putString("transaction", transaction).putString("product", product)
                        .putString("mock_token", mockToken).commit())
                    verifyDevelopment(product, mockToken, transaction)
                    return@launch
                }
                connect()
                val product = products.value[id] ?: error("product unavailable")
                val builder = BillingFlowParams.ProductDetailsParams.newBuilder().setProductDetails(product)
                SUBS[id]?.let { period ->
                    val offer = product.subscriptionOfferDetails?.firstOrNull {
                        it.offerId == null && it.pricingPhases.pricingPhaseList.any { phase ->
                            phase.billingPeriod == period
                        }
                    } ?: error("subscription unavailable")
                    builder.setOfferToken(offer.offerToken)
                }
                val params = BillingFlowParams.newBuilder().setObfuscatedAccountId(api.ownerID())
                    .setProductDetailsParamsList(listOf(builder.build())).build()
                val result = billing.launchBillingFlow(activity, params)
                if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                    update.value = Update("failed")
                    if (result.responseCode == BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED) restore()
                }
            } catch (_: Exception) { update.value = Update("failed") }
        }
    }

    private suspend fun verifyDevelopment(product: String, receipt: String, transaction: String) = verificationLock.withLock {
        update.value = Update("verifying")
        val response = api.verify(product, receipt, transaction)
        check(response.getString("status") in listOf("credited", "already_credited"))
        check(prefs.edit().remove("transaction").remove("product").remove("mock_token").commit())
        update.value = Update("credited", System.currentTimeMillis())
    }

    fun restore() {
        scope.launch {
            try {
                if (BuildConfig.LOOKUP_DEVELOPMENT && !BuildConfig.LOOKUP_REAL_BILLING) {
                    val transaction = prefs.getString("transaction", null) ?: return@launch
                    val mockToken = prefs.getString("mock_token", null) ?: return@launch
                    verifyDevelopment(prefs.getString("product", SINGLE)!!, mockToken, transaction)
                    return@launch
                }
                connect()
                for (type in listOf(BillingClient.ProductType.INAPP, BillingClient.ProductType.SUBS)) {
                    val purchases = suspendCancellableCoroutine<List<Purchase>> { continuation ->
                        billing.queryPurchasesAsync(QueryPurchasesParams.newBuilder().setProductType(type).build()) { result, list ->
                            if (!continuation.isActive) return@queryPurchasesAsync
                            if (result.responseCode == BillingClient.BillingResponseCode.OK) continuation.resume(list)
                            else continuation.resumeWithException(IllegalStateException("restore unavailable"))
                        }
                    }
                    purchases.forEach { process(it) }
                }
            } catch (_: Exception) { update.value = Update("failed") }
        }
    }

    private fun process(purchase: Purchase) {
        val product = purchase.products.singleOrNull()?.takeIf { it == SINGLE || it in SUBS } ?: return
        if (purchase.purchaseState == Purchase.PurchaseState.PENDING) {
            update.value = Update("pending"); return
        }
        if (purchase.purchaseState != Purchase.PurchaseState.PURCHASED) return
        scope.launch {
            verificationLock.withLock {
                try {
                    update.value = Update("verifying")
                    val response = api.verify(product, purchase.purchaseToken, purchase.orderId ?: purchase.purchaseToken)
                    val status = response.getString("status")
                    if (status == "pending") { update.value = Update("pending"); return@withLock }
                    if (status !in listOf("credited", "already_credited")) {
                        update.value = Update("expired"); return@withLock
                    }
                    // A lost response here is safe: the next owned-purchase query
                    // re-verifies idempotently before attempting finalization again.
                    suspendCancellableCoroutine<Unit> { continuation ->
                        fun complete(result: BillingResult) {
                            if (!continuation.isActive) return
                            if (result.responseCode == BillingClient.BillingResponseCode.OK) continuation.resume(Unit)
                            else continuation.resumeWithException(IllegalStateException("purchase confirmation failed"))
                        }
                        if (product == SINGLE) {
                            billing.consumeAsync(ConsumeParams.newBuilder().setPurchaseToken(purchase.purchaseToken).build()) { result, _ -> complete(result) }
                        } else if (!purchase.isAcknowledged) {
                            billing.acknowledgePurchase(AcknowledgePurchaseParams.newBuilder().setPurchaseToken(purchase.purchaseToken).build(), ::complete)
                        } else continuation.resume(Unit)
                    }
                    update.value = Update("credited", System.currentTimeMillis())
                } catch (_: Exception) { update.value = Update("failed") }
            }
        }
    }
}
