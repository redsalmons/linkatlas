import Foundation
import StoreKit

/// StoreKit 2 wrapper for lookupaddress.single and lookupaddress.pro.
/// Purchases are verified server-side before being considered "credited".
@MainActor
final class LookupBilling: ObservableObject {
    static let shared = LookupBilling()

    static let singleProductID = "lookupaddress.single"
    static let proProductID = "lookupaddress.pro"
    static let proYearProductID = "lookupaddress.pro.year"
    static let allProductIDs: Set<String> = [singleProductID, proProductID, proYearProductID]

    enum PurchaseState: Equatable {
        case idle
        case paying
        case verifying
        case pending
        case failed
        case expired
        case cancelled
        case credited(sequence: Int)
    }

    @Published var products: [String: Product] = [:]
    @Published var purchaseState: PurchaseState = .idle

    private var updateTask: Task<Void, Never>?
    private var creditedSequence = 0

    private init() {
        updateTask = listenForTransactions()
    }

    deinit {
        updateTask?.cancel()
    }

    // MARK: - Products

    func loadProducts() async {
        do {
            let fetched = try await Product.products(for: Array(Self.allProductIDs))
            var map: [String: Product] = [:]
            for product in fetched { map[product.id] = product }
            products = map
            NSLog("[Lookup] products: \(fetched.map { $0.id })")
        } catch {
            products = [:]
            NSLog("[Lookup] loadProducts failed: \(error)")
        }
    }

    func price(for productId: String) -> String? {
        guard let product = products[productId] else { return nil }
        return product.displayPrice
    }

    // MARK: - Purchase

    func buy(productId: String) async {
        guard isTerminal(purchaseState) else { return }
        guard let product = products[productId] else {
            purchaseState = .failed
            return
        }

        purchaseState = .paying

        do {
            let result = try await product.purchase()
            switch result {
            case .success(let verification):
                await handleVerification(verification, productId: productId)
            case .userCancelled:
                purchaseState = .cancelled
            case .pending:
                purchaseState = .pending
            @unknown default:
                purchaseState = .failed
            }
        } catch {
            purchaseState = .failed
        }
    }

    private func handleVerification(_ verification: VerificationResult<Transaction>,
                                    productId: String) async {
        purchaseState = .verifying
        // Extract JWS before unwrapping — it is the receipt the server verifies.
        let jws = verification.jwsRepresentation
        guard case .verified(let transaction) = verification else {
            purchaseState = .failed
            return
        }
        await verifyWithServer(jws: jws, transaction: transaction, productId: productId)
    }

    private func verifyWithServer(jws: String, transaction: Transaction, productId: String) async {
        guard let api = LookupServiceClient.shared else {
            purchaseState = .failed
            return
        }
        do {
            let transactionId = transaction.originalID.description
            let response = try await api.verify(
                product: productId,
                receipt: jws,
                transaction: transactionId
            )

            let status = response["status"] as? String ?? ""
            if status == "credited" || status == "already_credited" {
                creditedSequence += 1
                purchaseState = .credited(sequence: creditedSequence)
                await transaction.finish()
            } else if status == "pending" {
                purchaseState = .pending
            } else if status == "expired" || status == "revoked" {
                purchaseState = .expired
            } else {
                purchaseState = .failed
            }
        } catch {
            // Network failure — keep transaction unfinished for retry.
            purchaseState = .failed
        }
    }

    // MARK: - Restore

    func restorePurchases() async {
        purchaseState = .verifying
        for await result in Transaction.currentEntitlements {
            let jws = result.jwsRepresentation
            guard case .verified(let transaction) = result else { continue }
            let productId = transaction.productID
            guard Self.allProductIDs.contains(productId) else { continue }
            await verifyWithServer(jws: jws, transaction: transaction, productId: productId)
        }
        if case .verifying = purchaseState {
            purchaseState = .idle
        }
    }

    // MARK: - Transaction Listener

    private func listenForTransactions() -> Task<Void, Never> {
        Task {
            for await result in Transaction.updates {
                let jws = result.jwsRepresentation
                guard case .verified(let transaction) = result else { continue }
                let productId = transaction.productID
                guard Self.allProductIDs.contains(productId) else { continue }
                await verifyWithServer(jws: jws, transaction: transaction, productId: productId)
            }
        }
    }

    // MARK: - Helpers

    private func isTerminal(_ state: PurchaseState) -> Bool {
        switch state {
        case .idle, .cancelled, .failed, .expired, .credited:
            return true
        case .paying, .verifying, .pending:
            return false
        }
    }
}
