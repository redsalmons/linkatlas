import Foundation
import Network
import Security
import OSLog

private let httpLog = Logger(subsystem: "com.redsalmons.linkatlas", category: "PinnedHTTP")

/// Debug-only channel: device syslog is unreliable, so mirror key events
/// into Documents/lookupdbg.log which devicectl can pull back. No-op in
/// release builds so no per-request traffic is written to disk.
func dbgLog(_ msg: String) {
    #if DEBUG
    NSLog("[LinkAtlas] %@", msg)
    guard let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
    let url = dir.appendingPathComponent("lookupdbg.log")
    let line = "\(ISO8601DateFormatter().string(from: Date())) \(msg)\n"
    if let handle = try? FileHandle(forWritingTo: url) {
        handle.seekToEndOfFile()
        handle.write(Data(line.utf8))
        try? handle.close()
    } else {
        try? line.write(to: url, atomically: true, encoding: .utf8)
    }
    #endif
}

/// Minimal HTTPS client built on nw_connection so each request carries the
/// bundled client identity and validates the server against the bundled CA.
/// URLSession cannot be used: CFNetwork never issues the client-certificate
/// authentication challenge for identities that are not in the keychain, so
/// the server always sees an empty certificate and aborts the handshake.
final class PinnedHTTPClient {
    private let caCertificate: SecCertificate
    private let identityLock = NSLock()
    private var _identity: SecIdentity?
    private let queue = DispatchQueue(label: "com.redsalmons.linkatlas.pinned-http")

    private var identity: SecIdentity? {
        identityLock.lock()
        defer { identityLock.unlock() }
        return _identity
    }

    /// Called after device registration installs the server-issued client
    /// certificate. Connections before that use the bundled bootstrap
    /// identity, which the server restricts to challenge/register/refresh.
    func setIdentity(_ identity: SecIdentity) {
        identityLock.lock()
        _identity = identity
        identityLock.unlock()
    }

    init(bundle: Bundle = .main, caResource: String = "LookupCA") throws {
        guard let caURL = bundle.url(forResource: caResource, withExtension: "cer"),
              let caData = try? Data(contentsOf: caURL),
              let certificate = SecCertificateCreateWithData(nil, caData as CFData) else {
            throw URLError(.fileDoesNotExist)
        }
        self.caCertificate = certificate
    }

    private func peerTrusted(_ trust: sec_trust_t, host: String) -> Bool {
        let trustRef = sec_trust_copy_ref(trust).takeRetainedValue()
        SecTrustSetAnchorCertificates(trustRef, [caCertificate] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trustRef, true)
        var error: CFError?
        let ok = SecTrustEvaluateWithError(trustRef, &error)
        if !ok {
            httpLog.error("[PinnedHTTP] server trust rejected: \(error?.localizedDescription ?? "?")")
            dbgLog("[PinnedHTTP] server trust rejected: \(error?.localizedDescription ?? "?")")
        }
        return ok
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        guard let url = request.url, let host = url.host, url.scheme == "https" else {
            throw URLError(.badURL)
        }
        let port = url.port ?? 443
        let path = url.path.isEmpty ? "/" : url.path + (url.query.map { "?" + $0 } ?? "")
        let wireRequest = Self.encode(request, host: host, port: port, path: path)

        let tlsQueue = queue
        let identity = self.identity
        let configureTLS: @Sendable (nw_protocol_options_t) -> Void = { options in
            let sec = nw_tls_copy_sec_protocol_options(options)
            sec_protocol_options_set_tls_server_name(sec, host)
            sec_protocol_options_set_verify_block(sec, { [self] _, trust, complete in
                complete(self.peerTrusted(trust, host: host))
            }, tlsQueue)
            if let identity {
                if let secIdentity = sec_identity_create(identity) {
                    sec_protocol_options_set_local_identity(sec, secIdentity)
                    dbgLog("[PinnedHTTP] \(host): client identity set")
                } else {
                    dbgLog("[PinnedHTTP] \(host): sec_identity_create FAILED — no client cert")
                }
            } else {
                dbgLog("[PinnedHTTP] \(host): no identity — handshake will fail")
            }
        }
        let params = nw_parameters_create_secure_tcp(configureTLS, { _ in })
        let endpoint = nw_endpoint_create_host(host, "\(port)")
        let connection = nw_connection_create(endpoint, params)
        defer { nw_connection_cancel(connection) }

        let timeout = request.timeoutInterval > 0 ? request.timeoutInterval : 30
        let wire = try await Self.roundTrip(connection, payload: wireRequest, timeout: timeout)
        return try Self.decode(wire, url: url)
    }

    private static func encode(_ request: URLRequest, host: String, port: Int,
                               path: String) -> Data {
        var head = "\(request.httpMethod ?? "GET") \(path) HTTP/1.1\r\n"
        head += "Host: \(host)\(port == 443 ? "" : ":\(port)")\r\n"
        head += "Accept: application/json\r\n"
        head += "Connection: close\r\n"
        for (key, value) in request.allHTTPHeaderFields ?? [:] {
            head += "\(key): \(value)\r\n"
        }
        let body = request.httpBody ?? Data()
        head += "Content-Length: \(body.count)\r\n\r\n"
        return Data(head.utf8) + body
    }

    private static func roundTrip(_ connection: nw_connection_t, payload: Data,
                                  timeout: TimeInterval) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            let stateQueue = DispatchQueue(label: "com.redsalmons.linkatlas.pinned-http.state")
            let resumed = OSAllocatedUnfairLock(initialState: false)
            let finish: @Sendable (Result<Data, Error>) -> Void = { result in
                stateQueue.async {
                    let already = resumed.withLock { flag -> Bool in
                        defer { flag = true }; return flag
                    }
                    guard !already else { return }
                    cont.resume(with: result)
                }
            }
            stateQueue.asyncAfter(deadline: .now() + timeout) {
                nw_connection_cancel(connection)
                finish(.failure(URLError(.timedOut)))
            }

            nw_connection_set_queue(connection, stateQueue)
            nw_connection_set_state_changed_handler(connection) { state, error in
                switch state {
                case nw_connection_state_ready:
                    payload.withUnsafeBytes { bytes in
                        nw_connection_send(connection,
                                           DispatchData(bytes: bytes) as dispatch_data_t,
                                           nw_content_context_create("request"),
                                           false) { sendError in
                            if let sendError {
                                finish(.failure(Self.err(sendError)))
                            } else {
                                receiveAll(connection, Data(), finish)
                            }
                        }
                    }
                case nw_connection_state_failed, nw_connection_state_cancelled:
                    finish(.failure(error.map(Self.err) ?? URLError(.cannotConnectToHost)))
                default:
                    break
                }
            }
            nw_connection_start(connection)
        }
    }

    private static func receiveAll(_ connection: nw_connection_t, _ buffer: Data,
                                   _ finish: @escaping @Sendable (Result<Data, Error>) -> Void) {
        nw_connection_receive(connection, 1, 1 << 20) { content, _, isComplete, error in
            var next = buffer
            if let content { next.append(Data(content as DispatchData)) }
            if let error {
                finish(.failure(err(error)))
            } else if isComplete {
                finish(.success(next))
            } else {
                receiveAll(connection, next, finish)
            }
        }
    }

    private static func err(_ error: nw_error_t) -> Error {
        let msg = "nw_error domain=\(nw_error_get_error_domain(error).rawValue) code=\(nw_error_get_error_code(error))"
        httpLog.error("[PinnedHTTP] \(msg)")
        dbgLog("[PinnedHTTP] \(msg)")
        return NSError(domain: "nw_error", code: Int(nw_error_get_error_code(error)))
    }

    private static func decode(_ wire: Data, url: URL) throws -> (Data, URLResponse) {
        guard let headerEnd = wire.range(of: Data("\r\n\r\n".utf8)) else {
            throw URLError(.cannotParseResponse)
        }
        let head = String(data: wire[..<headerEnd.lowerBound], encoding: .utf8) ?? ""
        var lines = head.components(separatedBy: "\r\n")
        guard let statusLine = lines.first,
              let statusCode = Int(statusLine.split(separator: " ").dropFirst().first ?? "") else {
            throw URLError(.cannotParseResponse)
        }
        lines.removeFirst()
        var headers: [String: String] = [:]
        for line in lines where !line.isEmpty {
            if let idx = line.firstIndex(of: ":") {
                headers[String(line[..<idx]).trimmingCharacters(in: .whitespaces).lowercased()] =
                    String(line[line.index(after: idx)...]).trimmingCharacters(in: .whitespaces)
            }
        }
        var body = Data(wire[headerEnd.upperBound...])
        if headers["transfer-encoding"]?.lowercased().contains("chunked") == true {
            body = try decodeChunked(body)
        } else if let length = headers["content-length"].flatMap(Int.init), body.count > length {
            body = body.prefix(length)
        }
        let response = HTTPURLResponse(url: url, statusCode: statusCode,
                                       httpVersion: "HTTP/1.1", headerFields: headers)!
        return (body, response)
    }

    private static func decodeChunked(_ data: Data) throws -> Data {
        var out = Data()
        var rest = data[...]
        let crlf = Data("\r\n".utf8)
        while true {
            guard let lineEnd = rest.range(of: crlf) else { throw URLError(.cannotParseResponse) }
            let sizeLine = String(data: rest[..<lineEnd.lowerBound], encoding: .utf8) ?? ""
            guard let size = Int(sizeLine.split(separator: ";").first.map(String.init) ?? "", radix: 16) else {
                throw URLError(.cannotParseResponse)
            }
            rest = rest[lineEnd.upperBound...]
            if size == 0 { break }
            guard rest.count >= size + 2 else { throw URLError(.cannotParseResponse) }
            out.append(rest.prefix(size))
            rest = rest.dropFirst(size + 2)
        }
        return out
    }
}
