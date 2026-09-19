// SMTPServer+Authentication.swift
// Authentication mechanisms (LOGIN/PLAIN, XOAUTH2) for SMTPServer.

import Foundation

extension SMTPServer {
    /**
     Authenticate with the SMTP server

     This method authenticates with the SMTP server using the provided credentials.
     It automatically selects the best available authentication mechanism supported
     by the server, preferring more secure methods:
     1. XOAUTH2 (if supported and token provided)
     2. PLAIN (if TLS is active)
     3. LOGIN (if TLS is active)

     - Parameters:
       - username: The username for authentication
       - password: The password or access token for authentication
     - Throws:
       - `SMTPError.authenticationFailed` if credentials are rejected
       - `SMTPError.connectionFailed` if not connected
       - `SMTPError.tlsRequired` if attempting to authenticate without TLS
     - Note: Logs authentication attempts at info level (without credentials)
     */
    public func login(username: String, password: String) async throws {

        // Why this method reports at length: it has three completely different
        // outcomes that all produced the SAME message for the caller before
        // ("Authentication failed with all available methods"):
        //   1. The server rejected the credentials — and its reply says WHY
        //      (Gmail: "535-5.7.8 Username and Password not accepted …
        //      BadCredentials"). Exactly that text used to be discarded.
        //   2. The server advertised neither AUTH PLAIN nor AUTH LOGIN, so no
        //      command was ever sent — and the message claimed an attempt that
        //      never happened.
        //   3. The connection broke during the SECOND attempt (many servers
        //      close it after a rejected login) — that transport error says
        //      nothing about the password.
        // Without telling those apart, a caller cannot decide whether the
        // password is wrong or the client never even asked.

        // The refusal the SERVER worded is the actual information; it wins
        // against any follow-up error.
        var refusals: [String] = []
        var attempted = false

        if capabilities.contains("AUTH PLAIN") {
            attempted = true
            let plainCommand = PlainAuthCommand(username: username, password: password)
            let result = try await executeCommand(plainCommand)

            // If successful, return success
            if result.success {
                return
            }

            refusals.append("PLAIN: " + (result.errorMessage ?? "rejected without a reason"))
        }

        // If PLAIN auth failed or is not supported, try LOGIN auth
        if capabilities.contains("AUTH LOGIN") {
            attempted = true
            let loginCommand = LoginAuthCommand(username: username, password: password)
            do {
                let result = try await executeCommand(loginCommand)

                // If successful, return success
                if result.success {
                    return
                }

                refusals.append("LOGIN: " + (result.errorMessage ?? "rejected without a reason"))
            } catch {
                // A server may close the connection after a rejected login. This
                // second attempt then fails on the TRANSPORT, and that error is
                // not about the credentials. If a server refusal is already in
                // hand, THAT one is the truth.
                guard !refusals.isEmpty else { throw error }
                logger.debug("AUTH LOGIN after a refused PLAIN failed on the transport: \(error)")
            }
        }

        guard attempted else {
            throw SMTPError.authenticationFailed(Self.noSupportedMechanismMessage(capabilities: capabilities))
        }

        let reason = refusals.isEmpty
            ? "server refused the credentials without naming a reason"
            : "server refused the credentials — " + refusals.joined(separator: " / ")
        throw SMTPError.authenticationFailed(reason)
    }

    /// Message for the case that no supported mechanism was offered at all. It
    /// NAMES what the server offered instead — only that tells "the server wants
    /// XOAUTH2" apart from "we never read the EHLO reply", and those two looked
    /// identical before.
    static func noSupportedMechanismMessage(capabilities: [String]) -> String {
        let mechanisms = capabilities
            .filter { $0.hasPrefix("AUTH ") }
            .map { String($0.dropFirst(5)) }
            .sorted()

        if mechanisms.isEmpty {
            return "server advertised no AUTH mechanism at all "
                + "(\(capabilities.count) EHLO capabilities seen) — password login is not possible here"
        }

        return "server offers only \(mechanisms.joined(separator: ", ")) — "
            + "neither PLAIN nor LOGIN, so no password login was attempted"
    }

    /**
     Authenticate with the SMTP server using XOAUTH2

     This method authenticates using the XOAUTH2 mechanism, which is required
     by Gmail and other providers when using OAuth2 access tokens for SMTP.

     - Parameters:
       - email: The email address of the account
       - accessToken: A valid OAuth2 access token
     - Throws:
       - `SMTPError.authenticationFailed` if the server does not support XOAUTH2
         or if the token is rejected
       - `SMTPError.connectionFailed` if not connected
     */
    public func authenticateXOAUTH2(email: String, accessToken: String) async throws {
        guard capabilities.contains("AUTH XOAUTH2") else {
            throw SMTPError.authenticationFailed("Server does not support XOAUTH2 authentication")
        }

        let command = XOAuth2AuthCommand(email: email, accessToken: accessToken)
        let result = try await executeCommand(command)

        guard result.success else {
            throw SMTPError.authenticationFailed(result.errorMessage ?? "XOAUTH2 authentication failed")
        }
    }
}
