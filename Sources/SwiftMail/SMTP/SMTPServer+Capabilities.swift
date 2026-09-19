// SMTPServer+Capabilities.swift
// EHLO capability parsing and SIZE/8BITMIME helpers for SMTPServer.

import Foundation

extension SMTPServer {

    /// The name sent as the EHLO argument.
    ///
    /// RFC 5321 requires a Domain or an address-literal there — letters, digits,
    /// hyphens and dots. A device name does not have to satisfy that: on iOS
    /// `ProcessInfo.hostName` is derived from the user-chosen device name and may
    /// carry spaces or non-ASCII ("Höpkers iPad"). A space turns `EHLO a b` into a
    /// syntactically wrong command, and a strict server answers 501 — which the
    /// client then reports as a connection failure, pointing at everything except
    /// the real cause.
    ///
    /// A hostname that is already valid passes through untouched, so nothing
    /// changes for the servers this works with today.
    static func ehloHostname(_ raw: String = ProcessInfo.processInfo.hostName) -> String {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        let sanitized = String(raw.map { allowed.contains($0) ? $0 : "-" })
            .split(separator: ".", omittingEmptySubsequences: true)
            .map { label -> String in
                var trimmed = label
                while trimmed.first == "-" { trimmed = trimmed.dropFirst() }
                while trimmed.last == "-" { trimmed = trimmed.dropLast() }
                return String(trimmed)
            }
            .filter { !$0.isEmpty }
            .joined(separator: ".")

        // Nothing usable left (empty name, or only punctuation): `localhost` is a
        // valid Domain and every server accepts it. Sending an empty argument
        // would be a protocol error.
        return sanitized.isEmpty ? "localhost" : sanitized
    }

    /**
     Fetch server capabilities using EHLO command

     This method sends the EHLO command to the server and processes its response
     to determine the server's supported features. It's called automatically during
     connection and after STARTTLS, but can be called manually if needed.

     - Returns: Array of capability strings reported by the server
     - Throws:
       - `SMTPError.commandFailed` if the EHLO command fails
       - `SMTPError.connectionFailed` if not connected
     - Note: Updates the internal capabilities array with the server's response
     */
    @discardableResult
    public func fetchCapabilities() async throws -> [String] {
        let command = EHLOCommand(hostname: Self.ehloHostname())

        do {
            let response = try await executeCommand(command)

            // Parse the capabilities from the raw response
            let capabilities = parseCapabilities(from: response)

            // Store capabilities for later use
            self.capabilities = capabilities

            return capabilities
        } catch {
            throw error
        }
    }

    /**
     Parse server capabilities from EHLO response
     - Parameter response: The EHLO response message
     - Returns: Array of server capabilities
     */
    func parseCapabilities(from response: String) -> [String] {
        // Create a new array for capabilities
        var parsedCapabilities = [String]()

        // Split the response into lines
        let lines = response.split(separator: "\n")

        // Process each line (skip the first line which is the greeting)
        for line in lines.dropFirst() {
            // Extract the capability (remove the response code prefix if present)
            let capabilityLine = line.trimmingCharacters(in: .whitespacesAndNewlines)

            // For EHLO responses, each line starts with a response code (e.g., "250-AUTH LOGIN PLAIN")
            let prefix = capabilityLine.prefix(4)
            if capabilityLine.count > 4 && (prefix.hasPrefix("250-") || prefix.hasPrefix("250 ")) {
                // Extract the capability (after the response code)
                let capabilityPart = capabilityLine.dropFirst(4).trimmingCharacters(in: .whitespaces)

                // Special handling for AUTH capability which may list multiple methods
                if capabilityPart.hasPrefix("AUTH ") {
                    // Add the base AUTH capability
                    parsedCapabilities.append("AUTH")

                    // Extract and add each individual auth method
                    let authMethods = capabilityPart.dropFirst(5).split(separator: " ")

                    for method in authMethods {
                        let authMethod = "AUTH \(method)"
                        parsedCapabilities.append(authMethod)
                    }
                } else {
                    // For other capabilities, add them as-is
                    parsedCapabilities.append(capabilityPart)
                }
            }
        }

        return parsedCapabilities
    }

    static func maximumMessageSizeOctets(from capabilities: [String]) -> Int? {
        for capability in capabilities {
            guard capability.hasPrefix("SIZE ") else { continue }
            let value = capability.dropFirst("SIZE ".count).trimmingCharacters(in: .whitespaces)
            guard let octets = Int(value), octets > 0 else { continue }
            return octets
        }
        return nil
    }
}
