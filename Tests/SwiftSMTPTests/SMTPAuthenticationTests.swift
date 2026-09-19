import Foundation
import Testing
@testable import SwiftMail

/// These tests pin the two things that made an SMTP login failure impossible to
/// diagnose from the outside: the EHLO argument the client sends, and the message
/// it reports when no password mechanism was offered.
@Suite(.serialized, .timeLimit(.minutes(1)))
struct SMTPAuthenticationTests {

    // MARK: - EHLO hostname

    @Test
    func validHostnamePassesThroughUnchanged() {
        // The important half: nothing changes for the servers this already works
        // with. A hostname that is a legal Domain must not be rewritten.
        #expect(SMTPServer.ehloHostname("Christians-iPhone.local") == "Christians-iPhone.local")
        #expect(SMTPServer.ehloHostname("mail.example.com") == "mail.example.com")
        #expect(SMTPServer.ehloHostname("localhost") == "localhost")
    }

    @Test
    func spacesAndNonASCIIAreReplaced() {
        // A space makes `EHLO a b` a syntactically wrong command; an umlaut is not
        // allowed in a Domain without SMTPUTF8.
        #expect(SMTPServer.ehloHostname("Christians iPhone") == "Christians-iPhone")
        #expect(SMTPServer.ehloHostname("Höpkers iPad.local") == "H-pkers-iPad.local")
    }

    @Test
    func unusableHostnameFallsBackToLocalhost() {
        // An empty EHLO argument is a protocol error, so there has to be a
        // fallback — and it has to be a legal Domain.
        #expect(SMTPServer.ehloHostname("") == "localhost")
        #expect(SMTPServer.ehloHostname("...") == "localhost")
        #expect(SMTPServer.ehloHostname("   ") == "localhost")
        #expect(SMTPServer.ehloHostname("--") == "localhost")
    }

    @Test
    func leadingAndTrailingHyphensAreTrimmedPerLabel() {
        #expect(SMTPServer.ehloHostname(" iPad ") == "iPad")
        #expect(SMTPServer.ehloHostname("a b.c d") == "a-b.c-d")
    }

    // MARK: - "no supported mechanism" message

    @Test
    func emptyCapabilitiesSayThatNothingWasAdvertised() {
        let message = SMTPServer.noSupportedMechanismMessage(capabilities: [])

        // This is the case that used to be indistinguishable from a rejected
        // password: no command was ever sent.
        #expect(message.contains("no AUTH mechanism at all"))
        #expect(message.contains("0 EHLO capabilities"))
    }

    @Test
    func oAuthOnlyServerIsNamedInTheMessage() {
        let message = SMTPServer.noSupportedMechanismMessage(
            capabilities: ["SIZE 35882577", "AUTH", "AUTH XOAUTH2", "AUTH OAUTHBEARER"]
        )

        #expect(message.contains("XOAUTH2"))
        #expect(message.contains("OAUTHBEARER"))
        #expect(message.contains("neither PLAIN nor LOGIN"))
        // `AUTH` on its own is a marker, not a mechanism — it must not be listed.
        #expect(!message.contains(", ,"))
    }

    // MARK: - EHLO capability parsing

    @Test
    func gmailEHLOReplyYieldsPlainAndLoginMechanisms() async {
        // Verbatim shape of what Gmail answers on port 465, as the response
        // handler accumulates it (all lines, code prefixes intact). If AUTH PLAIN
        // is missing here, `login` sends nothing at all and reports a failure that
        // never involved the credentials.
        let reply = """
            250-smtp.gmail.com at your service, [203.0.113.7]
            250-SIZE 35882577
            250-8BITMIME
            250-AUTH LOGIN PLAIN XOAUTH2 PLAIN-CLIENTTOKEN OAUTHBEARER XOAUTH
            250-ENHANCEDSTATUSCODES
            250-PIPELINING
            250-CHUNKING
            250 SMTPUTF8
            """

        let server = SMTPServer(host: "smtp.gmail.com", port: 465, transportSecurity: .implicitTLS)
        let capabilities = await server.parseCapabilities(from: reply)

        #expect(capabilities.contains("AUTH PLAIN"))
        #expect(capabilities.contains("AUTH LOGIN"))
        #expect(capabilities.contains("AUTH XOAUTH2"))
        #expect(capabilities.contains("8BITMIME"))
        #expect(capabilities.contains("SIZE 35882577"))
    }
}
