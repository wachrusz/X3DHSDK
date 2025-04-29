import XCTest
import CryptoKit
@testable import X3DHSDK

final class RealUnicodeChatSimulationTests: XCTestCase {

    func testUnicodeChatBetweenUsers() throws {
        let identityKeyA = PrivateKey()
        let identityKeyB = PrivateKey()
        let signedPreKeyB = PrivateKey()

        let publicIdentityKeyB = identityKeyB.publicKey()
        let publicSignedPreKeyB = signedPreKeyB.publicKey()

        let initiator = HandshakeInitiator(identityKey: identityKeyA)
        let symmetricKeyA = try initiator.performHandshake(
            recipientIdentityKey: publicIdentityKeyB,
            recipientSignedPreKey: publicSignedPreKeyB
        )
        let ephemeralPublicKeyA = initiator.ephemeralPublicKey()

        let responder = HandshakeResponder(identityKey: identityKeyB, signedPreKey: signedPreKeyB)
        let symmetricKeyB = try responder.performHandshake(
            senderIdentityKey: identityKeyA.publicKey(),
            senderEphemeralKey: ephemeralPublicKeyA
        )

        XCTAssertEqual(
            symmetricKeyA.withUnsafeBytes { Data($0) },
            symmetricKeyB.withUnsafeBytes { Data($0) },
            "Symmetric keys after handshake should match"
        )

        let sessionCipherA = SessionCipher(privateKey: identityKeyA.internalKey, remotePublicKey: identityKeyB.publicKey().raw)
        let sessionCipherB = SessionCipher(privateKey: identityKeyB.internalKey, remotePublicKey: identityKeyA.publicKey().raw)

        for i in 1...50 {
            let randomMessage = randomUnicodeString(length: Int.random(in: 5...50))
            let messageData = randomMessage.data(using: .utf8)!

            let encryptedMessage = try sessionCipherA.encrypt(message: messageData)
            let decryptedData = try sessionCipherB.decrypt(ciphertext: encryptedMessage)
            let decryptedMessage = String(data: decryptedData, encoding: .utf8)

            XCTContext.runActivity(named: "Message \(i)") { _ in
                print("[\(i)] A -> B | Original: \(randomMessage)")
                print("[\(i)] A -> B | Decrypted: \(decryptedMessage ?? "<decode error>")\n")
            }

            XCTAssertEqual(decryptedMessage, randomMessage, "Unicode сообщение должно правильно дешифроваться")
        }
    }

    private func randomUnicodeString(length: Int) -> String {
        var string = ""
        for _ in 0..<length {
            let scalarValue = UInt32.random(in: 0x20...0x1F9FF)
            if let scalar = UnicodeScalar(scalarValue), scalar.isPrintable {
                string.append(Character(scalar))
            }
        }
        return string
    }
}

private extension UnicodeScalar {
    var isPrintable: Bool {
        return (0x20...0x7E).contains(value) || (0xA0...0x1FFF).contains(value) || (0x2000...0x2FFF).contains(value) || (0x3000...0xD7FF).contains(value) || (0xE000...0xFFFF).contains(value)
    }
}
