import XCTest
import CryptoKit
@testable import X3DHSDK

final class ForwardSecrecySessionCipherTests: XCTestCase {

    func testForwardSecrecyMessageExchange() throws {
        let identityKeyA = PrivateKey()
        let signingKeyA = SigningPrivateKey()

        let identityKeyB = PrivateKey()
        let signingKeyB = SigningPrivateKey()

        let publicKeyA = identityKeyA.publicKey()
        let signingPublicKeyA = signingKeyA.publicKey()

        let publicKeyB = identityKeyB.publicKey()
        let signingPublicKeyB = signingKeyB.publicKey()

        let senderCipher = ForwardSecrecySessionCipher(
            myIdentityKey: identityKeyA,
            theirIdentityPublicKey: publicKeyB
        )

        let receiverCipher = ForwardSecrecySessionCipher(
            myIdentityKey: identityKeyB,
            theirIdentityPublicKey: publicKeyA
        )

        for i in 1...50 {
            let message = randomUnicodeString(length: Int.random(in: 5...50))
            let messageData = message.data(using: .utf8)!

            let (ciphertext, ephemeralPublicKey, signature) = try senderCipher.encrypt(
                message: messageData,
                signingKey: signingKeyA
            )

            XCTContext.runActivity(named: "Message \(i)") { _ in
                print("\n[\(i)] ORIGINAL: \(message)")
                print("[\(i)] ENCRYPTED (hex): \(ciphertext.hexEncodedString())")
            }

            let decryptedData = try receiverCipher.decrypt(
                ciphertext: ciphertext,
                senderEphemeralPublicKey: ephemeralPublicKey,
                signature: signature,
                senderSigningPublicKey: signingPublicKeyA
            )

            guard let decryptedMessage = String(data: decryptedData, encoding: .utf8) else {
                XCTFail("[\(i)] Не удалось декодировать сообщение из данных")
                return
            }

            XCTContext.runActivity(named: "Decrypted Message \(i)") { _ in
                print("[\(i)] DECRYPTED: \(decryptedMessage)")
            }

            XCTAssertEqual(decryptedMessage, message, "Сообщение после шифрования и дешифрования должно совпадать")
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

private extension Data {
    func hexEncodedString() -> String {
        self.map { String(format: "%02hhx", $0) }.joined()
    }
}

private extension UnicodeScalar {
    var isPrintable: Bool {
        (0x20...0x7E).contains(value) ||
        (0xA0...0x1FFF).contains(value) ||
        (0x2000...0x2FFF).contains(value) ||
        (0x3000...0xD7FF).contains(value) ||
        (0xE000...0xFFFF).contains(value)
    }
}
