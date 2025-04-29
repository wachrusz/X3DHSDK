import XCTest
import CryptoKit
@testable import X3DHSDK

final class MessageEncryptorTests: XCTestCase {

    func testEncryptDecryptWithoutAdditionalKey() throws {
        let myPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let theirPrivateKey = Curve25519.KeyAgreement.PrivateKey()

        let myPublicKey = myPrivateKey.publicKey
        let theirPublicKey = theirPrivateKey.publicKey

        let senderCipher = SessionCipher(privateKey: myPrivateKey, remotePublicKey: theirPublicKey)
        let receiverCipher = SessionCipher(privateKey: theirPrivateKey, remotePublicKey: myPublicKey)

        let senderEncryptor = MessageEncryptor(sessionCipher: senderCipher)
        let receiverEncryptor = MessageEncryptor(sessionCipher: receiverCipher)

        let message = "Привет, мир!".data(using: .utf8)!

        let encrypted = try senderEncryptor.encrypt(message: message)
        let decrypted = try receiverEncryptor.decrypt(ciphertext: encrypted)

        XCTAssertEqual(decrypted, message, "Сообщение после дешифрования должно совпадать с оригиналом")
    }

    func testEncryptDecryptWithAdditionalKey() throws {
        let myPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let theirPrivateKey = Curve25519.KeyAgreement.PrivateKey()

        let myPublicKey = myPrivateKey.publicKey
        let theirPublicKey = theirPrivateKey.publicKey

        let senderCipher = SessionCipher(privateKey: myPrivateKey, remotePublicKey: theirPublicKey)
        let receiverCipher = SessionCipher(privateKey: theirPrivateKey, remotePublicKey: myPublicKey)

        let additionalKey = SymmetricKey(size: .bits256)

        let senderEncryptor = MessageEncryptor(sessionCipher: senderCipher, additionalKey: additionalKey)
        let receiverEncryptor = MessageEncryptor(sessionCipher: receiverCipher, additionalKey: additionalKey)

        let message = "Тестирование двойного шифрования".data(using: .utf8)!

        let encrypted = try senderEncryptor.encrypt(message: message)
        let decrypted = try receiverEncryptor.decrypt(ciphertext: encrypted)

        XCTAssertEqual(decrypted, message, "Сообщение после двойного дешифрования должно совпадать с оригиналом")
    }

    func testDecryptFailsWithWrongAdditionalKey() throws {
        let myPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let theirPrivateKey = Curve25519.KeyAgreement.PrivateKey()

        let myPublicKey = myPrivateKey.publicKey
        let theirPublicKey = theirPrivateKey.publicKey

        let senderCipher = SessionCipher(privateKey: myPrivateKey, remotePublicKey: theirPublicKey)
        let receiverCipher = SessionCipher(privateKey: theirPrivateKey, remotePublicKey: myPublicKey)

        let correctAdditionalKey = SymmetricKey(size: .bits256)
        let wrongAdditionalKey = SymmetricKey(size: .bits256)

        let senderEncryptor = MessageEncryptor(sessionCipher: senderCipher, additionalKey: correctAdditionalKey)
        let receiverEncryptor = MessageEncryptor(sessionCipher: receiverCipher, additionalKey: wrongAdditionalKey)

        let message = "Должно провалиться".data(using: .utf8)!

        let encrypted = try senderEncryptor.encrypt(message: message)

        XCTAssertThrowsError(try receiverEncryptor.decrypt(ciphertext: encrypted), "Дешифрование неправильным дополнительным ключом должно выбрасывать ошибку")
    }
}
