import XCTest
import CryptoKit
@testable import X3DHSDK

final class SessionCipherTests: XCTestCase {
    
    func testEncryptDecryptSuccess() throws {
        let myPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let theirPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let myPublicKey = myPrivateKey.publicKey
        let theirPublicKey = theirPrivateKey.publicKey

        let myCipher = SessionCipher(privateKey: myPrivateKey, remotePublicKey: theirPublicKey)
        let theirCipher = SessionCipher(privateKey: theirPrivateKey, remotePublicKey: myPublicKey)

        let message = "Привет, криптомир!".data(using: .utf8)!

        let ciphertext = try myCipher.encrypt(message: message)

        let decryptedMessage = try theirCipher.decrypt(ciphertext: ciphertext)

        XCTAssertEqual(decryptedMessage, message, "Дешифрованное сообщение должно совпадать с оригиналом")
    }
    
    func testDecryptWithWrongKeyFails() throws {
        let myPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let theirPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let wrongPrivateKey = Curve25519.KeyAgreement.PrivateKey()

        let myPublicKey = myPrivateKey.publicKey
        let theirPublicKey = theirPrivateKey.publicKey

        let myCipher = SessionCipher(privateKey: myPrivateKey, remotePublicKey: theirPublicKey)
        let wrongCipher = SessionCipher(privateKey: wrongPrivateKey, remotePublicKey: theirPublicKey)

        let message = "Это должно зафейлиться.".data(using: .utf8)!
        
        let ciphertext = try myCipher.encrypt(message: message)

        XCTAssertThrowsError(try wrongCipher.decrypt(ciphertext: ciphertext), "Дешифрование неправильным ключом должно выбрасывать ошибку")
    }
}
