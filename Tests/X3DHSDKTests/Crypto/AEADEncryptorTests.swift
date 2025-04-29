import XCTest
import CryptoKit
@testable import X3DHSDK

final class AEADEncryptorTests: XCTestCase {

    func testEncryptDecrypt() throws {
        let key = SymmetricKey(size: .bits256)
        print(key)
        let message = "Тестовое сообщение".data(using: .utf8)!

        let ciphertext = try AEADEncryptor.encrypt(plaintext: message, key: key)
        print(ciphertext)
        let decrypted = try AEADEncryptor.decrypt(ciphertext: ciphertext, key: key)
        print(decrypted)

        XCTAssertEqual(decrypted, message, "Расшифрованное сообщение должно совпадать с оригиналом")
    }
    
    func testDecryptWithWrongKeyFails() throws {
        let key = SymmetricKey(size: .bits256)
        print(key)
        let wrongKey = SymmetricKey(size: .bits256)
        print(wrongKey)

        let message = "Тест фейла при дешифровке".data(using: .utf8)!
        let ciphertext = try AEADEncryptor.encrypt(plaintext: message, key: key)
        print(ciphertext)

        XCTAssertThrowsError(try AEADEncryptor.decrypt(ciphertext: ciphertext, key: wrongKey), "Дешифрование неправильным ключом должно выбрасывать ошибку")
    }
}
