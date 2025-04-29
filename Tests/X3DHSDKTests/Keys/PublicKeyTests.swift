import XCTest
import CryptoKit
@testable import X3DHSDK

final class PublicKeyTests: XCTestCase {

    func testPublicKeySerializationDeserialization() throws {
        let privateKey = PrivateKey()
        let publicKey = privateKey.publicKey()

        let exportedData = publicKey.rawRepresentation()
        let restoredPublicKey = try PublicKey(data: exportedData)
        let restoredData = restoredPublicKey.rawRepresentation()

        XCTAssertEqual(exportedData, restoredData, "Сериализация и десериализация публичного ключа должны быть эквивалентны")
    }
}

