import XCTest
import CryptoKit
@testable import X3DHSDK

final class PrivateKeyTests: XCTestCase {

    func testPrivateKeyGeneration() {
        let privateKey = PrivateKey()
        let data = privateKey.rawRepresentation()
        
        XCTAssertEqual(data.count, 32, "Размер приватного ключа должен быть 32 байта для Curve25519")
    }

    func testPrivateKeySerializationDeserialization() throws {
        let originalKey = PrivateKey()
        let exportedData = originalKey.rawRepresentation()

        let restoredKey = try PrivateKey(data: exportedData)
        let restoredData = restoredKey.rawRepresentation()

        XCTAssertEqual(exportedData, restoredData, "Сериализация и десериализация должны быть эквивалентны")
    }
}
