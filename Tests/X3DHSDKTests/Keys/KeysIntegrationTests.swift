import XCTest
import CryptoKit
@testable import X3DHSDK

final class KeysIntegrationTests: XCTestCase {

    func testSharedSecretDerivation() throws {
        let userAPrivate = PrivateKey()
        let userBPrivate = PrivateKey()

        let userAPublic = userAPrivate.publicKey()
        let userBPublic = userBPrivate.publicKey()

        let sharedSecretA = try userAPrivate.sharedSecret(with: userBPublic)
        let sharedSecretB = try userBPrivate.sharedSecret(with: userAPublic)

        let sharedDataA = sharedSecretA.ssData()
        let sharedDataB = sharedSecretB.ssData()

        XCTAssertEqual(sharedDataA, sharedDataB, "Shared secrets должны совпадать при правильном обмене ключами")
    }
}

private extension SharedSecret {
    func ssData() -> Data {
        return self.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        ).withUnsafeBytes { Data($0) }
    }
}
