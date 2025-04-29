import Foundation
import CryptoKit

/// A utility for deriving symmetric encryption keys using HKDF.
public struct KeyDerivation {

    /// Derives a symmetric key from a shared secret using HKDF and SHA256.
    ///
    /// - Parameter sharedSecret: The `SharedSecret` resulting from key agreement.
    /// - Returns: A `SymmetricKey` suitable for AEAD encryption.
    public static func deriveSymmetricKey(sharedSecret: SharedSecret) -> SymmetricKey {
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "X3DHSDK-Salt".data(using: .utf8)!,
            sharedInfo: Data(),
            outputByteCount: 32
        )
    }

    /// Derives a symmetric key from raw data using HKDF and SHA256.
    ///
    /// This is useful when combining multiple shared secrets into one blob of data,
    /// for cases like multi-stage handshakes.
    ///
    /// - Parameter data: The raw input key material.
    /// - Returns: A `SymmetricKey` derived from the provided data.
    public static func deriveSymmetricKey(data: Data) -> SymmetricKey {
        let symmetricKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: data),
            salt: "X3DHSDK-Salt".data(using: .utf8)!,
            info: Data(),
            outputByteCount: 32
        )
        return symmetricKey
    }
}
