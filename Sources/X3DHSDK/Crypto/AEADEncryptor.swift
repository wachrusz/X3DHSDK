import Foundation
import CryptoKit

/// Utility for performing AEAD encryption and decryption using ChaCha20-Poly1305.
internal struct AEADEncryptor {

    /// Encrypts the given plaintext using ChaCha20-Poly1305 with the provided symmetric key.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - key: The symmetric key used for encryption.
    /// - Returns: A combined sealed box containing the nonce, ciphertext, and tag.
    /// - Throws: `X3DHError.encodingError` if encryption fails.
    public static func encrypt(plaintext: Data, key: SymmetricKey) throws -> Data {
        do {
            let sealedBox = try ChaChaPoly.seal(plaintext, using: key)
            return sealedBox.combined
        } catch {
            throw X3DHError.encodingError
        }
    }

    /// Decrypts the given ciphertext using ChaCha20-Poly1305 with the provided symmetric key.
    ///
    /// - Parameters:
    ///   - ciphertext: The combined data containing nonce, ciphertext, and tag.
    ///   - key: The symmetric key used for decryption.
    /// - Returns: The original decrypted plaintext.
    /// - Throws: `X3DHError.decryptionFailed` if decryption fails or the data is invalid.
    public static func decrypt(ciphertext: Data, key: SymmetricKey) throws -> Data {
        do {
            let sealedBox = try ChaChaPoly.SealedBox(combined: ciphertext)
            return try ChaChaPoly.open(sealedBox, using: key)
        } catch {
            throw X3DHError.decryptionFailed
        }
    }
}
