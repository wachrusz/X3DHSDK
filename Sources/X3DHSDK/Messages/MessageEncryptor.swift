import Foundation
import CryptoKit

/// Handles message encryption and decryption using layered encryption strategies.
internal struct MessageEncryptor {
    private let sessionCipher: SessionCipher
    private let additionalKey: SymmetricKey?

    /// Initializes a message encryptor with a session cipher and an optional additional encryption key.
    ///
    /// - Parameters:
    ///   - sessionCipher: The cipher used for session-level encryption.
    ///   - additionalKey: An optional symmetric key used for an extra encryption layer.
    public init(sessionCipher: SessionCipher, additionalKey: SymmetricKey? = nil) {
        self.sessionCipher = sessionCipher
        self.additionalKey = additionalKey
    }

    /// Encrypts a message using session cipher and an optional second encryption layer.
    ///
    /// - Parameter message: The plaintext message as `Data`.
    /// - Returns: The fully encrypted message.
    /// - Throws: `X3DHError.encodingError` if encryption fails.
    public func encrypt(message: Data) throws -> Data {
        do {
            let sessionEncrypted = try sessionCipher.encrypt(message: message)

            if let additionalKey = additionalKey {
                return try AEADEncryptor.encrypt(plaintext: sessionEncrypted, key: additionalKey)
            } else {
                return sessionEncrypted
            }
        } catch {
            throw X3DHError.encodingError
        }
    }

    /// Decrypts a message considering both encryption layers.
    ///
    /// - Parameter ciphertext: The encrypted message as `Data`.
    /// - Returns: The decrypted plaintext message.
    /// - Throws: `X3DHError.decryptionFailed` if decryption fails.
    public func decrypt(ciphertext: Data) throws -> Data {
        do {
            let decryptedLayer: Data
            if let additionalKey = additionalKey {
                decryptedLayer = try AEADEncryptor.decrypt(ciphertext: ciphertext, key: additionalKey)
            } else {
                decryptedLayer = ciphertext
            }

            return try sessionCipher.decrypt(ciphertext: decryptedLayer)
        } catch {
            throw X3DHError.decryptionFailed
        }
    }
}
