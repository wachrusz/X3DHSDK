import Foundation
import CryptoKit

/// A session cipher that performs message encryption and decryption
/// using a shared key derived from a key agreement between two parties.
internal struct SessionCipher {
    private let privateKey: Curve25519.KeyAgreement.PrivateKey
    private let remotePublicKey: Curve25519.KeyAgreement.PublicKey

    /// Initializes a new `SessionCipher` for symmetric encryption via ECDH.
    ///
    /// - Parameters:
    ///   - privateKey: Your own `Curve25519.KeyAgreement.PrivateKey`.
    ///   - remotePublicKey: The remote party's `Curve25519.KeyAgreement.PublicKey`.
    public init(privateKey: Curve25519.KeyAgreement.PrivateKey,
                remotePublicKey: Curve25519.KeyAgreement.PublicKey) {
        self.privateKey = privateKey
        self.remotePublicKey = remotePublicKey
    }

    /// Encrypts a message using the derived symmetric key from ECDH.
    ///
    /// - Parameter message: The plaintext message to encrypt.
    /// - Returns: The ciphertext as `Data`.
    /// - Throws: `X3DHError.encodingError` if encryption fails.
    public func encrypt(message: Data) throws -> Data {
        do {
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: remotePublicKey)
            let symmetricKey = KeyDerivation.deriveSymmetricKey(sharedSecret: sharedSecret)
            return try AEADEncryptor.encrypt(plaintext: message, key: symmetricKey)
        } catch {
            throw X3DHError.encodingError
        }
    }

    /// Decrypts a message using the derived symmetric key from ECDH.
    ///
    /// - Parameter ciphertext: The encrypted message to decrypt.
    /// - Returns: The decrypted plaintext as `Data`.
    /// - Throws: `X3DHError.decryptionFailed` if decryption fails.
    public func decrypt(ciphertext: Data) throws -> Data {
        do {
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: remotePublicKey)
            let symmetricKey = KeyDerivation.deriveSymmetricKey(sharedSecret: sharedSecret)
            return try AEADEncryptor.decrypt(ciphertext: ciphertext, key: symmetricKey)
        } catch {
            throw X3DHError.decryptionFailed
        }
    }
}
