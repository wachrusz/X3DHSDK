import Foundation
import CryptoKit

/// A cipher that provides forward secrecy for each message by using ephemeral keys.
public struct ForwardSecrecySessionCipher {
    private let myIdentityKey: PrivateKey
    private let theirIdentityPublicKey: PublicKey

    /// Initializes a forward secrecy session cipher.
    ///
    /// - Parameters:
    ///   - myIdentityKey: Your own long-term identity private key.
    ///   - theirIdentityPublicKey: The recipient's long-term identity public key.
    public init(myIdentityKey: PrivateKey, theirIdentityPublicKey: PublicKey) {
        self.myIdentityKey = myIdentityKey
        self.theirIdentityPublicKey = theirIdentityPublicKey
    }

    /// Encrypts a message using a newly generated ephemeral key, ensuring forward secrecy.
    ///
    /// - Parameters:
    ///   - message: The message data to encrypt.
    ///   - signingKey: The signing private key used to sign the ephemeral public key.
    /// - Returns: A tuple containing the ciphertext, ephemeral public key, and the signature of that key.
    /// - Throws: `X3DHError.encodingError` if encryption or signing fails.
    public func encrypt(
        message: Data,
        signingKey: SigningPrivateKey
    ) throws -> (ciphertext: Data, ephemeralPublicKey: PublicKey, signature: Data) {
        do {
            let ephemeralPrivateKey = PrivateKey()
            let ephemeralPublicKey = ephemeralPrivateKey.publicKey()

            let sharedSecret = try ephemeralPrivateKey.sharedSecret(with: theirIdentityPublicKey)
            let symmetricKey = KeyDerivation.deriveSymmetricKey(sharedSecret: sharedSecret)
            let encrypted = try AEADEncryptor.encrypt(plaintext: message, key: symmetricKey)
            let signature = try signingKey.sign(data: ephemeralPublicKey.rawRepresentation())

            return (encrypted, ephemeralPublicKey, signature)
        } catch {
            throw X3DHError.encodingError
        }
    }

    /// Decrypts a message using the sender's ephemeral public key and verifies the signature.
    ///
    /// - Parameters:
    ///   - ciphertext: The encrypted message data.
    ///   - senderEphemeralPublicKey: The ephemeral public key used to encrypt the message.
    ///   - signature: The signature of the ephemeral public key.
    ///   - senderSigningPublicKey: The sender's signing public key used to verify the signature.
    /// - Returns: The original plaintext message.
    /// - Throws: `X3DHError.invalidSignature` if the signature is invalid,
    ///           `X3DHError.decryptionFailed` if decryption fails.
    public func decrypt(
        ciphertext: Data,
        senderEphemeralPublicKey: PublicKey,
        signature: Data,
        senderSigningPublicKey: SigningPublicKey
    ) throws -> Data {
        
        guard senderSigningPublicKey.verify(signature: signature, for: senderEphemeralPublicKey.rawRepresentation()) else {
            throw X3DHError.invalidSignature
        }

        let sharedSecret = try myIdentityKey.sharedSecret(with: senderEphemeralPublicKey)
        let symmetricKey = KeyDerivation.deriveSymmetricKey(sharedSecret: sharedSecret)
        return try AEADEncryptor.decrypt(ciphertext: ciphertext, key: symmetricKey)
    }
}
