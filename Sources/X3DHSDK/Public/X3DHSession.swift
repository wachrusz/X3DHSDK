import Foundation
import CryptoKit

/// A high-level abstraction representing a secure session for encrypted communication using the X3DH protocol.
///
/// `X3DHSession` supports two types of session:
/// - **Session-based**: Lightweight session encryption using a static key agreement.
/// - **Forward secrecy-based**: Ensures stronger privacy by generating a new ephemeral key for every message.
public struct X3DHSession {
    private let sessionCipher: SessionCipher?
    private let forwardCipher: ForwardSecrecySessionCipher?
    private let signingKey: SigningPrivateKey?

    private init(
        sessionCipher: SessionCipher? = nil,
        forwardCipher: ForwardSecrecySessionCipher? = nil,
        signingKey: SigningPrivateKey? = nil
    ) {
        self.sessionCipher = sessionCipher
        self.forwardCipher = forwardCipher
        self.signingKey = signingKey
    }

    /// Creates a session using static key agreement.
    ///
    /// - Parameters:
    ///   - myPrivateKey: Your private key.
    ///   - theirPublicKey: The recipient's public key.
    ///   - additionalKey: Optional second-layer encryption key.
    /// - Returns: A configured `X3DHSession` instance.
    public static func sessionBased(
        myPrivateKey: PrivateKey,
        theirPublicKey: PublicKey,
        additionalKey: SymmetricKey? = nil
    ) -> X3DHSession {
        let cipher = SessionCipher(
            privateKey: myPrivateKey.internalKey,
            remotePublicKey: theirPublicKey.raw
        )
        return X3DHSession(sessionCipher: cipher)
    }

    /// Creates a forward secrecy session, using ephemeral key exchange and signatures for verification.
    ///
    /// - Parameters:
    ///   - myIdentityKey: Your long-term identity key.
    ///   - theirIdentityKey: Recipient's identity public key.
    ///   - signingKey: Your private signing key used to sign ephemeral public keys.
    /// - Returns: A configured `X3DHSession` instance.
    public static func forwardSecrecy(
        myIdentityKey: PrivateKey,
        theirIdentityKey: PublicKey,
        signingKey: SigningPrivateKey
    ) -> X3DHSession {
        let cipher = ForwardSecrecySessionCipher(
            myIdentityKey: myIdentityKey,
            theirIdentityPublicKey: theirIdentityKey
        )
        return X3DHSession(
            forwardCipher: cipher,
            signingKey: signingKey
        )
    }

    /// Encrypts a message using the configured session.
    ///
    /// - Parameter message: The plaintext message to encrypt.
    /// - Returns: An `EncryptedMessage` enum containing the ciphertext and metadata if needed.
    /// - Throws: `X3DHError.invalidSessionConfiguration` if the session is not properly configured.
    public func encrypt(message: Data) throws -> EncryptedMessage {
        if let cipher = sessionCipher {
            let encrypted = try cipher.encrypt(message: message)
            return .session(ciphertext: encrypted)
        }

        if let cipher = forwardCipher, let signingKey = signingKey {
            let (ciphertext, ephemeralKey, signature) = try cipher.encrypt(
                message: message,
                signingKey: signingKey
            )
            return .forward(
                ciphertext: ciphertext,
                ephemeralPublicKey: ephemeralKey,
                signature: signature
            )
        }

        throw X3DHError.invalidSessionConfiguration
    }

    /// Decrypts an `EncryptedMessage`, either session-based or forward secrecy-based.
    ///
    /// - Parameter message: The encrypted message.
    /// - Returns: The decrypted plaintext.
    /// - Throws:
    ///   - `X3DHError.invalidSessionConfiguration` if session is not properly initialized.
    ///   - `X3DHError.missingSigningPublicKey` if a signing key is required but not found.
    ///   - `X3DHError.invalidSignature` if signature verification fails.
    public func decrypt(
        message: EncryptedMessage
    ) throws -> Data {
        switch message {
        case .session(let ciphertext):
            guard let cipher = sessionCipher else {
                throw X3DHError.invalidSessionConfiguration
            }
            return try cipher.decrypt(ciphertext: ciphertext)

        case .forward(let ciphertext, let ephemeralKey, let signature):
            guard let cipher = forwardCipher else {
                throw X3DHError.invalidSessionConfiguration
            }

            guard let senderSigningKey = signingKey else {
                throw X3DHError.missingSigningPublicKey
            }

            return try cipher.decrypt(
                ciphertext: ciphertext,
                senderEphemeralPublicKey: ephemeralKey,
                signature: signature,
                senderSigningPublicKey: senderSigningKey.publicKey()
            )
        }
    }
}
