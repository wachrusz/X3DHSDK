import Foundation

/// Represents an encrypted message that can be either a regular session message
/// or a forward secrecy message with additional metadata.
public enum EncryptedMessage {
    /// A standard session-encrypted message.
    case session(ciphertext: Data)

    /// A message encrypted using forward secrecy, which includes the ciphertext,
    /// the ephemeral public key used in the exchange, and a digital signature.
    case forward(ciphertext: Data, ephemeralPublicKey: PublicKey, signature: Data)
}
