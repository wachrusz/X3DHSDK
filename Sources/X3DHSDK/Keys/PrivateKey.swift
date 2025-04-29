import Foundation
import CryptoKit

/// A wrapper around Curve25519 private keys for use in key agreement (X3DH).
public struct PrivateKey {
    private let raw: Curve25519.KeyAgreement.PrivateKey

    /// Initializes a new randomly generated private key.
    public init() {
        self.raw = Curve25519.KeyAgreement.PrivateKey()
    }

    /// Initializes a private key from a raw representation.
    ///
    /// - Parameter data: The raw representation of the private key.
    /// - Throws: An error if the data is not a valid Curve25519 private key.
    public init(data: Data) throws {
        self.raw = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
    }

    /// Returns the associated public key.
    ///
    /// - Returns: The public key corresponding to this private key.
    public func publicKey() -> PublicKey {
        return PublicKey(raw: raw.publicKey)
    }

    /// Performs Diffie-Hellman key agreement with a remote public key.
    ///
    /// - Parameter remote: The remote party's public key.
    /// - Returns: A `SharedSecret` used for key derivation.
    /// - Throws: An error if the key agreement fails.
    public func sharedSecret(with remote: PublicKey) throws -> SharedSecret {
        return try raw.sharedSecretFromKeyAgreement(with: remote.raw)
    }

    /// Returns the raw representation of this private key.
    ///
    /// - Returns: A `Data` value representing the private key.
    public func rawRepresentation() -> Data {
        return raw.rawRepresentation
    }

    /// Exposes the underlying CryptoKit key for internal use.
    internal var internalKey: Curve25519.KeyAgreement.PrivateKey {
        return raw
    }
}
