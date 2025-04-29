import Foundation
import CryptoKit

/// A wrapper for a Curve25519 private signing key used to generate digital signatures.
public struct SigningPrivateKey {
    private let raw: Curve25519.Signing.PrivateKey

    /// Generates a new Curve25519 signing private key.
    public init() {
        self.raw = Curve25519.Signing.PrivateKey()
    }

    /// Initializes the private key from raw data.
    ///
    /// - Parameter data: A `Data` object containing the raw key bytes.
    /// - Throws: An error if the data is invalid.
    public init(data: Data) throws {
        self.raw = try Curve25519.Signing.PrivateKey(rawRepresentation: data)
    }

    /// Signs a data blob using this private key.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The signature as `Data`.
    /// - Throws: An error if the signing fails.
    public func sign(data: Data) throws -> Data {
        return try raw.signature(for: data)
    }

    /// Returns the associated public key.
    ///
    /// - Returns: A `SigningPublicKey` derived from this private key.
    public func publicKey() -> SigningPublicKey {
        return SigningPublicKey(raw: raw.publicKey)
    }

    /// Returns the raw byte representation of the private key.
    ///
    /// - Returns: A `Data` object containing the raw key bytes.
    public func rawRepresentation() -> Data {
        return raw.rawRepresentation
    }
}

/// A wrapper for a Curve25519 public signing key used to verify digital signatures.
public struct SigningPublicKey {
    private let raw: Curve25519.Signing.PublicKey

    /// Initializes a public key from its raw representation.
    ///
    /// - Parameter data: A `Data` object containing the raw public key bytes.
    /// - Throws: An error if the data is not a valid public key.
    public init(data: Data) throws {
        self.raw = try Curve25519.Signing.PublicKey(rawRepresentation: data)
    }

    /// Internal initializer for using raw CryptoKit public keys.
    ///
    /// - Parameter raw: A `Curve25519.Signing.PublicKey` instance.
    internal init(raw: Curve25519.Signing.PublicKey) {
        self.raw = raw
    }

    /// Verifies a digital signature.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - data: The original signed data.
    /// - Returns: `true` if the signature is valid; otherwise, `false`.
    public func verify(signature: Data, for data: Data) -> Bool {
        return (try? raw.isValidSignature(signature, for: data)) ?? false
    }

    /// Returns the raw byte representation of the public key.
    ///
    /// - Returns: A `Data` object containing the raw public key bytes.
    public func rawRepresentation() -> Data {
        return raw.rawRepresentation
    }
}
