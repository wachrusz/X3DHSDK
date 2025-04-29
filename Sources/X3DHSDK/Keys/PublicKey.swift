import Foundation
import CryptoKit

/// A wrapper around a Curve25519 public key used for key agreement in the X3DH protocol.
public struct PublicKey {
    internal let raw: Curve25519.KeyAgreement.PublicKey

    /// Initializes a public key from its raw representation.
    ///
    /// - Parameter data: A `Data` object containing the raw public key bytes.
    /// - Throws: An error if the data does not represent a valid Curve25519 public key.
    public init(data: Data) throws {
        self.raw = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data)
    }

    /// Internal initializer used for creating `PublicKey` from a raw CryptoKit public key.
    ///
    /// - Parameter raw: A `Curve25519.KeyAgreement.PublicKey` instance.
    internal init(raw: Curve25519.KeyAgreement.PublicKey) {
        self.raw = raw
    }

    /// Returns the raw byte representation of the public key.
    ///
    /// - Returns: A `Data` object containing the public key's raw bytes.
    public func rawRepresentation() -> Data {
        return raw.rawRepresentation
    }
}
