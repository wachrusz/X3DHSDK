import Foundation

public enum X3DHError: Error, LocalizedError {
    case invalidSessionConfiguration
    case missingSigningPublicKey
    case invalidSignature
    case decryptionFailed
    case invalidKeyData
    case keyAgreementFailed
    case encodingError
    case decodingError
    case unknown

    public var errorDescription: String? {
        switch self {
        case .invalidSignature:
            return "Invalid signature. The message may have been tampered with."
        case .decryptionFailed:
            return "Failed to decrypt message. Possibly due to corrupted ciphertext or wrong key."
        case .invalidKeyData:
            return "Invalid key data provided."
        case .keyAgreementFailed:
            return "Key agreement process failed."
        case .encodingError:
            return "Failed to encode data."
        case .decodingError:
            return "Failed to decode data."
        case .unknown:
            return "An unknown error occurred."
        case .invalidSessionConfiguration:
            return "Invalid session configuration. Check your cipher initialization."
        case .missingSigningPublicKey:
            return "Missing signing public key. Cannot verify message signature."
        }
    }
}

