# ``X3DHSDK``

## Summary

X3DHSDK is a Swift Package that provides an implementation of the Extended Triple Diffie-Hellman (X3DH) key agreement protocol. It enables secure end-to-end encryption with support for forward secrecy and message authentication.

Built using CryptoKit, this library is designed for use in Swift-based applications, especially on mobile platforms.

## Overview

The SDK includes:

- **X3DH Handshake**: Securely establishes a shared session key between two parties.
- **Session Ciphers**: Provides symmetric encryption and decryption using ChaChaPoly (ChaCha20-Poly1305).
- **Forward Secrecy**: Optional ephemeral key-based encryption for each message.
- **Key Abstractions**: Easy-to-use wrappers for Curve25519 keys and Ed25519 signatures.
- **Message Layer**: High-level encrypt/decrypt interfaces for secure message exchange.

## Usage

```swift
import X3DHSDK

let aliceIK = PrivateKey()
let bobIK = PrivateKey()
let bobSPK = PrivateKey()

let initiator = HandshakeInitiator(identityKey: aliceIK)
let responder = HandshakeResponder(identityKey: bobIK, signedPreKey: bobSPK)

let aliceSessionKey = try initiator.performHandshake(
    recipientIdentityKey: bobIK.publicKey(),
    recipientSignedPreKey: bobSPK.publicKey()
)

let bobSessionKey = try responder.performHandshake(
    senderIdentityKey: aliceIK.publicKey(),
    senderEphemeralKey: initiator.ephemeralPublicKey()
)
```

## Topics

### Key Structures
- `PrivateKey`
- `PublicKey`
- `SigningKeyPair`
- `SigningPublicKey`
- `SymmetricKey`

### Crypto Utilities
- `SessionCipher`
- `ForwardSecrecySessionCipher`
- `AEADEncryptor`
- `KeyDerivation`
- `ByteUtils`

### Handshake
- `HandshakeInitiator`
- `HandshakeResponder`

### Message Layer
- `EncryptedMessage`
- `MessageEncryptor`
- `X3DHSession`

### Errors
- `X3DHError`

---

> **Disclaimer:** This library is not certified for use in critical infrastructure. It's intended for educational, experimental, and app-level usage.
