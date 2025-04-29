# X3DHSDK

A lightweight, modular implementation of the X3DH (Extended Triple Diffie-Hellman) key agreement protocol in Swift. Built with CryptoKit. Optimized for mobile use cases and forward secrecy.

## 📦 Features

- X3DH-compatible handshake
- Support for ephemeral and identity keys
- Optional forward secrecy
- Message encryption and decryption with AEAD (ChaCha20-Poly1305)
- Signature verification using Ed25519
- Unicode-safe message encoding
- Fully tested with simulated Unicode chat environments

## 🔧 Installation

Add to your `Package.swift`:

```swift
.package(url: "https://github.com/yourusername/X3DHSDK.git", from: "1.0.0")
```

Then import:

```swift
import X3DHSDK
```

## ⚙️ Basic Usage

### Handshake

```swift
let aliceIdentityKey = PrivateKey()
let bobIdentityKey = PrivateKey()
let bobSignedPreKey = PrivateKey()

let initiator = HandshakeInitiator(identityKey: aliceIdentityKey)
let responder = HandshakeResponder(identityKey: bobIdentityKey, signedPreKey: bobSignedPreKey)

let sessionKeyForAlice = try initiator.performHandshake(
    recipientIdentityKey: bobIdentityKey.publicKey(),
    recipientSignedPreKey: bobSignedPreKey.publicKey()
)

let sessionKeyForBob = try responder.performHandshake(
    senderIdentityKey: aliceIdentityKey.publicKey(),
    senderEphemeralKey: initiator.ephemeralPublicKey()
)
```

### Session Encryption

```swift
let cipher = SessionCipher(
    privateKey: aliceIdentityKey.internalKey,
    remotePublicKey: bobIdentityKey.publicKey().raw
)

let encrypted = try cipher.encrypt(message: Data("Hello Bob!".utf8))
let decrypted = try cipher.decrypt(ciphertext: encrypted)
```

### Forward Secrecy

```swift
let fsCipher = ForwardSecrecySessionCipher(
    myIdentityKey: aliceIdentityKey,
    theirIdentityPublicKey: bobIdentityKey.publicKey()
)

let (ciphertext, ephemeralKey, signature) = try fsCipher.encrypt(
    message: Data("Secret".utf8),
    signingKey: SigningPrivateKey()
)

let plaintext = try fsCipher.decrypt(
    ciphertext: ciphertext,
    senderEphemeralPublicKey: ephemeralKey,
    signature: signature,
    senderSigningPublicKey: SigningPrivateKey().publicKey()
)
```

## 🧪 Testing

```bash
swift test
```

Includes:
- Forward secrecy tests
- Unicode chat simulations
- Signature validation
- Session key derivation
- Zero dependency on hope

## ⚠️ Disclaimer

This SDK is educational and not certified for military-grade crypto. Use at your own risk. Paranoia not included.


