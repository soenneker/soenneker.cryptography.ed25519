[![](https://img.shields.io/nuget/v/soenneker.cryptography.ed25519.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.cryptography.ed25519/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.cryptography.ed25519/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.cryptography.ed25519/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.cryptography.ed25519.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.cryptography.ed25519/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.cryptography.ed25519/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.cryptography.ed25519/actions/workflows/codeql.yml)

# Soenneker.Cryptography.Ed25519

Provides utility methods for verifying Ed25519 digital signatures using public keys and messages encoded in base64 or as byte arrays.

## Install

```bash
dotnet add package Soenneker.Cryptography.Ed25519
```

## Quick start

```csharp
using Soenneker.Cryptography.Ed25519;

var result = Ed25519Util.Verify("value", "value", "value");
```

Verifies ed25519.

## What you get

- `Ed25519Util` — Provides utility methods for verifying Ed25519 digital signatures using public keys and messages encoded in base64 or as byte arrays.

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `Ed25519Util.Verify(publicKeyBase64, signatureBase64, message)` | Verifies ed25519. | true if the signature is valid for the specified message and public key; otherwise, false. |

## Important behavior

- `Ed25519Util`: This class is intended for scenarios where Ed25519 signature verification is required, such as validating messages or data integrity. All methods are static and thread-safe. The class does not provide key generation or signing functionality; it focuses solely on signature verification. Methods return `true` if the signature is valid for the given message and public key; otherwise, `false`. Invalid or improperly formatted inputs will result in a `false` return value rather than an exception.
- `Ed25519Util.Verify(publicKeyBase64, signatureBase64, message)`: This method performs input validation and returns false if the message is null, empty, or consists only of whitespace. For improved performance when working with large messages, consider using the overload that accepts a byte array.
- `Ed25519Util.Verify(publicKeyBase64, signatureBase64, messageBytes)`: This method returns false if any input is invalid or if the signature verification fails. The verification uses the Ed25519 algorithm and does not throw exceptions for invalid input or failed verification.
