[![](https://img.shields.io/nuget/v/soenneker.cryptography.ed25519.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.cryptography.ed25519/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.cryptography.ed25519/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.cryptography.ed25519/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.cryptography.ed25519.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.cryptography.ed25519/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.cryptography.ed25519/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.cryptography.ed25519/actions/workflows/codeql.yml)

# Soenneker.Cryptography.Ed25519

Static helpers for verifying Ed25519 signatures with Base64-encoded public keys and signatures.

## Installation

```bash
dotnet add package Soenneker.Cryptography.Ed25519
```

## Verify bytes

```csharp
using Soenneker.Cryptography.Ed25519;

byte[] payload = await File.ReadAllBytesAsync(path, cancellationToken);

bool valid = Ed25519Util.Verify(
    publicKeyBase64,
    signatureBase64,
    payload);

if (!valid)
    throw new InvalidDataException("The Ed25519 signature is invalid.");
```

The public key must decode to exactly 32 bytes and the signature to exactly 64 bytes. Inputs use standard Base64, not hexadecimal or Base64url. Malformed Base64, incorrect lengths, empty messages, and signature mismatches return `false`.

## Verify text

```csharp
bool valid = Ed25519Util.Verify(
    publicKeyBase64,
    signatureBase64,
    "the exact signed text");
```

The string overload verifies the UTF-8 bytes of the supplied text and returns `false` for null, empty, or whitespace-only text. Use the byte-array overload when the producer signed raw bytes or when text normalization and line endings might differ.

## Security notes

Ed25519 verifies exact bytes. Do not parse and reserialize JSON, normalize text, change encodings, or alter line endings before verification unless the signing protocol explicitly defines that canonicalization.

A `true` result proves that the matching private key signed those bytes. It does not establish who owns the public key, whether the message is fresh, or whether it is safe to process. Obtain the public key through a trusted channel and enforce any timestamp, nonce, audience, or replay rules required by the protocol.

The utility performs verification only; it does not generate keys or create signatures. All methods are static and require no dependency-injection registration.
