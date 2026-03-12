using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Soenneker.Extensions.String;
using System;
using System.Buffers;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;

namespace Soenneker.Cryptography.Ed25519;

/// <summary>
/// Provides utility methods for verifying Ed25519 digital signatures using public keys and messages encoded in base64
/// or as byte arrays.
/// </summary>
/// <remarks>This class is intended for scenarios where Ed25519 signature verification is required, such as
/// validating messages or data integrity. All methods are static and thread-safe. The class does not provide key
/// generation or signing functionality; it focuses solely on signature verification. Methods return <see
/// langword="true"/> if the signature is valid for the given message and public key; otherwise, <see
/// langword="false"/>. Invalid or improperly formatted inputs will result in a <see langword="false"/> return value
/// rather than an exception.</remarks>
public static class Ed25519Util
{
    private const int _publicKeySize = 32;
    private const int _signatureSize = 64;

    /// <summary>
    /// Verifies that the specified signature is valid for the given message and public key using base64-encoded inputs.
    /// </summary>
    /// <remarks>This method performs input validation and returns false if the message is null, empty, or
    /// consists only of whitespace. For improved performance when working with large messages, consider using the
    /// overload that accepts a byte array.</remarks>
    /// <param name="publicKeyBase64">The public key used to verify the signature, encoded as a base64 string. Must not be null or empty.</param>
    /// <param name="signatureBase64">The signature to verify, encoded as a base64 string. Must not be null or empty.</param>
    /// <param name="message">The message whose signature is to be verified. Must not be null, empty, or consist only of whitespace.</param>
    /// <returns>true if the signature is valid for the specified message and public key; otherwise, false.</returns>
    [Pure]
    public static bool Verify(string publicKeyBase64, string signatureBase64, string message)
    {
        if (message.IsNullOrWhiteSpace())
            return false;

        // unavoidable allocation unless caller provides byte[]
        return Verify(publicKeyBase64, signatureBase64, message.ToBytes());
    }

    /// <summary>
    /// Verifies that the specified signature is valid for the given message using the provided Ed25519 public key.
    /// </summary>
    /// <remarks>This method returns false if any input is invalid or if the signature verification fails. The
    /// verification uses the Ed25519 algorithm and does not throw exceptions for invalid input or failed
    /// verification.</remarks>
    /// <param name="publicKeyBase64">The Ed25519 public key encoded as a Base64 string. Must not be null, empty, or contain whitespace only.</param>
    /// <param name="signatureBase64">The signature to verify, encoded as a Base64 string. Must not be null, empty, or contain whitespace only.</param>
    /// <param name="messageBytes">The message data as a byte array. Must not be null or empty.</param>
    /// <returns>true if the signature is valid for the message and public key; otherwise, false.</returns>
    [Pure]
    public static bool Verify(string publicKeyBase64, string signatureBase64, byte[] messageBytes)
    {
        if (messageBytes is null || messageBytes.Length == 0)
            return false;

        if (publicKeyBase64.IsNullOrWhiteSpace() || signatureBase64.IsNullOrWhiteSpace())
            return false;

        byte[] pubKey = ArrayPool<byte>.Shared.Rent(_publicKeySize);
        byte[] sig = ArrayPool<byte>.Shared.Rent(_signatureSize);

        try
        {
            if (!TryDecodeBase64Fixed(publicKeyBase64, pubKey, _publicKeySize))
                return false;

            if (!TryDecodeBase64Fixed(signatureBase64, sig, _signatureSize))
                return false;

            var keyParam = new Ed25519PublicKeyParameters(pubKey, 0);
            var verifier = new Ed25519Signer();

            verifier.Init(false, keyParam);
            verifier.BlockUpdate(messageBytes, 0, messageBytes.Length);

            return verifier.VerifySignature(sig);
        }
        finally
        {
            // Avoid clearing the entire rented buffers (which may be larger than the written lengths).
            CryptographicOperations.ZeroMemory(pubKey.AsSpan(0, _publicKeySize));
            CryptographicOperations.ZeroMemory(sig.AsSpan(0, _signatureSize));
            ArrayPool<byte>.Shared.Return(pubKey, clearArray: false);
            ArrayPool<byte>.Shared.Return(sig, clearArray: false);
        }
    }

    private static bool TryDecodeBase64Fixed(string base64, byte[] rented, int expectedLength)
    {
        return Convert.TryFromBase64String(base64, rented.AsSpan(0, expectedLength), out int written) && written == expectedLength;
    }
}