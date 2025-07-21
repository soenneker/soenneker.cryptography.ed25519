using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Soenneker.Extensions.String;
using System.Diagnostics.Contracts;

namespace Soenneker.Cryptography.Ed25519;

/// <summary>
/// A lightweight C# library providing utilities for verifying Ed25519 digital signatures using public keys
/// </summary>
public static class Ed25519Util
{
    /// <summary>
    /// Verifies an Ed25519 signature against a message using a public key.
    /// </summary>
    /// <param name="publicKeyBase64">Base64-encoded Ed25519 public key.</param>
    /// <param name="signatureBase64">Base64-encoded signature to verify.</param>
    /// <param name="message">Raw message that was signed (as string or byte[]).</param>
    /// <returns>True if the signature is valid; otherwise false.</returns>
    [Pure]
    public static bool Verify(string publicKeyBase64, string signatureBase64, string message)
    {
        if (message.IsNullOrWhiteSpace())
            return false;

        return Verify(publicKeyBase64, signatureBase64, message.ToBytes());
    }

    /// <summary>
    /// Verifies an Ed25519 signature against a message using a public key.
    /// </summary>
    /// <param name="publicKeyBase64">Base64-encoded Ed25519 public key.</param>
    /// <param name="signatureBase64">Base64-encoded signature to verify.</param>
    /// <param name="messageBytes">Raw message that was signed.</param>
    /// <returns>True if the signature is valid; otherwise false.</returns>
    [Pure]
    public static bool Verify(string publicKeyBase64, string signatureBase64, byte[] messageBytes)
    {
        try
        {
            byte[] publicKey = publicKeyBase64.ToBytesFromBase64();
            byte[] signature = signatureBase64.ToBytesFromBase64();

            if (publicKey.Length != 32 || signature.Length != 64)
                return false;

            var keyParam = new Ed25519PublicKeyParameters(publicKey, 0);
            var verifier = new Ed25519Signer();
            verifier.Init(false, keyParam);
            verifier.BlockUpdate(messageBytes, 0, messageBytes.Length);
            return verifier.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }
}