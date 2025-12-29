namespace d0x2a.EmbeddedSsh.Transport.Algorithms;

/// <summary>
/// Interface for SSH key exchange algorithms.
/// </summary>
public interface IKexAlgorithm
{
    /// <summary>
    /// Gets the algorithm name as used in SSH protocol.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Generates an ephemeral key pair for this key exchange.
    /// </summary>
    /// <returns>Tuple of (private key, public key).</returns>
    (byte[] PrivateKey, byte[] PublicKey) GenerateKeyPair();

    /// <summary>
    /// Computes the shared secret from our private key and peer's public key.
    /// </summary>
    /// <param name="privateKey">Our ephemeral private key.</param>
    /// <param name="peerPublicKey">Peer's ephemeral public key.</param>
    /// <returns>Shared secret as mpint-compatible bytes.</returns>
    byte[] ComputeSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey);

    /// <summary>
    /// Computes the exchange hash H using SHA-256.
    /// </summary>
    /// <param name="clientVersion">Client version string (without CRLF).</param>
    /// <param name="serverVersion">Server version string (without CRLF).</param>
    /// <param name="clientKexInit">Client's SSH_MSG_KEXINIT payload.</param>
    /// <param name="serverKexInit">Server's SSH_MSG_KEXINIT payload.</param>
    /// <param name="hostKeyBlob">Server's host key blob.</param>
    /// <param name="clientEphemeral">Client's ephemeral public key.</param>
    /// <param name="serverEphemeral">Server's ephemeral public key.</param>
    /// <param name="sharedSecret">Computed shared secret (mpint format).</param>
    /// <returns>Exchange hash H (32 bytes for SHA-256).</returns>
    byte[] ComputeExchangeHash(
        ReadOnlySpan<byte> clientVersion,
        ReadOnlySpan<byte> serverVersion,
        ReadOnlySpan<byte> clientKexInit,
        ReadOnlySpan<byte> serverKexInit,
        ReadOnlySpan<byte> hostKeyBlob,
        ReadOnlySpan<byte> clientEphemeral,
        ReadOnlySpan<byte> serverEphemeral,
        ReadOnlySpan<byte> sharedSecret);
}
