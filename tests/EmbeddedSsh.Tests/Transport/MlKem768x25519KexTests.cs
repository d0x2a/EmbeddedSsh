using System.Security.Cryptography;
using d0x2a.EmbeddedSsh.Crypto;
using d0x2a.EmbeddedSsh.Transport;
using d0x2a.EmbeddedSsh.Transport.Algorithms;

namespace d0x2a.EmbeddedSsh.Tests.Transport;

public class MlKem768x25519KexTests
{
    private const int MlKemEkSize = 1184;
    private const int MlKemCtSize = 1088;
    private const int X25519PkSize = 32;
    private const int ClientInitSize = MlKemEkSize + X25519PkSize; // 1216
    private const int ServerReplySize = MlKemCtSize + X25519PkSize; // 1120

    private static bool IsSupported => MLKem.IsSupported;

    /// <summary>
    /// Builds a C_INIT payload: ML-KEM-768 encapsulation key (1184) || X25519 pk (32).
    /// Returns (clientInit, mlkemKey, x25519Private) for round-trip testing.
    /// </summary>
    private static (byte[] ClientInit, MLKem MlKemKey, byte[] X25519Private) BuildClientInit()
    {
        // ML-KEM-768 key generation
        var mlkemKey = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        var ek = new byte[MlKemEkSize];
        mlkemKey.ExportEncapsulationKey(ek);

        // X25519 keypair
        var (x25519Private, x25519Public) = X25519.GenerateKeyPair();

        // C_INIT = ek || X25519 pk
        var clientInit = new byte[ClientInitSize];
        ek.CopyTo(clientInit.AsSpan());
        x25519Public.CopyTo(clientInit.AsSpan(MlKemEkSize));

        return (clientInit, mlkemKey, x25519Private);
    }

    [Fact]
    public void ServerExchange_ProducesCorrectSizes()
    {
        if (!IsSupported) return;

        var kex = new MlKem768x25519Kex();
        var (clientInit, mlkemKey, _) = BuildClientInit();

        try
        {
            var result = kex.ServerExchange(clientInit);

            Assert.Equal(ServerReplySize, result.ServerEphemeral.Length); // 1120
            Assert.Equal(32, result.SharedSecret.Length); // SHA-256 output
        }
        finally
        {
            mlkemKey.Dispose();
        }
    }

    [Fact]
    public void ServerExchange_SharedSecretMatchesClientSide()
    {
        if (!IsSupported) return;

        var kex = new MlKem768x25519Kex();
        var (clientInit, mlkemKey, x25519Private) = BuildClientInit();

        try
        {
            var result = kex.ServerExchange(clientInit);

            // Client-side: extract ciphertext and server X25519 pk from S_REPLY
            var serverCiphertext = result.ServerEphemeral.AsSpan(0, MlKemCtSize);
            var serverX25519Pk = result.ServerEphemeral.AsSpan(MlKemCtSize, X25519PkSize);

            // Client decapsulates ML-KEM
            var kPq = new byte[32];
            mlkemKey.Decapsulate(serverCiphertext, kPq);

            // Client computes X25519 shared secret
            var kCl = X25519.ComputeSharedSecret(x25519Private, serverX25519Pk);

            // Client derives K = SHA-256(K_PQ || K_CL)
            var clientK = SHA256.HashData([.. kPq, .. kCl]);

            Assert.Equal(clientK, result.SharedSecret);
        }
        finally
        {
            mlkemKey.Dispose();
        }
    }

    [Fact]
    public void ServerExchange_InvalidLength_Throws()
    {
        if (!IsSupported) return;

        var kex = new MlKem768x25519Kex();

        // Too short
        Assert.Throws<ArgumentException>(() => kex.ServerExchange(new byte[100]));

        // Too long
        Assert.Throws<ArgumentException>(() => kex.ServerExchange(new byte[ClientInitSize + 1]));
    }

    [Fact]
    public void ServerExchange_InvalidMlKemKey_Throws()
    {
        if (!IsSupported) return;

        var kex = new MlKem768x25519Kex();

        // All-zeros encapsulation key should cause MLKem to throw
        var badInit = new byte[ClientInitSize];
        Random.Shared.NextBytes(badInit.AsSpan(MlKemEkSize)); // valid X25519 pk portion

        var ex = Record.Exception(() => kex.ServerExchange(badInit));
        Assert.NotNull(ex);
    }

    [Fact]
    public void SharedSecretEncoding_IsString()
    {
        var kex = new MlKem768x25519Kex();
        Assert.Equal(SharedSecretEncoding.String, kex.SharedSecretEncoding);
    }

    [Fact]
    public void ComputeExchangeHash_EncodesKAsString()
    {
        if (!IsSupported) return;

        var kex = new MlKem768x25519Kex();
        var curve = new Curve25519Kex();

        var clientVersion = "SSH-2.0-TestClient"u8.ToArray();
        var serverVersion = "SSH-2.0-TestServer"u8.ToArray();
        var clientKexInit = new byte[100];
        var serverKexInit = new byte[100];
        var hostKeyBlob = new byte[51];
        var clientEphemeral = new byte[64];
        var serverEphemeral = new byte[64];
        // Use a shared secret where mpint and string encoding differ
        // (high bit set = mpint adds a leading zero byte)
        var sharedSecret = new byte[32];
        sharedSecret[0] = 0x80; // high bit set

        Random.Shared.NextBytes(clientKexInit);
        Random.Shared.NextBytes(serverKexInit);
        Random.Shared.NextBytes(hostKeyBlob);
        Random.Shared.NextBytes(clientEphemeral);
        Random.Shared.NextBytes(serverEphemeral);

        var hybridHash = kex.ComputeExchangeHash(
            clientVersion, serverVersion,
            clientKexInit, serverKexInit,
            hostKeyBlob,
            clientEphemeral, serverEphemeral,
            sharedSecret);

        var curveHash = curve.ComputeExchangeHash(
            clientVersion, serverVersion,
            clientKexInit, serverKexInit,
            hostKeyBlob,
            clientEphemeral, serverEphemeral,
            sharedSecret);

        Assert.Equal(32, hybridHash.Length);
        Assert.Equal(32, curveHash.Length);

        // They should differ because one encodes K as string, the other as mpint
        Assert.NotEqual(hybridHash, curveHash);
    }

    [Fact]
    public void ComputeExchangeHash_IsDeterministic()
    {
        if (!IsSupported) return;

        var kex = new MlKem768x25519Kex();

        var clientVersion = "SSH-2.0-TestClient"u8.ToArray();
        var serverVersion = "SSH-2.0-TestServer"u8.ToArray();
        var clientKexInit = new byte[100];
        var serverKexInit = new byte[100];
        var hostKeyBlob = new byte[51];
        var clientEphemeral = new byte[ClientInitSize];
        var serverEphemeral = new byte[ServerReplySize];
        var sharedSecret = new byte[32];

        Random.Shared.NextBytes(clientKexInit);
        Random.Shared.NextBytes(serverKexInit);
        Random.Shared.NextBytes(hostKeyBlob);
        Random.Shared.NextBytes(clientEphemeral);
        Random.Shared.NextBytes(serverEphemeral);
        Random.Shared.NextBytes(sharedSecret);

        var hash1 = kex.ComputeExchangeHash(
            clientVersion, serverVersion,
            clientKexInit, serverKexInit,
            hostKeyBlob,
            clientEphemeral, serverEphemeral,
            sharedSecret);

        var hash2 = kex.ComputeExchangeHash(
            clientVersion, serverVersion,
            clientKexInit, serverKexInit,
            hostKeyBlob,
            clientEphemeral, serverEphemeral,
            sharedSecret);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void KeyDerivation_StringEncoding_DiffersFromMpint()
    {
        var sharedSecret = new byte[32];
        sharedSecret[0] = 0x80; // high bit set — mpint will add leading zero, string won't

        var exchangeHash = new byte[32];
        var sessionId = new byte[32];
        Random.Shared.NextBytes(exchangeHash);
        Random.Shared.NextBytes(sessionId);

        var mpintKey = KeyDerivation.DeriveKey(
            sharedSecret, exchangeHash,
            KeyDerivation.KeyId.EncryptionKeyClientToServer, sessionId, 32,
            SharedSecretEncoding.Mpint);

        var stringKey = KeyDerivation.DeriveKey(
            sharedSecret, exchangeHash,
            KeyDerivation.KeyId.EncryptionKeyClientToServer, sessionId, 32,
            SharedSecretEncoding.String);

        Assert.NotEqual(mpintKey, stringKey);
    }
}
