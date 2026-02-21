using System.Buffers.Binary;
using d0x2a.EmbeddedSsh.Crypto;
using d0x2a.EmbeddedSsh.Transport;
using d0x2a.EmbeddedSsh.Transport.Algorithms;

namespace d0x2a.EmbeddedSsh.Tests.Transport;

public class TransportTests
{
    #region Key Derivation Tests

    [Fact]
    public void KeyDerivation_DeriveKey_ProducesCorrectLength()
    {
        var sharedSecret = new byte[32];
        var exchangeHash = new byte[32];
        var sessionId = new byte[32];
        Random.Shared.NextBytes(sharedSecret);
        Random.Shared.NextBytes(exchangeHash);
        Random.Shared.NextBytes(sessionId);

        var key32 = KeyDerivation.DeriveKey(sharedSecret, exchangeHash,
            KeyDerivation.KeyId.EncryptionKeyClientToServer, sessionId, 32);
        Assert.Equal(32, key32.Length);

        var key64 = KeyDerivation.DeriveKey(sharedSecret, exchangeHash,
            KeyDerivation.KeyId.EncryptionKeyServerToClient, sessionId, 64);
        Assert.Equal(64, key64.Length);
    }

    [Fact]
    public void KeyDerivation_DeriveKey_DifferentIdsProduceDifferentKeys()
    {
        var sharedSecret = new byte[32];
        var exchangeHash = new byte[32];
        var sessionId = new byte[32];
        Random.Shared.NextBytes(sharedSecret);
        Random.Shared.NextBytes(exchangeHash);
        Random.Shared.NextBytes(sessionId);

        var keyA = KeyDerivation.DeriveKey(sharedSecret, exchangeHash,
            KeyDerivation.KeyId.IvClientToServer, sessionId, 32);
        var keyB = KeyDerivation.DeriveKey(sharedSecret, exchangeHash,
            KeyDerivation.KeyId.IvServerToClient, sessionId, 32);
        var keyC = KeyDerivation.DeriveKey(sharedSecret, exchangeHash,
            KeyDerivation.KeyId.EncryptionKeyClientToServer, sessionId, 32);

        Assert.NotEqual(keyA, keyB);
        Assert.NotEqual(keyA, keyC);
        Assert.NotEqual(keyB, keyC);
    }

    [Fact]
    public void KeyDerivation_DeriveAllKeys_ReturnsAllKeys()
    {
        var sharedSecret = new byte[32];
        var exchangeHash = new byte[32];
        var sessionId = new byte[32];
        Random.Shared.NextBytes(sharedSecret);
        Random.Shared.NextBytes(exchangeHash);
        Random.Shared.NextBytes(sessionId);

        var (c2s, s2c) = KeyDerivation.DeriveAllKeys(
            sharedSecret, exchangeHash, sessionId,
            ivSize: 8, keySize: 64, integrityKeySize: 32);

        Assert.Equal(8, c2s.Iv.Length);
        Assert.Equal(64, c2s.EncryptionKey.Length);
        Assert.Equal(32, c2s.IntegrityKey.Length);

        Assert.Equal(8, s2c.Iv.Length);
        Assert.Equal(64, s2c.EncryptionKey.Length);
        Assert.Equal(32, s2c.IntegrityKey.Length);

        // Keys should be different between directions
        Assert.NotEqual(c2s.EncryptionKey, s2c.EncryptionKey);
    }

    #endregion

    #region ChaCha20-Poly1305 Cipher Tests

    [Fact]
    public void ChaCha20Poly1305Cipher_EncryptDecrypt_RoundTrip()
    {
        var cipher = new ChaCha20Poly1305Cipher();
        var key = new byte[64];
        Random.Shared.NextBytes(key);
        cipher.Initialize(key, ReadOnlySpan<byte>.Empty);

        // Create a test packet: length (4) + padding_length (1) + payload + padding
        var payload = "Hello, SSH!"u8.ToArray();
        var paddingLength = 8;
        var packetLength = 1 + payload.Length + paddingLength;

        var plaintext = new byte[4 + packetLength];
        BinaryPrimitives.WriteUInt32BigEndian(plaintext, (uint)packetLength);
        plaintext[4] = (byte)paddingLength;
        payload.CopyTo(plaintext.AsSpan(5));
        Random.Shared.NextBytes(plaintext.AsSpan(5 + payload.Length, paddingLength));

        // Encrypt
        var ciphertext = new byte[plaintext.Length + cipher.TagSize];
        var encryptedLen = cipher.Encrypt(0, plaintext, ciphertext);
        Assert.Equal(plaintext.Length + cipher.TagSize, encryptedLen);

        // Decrypt with same cipher (need fresh instance with same key)
        var decryptCipher = new ChaCha20Poly1305Cipher();
        decryptCipher.Initialize(key, ReadOnlySpan<byte>.Empty);

        var decrypted = new byte[plaintext.Length];
        var decryptedLen = decryptCipher.Decrypt(0, ciphertext, decrypted);
        Assert.Equal(plaintext.Length, decryptedLen);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void ChaCha20Poly1305Cipher_DecryptLength_Works()
    {
        var cipher = new ChaCha20Poly1305Cipher();
        var key = new byte[64];
        Random.Shared.NextBytes(key);
        cipher.Initialize(key, ReadOnlySpan<byte>.Empty);

        // Create a packet with known length
        var packetLength = 100u;
        var plaintext = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(plaintext, packetLength);

        // Encrypt just the length portion using ChaCha20 with the length key (K_2)
        // Per OpenSSH: K_2 = bytes 32-63 = header_ctx for length encryption
        var lengthKey = key.AsSpan(32, 32).ToArray();
        // Nonce is 8-byte sequence number in big-endian (OpenSSH format)
        var nonce = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(nonce, 0); // seq = 0
        var encryptedLength = new byte[4];
        ChaCha20.ProcessOpenSsh(lengthKey, nonce, 0, plaintext, encryptedLength);

        var decryptedLength = cipher.DecryptLength(0, encryptedLength);
        Assert.Equal(packetLength, decryptedLength);
    }

    [Fact]
    public void ChaCha20Poly1305Cipher_TamperedCiphertext_FailsAuthentication()
    {
        var cipher = new ChaCha20Poly1305Cipher();
        var key = new byte[64];
        Random.Shared.NextBytes(key);
        cipher.Initialize(key, ReadOnlySpan<byte>.Empty);

        var plaintext = new byte[20];
        BinaryPrimitives.WriteUInt32BigEndian(plaintext, 16);
        plaintext[4] = 8; // padding length
        Random.Shared.NextBytes(plaintext.AsSpan(5));

        var ciphertext = new byte[plaintext.Length + cipher.TagSize];
        cipher.Encrypt(0, plaintext, ciphertext);

        // Tamper with ciphertext
        ciphertext[10] ^= 0xFF;

        var decryptCipher = new ChaCha20Poly1305Cipher();
        decryptCipher.Initialize(key, ReadOnlySpan<byte>.Empty);

        var decrypted = new byte[plaintext.Length];
        var result = decryptCipher.Decrypt(0, ciphertext, decrypted);
        Assert.Equal(-1, result); // Authentication failed
    }

    #endregion

    #region Curve25519 Key Exchange Tests

    [Fact]
    public void Curve25519Kex_ServerExchange_ProducesValidResult()
    {
        var kex = new Curve25519Kex();

        // Generate a client keypair using X25519 directly
        var (clientPrivate, clientPublic) = X25519.GenerateKeyPair();

        var result = kex.ServerExchange(clientPublic);

        Assert.Equal(32, result.ServerEphemeral.Length);
        Assert.Equal(32, result.SharedSecret.Length);
    }

    [Fact]
    public void Curve25519Kex_ServerExchange_SharedSecretMatchesClientSide()
    {
        var kex = new Curve25519Kex();

        // Generate a client keypair
        var (clientPrivate, clientPublic) = X25519.GenerateKeyPair();

        var result = kex.ServerExchange(clientPublic);

        // Client computes shared secret from server's ephemeral
        var clientShared = X25519.ComputeSharedSecret(clientPrivate, result.ServerEphemeral);

        Assert.Equal(clientShared, result.SharedSecret);
    }

    [Fact]
    public void Curve25519Kex_SharedSecretEncoding_IsMpint()
    {
        var kex = new Curve25519Kex();
        Assert.Equal(SharedSecretEncoding.Mpint, kex.SharedSecretEncoding);
    }

    [Fact]
    public void Curve25519Kex_ComputeExchangeHash_ProducesConsistentHash()
    {
        var kex = new Curve25519Kex();

        var clientVersion = "SSH-2.0-TestClient"u8.ToArray();
        var serverVersion = "SSH-2.0-TestServer"u8.ToArray();
        var clientKexInit = new byte[100];
        var serverKexInit = new byte[100];
        var hostKeyBlob = new byte[51];
        var clientEphemeral = new byte[32];
        var serverEphemeral = new byte[32];
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

        Assert.Equal(32, hash1.Length); // SHA-256
        Assert.Equal(hash1, hash2);
    }

    #endregion

    #region Null Cipher Tests

    [Fact]
    public void NullCipher_PassesThrough()
    {
        var cipher = NullCipher.Instance;
        var plaintext = "Test data"u8.ToArray();
        var output = new byte[plaintext.Length];

        var encrypted = cipher.Encrypt(0, plaintext, output);
        Assert.Equal(plaintext.Length, encrypted);
        Assert.Equal(plaintext, output);

        var decrypted = new byte[plaintext.Length];
        var decryptedLen = cipher.Decrypt(0, output, decrypted);
        Assert.Equal(plaintext.Length, decryptedLen);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void NullCipher_DecryptLength_ReadsPlaintext()
    {
        var cipher = NullCipher.Instance;
        var lengthBytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(lengthBytes, 12345);

        var length = cipher.DecryptLength(0, lengthBytes);
        Assert.Equal(12345u, length);
    }

    #endregion
}
