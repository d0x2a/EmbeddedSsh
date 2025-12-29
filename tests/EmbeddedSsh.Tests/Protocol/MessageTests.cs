using com.d0x2a.EmbeddedSsh.Protocol;
using com.d0x2a.EmbeddedSsh.Protocol.Messages;

namespace com.d0x2a.EmbeddedSsh.Tests.Protocol;

public class MessageTests
{
    [Fact]
    public void KexInitMessage_RoundTrip()
    {
        var original = new KexInitMessage
        {
            KexAlgorithms = ["curve25519-sha256", "curve25519-sha256@libssh.org"],
            HostKeyAlgorithms = ["ssh-ed25519"],
            EncryptionAlgorithmsClientToServer = ["chacha20-poly1305@openssh.com"],
            EncryptionAlgorithmsServerToClient = ["chacha20-poly1305@openssh.com"],
            MacAlgorithmsClientToServer = ["hmac-sha2-256-etm@openssh.com"],
            MacAlgorithmsServerToClient = ["hmac-sha2-256-etm@openssh.com"],
            CompressionAlgorithmsClientToServer = ["none"],
            CompressionAlgorithmsServerToClient = ["none"],
            FirstKexPacketFollows = false
        };

        var buffer = new byte[1000];
        var written = MessageParser.Write(original, buffer);

        var parsed = MessageParser.Parse(buffer.AsSpan(0, written)) as KexInitMessage;

        Assert.NotNull(parsed);
        Assert.Equal(original.KexAlgorithms, parsed.KexAlgorithms);
        Assert.Equal(original.HostKeyAlgorithms, parsed.HostKeyAlgorithms);
        Assert.Equal(original.EncryptionAlgorithmsClientToServer, parsed.EncryptionAlgorithmsClientToServer);
        Assert.Equal(original.CompressionAlgorithmsClientToServer, parsed.CompressionAlgorithmsClientToServer);
        Assert.Equal(original.FirstKexPacketFollows, parsed.FirstKexPacketFollows);
    }

    [Fact]
    public void DisconnectMessage_RoundTrip()
    {
        var original = new DisconnectMessage
        {
            Reason = DisconnectReason.ByApplication,
            Description = "Normal disconnect",
            LanguageTag = "en"
        };

        var buffer = new byte[100];
        var written = MessageParser.Write(original, buffer);

        var parsed = MessageParser.Parse(buffer.AsSpan(0, written)) as DisconnectMessage;

        Assert.NotNull(parsed);
        Assert.Equal(DisconnectReason.ByApplication, parsed.Reason);
        Assert.Equal("Normal disconnect", parsed.Description);
        Assert.Equal("en", parsed.LanguageTag);
    }

    [Fact]
    public void ServiceRequestMessage_RoundTrip()
    {
        var original = new ServiceRequestMessage
        {
            ServiceName = "ssh-userauth"
        };

        var buffer = new byte[50];
        var written = MessageParser.Write(original, buffer);

        var parsed = MessageParser.Parse(buffer.AsSpan(0, written)) as ServiceRequestMessage;

        Assert.NotNull(parsed);
        Assert.Equal("ssh-userauth", parsed.ServiceName);
    }

    [Fact]
    public void UserauthRequestMessage_None_RoundTrip()
    {
        var original = new UserauthRequestMessage
        {
            Username = "testuser",
            ServiceName = "ssh-connection",
            MethodName = "none"
        };

        var buffer = new byte[100];
        var written = MessageParser.Write(original, buffer);

        var parsed = MessageParser.Parse(buffer.AsSpan(0, written)) as UserauthRequestMessage;

        Assert.NotNull(parsed);
        Assert.Equal("testuser", parsed.Username);
        Assert.Equal("ssh-connection", parsed.ServiceName);
        Assert.Equal("none", parsed.MethodName);
    }

    [Fact]
    public void UserauthRequestMessage_PublicKey_Query_RoundTrip()
    {
        var publicKeyBlob = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        var original = new UserauthRequestMessage
        {
            Username = "testuser",
            ServiceName = "ssh-connection",
            MethodName = "publickey",
            HasSignature = false,
            PublicKeyAlgorithm = "ssh-ed25519",
            PublicKeyBlob = publicKeyBlob
        };

        var buffer = new byte[200];
        var written = MessageParser.Write(original, buffer);

        var parsed = MessageParser.Parse(buffer.AsSpan(0, written)) as UserauthRequestMessage;

        Assert.NotNull(parsed);
        Assert.Equal("testuser", parsed.Username);
        Assert.Equal("publickey", parsed.MethodName);
        Assert.False(parsed.HasSignature);
        Assert.Equal("ssh-ed25519", parsed.PublicKeyAlgorithm);
        Assert.Equal(publicKeyBlob, parsed.PublicKeyBlob!.Value.ToArray());
    }

    [Fact]
    public void UserauthRequestMessage_PublicKey_WithSignature_RoundTrip()
    {
        var publicKeyBlob = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var signature = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50 };

        var original = new UserauthRequestMessage
        {
            Username = "testuser",
            ServiceName = "ssh-connection",
            MethodName = "publickey",
            HasSignature = true,
            PublicKeyAlgorithm = "ssh-ed25519",
            PublicKeyBlob = publicKeyBlob,
            Signature = signature
        };

        var buffer = new byte[200];
        var written = MessageParser.Write(original, buffer);

        var parsed = MessageParser.Parse(buffer.AsSpan(0, written)) as UserauthRequestMessage;

        Assert.NotNull(parsed);
        Assert.True(parsed.HasSignature);
        Assert.Equal(signature, parsed.Signature!.Value.ToArray());
    }

    [Fact]
    public void ChannelOpenMessage_RoundTrip()
    {
        var original = new ChannelOpenMessage
        {
            ChannelType = "session",
            SenderChannel = 0,
            InitialWindowSize = 2097152,
            MaximumPacketSize = 32768
        };

        var buffer = new byte[100];
        var written = MessageParser.Write(original, buffer);

        var parsed = MessageParser.Parse(buffer.AsSpan(0, written)) as ChannelOpenMessage;

        Assert.NotNull(parsed);
        Assert.Equal("session", parsed.ChannelType);
        Assert.Equal(0u, parsed.SenderChannel);
        Assert.Equal(2097152u, parsed.InitialWindowSize);
        Assert.Equal(32768u, parsed.MaximumPacketSize);
    }

    [Fact]
    public void ChannelDataMessage_RoundTrip()
    {
        var data = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }; // "Hello"

        var original = new ChannelDataMessage
        {
            RecipientChannel = 42,
            Data = data
        };

        var buffer = new byte[100];
        var written = MessageParser.Write(original, buffer);

        var parsed = MessageParser.Parse(buffer.AsSpan(0, written)) as ChannelDataMessage;

        Assert.NotNull(parsed);
        Assert.Equal(42u, parsed.RecipientChannel);
        Assert.Equal(data, parsed.Data.ToArray());
    }

    [Fact]
    public void ChannelRequestMessage_Exec_RoundTrip()
    {
        var original = new ChannelRequestMessage
        {
            RecipientChannel = 0,
            RequestType = "exec",
            WantReply = true,
            Command = "ls -la"
        };

        var buffer = new byte[100];
        var written = MessageParser.Write(original, buffer);

        var parsed = MessageParser.Parse(buffer.AsSpan(0, written)) as ChannelRequestMessage;

        Assert.NotNull(parsed);
        Assert.Equal("exec", parsed.RequestType);
        Assert.True(parsed.WantReply);
        Assert.Equal("ls -la", parsed.Command);
    }

    [Fact]
    public void ChannelRequestMessage_ExitStatus_RoundTrip()
    {
        var original = ChannelRequestMessage.CreateExitStatus(0, 42);

        var buffer = new byte[100];
        var written = MessageParser.Write(original, buffer);

        var parsed = MessageParser.Parse(buffer.AsSpan(0, written)) as ChannelRequestMessage;

        Assert.NotNull(parsed);
        Assert.Equal("exit-status", parsed.RequestType);
        Assert.False(parsed.WantReply);
        Assert.Equal(42u, parsed.ExitStatus);
    }

    [Fact]
    public void NewKeysMessage_Singleton()
    {
        var buffer = new byte[] { (byte)SshMessageType.NewKeys };
        var parsed = MessageParser.Parse(buffer) as NewKeysMessage;

        Assert.Same(NewKeysMessage.Instance, parsed);
    }

    [Fact]
    public void UserauthSuccessMessage_Singleton()
    {
        var buffer = new byte[] { (byte)SshMessageType.UserauthSuccess };
        var parsed = MessageParser.Parse(buffer) as UserauthSuccessMessage;

        Assert.Same(UserauthSuccessMessage.Instance, parsed);
    }

    [Fact]
    public void MessageParser_ThrowsOnUnknownType()
    {
        var buffer = new byte[] { 0xFF }; // Unknown message type

        Assert.Throws<SshProtocolException>(() => MessageParser.Parse(buffer));
    }

    [Fact]
    public void MessageParser_ThrowsOnEmptyPayload()
    {
        Assert.Throws<SshProtocolException>(() => MessageParser.Parse(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void GetTotalSize_IncludesMessageType()
    {
        var message = new ServiceRequestMessage { ServiceName = "test" };
        var size = MessageParser.GetTotalSize(message);

        // 1 (type) + 4 (length) + 4 (test)
        Assert.Equal(1 + 4 + 4, size);
    }
}
