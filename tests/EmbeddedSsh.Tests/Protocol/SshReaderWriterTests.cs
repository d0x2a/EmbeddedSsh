using d0x2a.EmbeddedSsh.Protocol;

namespace d0x2a.EmbeddedSsh.Tests.Protocol;

public class SshReaderWriterTests
{
    [Fact]
    public void WriteByte_ReadByte_RoundTrip()
    {
        var buffer = new byte[1];
        var writer = new SshWriter(buffer);
        writer.WriteByte(0x42);

        var reader = new SshReader(buffer);
        Assert.Equal(0x42, reader.ReadByte());
    }

    [Fact]
    public void WriteBoolean_ReadBoolean_RoundTrip()
    {
        var buffer = new byte[2];
        var writer = new SshWriter(buffer);
        writer.WriteBoolean(true);
        writer.WriteBoolean(false);

        var reader = new SshReader(buffer);
        Assert.True(reader.ReadBoolean());
        Assert.False(reader.ReadBoolean());
    }

    [Fact]
    public void WriteUInt32_ReadUInt32_RoundTrip()
    {
        var buffer = new byte[4];
        var writer = new SshWriter(buffer);
        writer.WriteUInt32(0x12345678);

        var reader = new SshReader(buffer);
        Assert.Equal(0x12345678u, reader.ReadUInt32());

        // Verify big-endian encoding
        Assert.Equal(0x12, buffer[0]);
        Assert.Equal(0x34, buffer[1]);
        Assert.Equal(0x56, buffer[2]);
        Assert.Equal(0x78, buffer[3]);
    }

    [Fact]
    public void WriteUInt64_ReadUInt64_RoundTrip()
    {
        var buffer = new byte[8];
        var writer = new SshWriter(buffer);
        writer.WriteUInt64(0x123456789ABCDEF0);

        var reader = new SshReader(buffer);
        Assert.Equal(0x123456789ABCDEF0ul, reader.ReadUInt64());

        // Verify big-endian encoding
        Assert.Equal(0x12, buffer[0]);
        Assert.Equal(0x34, buffer[1]);
        Assert.Equal(0x56, buffer[2]);
        Assert.Equal(0x78, buffer[3]);
        Assert.Equal(0x9A, buffer[4]);
        Assert.Equal(0xBC, buffer[5]);
        Assert.Equal(0xDE, buffer[6]);
        Assert.Equal(0xF0, buffer[7]);
    }

    [Fact]
    public void WriteBinaryString_ReadBinaryString_RoundTrip()
    {
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var buffer = new byte[4 + data.Length];

        var writer = new SshWriter(buffer);
        writer.WriteBinaryString(data);

        var reader = new SshReader(buffer);
        var result = reader.ReadBinaryString();

        Assert.Equal(data, result.ToArray());
    }

    [Fact]
    public void WriteString_ReadString_RoundTrip()
    {
        const string testString = "Hello, SSH!";
        var buffer = new byte[100];

        var writer = new SshWriter(buffer);
        writer.WriteString(testString);

        var reader = new SshReader(buffer);
        var result = reader.ReadString();

        Assert.Equal(testString, result);
    }

    [Fact]
    public void WriteString_UTF8_RoundTrip()
    {
        const string testString = "Hello, 世界! 🌍";
        var buffer = new byte[100];

        var writer = new SshWriter(buffer);
        writer.WriteString(testString);

        var reader = new SshReader(buffer);
        var result = reader.ReadString();

        Assert.Equal(testString, result);
    }

    [Fact]
    public void WriteNameList_ReadNameList_RoundTrip()
    {
        var names = new[] { "aes256-ctr", "chacha20-poly1305@openssh.com", "aes128-ctr" };
        var buffer = new byte[100];

        var writer = new SshWriter(buffer);
        writer.WriteNameList(names);

        var reader = new SshReader(buffer);
        var result = reader.ReadNameList();

        Assert.Equal(names, result);
    }

    [Fact]
    public void WriteNameList_Empty_RoundTrip()
    {
        var names = Array.Empty<string>();
        var buffer = new byte[4];

        var writer = new SshWriter(buffer);
        writer.WriteNameList(names);

        var reader = new SshReader(buffer);
        var result = reader.ReadNameList();

        Assert.Empty(result);
    }

    [Fact]
    public void WriteMpint_Positive_NoLeadingZero()
    {
        // Value 0x7FFFFFFF (no high bit set)
        var value = new byte[] { 0x7F, 0xFF, 0xFF, 0xFF };
        var buffer = new byte[8];

        var writer = new SshWriter(buffer);
        writer.WriteMpint(value);

        var reader = new SshReader(buffer);
        var result = reader.ReadMpint();

        Assert.Equal(value, result.ToArray());
    }

    [Fact]
    public void WriteMpint_Positive_WithLeadingZero()
    {
        // Value 0x80000000 (high bit set, needs leading zero for positive)
        var value = new byte[] { 0x80, 0x00, 0x00, 0x00 };
        var buffer = new byte[10];

        var writer = new SshWriter(buffer);
        writer.WriteMpint(value);

        var reader = new SshReader(buffer);
        var result = reader.ReadMpint();

        // Result should have leading zero
        Assert.Equal(5, result.Length);
        Assert.Equal(0x00, result[0]);
        Assert.Equal(0x80, result[1]);
    }

    [Fact]
    public void WriteMpint_Zero()
    {
        var value = new byte[] { 0x00, 0x00, 0x00 };
        var buffer = new byte[10];

        var writer = new SshWriter(buffer);
        writer.WriteMpint(value);

        var reader = new SshReader(buffer);
        var result = reader.ReadMpint();

        Assert.Empty(result.ToArray());
    }

    [Fact]
    public void WriteMpint_SkipsLeadingZeros()
    {
        var value = new byte[] { 0x00, 0x00, 0x01, 0x02 };
        var buffer = new byte[10];

        var writer = new SshWriter(buffer);
        writer.WriteMpint(value);

        var reader = new SshReader(buffer);
        var result = reader.ReadMpint();

        Assert.Equal(new byte[] { 0x01, 0x02 }, result.ToArray());
    }

    [Fact]
    public void Reader_ThrowsOnOverflow()
    {
        var buffer = new byte[2];
        var reader = new SshReader(buffer);

        var ex = Record.Exception(() =>
        {
            var r = new SshReader(buffer);
            r.ReadUInt32();
        });
        Assert.IsType<SshProtocolException>(ex);
    }

    [Fact]
    public void Writer_ThrowsOnOverflow()
    {
        var buffer = new byte[2];

        var ex = Record.Exception(() =>
        {
            var w = new SshWriter(buffer);
            w.WriteUInt32(123);
        });
        Assert.IsType<SshProtocolException>(ex);
    }

    [Fact]
    public void Reader_Position_TracksCorrectly()
    {
        var buffer = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var reader = new SshReader(buffer);

        Assert.Equal(0, reader.Position);
        Assert.Equal(5, reader.Remaining);

        reader.ReadByte();
        Assert.Equal(1, reader.Position);
        Assert.Equal(4, reader.Remaining);

        reader.Skip(2);
        Assert.Equal(3, reader.Position);
        Assert.Equal(2, reader.Remaining);
    }

    [Fact]
    public void Writer_Position_TracksCorrectly()
    {
        var buffer = new byte[10];
        var writer = new SshWriter(buffer);

        Assert.Equal(0, writer.Position);
        Assert.Equal(10, writer.Remaining);

        writer.WriteByte(0x01);
        Assert.Equal(1, writer.Position);
        Assert.Equal(9, writer.Remaining);

        writer.WriteUInt32(0x12345678);
        Assert.Equal(5, writer.Position);
        Assert.Equal(5, writer.Remaining);
    }

    [Fact]
    public void GetBinaryStringSize_CalculatesCorrectly()
    {
        Assert.Equal(4, SshWriter.GetBinaryStringSize(0));
        Assert.Equal(14, SshWriter.GetBinaryStringSize(10));
        Assert.Equal(104, SshWriter.GetBinaryStringSize(100));
    }

    [Fact]
    public void GetNameListSize_CalculatesCorrectly()
    {
        Assert.Equal(4, SshWriter.GetNameListSize(Array.Empty<string>()));
        Assert.Equal(4 + 3, SshWriter.GetNameListSize(new[] { "abc" }));
        Assert.Equal(4 + 3 + 1 + 3, SshWriter.GetNameListSize(new[] { "abc", "def" })); // comma between
    }
}
