using System.Net;
using System.Text;
using d0x2a.EmbeddedSsh;
using d0x2a.EmbeddedSsh.Auth;
using d0x2a.EmbeddedSsh.Connection;
using d0x2a.EmbeddedSsh.HostKeys;

const int Port = 2222;
const string HostKeyPath = "host_key";

Console.WriteLine("EmbeddedSsh Example Server");
Console.WriteLine("==========================");
Console.WriteLine();

// Load or generate host key
Ed25519HostKey hostKey;
if (File.Exists(HostKeyPath))
{
    Console.WriteLine($"Loading host key from {HostKeyPath}");
    hostKey = Ed25519HostKey.FromOpenSshFile(HostKeyPath);
}
else
{
    Console.WriteLine("Generating new host key...");
    hostKey = Ed25519HostKey.Generate();
    File.WriteAllText(HostKeyPath, hostKey.ExportOpenSshPrivateKey("EmbeddedSsh Example"));
    Console.WriteLine($"Saved host key to {HostKeyPath}");
}

// Load authorized keys
// Priority: 1) AUTHORIZED_KEYS env var, 2) ~/.ssh/authorized_keys, 3) scan ~/.ssh/*.pub
var sshDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
var authorizedKeys = new List<AuthorizedKey>();

var authorizedKeysPath = Environment.GetEnvironmentVariable("AUTHORIZED_KEYS");
if (!string.IsNullOrEmpty(authorizedKeysPath) && File.Exists(authorizedKeysPath))
{
    // Use specified authorized_keys file
    var content = File.ReadAllText(authorizedKeysPath);
    authorizedKeys.AddRange(AuthorizedKeysAuthenticator.ParseAuthorizedKeysFile(content));
    Console.WriteLine($"Loaded {authorizedKeys.Count} key(s) from {authorizedKeysPath}");
}
else
{
    // Try standard authorized_keys file
    var standardAuthKeysPath = Path.Combine(sshDir, "authorized_keys");
    if (File.Exists(standardAuthKeysPath))
    {
        var content = File.ReadAllText(standardAuthKeysPath);
        authorizedKeys.AddRange(AuthorizedKeysAuthenticator.ParseAuthorizedKeysFile(content));
        Console.WriteLine($"Loaded {authorizedKeys.Count} key(s) from {standardAuthKeysPath}");
    }
    else
    {
        // Scan for all *.pub files in ~/.ssh/
        if (Directory.Exists(sshDir))
        {
            foreach (var pubKeyFile in Directory.GetFiles(sshDir, "*.pub"))
            {
                var pubKeyContent = File.ReadAllText(pubKeyFile);
                var key = AuthorizedKeysAuthenticator.ParseAuthorizedKeyLine(pubKeyContent.Trim());
                if (key != null)
                {
                    authorizedKeys.Add(key);
                    Console.WriteLine($"Loaded {key.Algorithm} key from {pubKeyFile}");
                }
            }
        }
    }
}

if (authorizedKeys.Count == 0)
{
    Console.WriteLine("Warning: No SSH public keys found");
    Console.WriteLine("Options:");
    Console.WriteLine("  - Set AUTHORIZED_KEYS environment variable to path of authorized_keys file");
    Console.WriteLine("  - Create ~/.ssh/authorized_keys");
    Console.WriteLine("  - Generate keys with: ssh-keygen -t ed25519");
}

// Configure the server with SSH key authentication
var options = new SshServerOptions
{
    ServerVersion = "SSH-2.0-EmbeddedSsh_Example",
    Banner = "Welcome to EmbeddedSsh Example Server!\r\n",
    Authenticator = new AuthorizedKeysAuthenticator(new Dictionary<string, IEnumerable<AuthorizedKey>>
    {
        [Environment.UserName] = authorizedKeys
    })
};
options.HostKeys.Add(hostKey);

// Create and start the server
await using var server = new SshServer(options, new IPEndPoint(IPAddress.Any, Port));

Console.WriteLine($"Starting SSH server on port {Port}...");
Console.WriteLine();
Console.WriteLine($"SSH key authentication enabled for user: {Environment.UserName}");
Console.WriteLine();
Console.WriteLine($"Connect with: ssh -p 2222 {Environment.UserName}@localhost");
Console.WriteLine();
Console.WriteLine("Press Ctrl+C to stop the server.");
Console.WriteLine();

// Handle Ctrl+C
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    Console.WriteLine("\nShutting down...");
    cts.Cancel();
};

// Track connections - NOTE: This handler must return quickly!
// The server awaits this before calling RunAsync(), so we spawn a background task.
server.ConnectionAccepted += connection =>
{
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Connection accepted (state: {connection.State})");

    // Handle the connection in a background task (don't block the event handler!)
    _ = Task.Run(async () =>
    {
        try
        {
            // Wait for connection to be authenticated
            while (!cts.IsCancellationRequested &&
                   connection.State != ConnectionState.Connected &&
                   connection.State != ConnectionState.Disconnected)
            {
                await Task.Delay(50, cts.Token);
            }

            if (connection.State == ConnectionState.Connected)
            {
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] User authenticated: {connection.User?.Username}");
            }

            while (!cts.IsCancellationRequested && connection.State == ConnectionState.Connected)
            {
                var channel = await connection.AcceptChannelAsync(cts.Token);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Channel opened: {channel.ChannelType} (User: {connection.User?.Username})");

                // Handle the channel in a background task
                _ = HandleChannelAsync(channel, connection.User?.Username ?? "unknown", cts.Token);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Connection handler error: {ex.Message}");
        }
    });

    return Task.CompletedTask;
};

server.ConnectionClosed += (connection, error) =>
{
    var user = connection.User?.Username ?? "unauthenticated";
    if (error != null)
    {
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Connection closed ({user}): {error.Message}");
        if (error.InnerException != null)
            Console.WriteLine($"    Inner: {error.InnerException.Message}");
        Console.WriteLine($"    State was: {connection.State}");
        Console.WriteLine($"    Stack: {error.StackTrace}");
    }
    else
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Connection closed ({user})");
};

// Start the server
server.Start();
Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Server started and listening on port {Port}");

// Wait until cancelled
try
{
    await Task.Delay(Timeout.Infinite, cts.Token);
}
catch (OperationCanceledException)
{
    // Expected
}

Console.WriteLine("Server stopped.");

// Channel handler - implements a simple echo shell
static async Task HandleChannelAsync(SshChannel channel, string username, CancellationToken ct)
{
    try
    {
        // Wait for shell or exec request
        await Task.Delay(100, ct); // Brief delay to allow request processing

        if (channel.ShellRequested || channel.Command != null)
        {
            if (channel.Command != null)
            {
                // Execute command and return result
                await ExecuteCommandAsync(channel, channel.Command, username, ct);
            }
            else
            {
                // Interactive shell mode
                await RunShellAsync(channel, username, ct);
            }
        }
        else
        {
            // No shell/exec request, just echo any data received
            await EchoModeAsync(channel, ct);
        }

        await channel.SendExitStatusAsync(0, ct);
    }
    catch (OperationCanceledException)
    {
        // Normal
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Channel error: {ex.Message}");
        try
        {
            await channel.SendExitStatusAsync(1, ct);
        }
        catch { }
    }
    finally
    {
        await channel.CloseAsync(ct);
    }
}

static async Task ExecuteCommandAsync(SshChannel channel, string command, string username, CancellationToken ct)
{
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Executing command for {username}: {command}");

    var response = command.Trim().ToLowerInvariant() switch
    {
        "whoami" => $"{username}\r\n",
        "hostname" => "embeddedssh-example\r\n",
        "date" => $"{DateTime.Now:R}\r\n",
        "uptime" => $"up {Environment.TickCount64 / 1000} seconds\r\n",
        "uname" or "uname -a" => "EmbeddedSsh 1.0.0 .NET\r\n",
        "pwd" => "/home/" + username + "\r\n",
        "echo" => "\r\n",
        var cmd when cmd.StartsWith("echo ") => cmd[5..] + "\r\n",
        "help" => "Available commands:\r\n" +
            "  whoami    - Display current user\r\n" +
            "  hostname  - Display hostname\r\n" +
            "  date      - Display current date and time\r\n" +
            "  uptime    - Display system uptime\r\n" +
            "  uname     - Display system information\r\n" +
            "  pwd       - Display current directory\r\n" +
            "  echo      - Echo text back\r\n" +
            "  help      - Display this help message\r\n",
        _ => $"Command not found: {command}\r\n"
    };

    await channel.WriteAsync(Encoding.UTF8.GetBytes(response), ct);
}

static async Task RunShellAsync(SshChannel channel, string username, CancellationToken ct)
{
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Starting shell for {username}");

    var prompt = $"{username}@embeddedssh:~$ ";
    var welcomeMessage = $"" +
        $"Type 'help' for available commands, 'exit' to disconnect.\r\n\r\n" +
        prompt;

    await channel.WriteAsync(Encoding.UTF8.GetBytes(welcomeMessage), ct);

    var inputBuffer = new StringBuilder();

    while (!ct.IsCancellationRequested && !channel.EofReceived)
    {
        var data = await channel.ReadAsync(ct);
        if (data.IsEmpty)
            break;

        await channel.AdjustLocalWindowAsync((uint)data.Length, ct);

        // Copy to array to avoid span across await boundaries
        var bytes = data.ToArray();
        for (var i = 0; i < bytes.Length; i++)
        {
            var b = bytes[i];
            if (b == '\r' || b == '\n')
            {
                // Echo newline
                await channel.WriteAsync("\r\n"u8.ToArray(), ct);

                var command = inputBuffer.ToString().Trim();
                inputBuffer.Clear();

                if (command.Equals("exit", StringComparison.OrdinalIgnoreCase) ||
                    command.Equals("quit", StringComparison.OrdinalIgnoreCase))
                {
                    await channel.WriteAsync("Goodbye!\r\n"u8.ToArray(), ct);
                    return;
                }

                if (!string.IsNullOrEmpty(command))
                {
                    await ExecuteCommandAsync(channel, command, username, ct);
                }

                await channel.WriteAsync(Encoding.UTF8.GetBytes(prompt), ct);
            }
            else if (b == 127 || b == 8) // Backspace or DEL
            {
                if (inputBuffer.Length > 0)
                {
                    inputBuffer.Length--;
                    await channel.WriteAsync("\b \b"u8.ToArray(), ct); // Erase character
                }
            }
            else if (b >= 32) // Printable character
            {
                inputBuffer.Append((char)b);
                await channel.WriteAsync(new byte[] { b }, ct); // Echo character
            }
        }
    }
}

static async Task EchoModeAsync(SshChannel channel, CancellationToken ct)
{
    // Simple echo mode - just echo back any received data
    while (!ct.IsCancellationRequested && !channel.EofReceived)
    {
        var data = await channel.ReadAsync(ct);
        if (data.IsEmpty)
            break;

        await channel.AdjustLocalWindowAsync((uint)data.Length, ct);
        await channel.WriteAsync(data, ct);
    }
}
