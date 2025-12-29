# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EmbeddedSsh is a minimal, embeddable SSH-2 server library for .NET 10.0 following RFC 4251-4254. It has zero external dependencies (all cryptographic primitives implemented from scratch).

## Build and Test Commands

```bash
# Build the solution
dotnet build

# Run all tests
dotnet test

# Run specific test class
dotnet test --filter "ClassName"

# Run specific test method
dotnet test --filter "FullyQualifiedName~TestMethodName"

# Example: run only Ed25519 tests
dotnet test --filter "Ed25519"
```

## Architecture

### Layered Structure (follows SSH RFC architecture)

1. **Protocol Layer** (`Protocol/`)
   - `SshReader`/`SshWriter`: ref structs for binary serialization of SSH types (RFC 4251 §5)
   - `Messages/`: Record types for all SSH message types
   - `MessageTypes.cs`: Enum of SSH message type codes

2. **Crypto Layer** (`Crypto/`)
   - Pure managed implementations with no external dependencies
   - `ChaCha20.cs`: Stream cipher (RFC 7539)
   - `Poly1305.cs`: MAC using 130-bit arithmetic with 5 limbs
   - `X25519.cs`: ECDH key exchange (RFC 7748)
   - `Ed25519.cs`: Signatures (RFC 8032) - uses 10-limb radix-2^25.5 field representation

3. **Transport Layer** (`Transport/`)
   - `TransportLayer.cs`: Version exchange, packet framing, encryption
   - `KeyDerivation.cs`: Derives cipher/MAC keys from shared secret
   - `Algorithms/`: Cipher and key exchange algorithm implementations

4. **Auth Layer** (`Auth/`)
   - `IAuthenticator`: Interface for authentication methods
   - `AuthorizedKeysAuthenticator`: Public key authentication
   - `PasswordAuthenticator`: Password authentication

5. **Connection Layer** (`Connection/`)
   - `ConnectionLayer.cs`: Channel management, global requests
   - `ChannelManager.cs`: Track open channels, window sizes
   - `SshChannel.cs`: Channel abstraction with read/write APIs

6. **Server Integration**
   - `SshServer.cs`: Main server with TcpListener
   - `SshConnection.cs`: Per-connection state machine
   - `HostKeys/`: Host key implementations (Ed25519HostKey)

### Connection State Machine

```
AwaitingVersion → AwaitingKexInit → KexInProgress → AwaitingNewKeys
→ AwaitingServiceRequest → Authenticating → Connected
```

### Field Arithmetic Convention

Crypto implementations use 10-limb representation for field elements mod 2^255-19:
- Limbs alternate between 26 and 25 bits
- Position weights: 2^0, 2^26, 2^51, 2^77, 2^102, 2^128, 2^153, 2^179, 2^204, 2^230
- Signed limbs allow for efficient subtraction without borrowing

## Testing Notes

- `SshReader`/`SshWriter` are ref structs - use `Record.Exception()` instead of `Assert.Throws()` in tests
- Crypto tests use RFC test vectors (RFC 7539 for ChaCha20/Poly1305, RFC 7748 for X25519, RFC 8032 for Ed25519)
