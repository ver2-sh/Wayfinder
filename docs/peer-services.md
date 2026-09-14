# Peer services v1

Applications can expose a named private byte-stream service through Wayfinder.
Either member can open a service on another member. There is no coordinator,
additional overlay, public application listener, shell execution, or MCP data
plane. Applications define their own protocol and remain responsible for their
own authorization within the trusted membership boundary.

## Local contract

The administrator starts Wayfinder with an explicit application capability:

```sh
wayfinder daemon --peer-service example.service.v1=/run/wayfinder-app/example.json
```

The parent directory must already exist, and the absolute descriptor path must
be outside Wayfinder's private data directory. The option is repeatable for
separate services. The daemon writes a 0600 descriptor with `version: 1`,
`service`, loopback `address` and `service_address`, and a random 256-bit
`credential`. Grant the application read access only to this file (for example,
transfer file ownership to its dedicated account); keep the parent writable only
by the Wayfinder administrator. Use equivalent restricted Windows ACLs.
No access to the private Wayfinder directory is needed. Reapply the file grant
after daemon restart; the capability is ephemeral and clients reread the path.
Normal shutdown removes it; remove a stale descriptor explicitly after a crash.

This credential is cryptographically separate from both administration and MCP.
It authorizes only its exact service name for registration and opening. It cannot
create/join/invite/remove membership, execute shell commands, or read identity,
configuration, MCP bearer or durable state. `/control` remains the private,
high-privilege TUI/CLI administration contract. Norted Link is an application
protocol over this generic transport; Wayfinder has no Norted-specific behavior.

POST `{"op":"status"}` to `http://<address>/peer-service` with
`Authorization: Bearer <credential>`, a loopback Host and no Origin. Its `value`
contains only `nodes` (stable `id`, display `name`, `local`, `reachable`) and
`conflict`. No keys or network configuration are returned.

Register through the same `/peer-service` endpoint:

```json
{
  "op": "register_service",
  "service": "example.service.v1",
  "address": "127.0.0.1:43210",
  "credential": "<application-generated random 256-bit hex credential>"
}
```

The response uses the `value` / `error` envelope. Successful
registration returns `{"version":1,"lease_seconds":60}`. Renew before 60 seconds
by sending the same service, endpoint and application credential. An unexpired
registration cannot be overwritten with another credential or address. Removal
uses `{"op":"unregister_service","service":"example.service.v1","credential":"..."}`.
Registrations exist only in memory, expire without renewal, and disappear when
Wayfinder stops. A crashed application may need to wait for its previous lease
to expire before registering a new instance. Expiration stops new admissions;
it does not revoke streams already admitted.

Service names contain 1–96 lowercase ASCII letters, digits, dots, hyphens or
underscores. Endpoints must be literal loopback socket addresses with nonzero
ports. There are at most 32 registrations and 32 active service streams per
daemon, shared between incoming and outgoing service use.

To open a remote service, connect TCP to `service_address` and send a four-byte
big-endian unsigned JSON byte length followed by UTF-8 JSON:

```json
{
  "version": 1,
  "credential": "<scoped peer-service capability credential>",
  "target": "<full stable peer node ID>",
  "service": "example.service.v1"
}
```

The local daemon replies using the same framing with
`{"version":1,"ready":true}` or `{"version":1,"error":"..."}`. Header JSON is
limited to 16 KiB. An open operation has a five-second setup deadline. A full
stable node ID is required; this API does not resolve display names or forward
to an intermediate node.

Before acknowledging admission, the destination daemon connects only to its
locally registered endpoint and sends this framed preface:

```json
{
  "version": 1,
  "credential": "<application registration credential>",
  "source": "<authenticated initiating node ID>",
  "target": "<this node ID>",
  "service": "example.service.v1"
}
```

The application must verify the credential and expected service, version and
target, then reply with framed `{"version":1,"ready":true}`. After both ready
responses, the stream carries application bytes without further local framing.
A plain HTTP application therefore needs a small preface adapter; Wayfinder
does not inject HTTP authentication, interpret URLs, or expose arbitrary ports.
The registration credential stays on the destination machine. Neither this
preface nor discovery returns peer keys or MCP credentials.

## Peer transport and security

The existing pinned Noise connection starts with a JSON request
`{"op":"service","version":1,"head":"<membership hash>","target":"<ID>","service":"..."}`.
The receiver checks the authenticated Noise identity against its current
membership, requires the exact current membership head and its own target ID,
and replies with `ServiceReady` version 1 or the existing explicit Error reply.
Untrusted identities, known revocations, membership conflicts, unknown services,
stopped applications, expired leases and capacity failures fail admission.
An older daemon lacking this primitive cannot provide a service stream.

After admission, the same Noise session carries length-prefixed encrypted
records. Plaintext begins with byte 0 and 1–32768 payload bytes, or byte 1 alone
for a clean close. Encrypted records are at most 32785 bytes. Each direction has
one reader/writer pump and bounded buffers; a slow reader applies TCP
backpressure across the whole path. Large application requests are streamed as
records and do not use the existing 16 MiB JSON RPC message buffer.

Membership authorization occurs on admission. Its eventual revocation and
conflict semantics are exactly those documented in [architecture](architecture.md).
Service leases do not create another membership or trust system. Authorized
members already have Wayfinder shell authority; this is not a hostile tenant
isolation mechanism.

## Cancellation and failures

Closing either local application stream closes both directions of the peer
stream and the destination socket. Half-close is intentionally a full service
close. Applications must not close their write half while expecting a response.
Daemon shutdown cancels all service streams. Dropped/invalid encrypted records
close the stream; TCP truncation is not an authenticated clean close.

There is no service reopen, replay, fallback, or automatic operation retry.
Failure before ready means no caller application bytes were forwarded. After
ready, loss of the connection can leave an operation's outcome unknown. The
application protocol must define completion and errors and check owner state
before retrying side effects. Cancellation cannot undo already admitted work.
Service capacity exhaustion closes or rejects admission; callers must treat
either as an explicit failure and must never silently select another target.
