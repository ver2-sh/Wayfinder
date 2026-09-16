# MCP OAuth and gateway deployment

## Hosted setup

Install Wayfinder agents, create a chain on the first device, and join the others.
Keep at least one administrative device connected. Use
`https://mcp.usewayfinder.app` as the MCP URL in ChatGPT or another MCP client.
Everyone uses this URL; OAuth grants distinguish chains. No personal MCP server,
email login or hosted account is required.

The client can dynamically register with `POST /oauth/register`, giving its exact
callback URI in `redirect_uris` (one URI per registration), a display name and
`token_endpoint_auth_method` (`none`, `client_secret_basic` or `client_secret_post`).
Confidential clients receive a secret once; the gateway persists only its hash.
Public clients use PKCE without a client secret. Client names are self-reported.
Register additional callback URIs as separate clients. Metadata URLs:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`

The MCP endpoint is `/`. The authorization request uses `response_type=code`,
`resource` equal to the exact gateway origin, the registered `client_id` and
`redirect_uri`, an S256 PKCE challenge, desired `scope` (`read`, `exec`, or both),
and the MCP client's state. The token request uses the same resource and redirect
and the original verifier. Tokens are never accepted in URLs.

In the browser, copy the displayed pairing code and run:

```sh
wayfinder authorize ABCDEF-123456
```

Check the gateway, Chain ID, client ID/name, callback URI and scopes. Type `yes`
only for a connection you initiated. The admin device signs the exact request
details. Refresh the browser page to finish OAuth. No browser-side approval or
recovery phrase input exists. Pairing expires in ten minutes. Authorization codes
expire in one minute and are consumed even on a failed exchange. S256 is mandatory.

`wayfinder auth list` shows grants, chain/client binding and scopes, and
`wayfinder auth revoke GRANT_ID` revokes one. Access tokens last at most an hour.
Refresh tokens rotate and last at most 30 days from grant creation. Reusing a
spent refresh token revokes the whole grant. Grant revocation denies subsequent
requests, but does not undo a command already dispatched.

## Self-hosting

Build the exact same open-source gateway used by the hosted deployment:

```sh
cargo build --release -p wayfinder-gateway
sudo install -m 0755 target/release/wayfinder-gateway /usr/local/bin/wayfinder-gateway
```

Use `deploy/wayfinder-gateway.service`, changing `--public-url` to your canonical
HTTPS origin before installing it. Its dynamic service user owns a private
`/var/lib/wayfinder-gateway` SQLite directory. It has no device identity and cannot
execute local commands on its own. Keep the service on loopback port 3000.

```sh
sudo install -m 0644 deploy/wayfinder-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wayfinder-gateway.service
```

Terminate TLS with your chosen reverse proxy. For example, a Caddy site:

```caddyfile
wayfinder.example.com {
    reverse_proxy 127.0.0.1:3000 {
        header_up Host 127.0.0.1
    }
}
```

[Caddy supports WebSocket upgrades automatically](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#streaming). Avoid negative `flush_interval`, which disables backend cancellation on early client disconnect. Ensure your actual proxy passes
Authorization, Origin, methods, query strings, streaming bodies, responses,
WWW-Authenticate and Location unchanged; does not retry side-effecting requests;
and does not log query strings, credentials or command bodies. Host must be
loopback at the gateway. Forwarded-host headers never choose an issuer/backend.
The gateway rejects browser Origins on agent/admin/MCP endpoints, while OAuth
browser requests may use its exact origin. Disable caching and external auth
challenges on the MCP/OAuth hostname. Do not open port 3000 publicly.

Agent enrollment:

```sh
wayfinder chain create --name laptop --gateway https://wayfinder.example.com
# Or join the same chain on another installation:
wayfinder chain join --name workstation --gateway https://wayfinder.example.com
```

The gateway URL is independent of identity. To move an existing device:

```sh
sudo systemctl stop wayfinder.service
wayfinder gateway https://wayfinder.example.com
sudo systemctl start wayfinder.service
```

The command requires interactive destination confirmation, re-registers this
same key/certificate, and saves the new URL only after successful registration.
A failed move leaves the old configuration intact. No automatic fallback exists.
Other devices need the same explicit move; configure the MCP client for the new
URL and reauthorize. A new gateway does not inherit revocations or grants. To
preserve those, move a consistent private database backup to the new gateway
instead. Grants have a resource origin binding: changing the public origin
requires new OAuth authorization.

For local development, `http://127.0.0.1:PORT` and explicit IPv6 loopback HTTP
origins are allowed. Remote plaintext origins and noncanonical URLs are rejected.
A default gateway is only an installation default, never a cryptographic domain.

## Operations

Use a single gateway process and persistent disk. Back up the SQLite database
while stopped, or use SQLite's backup API. Protect backups like the live registry:
although it contains no identity private keys or raw bearer tokens, it controls
membership revocations and grants. Do not restore stale revocation data casually.
There are no migration tools for old unreleased state.

Connection availability is ephemeral. A gateway restart discards pending OAuth
flows, one-time challenges and active sockets; agents reconnect with durable
keys. Already-dispatched execution can have an uncertain outcome and is never
retried. Revocation terminates device sessions; network failures can delay
cancellation until the agent detects loss or reaches the command deadline.

The official Cloudflare Worker/VPC/tunnel remains deployment infrastructure.
Self-hosting needs none of it. See Wayfinder-Cloudflare for its hosted deployment
contract. No OpenAI Tunnel or peer-address configuration is part of Wayfinder.


## Admission and registration lifetime

Unapproved dynamic registrations expire after one hour or a gateway restart;
register again if authorization has not completed. Once a grant is issued, the
client registration persists for the lifetime of its grants. Expired grants and
tokens are collected; device revocations remain permanent. A client can have four
unapproved requests at once. Requests expire after ten minutes.

Public deployments must rate-limit connection attempts, dynamic registration and
OAuth/device endpoints at their TLS ingress. The generic gateway never trusts
Cloudflare or forwarded IP headers for authorization. Capacity limits reject new
work without evicting authenticated sessions or active grants. Wait before retrying
admission failures; new-device admission is bounded separately from reconnects.
