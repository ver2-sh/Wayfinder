# Self-hosted remote MCP

One HTTPS origin routes to **one Wayfinder installation**. Wayfinder authenticates
MCP clients and controls the existing Noise-authenticated peer graph. Credentials
are not replicated or forwarded. Public TLS terminates at a reverse proxy.

```text
MCP client → HTTPS mcp.usewayfinder.app → Caddy → 127.0.0.1:3000
                                                    ↓
                                           Wayfinder gateway
                                                    ↓
                                      existing authenticated peers
```

The hostname below is an operator example, not a product constant.

## 1. Enable the listener

For a new installation, initialize as the service account (provision its data
directory with mode 0700 first):

```sh
wayfinder --data-dir /var/lib/wayfinder init --name gateway \
  --mcp-enabled --mcp-listen 127.0.0.1:3000 \
  --mcp-public-url https://mcp.usewayfinder.app
```

For an existing installation, stop the daemon and set these fields in its private
`config.json`, preserving identity, node name, peer addresses and membership:

```json
{
  "mcp_enabled": true,
  "mcp_listen": "127.0.0.1:3000",
  "mcp_public_url": "https://mcp.usewayfinder.app"
}
```

This is a fragment, not a replacement configuration. Remove the old `mcp_token`
field if present. There is no compatibility reader or automatic migration.
`mcp_public_url` must be a canonical HTTPS origin without a trailing slash;
set it to `null` to disable OAuth while retaining direct bearer authentication.
MCP is disabled by default; it never has an unauthenticated development mode.
Restart your existing service supervisor. No application TLS listener is added.

## 2. Publish HTTPS

Point the DNS A record for `mcp.usewayfinder.app` to the gateway's public ingress
address. Publish an AAAA record only if IPv6 routes to the same ingress. Forward
TCP 80/443 to that machine if necessary. Keep the MCP backend and private control
ports inaccessible from the internet.

Install Caddy using its [official installation instructions](https://caddyserver.com/docs/install).
Add this site to `/etc/caddy/Caddyfile`:

```caddyfile
mcp.usewayfinder.app {
    reverse_proxy 127.0.0.1:3000 {
        header_up Host 127.0.0.1:3000
        transport http {
            response_header_timeout 310s
        }
    }
}
```

Then validate and reload:

```sh
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Start Caddy instead if this is its first deployment. Caddy obtains/renews TLS
certificates. Proxy all paths without stripping prefixes so OAuth discovery and
callbacks reach Wayfinder. Preserve Authorization, MCP headers, queries, status
codes and response content types. Do not inject a shared bearer, enable retries,
or add request/response buffering. Caddy's default SSE behavior flushes streaming
responses. Avoid negative `flush_interval`: it can prevent upstream cancellation
when a client disconnects. See [Caddy reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).

The backend requires loopback Host values and rejects browser Origin on MCP.
OAuth browser requests accept only the configured issuer Origin. Do not remove
Origin at the proxy. Public listener addresses require explicit configuration;
a non-loopback backend still requires a proxy Host rewrite and protected transit.
Keep proxy access/debug logging off for these routes, especially OAuth query
strings, Authorization headers and token response bodies.

## 3. Direct bearer clients (including Codex)

Run as the daemon account with its data directory:

```sh
wayfinder --data-dir /var/lib/wayfinder auth create codex --permissions read,exec
wayfinder --data-dir /var/lib/wayfinder auth list
```

Save the displayed `wf_<id>_<secret>` token in the client's secret storage now.
It is returned only on creation. Defaults are read only. Configure the client:

- Transport: Streamable HTTP
- URL: `https://mcp.usewayfinder.app` (MCP lives at `/`)
- Header on every request: `Authorization: Bearer <token>`

For Codex, use its [documented bearer environment setting](https://developers.openai.com/codex/mcp):

```toml
[mcp_servers.wayfinder]
url = "https://mcp.usewayfinder.app"
bearer_token_env_var = "WAYFINDER_MCP_TOKEN"
tool_timeout_sec = 310
```

Make the environment variable available to the **client process**, using its
secret manager or a private prompt. Do not set it on the Wayfinder daemon or
paste the token into commands, URLs, repository files, or logs.

## 4. ChatGPT OAuth

[ChatGPT developer mode](https://developers.openai.com/api/docs/guides/developer-mode)
supports OAuth for authenticated remote MCP; a static API-key field is not its
supported flow. Wayfinder provides installation-local authorization code flow
with S256 PKCE, confidential client authentication and refresh tokens. No external
identity provider or hosted user account is required.

1. Enable developer mode in ChatGPT's **Settings → Security and login**. Create a
   developer-mode app in the Plugins page using `https://mcp.usewayfinder.app`.
   Select OAuth with **your own client ID and client secret**.
2. Copy the exact redirect URI shown by ChatGPT. Wayfinder advertises RFC 9207
   issuer identification, for which OpenAI documents the stable callback
   `https://chatgpt.com/connector_platform_oauth_redirect`. Use the URI shown in
   your app's management page if it differs; no wildcard redirects are accepted.
3. Pre-register that URI locally:

   ```sh
   wayfinder --data-dir /var/lib/wayfinder auth oauth-register chatgpt-client \
     --redirect-uri https://chatgpt.com/connector_platform_oauth_redirect
   ```

   Save the displayed client ID and **one-time client secret** in ChatGPT's OAuth
   fields. These are OAuth client credentials, not an MCP bearer token. Client
   registration alone grants no node access. Wayfinder supports
   `client_secret_basic` and `client_secret_post`, with PKCE required for both.
4. Connect the app. The browser opens Wayfinder's authorization page showing a
   request ID, client name, exact redirect and requested scopes. On the host:

   ```sh
   wayfinder --data-dir /var/lib/wayfinder auth pending
   wayfinder --data-dir /var/lib/wayfinder auth approve REQUEST_ID \
     --name chatgpt --permissions read,exec
   ```

   Compare the browser request ID and redirect with `auth pending`. Approve only
   a flow you initiated. Default approval is read only; requested permissions are
   an upper bound. `exec` permits shell execution as the daemon account. Return
   to the same browser page and refresh it to complete the OAuth redirect.
5. ChatGPT exchanges the one-use code and supplies the bearer token itself. Ask
   it to call Wayfinder `nodes`, then run `printf connected` on a selected node.

Authorization requests expire after ten minutes and codes after one minute;
restart discards unfinished authorizations. Access tokens last one hour; refresh
tokens rotate and the grant expires after 30 days, then reconnect with a new grant
name. A refresh invalidates the previous access token. Reusing a consumed refresh
token revokes the grant; after a lost refresh response, reconnect rather than
retrying the old refresh token indefinitely.

Details and callback rules: [OpenAI authentication documentation](https://developers.openai.com/apps-sdk/build/auth).
OAuth is generic; no ChatGPT-specific hostname or routing appears in the code.
The production ChatGPT account flow must be checked after public DNS/TLS cutover;
local protocol validation cannot prove account-specific UI availability.

## 5. Revoke and rotate

```sh
wayfinder --data-dir /var/lib/wayfinder auth list
wayfinder --data-dir /var/lib/wayfinder auth revoke chatgpt
wayfinder --data-dir /var/lib/wayfinder auth oauth-clients
wayfinder --data-dir /var/lib/wayfinder auth oauth-revoke-client chatgpt-client
```

`auth revoke` disables that named credential, including its OAuth refresh token.
`oauth-revoke-client` disables client authentication and all its grants. Revoke
and re-register under a new name to rotate an OAuth client secret. Direct bearer
rotation similarly uses `auth create NEW_NAME` followed by revoking the old name.
No restart or remote-peer credential update is needed. Already-admitted commands
are not retroactively canceled.

`auth list` contains ID, name, permissions, creation/last-use/revocation times
(Unix seconds; `revoked: null` means not revoked; OAuth expiry still applies). `oauth-clients` excludes all secrets.
Only local administrators can manage credentials; there is no remotely grantable
admin scope. Shell execution remains bounded by OS permissions, not this API
capability distinction.

## Storage and protocol

The daemon holds the existing data-directory lock and owns versioned
`credentials.json` beside config/identity/state. It uses existing 0600 atomic,
fsynced JSON writes; no new database engine. A new store starts empty. Missing
credentials therefore authorize nobody; malformed stores fail startup. The
service-account example uses `/var/lib/wayfinder`; existing OS data directories
remain supported without relocation.

Tokens contain an independent random identifier and 256-bit OS-random secret.
Only SHA-256 verifiers are stored and compared in constant time. Random API
secrets do not need password KDF cost: offline guessing 256 random bits is
infeasible. OAuth refresh tokens and client secrets also use this verifier model;
issuer, client, scopes and expiries are local grant bindings. Last use persists
at most once per minute per credential. Backups contain sensitive verifiers;
restoring an old backup also restores old revocation state.

The native rmcp 3.3.0 stateless HTTP service supports current 2026-07-28 discovery
and legacy initialization. It owns protocol headers, JSON/SSE negotiation, body
limits, errors and disconnect cancellation. No custom MCP transport or session
manager is introduced. Unauthenticated MCP requests receive 401 with a Bearer
challenge (OAuth metadata URL when enabled). Wrong capabilities fail in tool
handlers. Unknown routes, including the removed `/mcp`, return 404.

References: [current MCP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
[MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
A root endpoint is valid. OAuth uses local pre-registration rather than dynamic
registration or remotely fetched client metadata. No hosted routing is involved.

## Existing norted host cutover

Inspection on 2026-09-15 found `/etc/systemd/system/wayfinder.service` runs as
`root`, with working directory `/srv/norted/repos/project-wayfinder`, executable
`target/release/wayfinder`, data at `/root/.local/share/wayfinder`, MCP
`127.0.0.1:3000`, and existing peer listen/advertise `100.117.187.71:3001`.
No Caddy/nginx configuration was present. The OpenAI Tunnel service is external
to this repository. These instructions preserve the current peer identity.

1. On the host, stop `wayfinder.service`. Keep a private backup of its data
   directory. Edit `/root/.local/share/wayfinder/config.json`: remove `mcp_token`,
   add `mcp_enabled: true` and
   `mcp_public_url: "https://mcp.usewayfinder.app"`. Preserve all other values and
   file mode 0600. **Do not run init on this existing directory.**
2. Build/install the changed checkout with the repository's service wrapper as
   root (this refreshes the stale unit's required application runtime directory
   and group as well as restarting it):

   ```sh
   cd /srv/norted/repos/project-wayfinder
   WAYFINDER_DATA_DIR=/root/.local/share/wayfinder ./wayfinder-service.sh install
   systemctl status wayfinder.service --no-pager
   ```

   The existing unit runs shell commands as root. This cutover preserves that
   behavior; moving to a dedicated least-privileged service account is a separate
   OS deployment change. Do not assume the MCP capability model isolates root
   commands from host administration.
3. Install/configure Caddy and DNS exactly as in section 2. Confirm:

   ```sh
   curl -i https://mcp.usewayfinder.app/
   curl -fsS https://mcp.usewayfinder.app/.well-known/oauth-protected-resource
   ```

   Expect 401 plus `WWW-Authenticate` on `/`, and JSON containing the exact
   issuer on metadata. A successful HTML page or 404 at `/` indicates bad routing.
4. Follow section 3 for Codex and section 4 for ChatGPT, replacing
   `--data-dir /var/lib/wayfinder` with
   `--data-dir /root/.local/share/wayfinder`. Use the new executable directly if
   the global wrapper has not yet been refreshed:
   `/srv/norted/repos/project-wayfinder/target/release/wayfinder`.
5. Confirm `nodes` shows the existing graph and `exec` works on the intended
   target. Verify a read-only credential cannot execute. Revoke a temporary
   credential and confirm its next request receives 401.
6. After the direct HTTPS connection works, disable the external ingress service:

   ```sh
   sudo systemctl disable --now openai-wayfinder-tunnel.service
   ```

   Remove the old tunnel connection from the MCP client. No repository-owned
   tunnel implementation remains to remove, and the running service was not
   altered during development of this change.
