# Project Wayfinder

Wayfinder is a self-hosted, authenticated MCP bridge that executes shell commands on the machine running it, as the operating-system user running it.

```text
MCP client → authenticated Streamable HTTP → Wayfinder exec → local shell → host OS
```

It is deliberately not a server-management framework. There are no file, Git, service, SSH, fleet, or workflow APIs, no persistent terminal sessions, and no web UI. Use ordinary shell commands for host operations. There is no mandatory hosted relay, vendor account, or telemetry service.

## Run locally

Use Node.js 24 LTS (or Node.js 26) and npm.

```sh
npm ci
```

Copy `.env.example` to `.env`. Replace the token placeholder with a cryptographically random value; this command generates one:

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Keep the token private. `.env` is ignored by Git. Shell-provided environment variables take precedence over `.env`.

```sh
npm run dev       # run TypeScript; restart on changes
npm run build     # compile into dist/
npm start         # run the compiled server
```

The default endpoint is `http://127.0.0.1:3000/mcp`. Ctrl+C shuts down the server and terminates active commands. SIGTERM is also handled where the OS supports it.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `WAYFINDER_TOKEN` | Required | Random bearer token, at least 32 characters; the example placeholder is rejected |
| `WAYFINDER_HOST` | `127.0.0.1` | Listen address |
| `WAYFINDER_PORT` | `3000` | Listen port, 1–65535 |
| `WAYFINDER_TIMEOUT_MS` | `30000` | Default command timeout in milliseconds |
| `WAYFINDER_MAX_TIMEOUT_MS` | `300000` | Maximum accepted timeout in milliseconds |

Timeouts must be positive integers, with the default no greater than the maximum. The maximum cannot exceed 2,147,483,647 milliseconds. Missing or invalid authentication configuration prevents startup. Changing the token requires restarting the process.

## Connect a client

Configure a client supporting MCP Streamable HTTP with the `/mcp` URL and this header on every request:

```text
Authorization: Bearer <your-token>
```

The client discovers and calls the single `exec` tool through the official MCP protocol. Configure its request timeout to exceed the command timeout plus network overhead. This scaffold uses a configured bearer secret, without OAuth discovery or interactive login. Browser-origin requests are rejected; use a client that can make direct HTTP requests and supply authorization headers.

## `exec` contract

| Input | Meaning |
| --- | --- |
| `command` | Required nonempty shell command, passed unchanged |
| `cwd` | Optional working directory; defaults to the Wayfinder process directory |
| `timeout` | Optional positive integer milliseconds, bounded by configuration |
| `env` | Optional string-to-string environment overrides, merged with the server environment |

Commands use the platform shell (`/bin/sh` on Unix; `ComSpec`/`cmd.exe` on Windows). Shell syntax therefore depends on the host. Standard input is closed; interactive commands and persistent shells are unsupported. Environment and working-directory changes do not persist between calls.

Results appear as MCP `structuredContent` and matching JSON text:

```json
{
  "stdout": "hello\n",
  "stderr": "",
  "exitCode": 0,
  "signal": null,
  "timedOut": false
}
```

`exitCode` is the real shell exit code, or `null` when unavailable (for example, a spawn error or Unix signal termination). `signal` records a termination signal when reported by Node. Spawn errors, cancellation, and output-limit failures add an `error` string. Nonzero or missing exit codes, timeouts, and execution errors set MCP `isError: true`. A command's stdout and stderr remain separate and are decoded as UTF-8.

Each output stream is limited to 1 MiB to bound buffered output. Exceeding a limit terminates the command, returns the captured prefix, and explicitly reports truncation as an error. Timeouts kill the process group on Unix and use Windows `taskkill /T /F` to kill the command tree. These mechanisms handle ordinary shell descendants, but cannot contain deliberately detached processes or commands that escape their original process tree. Do not use this version for launching background services. Forced shutdown of Wayfinder itself cannot guarantee child cleanup.

## Security model

Wayfinder authenticates clients; the OS account authorizes machine capabilities. A valid token grants arbitrary shell execution with that account's access, including access to files, network, and inherited environment. Authentication uses constant-time comparison of fixed-length token hashes and runs before the MCP handler on every HTTP request. Credentials and commands are not logged by Wayfinder.

Wayfinder is **not a sandbox**. Run it under a dedicated, least-privileged account with only the access you intend to grant. There is no application command allowlist, filesystem policy, privilege escalation helper, or per-user permission layer. Concurrent authenticated requests can execute concurrently; this is not a resource-isolation service.

Loopback is the default, with SDK host-header validation for loopback bindings. Any supplied browser Origin header is rejected. **Remote use requires encrypted transport**, normally HTTPS terminated by a standard reverse proxy. Bearer authentication does not make plaintext networking safe. Limit access to the backend listener, ensure the proxy preserves authorization, and do not expose a plaintext backend directly. No custom TLS stack or external service is required.

## Implementation

The official MCP SDK provides Streamable HTTP handling and tool schemas. `src/server.ts` connects the handler to Node HTTP; `src/auth.ts` owns bearer verification; `src/exec.ts` owns command execution; `src/config.ts` validates configuration; `src/index.ts` starts and stops the process. There is no application session storage or persistent shell state.

Licensed under Apache-2.0; see [LICENSE](LICENSE).
