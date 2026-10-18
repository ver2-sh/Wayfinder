# Code intelligence

Wayfinder's `code` MCP tool provides semantic navigation, references, diagnostics, symbol edits, cross-file renames, file operations and persistent project memories on an enrolled device. The agent manages an unchanged, local code backend; users do not configure another application, MCP server, dashboard or account.

## Use

First choose a device using `nodes`. `code_intelligence: true` means its currently authenticated agent supports the protocol; it is not a grant, hardware attestation or an indication that a runtime is already installed.

Discover operations for an absolute project directory on that device:

```json
{"target":"my-device","action":"tools","project":"C:\\Projects\\example"}
```

Linux/macOS projects use their ordinary absolute paths, such as `/home/me/projects/example`. The returned tool catalogue includes actual upstream `inputSchema` definitions. Call a returned tool by its Wayfinder name:

```json
{"target":"my-device","action":"call","project":"C:\\Projects\\example","tool":"code_find_symbol","arguments":{"name_path_pattern":"resolve_profile","include_body":true}}
```

The optional `timeout` is a total deadline in milliseconds, including setup and queueing, between 1 and 300000; its default is 270000. Setup is lazy: the first `tools` or `call` request prepares the private runtime and project automatically. An explicit `prepare` action can prepare just the runtime (omit `project`) or a project. `status` never installs anything. `close` stops a project's code process and retains its memories and configuration.

All operations require the existing `exec` scope, including project reads, status, discovery and preparation. `read` still authorizes only device discovery. Execution uses the device agent's OS account and is **not sandboxed**. The configured gateway can see code requests and results under the existing MCP trust model; this is not the end-to-end encrypted application-service relay.

## Local controls

The Settings screen includes Code intelligence, an enable/disable control, readiness status, selected runtime version, an automatic-runtime-updates toggle, and Prepare code runtime. It never shows a second application or changes login startup. The CLI provides the same controls:

```text
wayfinder code status
wayfinder code prepare
wayfinder code update --check
wayfinder code update
wayfinder code auto-updates false
wayfinder code auto-updates true
wayfinder code rollback
wayfinder code disable
wayfinder code enable
wayfinder code clean
wayfinder code licenses
```

`--data-dir` continues to select the Wayfinder installation. Enabling only permits on-demand use; it does not install, start or index anything immediately. Disabling prevents new code work and cancels active code sessions without stopping the Wayfinder agent or shell operations. A cancellation cannot undo edits already applied; inspect files before repeating an interrupted operation.

`clean` requires the feature to be disabled and no process to hold a runtime lease. It removes managed runtime downloads, package caches, language-server installations, logs, disposable update probes and rebuildable project indexes. Project memories and configuration, user repositories, Wayfinder identities, grants and gateway settings are retained. Non-interactive deliberate cleanup can use `--yes`. Code memory tools allow agents to list, read, edit, rename and delete individual project memories; onboarding and automatic memory generation are not forced on the user.

## Runtime ownership and isolation

The private directory `<Wayfinder data>/code-intelligence` contains an embedded bootstrap recipe, approved channel recipes, verified download caches, an isolated Python environment, private Node.js/npm, and per-project backend state. It does not replace global Python, Node.js, compiler/toolchain installations, package-manager settings or PATH. The runtime includes the exact upstream source archive, frozen dependency lock and license files.

Runtime archives are pinned by version/revision and SHA-256, downloaded only over HTTPS from the approved origins, verified before extraction/execution, and bounded in size. Archive traversal and outside-root links are rejected. Install work is cross-process locked and has no ready marker until the complete environment passes version/import verification. An interrupted installation is not activated; verified downloads can be reused by a later explicit request. Compatible runtime updates arrive through the independent release channel below, not through a Wayfinder binary update. No environment is updated in place. The active and previous working installations are retained; superseded or rejected candidate environments are pruned only when no code process holds a runtime lease.

Each canonical project path has a separate private configuration, memory directory, language-server session and work lock. Repositories with the same basename do not share state. Repository `.serena` settings are neither imported nor changed, so repository-supplied startup commands cannot be activated by opening a project. Native backend project-trust gates remain enabled. Context and caches are local to the selected device; there is no repository replication or cross-device memory synchronization.

Up to four project sessions are retained per agent, with one operation at a time per project. Idle sessions stop after ten minutes. Shutdown, cancellation and disabling use native process groups on Unix and job objects on Windows to clean up descendants. No public backend port is opened; communication is private stdio MCP. Diagnostic output is bounded and stored locally when necessary.

## Independent runtime updates

Automatic code-runtime updates are enabled by default, independently of Wayfinder application updates. They consult the fixed HTTPS endpoint `https://usewayfinder.app/code-runtime/v1/stable.json`. The channel contains a schema version, integration version, monotonically increasing release sequence and exact artifact versions/revisions and SHA-256 hashes. It does not contain executable commands. The trusted HTTPS origin and Web PKI authenticate the metadata; this is not an independently signed/offline-verifiable manifest. Redirects, oversized responses, unknown fields, unsupported integration versions, older sequences and changed contents at an already-seen sequence are rejected. Artifact paths remain restricted to the approved upstream repositories and distribution origins.

The first code-runtime preparation checks this channel. Once installed, the daemon also checks when retained project sessions have closed or expired. Attempts, including failed checks, are cached for 24 hours. Status/ordinary installation alone never downloads an unused code runtime. Network/channel failure leaves an installed runtime usable; a fresh installation can still prepare the embedded bootstrap recipe. An upstream release is not adopted merely because it exists: a maintainer must approve and publish its exact compatible channel recipe.

An offered candidate is prepared in a separate private environment and qualified using real MCP discovery, symbol lookup, references, cross-file renaming and symbol editing against disposable Python files. This is an integration smoke test, not a guarantee for every language or repository. The active pointer changes atomically only after successful qualification. Updates are deferred while any code session holds a runtime lease, and never kill a user's running code session. Checks/installations have bounded deadlines and can be cancelled. Qualification never operates on a user's project. Interrupted preparation does not activate an incomplete candidate.

A failed candidate leaves the selected working runtime intact and is quarantined by recipe identity instead of being automatically retried on every call. When a selected update suffers a backend startup/process failure, a retained previous installation is selected for future sessions. `wayfinder code rollback` provides the same selection change explicitly. Existing sessions retain their environment until they close. No rollback undoes source edits, retries a user tool call, or replays an interrupted edit. The original call still reports its failure/unknown outcome.

`wayfinder code update --check` bypasses the check cache but never prepares or activates a candidate. `wayfinder code update` checks and attempts a qualified update, deferring activation while sessions are in use. `wayfinder code auto-updates false` stops future automatic checks and installations without disabling code intelligence; `true` enables them again. The Settings screen exposes the same automatic-updates preference. Explicit update commands remain available with automatic updates disabled. Update status reports the selected/offered/previous versions, pending state, last error and rejected recipe. These operations do not modify Wayfinder application-update settings, identity, grants, services or user repositories.

Normal compatible backend releases require only a new approved channel manifest, not a Wayfinder application update. Breaking changes to the integration require a deliberate Wayfinder update. The existing embedded bootstrap remains available for first use when the channel is unavailable; it is not an automatic downgrade of a previously selected channel runtime. Cleanup preserves update preferences, selection and sequence history alongside project memories, so re-enabling after cleanup reinstalls the selected recipe rather than forgetting the update trust state.

## Language capabilities and limits

The free language-server backend owns language detection, language-server acquisition, code analysis and editing. Python and JavaScript/TypeScript need no separately installed Python or Node.js for the managed backend. Other languages retain upstream requirements for their SDKs, project dependencies or build environments; Wayfinder does not silently install global toolchains, elevate privileges or fabricate unavailable semantics. Errors identify the failed operation and local diagnostics. The tool catalogue, not file extension or repository origin, is the authority for a supported operation, and a language server can still report that a particular operation is unsupported.

The integration exposes the reviewed tool surface in `wayfinder_core::code::TOOLS`, returned as `code_*` names with native argument schemas. It does not expose upstream project switching, onboarding, dashboard controls, shell execution or the Python REPL. Wayfinder's existing `exec` already supplies general shell execution. Paid IDE-plugin-only features are not claimed by this LSP integration.

Tool content, source text, paths, memory contents and structured results are returned without branding substitutions or lossy rewriting. Static tool names/descriptions are Wayfinder-facing. Network or process loss after dispatch produces an explicit unknown outcome, never an automatic retry. A failed runtime may be rolled back for future sessions, but the original operation is not repeated. Editing responses do not imply a project build or test passed.

## Compatibility and licensing

Both self-hosted and hosted Wayfinder gateways expose the same `code` contract. New agents negotiate authenticated session version 3; existing version-2 agents retain ordinary discovery and shell behavior. Code calls to older agents fail before dispatch. Identity, grants, application-service streams and existing CLI behavior are preserved.

The managed backend is Serena at the selected, verified revision. `crates/wayfinder-code/pins.json` supplies the embedded bootstrap revision; an approved channel recipe can select a newer compatible revision independently. Its application is GPL-3.0-or-later and SolidLSP is MIT; their source and notices are retained. Wayfinder's own code remains Apache-2.0. `wayfinder code licenses` and [the dependency notice](../crates/wayfinder-code/NOTICE.md) give the upstream source and distribution details without requiring users to interact with the backend during normal operation.
