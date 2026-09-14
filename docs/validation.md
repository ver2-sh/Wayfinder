# Generic application service validation — 2026-09-14

Started from clean upstream `ed6da2d`. No changes were pushed and no repository
tests were added. Historical application-specific notes were removed.

`./validate.sh` passed formatting, workspace check, Clippy with warnings denied
and workspace tests (no repository test cases). The release executable built;
`git diff --check` and service-script shell syntax checks passed. The installed
wrapper forwards application commands; direct and symlinked invocations of
`services list` passed with explicit and environment-selected data directories.

External isolated-process validation exercised two fresh identities and arbitrary
`echo.private.v1` and `calendar.events.v1` services:

- 60 security assertions passed: sanitized node discovery, independent service
  credentials, rejection at administration and MCP, exact-name scope enforcement,
  dedicated Unix group read access, private-state denial, registration/renewal,
  unregistration and actual bidirectional encrypted echo streams.
- 18 lifecycle assertions passed: offline persistent configuration, two active
  services, rejection of one service's credential at the other, credential
  rotation, retained mode 0640 and group ownership, automatic crash-stale
  descriptor replacement, configured services on TUI-started daemons, visible
  service status, clean TUI-owned shutdown, persistent daemon survival after an
  attached TUI exits, and explicit pending removal applied at restart.
- A third member remained a normal generic node regardless of which application
  services it exposed. Node discovery returned only IDs, names, local/reachable
  flags and conflict state. No application classification was published.

Source/documentation audit found no application-specific product or hardware
semantics. Application registration uses its scoped endpoint; obsolete
administration registration operations and daemon capability flags were removed.

Validation used isolated processes on one Linux host. Physical multi-machine,
Windows ACL and macOS deployment were not tested. Service add/remove changes
apply at daemon restart, explicitly distinguished from active capability access.
See [peer services](peer-services.md) for the supported setup and lifecycle.
