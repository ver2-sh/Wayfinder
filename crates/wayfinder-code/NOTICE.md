# Wayfinder code intelligence — third-party notices

Wayfinder manages an unchanged, host-local installation of Serena. Code intelligence does not use a hosted Serena service.

Serena application: GPL-3.0-or-later, copyright its contributors.
SolidLSP (within Serena): MIT, copyright its contributors.
Upstream: https://github.com/oraios/serena
Embedded bootstrap source: https://github.com/oraios/serena/tree/d9e4c796fae0207ba6848d1df4b331122a5567b5
License overview: https://github.com/oraios/serena/blob/d9e4c796fae0207ba6848d1df4b331122a5567b5/LICENSE

Compatible channel updates may select a different unchanged upstream revision. `wayfinder code status` reports the selected recipe; its retained source and installed notices identify the exact revision.

The exact source archive, license files and frozen dependency lock are retained under Wayfinder's private code-intelligence directory: downloads/<source SHA-256> and runtimes/<recipe>/source/. The installed application's LICENSE and LICENSES directory are authoritative. Redistributors of this backend must preserve the notices and comply with its GPL source/distribution requirements. Wayfinder's original source remains Apache-2.0; this notice does not relicense upstream components.

uv: Apache-2.0 OR MIT, https://github.com/astral-sh/uv
CPython: Python Software Foundation License and bundled dependency notices, https://www.python.org/psf/license/
Other Python packages: their installed distribution license notices and the retained upstream uv.lock identify their sources and licenses.

No upstream source, licensing notice or attribution is removed. Normal Wayfinder setup and operation require no separate backend account, configuration, dashboard or MCP connection.

Node.js (including npm): MIT and bundled notices, https://nodejs.org/ . The exact official runtime archive and its LICENSE are retained with the recipe.
