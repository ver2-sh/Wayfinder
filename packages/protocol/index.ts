/** Normative Web-runtime wire codec. The Rust core owns the same byte layouts.
 * No Cloudflare dependencies, credentials, phrase handling, or root key material.
 */
export interface Certificate {
  version: number;
  chain_id: string;
  root_public: string;
  device_id: string;
  device_public: string;
  role: "admin" | "member";
  name: string;
  signature: string;
}
export interface Admission {
  certificate: Certificate;
  nonce: string;
  signature: string;
}
export interface Operation {
  operation: string;
  device_id?: string;
  code?: string;
  request_hash?: string;
  grant_id?: string;
}
export interface SignedOperation {
  certificate: Certificate;
  nonce: string;
  operation: Operation;
  signature: string;
}
export const encoder = new TextEncoder();
export function requireThat(
  v: unknown,
  message = "Invalid request",
): asserts v {
  if (!v) throw new Error(message);
}
export const hex = (v: ArrayBuffer | Uint8Array) =>
  Array.from(
    new Uint8Array(
      v instanceof Uint8Array
        ? v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength)
        : v,
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
export function unhex(s: string, bytes: number): Uint8Array<ArrayBuffer> {
  requireThat(
    typeof s === "string" && new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(s),
  );
  return Uint8Array.from(s.match(/../g)!.map((b) => parseInt(b, 16)));
}
export const random = () => hex(crypto.getRandomValues(new Uint8Array(32)));
export const now = () => Math.floor(Date.now() / 1000);
export const hash = async (v: string | Uint8Array<ArrayBuffer>) =>
  hex(
    await crypto.subtle.digest(
      "SHA-256",
      typeof v === "string" ? encoder.encode(v) : v,
    ),
  );
export const cat = (...a: Uint8Array[]): Uint8Array<ArrayBuffer> => {
  const b = new Uint8Array(a.reduce((n, v) => n + v.length, 0));
  let p = 0;
  for (const v of a) {
    b.set(v, p);
    p += v.length;
  }
  return b;
};
export function u32(n: number) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}
export const field = (s: string) => {
  const b = encoder.encode(s);
  return cat(u32(b.length), b);
};
export function exact(v: object, keys: string[]) {
  requireThat(
    v !== null &&
      typeof v === "object" &&
      !Array.isArray(v) &&
      Object.keys(v).length === keys.length &&
      Object.keys(v).every((k) => keys.includes(k)),
  );
}
export function validName(v: string) {
  requireThat(
    typeof v === "string" &&
      encoder.encode(v).length > 0 &&
      encoder.encode(v).length <= 64 &&
      /^[\p{Alphabetic}\p{Number}_. -]+$/u.test(v) &&
      v.trim() === v,
  );
}
export function certificateJSON(c: Certificate): string {
  return JSON.stringify({
    version: c.version,
    chain_id: c.chain_id,
    root_public: c.root_public,
    device_id: c.device_id,
    device_public: c.device_public,
    role: c.role,
    name: c.name,
    signature: c.signature,
  });
}
export function certificateBytes(c: Certificate) {
  return cat(
    encoder.encode("wayfinder/membership/v1\0"),
    u32(c.version),
    field(c.chain_id),
    unhex(c.root_public, 32),
    field(c.device_id),
    unhex(c.device_public, 32),
    new Uint8Array([c.role === "admin" ? 1 : 2]),
    field(c.name),
  );
}
export async function verify(
  publicKey: string,
  bytes: Uint8Array<ArrayBuffer>,
  signature: string,
) {
  const key = await crypto.subtle.importKey(
    "raw",
    unhex(publicKey, 32),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  requireThat(
    await crypto.subtle.verify("Ed25519", key, unhex(signature, 64), bytes),
    "Signature denied",
  );
}
export async function verifyCertificate(c: Certificate) {
  exact(c, [
    "version",
    "chain_id",
    "root_public",
    "device_id",
    "device_public",
    "role",
    "name",
    "signature",
  ]);
  requireThat(c.version === 1 && ["admin", "member"].includes(c.role));
  validName(c.name);
  requireThat(
    c.chain_id ===
      "wfc1_" +
        (await hash(
          cat(
            encoder.encode("wayfinder/chain-id/v1\0"),
            unhex(c.root_public, 32),
          ),
        )),
  );
  requireThat(
    c.device_id ===
      "wfd1_" +
        (await hash(
          cat(
            encoder.encode("wayfinder/device-id/v1\0"),
            unhex(c.device_public, 32),
          ),
        )),
  );
  await verify(c.root_public, certificateBytes(c), c.signature);
}
export const SESSION_VERSION = 2;
/** Generic application service transport over `/service` relay sockets. */
export const SERVICE_VERSION = 1;
export const DEVICE_ID = /^wfd1_[0-9a-fA-F]{64}$/;
export const STREAM_ID = /^[0-9a-fA-F]{64}$/;
export function validServiceName(v: string) {
  requireThat(
    typeof v === "string" && v.length >= 1 && v.length <= 96 && /^[a-z0-9._-]+$/.test(v),
  );
}
export interface PlatformDescriptor {
  platform: "windows" | "linux" | "macos" | "other";
  arch: string;
}
export async function sessionProof(
  gateway: string,
  nonce: string,
  c: Certificate,
  metadata: PlatformDescriptor,
  version: number = SESSION_VERSION,
) {
  requireThat(version === SESSION_VERSION || version === CODE_SESSION_VERSION);
  exact(metadata, ["platform", "arch"]);
  requireThat(
    ["windows", "linux", "macos", "other"].includes(metadata.platform) &&
      typeof metadata.arch === "string" &&
      /^[a-z0-9_]{1,32}$/.test(metadata.arch),
  );
  return cat(
    encoder.encode(`wayfinder/session/v${version}\0`),
    field(gateway),
    field(nonce),
    field(await hash(certificateBytes(c))),
    field(metadata.platform),
    field(metadata.arch),
  );
}
export function operationJSON(op: Operation) {
  const fields: Record<string, string[]> = {
    devices: [],
    revoke_device: ["device_id"],
    promote_device: ["device_id"],
    demote_device: ["device_id"],
    pending: ["code"],
    approve: ["code", "request_hash"],
    grants: [],
    revoke_grant: ["grant_id"],
  };
  requireThat(Object.hasOwn(fields, op.operation));
  exact(op, ["operation", ...fields[op.operation]]);
  const canonical: Record<string, string> = { operation: op.operation };
  for (const k of fields[op.operation]) {
    const v = (op as unknown as Record<string, string>)[k];
    requireThat(typeof v === "string");
    canonical[k] = v;
  }
  if (op.operation === "promote_device" || op.operation === "demote_device")
    requireThat(typeof op.device_id === "string" && /^wfd1_[0-9a-f]{64}$/.test(op.device_id));
  return JSON.stringify(canonical);
}
export async function operationProof(
  gateway: string,
  nonce: string,
  c: Certificate,
  op: Operation,
) {
  return cat(
    encoder.encode("wayfinder/administration/v1\0"),
    field(gateway),
    field(nonce),
    field(await hash(certificateBytes(c))),
    field(operationJSON(op)),
  );
}
export async function admissionBytes(
  c: Certificate,
  gateway: string,
  nonce: string,
) {
  await verifyCertificate(c);
  return cat(
    encoder.encode("wayfinder/admission/v1\0"),
    field(gateway),
    field(nonce),
    field(await hash(certificateBytes(c))),
  );
}
export interface Approval {
  id: string;
  client_id: string;
  client_name: string;
  redirect_uri: string;
  permissions: string[];
  expires: number;
}
export const approvalJSON = (a: Approval) =>
  JSON.stringify({
    id: a.id,
    client_id: a.client_id,
    client_name: a.client_name,
    redirect_uri: a.redirect_uri,
    permissions: a.permissions,
    expires: a.expires,
  });
export function permissions(scope: string) {
  requireThat(typeof scope === "string");
  const p = scope.trim().split(/\s+/);
  requireThat(p.length > 0 && p.every((v) => ["read", "exec"].includes(v)));
  return ["read", "exec"].filter((v) => p.includes(v));
}
export function validRedirect(v: string) {
  requireThat(typeof v === "string" && v.length <= 2048);
  const u = new URL(v);
  requireThat(
    u.hostname &&
      !u.username &&
      !u.password &&
      !u.hash &&
      (u.protocol === "https:" ||
        (u.protocol === "http:" &&
          ["127.0.0.1", "[::1]"].includes(u.hostname))),
  );
}
export interface ExecInput {
  target?: string | null;
  command: string;
  cwd?: string | null;
  timeout?: number | null;
  env?: Record<string, string> | null;
}
export function validateExec(v: ExecInput) {
  requireThat(
    v &&
      Object.keys(v).every((k) =>
        ["target", "command", "cwd", "timeout", "env"].includes(k),
      ),
  );
  requireThat(
    typeof v.command === "string" &&
      v.command.trim() &&
      encoder.encode(v.command).length <= 65536 &&
      !v.command.includes("\0"),
  );
  requireThat(
    v.timeout == null ||
      (Number.isSafeInteger(v.timeout) &&
        v.timeout >= 1 &&
        v.timeout <= 300000),
  );
  requireThat(v.target == null || typeof v.target === "string");
  requireThat(
    v.cwd == null ||
      (typeof v.cwd === "string" && v.cwd.length > 0 && !v.cwd.includes("\0")),
  );
  if (v.env != null) {
    requireThat(typeof v.env === "object" && !Array.isArray(v.env));
    for (const [k, val] of Object.entries(v.env))
      requireThat(
        k && !/[=\0]/.test(k) && typeof val === "string" && !val.includes("\0"),
      );
  }
}

export const CODE_TOOLS = [
  "read_file",
  "create_text_file",
  "list_dir",
  "find_file",
  "replace_content",
  "replace_in_files",
  "delete_lines",
  "replace_lines",
  "insert_at_line",
  "search_for_pattern",
  "restart_language_server",
  "get_symbols_overview",
  "find_symbol",
  "find_referencing_symbols",
  "find_implementations",
  "find_declaration",
  "get_diagnostics_for_file",
  "get_diagnostics_for_symbol",
  "replace_symbol_body",
  "insert_after_symbol",
  "insert_before_symbol",
  "rename_symbol",
  "write_memory",
  "read_memory",
  "list_memories",
  "delete_memory",
  "rename_memory",
  "edit_memory"
] as const;
export const CODE_SESSION_VERSION = 3;
export const CODE_DEFAULT_TIMEOUT = 270000;
export interface CodeInput {
  target: string;
  action: "status" | "prepare" | "tools" | "call" | "close";
  project?: string | null;
  tool?: string | null;
  arguments?: Record<string, unknown> | null;
  timeout?: number | null;
}
export interface CodeResult {
  target: string;
  project: string | null;
  result: Record<string, unknown> | null;
  error: string | null;
  timedOut: boolean;
  outcomeUnknown: boolean;
}
export function validateCode(input: CodeInput) {
  requireThat(input !== null && typeof input === "object" && !Array.isArray(input));
  requireThat(Object.keys(input).every(k => ["target", "action", "project", "tool", "arguments", "timeout"].includes(k)));
  requireThat(typeof input.target === "string" && input.target.trim().length > 0 && encoder.encode(input.target).length <= 256 && !input.target.includes("\0"), "Explicit device target required");
  requireThat(["status", "prepare", "tools", "call", "close"].includes(input.action));
  if (input.project != null) requireThat(typeof input.project === "string" && input.project.trim().length > 0 && encoder.encode(input.project).length <= 8192 && !input.project.includes("\0"), "Invalid project directory");
  if (["tools", "call", "close"].includes(input.action)) requireThat(input.project != null, "Project directory required");
  if (input.action === "call") {
    requireThat(typeof input.tool === "string" && input.tool.startsWith("code_") && (CODE_TOOLS as readonly string[]).includes(input.tool.slice(5)), "Use a code_* operation from action=tools");
    if (input.arguments != null) requireThat(typeof input.arguments === "object" && !Array.isArray(input.arguments));
  } else requireThat(input.tool == null && input.arguments == null, "Tool arguments are only valid for action=call");
  if (input.timeout != null) requireThat(Number.isInteger(input.timeout) && input.timeout >= 1 && input.timeout <= 300000);
  const normalized = { target: input.target, action: input.action, project: input.project ?? null, tool: input.tool ?? null, arguments: input.arguments ?? null, timeout: input.timeout ?? null };
  requireThat(encoder.encode(JSON.stringify(normalized)).length <= 65536, "Code request exceeds 64 KiB");
}
export function validateCodeResult(result: CodeResult) {
  exact(result, ["target", "project", "result", "error", "timedOut", "outcomeUnknown"]);
  requireThat(typeof result.target === "string" && (result.project === null || typeof result.project === "string") && (result.error === null || typeof result.error === "string") && typeof result.timedOut === "boolean" && typeof result.outcomeUnknown === "boolean");
  requireThat(result.result === null || (typeof result.result === "object" && !Array.isArray(result.result)));
  requireThat(encoder.encode(JSON.stringify(result)).length <= 1048576, "Code result exceeds 1 MiB");
}
export const codeTool = {
  name: "code",
  description: "Wayfinder code intelligence on an explicit device and absolute project path. Use action=tools to discover code_* operations and their inputSchema, then action=call with tool and arguments. Includes symbols, references, diagnostics, structured edits, refactoring and project memories. status does not install; prepare provisions on demand; close releases a project session. All actions require exec permission. No sandbox, fallback or automatic retry. Timeout includes setup and queueing.",
  inputSchema: {
    type: "object",
    properties: {
      target: { type: "string" },
      action: { type: "string", enum: ["status", "prepare", "tools", "call", "close"] },
      project: { type: ["string", "null"] },
      tool: { type: ["string", "null"] },
      arguments: { type: ["object", "null"], additionalProperties: true },
      timeout: { type: ["integer", "null"], minimum: 1, maximum: 300000 },
    },
    required: ["target", "action"], additionalProperties: false,
  },
  _meta: { securitySchemes: [{ type: "oauth2", scopes: ["exec"] }] },
};
