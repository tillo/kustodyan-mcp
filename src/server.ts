#!/usr/bin/env node
/**
 * kustodyan-mcp — a Model Context Protocol server for the Kustodyan data-protection
 * API (RegData Protection Suite). It exposes contextual protect / unprotect / search
 * over the Identity + Engine APIs so AI agents and apps can protect PII safely.
 *
 * Transports:
 *   - stdio (default) — for local use, e.g. `npx kustodyan-mcp`
 *   - streamable HTTP — set KUSTODYAN_MCP_TRANSPORT=http (used by the hosted image)
 *
 * Configuration (env):
 *   KUSTODYAN_IDENTITY_URL   e.g. https://<env>.kustodyan.io/api/identity
 *   KUSTODYAN_ENGINE_URL     e.g. https://<env>.kustodyan.io/api/engine
 *   KUSTODYAN_CLIENT_ID      API client id from CoreAdmin
 *   KUSTODYAN_CLIENT_SECRET  API client secret from CoreAdmin
 *   KUSTODYAN_DATA_MODEL     (optional) path to a data-model manifest JSON
 *   KUSTODYAN_MCP_TRANSPORT  stdio | http   (default stdio)
 *   KUSTODYAN_HTTP_HOST/PORT host/port for the HTTP transport (default 127.0.0.1 / 9090)
 */
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import express from "express";
import {
  RpsClient, loadConfigFromEnv, decodeJwt, guid,
  type TransformInput, type TransformOutput, type Evidence, type TransformInstance,
} from "./rps.js";
import { loadDataModel, knownProperty, type DataModel } from "./datamodel.js";

const VERSION = "0.1.0";

// ---------- transform helpers ----------

interface FieldInput { className?: string; propertyName: string; value: string; }

function buildContextualTransform(
  model: DataModel, action: string, role: string, fields: FieldInput[],
  extraEvidences: Evidence[] = [], logging?: Evidence[],
): TransformInput {
  // The reference configuration places BOTH Role and Action evidence in the rights
  // and processing contexts (the engine routes by matching the full evidence set).
  const evidences: Evidence[] = [
    { name: model.roleEvidenceName, value: role },
    { name: model.actionEvidenceName, value: action },
    ...extraEvidences,
  ];
  const rg = guid("rc"), pg = guid("pc"), reqg = guid("req");
  const input: TransformInput = {
    rightsContexts: [{ guid: rg, evidences }],
    processingContexts: [{ guid: pg, evidences }],
    requests: [{
      guid: reqg, rightsContext: rg, processingContext: pg,
      instances: fields.map((f) => ({
        className: f.className ?? model.defaultClassName,
        propertyName: f.propertyName,
        value: f.value,
      })),
    }],
  };
  if (logging?.length) input.loggingContext = { evidences: logging };
  return input;
}

function summariseInstances(out: TransformOutput): {
  ok: boolean;
  instances: Array<{ className?: string; propertyName?: string; value?: string; error?: { code: string; message: string } }>;
  error?: { code: string; message: string };
} {
  if (out.error) return { ok: false, instances: [], error: out.error };
  const insts: TransformInstance[] = out.responses?.flatMap((r) => r.instances) ?? [];
  const anyErr = insts.some((i) => i.error);
  return {
    ok: !anyErr,
    instances: insts.map((i) => ({
      className: i.className, propertyName: i.propertyName, value: i.value, error: i.error,
    })),
  };
}

function jsonResult(obj: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(obj, null, 2) }], structuredContent: obj as Record<string, unknown> };
}
function textResult(text: string) {
  return { content: [{ type: "text" as const, text }] };
}
function errorResult(message: string) {
  return { content: [{ type: "text" as const, text: message }], isError: true };
}

// ---------- server assembly ----------

const fieldSchema = z.object({
  className: z.string().optional().describe("Logical class of the data instance; defaults to the configured default className."),
  propertyName: z.string().describe("Logical property/field name as configured in CoreAdmin (e.g. emailAddress)."),
  value: z.string().describe("The value to transform."),
});
const evidenceSchema = z.object({ name: z.string(), value: z.string() });

export function buildServer(client: RpsClient, model: DataModel): McpServer {
  const server = new McpServer(
    { name: "kustodyan-mcp", version: VERSION },
    { instructions:
        "Tools to protect/unprotect/search data via the Kustodyan (RegData RPS) Engine API. " +
        "Behaviour is server-configured and selected by evidence: a Role (who) and an Action " +
        "(Protect/Unprotect/Search). Use `protect` on write and `unprotect` on read; `unprotect` " +
        "returns cleartext and must be treated as sensitive. Call `list_data_model` to discover " +
        "configured classes/properties/roles. Read kustodyan://guide/best-practices first." },
  );

  // protect
  server.registerTool("protect", {
    title: "Protect data (encrypt / tokenize / anonymize)",
    description:
      "Protect one or more field values for a given role. The exact technique (encryption, " +
      "tokenization, anonymization, masking) is server-configured per (className, propertyName). " +
      "Returns each field's protected value joined to its original. Protect data as early as possible.",
    inputSchema: {
      fields: z.array(fieldSchema).min(1).describe("Field values to protect."),
      role: z.string().default(model.defaultRole ?? "").describe("Role evidence (who is asking), e.g. R_MANAGER."),
      evidences: z.array(evidenceSchema).optional().describe("Extra evidence key/value pairs beyond Role/Action."),
      loggingAttributes: z.array(evidenceSchema).optional().describe("Optional audit-log attributes for this call."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  }, async ({ fields, role, evidences, loggingAttributes }) => {
    const input = buildContextualTransform(model, model.protectAction, role, fields, evidences ?? [], loggingAttributes);
    const out = await client.transform(input);
    const s = summariseInstances(out);
    const joined = s.instances.map((inst, i) => ({
      className: inst.className, propertyName: inst.propertyName,
      original: fields[i]?.value, protected: inst.value, error: inst.error,
    }));
    return jsonResult({ ok: s.ok, action: model.protectAction, role, httpStatus: out.httpStatus, fields: joined, error: s.error });
  });

  // unprotect
  server.registerTool("unprotect", {
    title: "Unprotect data (reveal — SENSITIVE)",
    description:
      "Reverse a protection to recover the original value, for a role permitted to do so. " +
      "⚠️ Returns CLEARTEXT sensitive data — treat the result as confidential, never log it, and " +
      "only call when the caller is authorised. Depending on the role the engine may instead return " +
      "a masked value or the stored protected value.",
    inputSchema: {
      fields: z.array(fieldSchema).min(1).describe("Protected field values to unprotect."),
      role: z.string().default(model.defaultRole ?? "").describe("Role evidence; must have unprotect rights, e.g. R_MANAGER."),
      evidences: z.array(evidenceSchema).optional(),
      loggingAttributes: z.array(evidenceSchema).optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  }, async ({ fields, role, evidences, loggingAttributes }) => {
    const input = buildContextualTransform(model, model.unprotectAction, role, fields, evidences ?? [], loggingAttributes);
    const out = await client.transform(input);
    const s = summariseInstances(out);
    const joined = s.instances.map((inst, i) => ({
      className: inst.className, propertyName: inst.propertyName,
      protected: fields[i]?.value, revealed: inst.value, error: inst.error,
    }));
    return jsonResult({ ok: s.ok, action: model.unprotectAction, role, httpStatus: out.httpStatus, fields: joined, error: s.error });
  });

  // search
  server.registerTool("search", {
    title: "Search token for a protected value",
    description:
      "Run the Search operation for a value to obtain a search token you can compare against a " +
      "stored protected column (availability and operators depend on the protection scheme).",
    inputSchema: {
      fields: z.array(fieldSchema).min(1),
      role: z.string().default(model.defaultRole ?? ""),
      evidences: z.array(evidenceSchema).optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ fields, role, evidences }) => {
    const input = buildContextualTransform(model, model.searchAction, role, fields, evidences ?? []);
    const out = await client.transform(input);
    const s = summariseInstances(out);
    return jsonResult({ ok: s.ok, action: model.searchAction, role, httpStatus: out.httpStatus, tokens: s.instances, error: s.error });
  });

  // transform (low-level passthrough)
  server.registerTool("transform", {
    title: "Low-level transform (full passthrough)",
    description:
      "Escape hatch: send a fully-formed Engine transform payload (rightsContexts, processingContexts, " +
      "requests) for advanced cases (multiple contexts, dependency contexts). Prefer protect/unprotect/search.",
    inputSchema: {
      rightsContexts: z.array(z.object({ guid: z.string(), evidences: z.array(evidenceSchema) })).min(1),
      processingContexts: z.array(z.object({ guid: z.string(), evidences: z.array(evidenceSchema) })),
      requests: z.array(z.object({
        guid: z.string(), rightsContext: z.string(), processingContext: z.string(),
        instances: z.array(z.object({ className: z.string().optional(), propertyName: z.string().optional(), value: z.string() })),
      })).min(1),
      loggingContext: z.object({ evidences: z.array(evidenceSchema) }).optional(),
    },
  }, async (args) => {
    const out = await client.transform(args as unknown as TransformInput);
    return jsonResult(out);
  });

  // validate_transform (local, no network)
  server.registerTool("validate_transform", {
    title: "Validate a transform payload (local)",
    description: "Statically validate a transform payload before sending it: required fields, evidence shape, and that each request's rightsContext/processingContext references a declared context guid.",
    inputSchema: {
      rightsContexts: z.array(z.object({ guid: z.string(), evidences: z.array(evidenceSchema) })).optional(),
      processingContexts: z.array(z.object({ guid: z.string(), evidences: z.array(evidenceSchema) })).optional(),
      requests: z.array(z.object({
        guid: z.string().optional(), rightsContext: z.string().optional(), processingContext: z.string().optional(),
        instances: z.array(z.object({ className: z.string().optional(), propertyName: z.string().optional(), value: z.string().optional() })).optional(),
      })).optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async (input) => {
    const issues: string[] = [];
    const rc = new Set((input.rightsContexts ?? []).map((c) => c.guid));
    const pc = new Set((input.processingContexts ?? []).map((c) => c.guid));
    if (!input.rightsContexts?.length) issues.push("rightsContexts is required and must have ≥1 entry.");
    if (!input.requests?.length) issues.push("requests is required and must have ≥1 entry.");
    (input.rightsContexts ?? []).forEach((c, i) => { if (!c.evidences?.length) issues.push(`rightsContexts[${i}] has no evidences.`); });
    (input.requests ?? []).forEach((r, i) => {
      if (!r.rightsContext) issues.push(`requests[${i}].rightsContext missing.`);
      else if (!rc.has(r.rightsContext)) issues.push(`requests[${i}].rightsContext '${r.rightsContext}' does not match any rightsContexts[].guid.`);
      if (r.processingContext && !pc.has(r.processingContext)) issues.push(`requests[${i}].processingContext '${r.processingContext}' does not match any processingContexts[].guid.`);
      if (!r.instances?.length) issues.push(`requests[${i}].instances missing/empty.`);
      (r.instances ?? []).forEach((inst, j) => {
        if (inst.value === undefined) issues.push(`requests[${i}].instances[${j}].value missing.`);
        if (inst.className && inst.propertyName && !knownProperty(model, inst.className, inst.propertyName))
          issues.push(`requests[${i}].instances[${j}] (${inst.className}.${inst.propertyName}) is not in the known data model (may still be valid server-side).`);
      });
    });
    return jsonResult({ valid: issues.length === 0, issues });
  });

  // whoami
  server.registerTool("whoami", {
    title: "Identity / credential check",
    description: "Fetch an access token and report the (non-sensitive) JWT claims — client id, scope, expiry — to confirm credentials and which environment is configured.",
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async () => {
    try {
      const t = await client.getToken(true);
      const c = decodeJwt(t.token);
      const pick = (k: string) => c[k];
      return jsonResult({
        ok: true,
        identityUrl: client.config.identityUrl,
        engineUrl: client.config.engineUrl,
        clientId: client.config.clientId,
        scope: t.scope ?? pick("scope"),
        expiresIn: t.expiresIn,
        claims: { sub: pick("sub"), client_id: pick("client_id"), iss: pick("iss"), aud: pick("aud"), exp: pick("exp") },
      });
    } catch (e) {
      return errorResult(`whoami failed: ${(e as Error).message}`);
    }
  });

  // health
  server.registerTool("health", {
    title: "Health check (identity + engine reachability)",
    description: "Verify the Identity API issues a token and the Engine API endpoint is reachable.",
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async () => {
    const result: Record<string, unknown> = {};
    try { await client.getToken(true); result.identity = "ok"; }
    catch (e) { result.identity = `error: ${(e as Error).message}`; }
    try {
      // A minimal malformed transform proves engine reachability without consuming a transformation.
      const out = await client.transform({ rightsContexts: [], processingContexts: [], requests: [] } as TransformInput);
      result.engine = `reachable (http ${out.httpStatus})`;
    } catch (e) { result.engine = `error: ${(e as Error).message}`; }
    result.ok = result.identity === "ok" && String(result.engine).startsWith("reachable");
    return jsonResult(result);
  });

  // list_data_model
  server.registerTool("list_data_model", {
    title: "List configured classes / properties / roles",
    description: "Return the data-model manifest: which (className, propertyName) fields are protectable, the roles and their behaviour, and the Action vocabulary. Use this to discover what you can protect.",
    annotations: { readOnlyHint: true, openWorldHint: false },
  }, async () => jsonResult(model));

  // ---------- resources ----------
  server.registerResource("contextualisation-guide", "kustodyan://guide/contextualisation",
    { title: "Contextualisation guide", description: "How Role/Action evidence and className/propertyName drive transforms.", mimeType: "text/markdown" },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: "text/markdown", text: GUIDE_CONTEXT }] }));

  server.registerResource("best-practices", "kustodyan://guide/best-practices",
    { title: "Best practices for piloting", description: "Safe, effective use of the protect/unprotect tools.", mimeType: "text/markdown" },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: "text/markdown", text: GUIDE_BEST }] }));

  server.registerResource("data-model", "kustodyan://data-model",
    { title: "Data model manifest", description: "Configured classes, properties, roles and actions.", mimeType: "application/json" },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: "application/json", text: JSON.stringify(model, null, 2) }] }));

  // ---------- prompt ----------
  server.registerPrompt("protect_record", {
    title: "Protect a record's PII",
    description: "Guide the assistant to protect the sensitive fields of a record using the right role and per-field properties.",
    argsSchema: { className: z.string().optional(), role: z.string().optional() },
  }, ({ className, role }) => ({
    messages: [{
      role: "user",
      content: { type: "text", text:
        `Protect the personally-identifiable fields of the following record using the kustodyan-mcp \`protect\` tool.\n` +
        `- className: ${className ?? model.defaultClassName}\n- role: ${role ?? model.defaultRole}\n` +
        `First call \`list_data_model\` to see which propertyNames are protectable, then call \`protect\` with one entry per sensitive field. ` +
        `Do not invent propertyNames. Never echo the cleartext back after protecting. Report only the protected values and any per-field errors.` },
    }],
  }));

  return server;
}

const GUIDE_CONTEXT = `# Kustodyan contextualisation

Every call to the Engine goes through a single \`transform\` operation. What happens to a value
is decided by **evidence** you send, matched against the server configuration:

- **Role** evidence (e.g. \`R_MANAGER\`) — *who* is asking. Controls whether each field is
  transformed, returned as-is, masked, or nullified.
- **Action** evidence — *what* operation: \`Protect\`, \`Unprotect\`, or \`Search\`.
- **(className, propertyName)** — *which* field. Selects the configured transformer sequence
  (encryption, tokenization, anonymization, masking…). The technique is **server-configured**,
  never chosen by the caller.

The same endpoint and the same payload shape serve protect, unprotect and search — only the
evidence changes. Evidence keys/values are matched case-insensitively.`;

const GUIDE_BEST = `# Best practices (piloting)

- **Protect early, unprotect late.** Protect on write; only unprotect at the moment of use.
- **Treat \`unprotect\` as sensitive.** It returns cleartext. Never log it, never persist it, and
  only call it for an authorised role. Prefer a masking role (e.g. R_OPERATOR) when a partial
  value suffices.
- **Discover, don't guess.** Call \`list_data_model\` (or read \`kustodyan://data-model\`) to learn
  valid \`propertyName\`s and roles. Use \`validate_transform\` before low-level calls.
- **Batch fields** into one \`protect\`/\`unprotect\` call where possible.
- **Handle partial errors.** A call can succeed (HTTP 200) while individual fields carry an
  \`error\` and a null value — always inspect per-field results.
- **Roles change outcomes.** The same field may come back cleartext, masked, or as the stored
  protected value depending on the role — this is by design.`;

// ---------- transports ----------

async function runStdio(client: RpsClient, model: DataModel) {
  const server = buildServer(client, model);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("[kustodyan-mcp] stdio transport ready\n");
}

async function runHttp(client: RpsClient, model: DataModel) {
  const host = process.env.KUSTODYAN_HTTP_HOST || "127.0.0.1";
  const port = Number(process.env.KUSTODYAN_HTTP_PORT || process.env.PORT || 9090);
  const app = express();
  app.use(express.json({ limit: "4mb" }));

  app.get("/healthz", (_req, res) => res.status(200).json({ status: "ok", version: VERSION }));

  app.post("/mcp", async (req, res) => {
    // Stateless: a fresh server + transport per request.
    const server = buildServer(client, model);
    // Stateless JSON request/response (no server-initiated SSE streams) — the gate in
    // front is a simple bearer proxy, and each call is independent.
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => { transport.close(); server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e) {
      process.stderr.write(`[kustodyan-mcp] request error: ${(e as Error).message}\n`);
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
    }
  });

  app.listen(port, host, () => process.stderr.write(`[kustodyan-mcp] streamable HTTP transport on http://${host}:${port}/mcp\n`));
}

async function main() {
  const transport = (process.env.KUSTODYAN_MCP_TRANSPORT || (process.argv.includes("--http") ? "http" : "stdio")).toLowerCase();
  const client = new RpsClient(loadConfigFromEnv());
  const model = loadDataModel();
  if (transport === "http") await runHttp(client, model);
  else await runStdio(client, model);
}

// Only auto-start when executed directly (so the module can be imported for tests/embedding).
const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  main().catch((e) => { process.stderr.write(`[kustodyan-mcp] fatal: ${(e as Error).stack || e}\n`); process.exit(1); });
}
