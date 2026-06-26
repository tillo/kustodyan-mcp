# kustodyan-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for the
**[Kustodyan](https://kustodyan.com) data-protection API** (powered by the RegData
Protection Suite). It lets AI agents and applications **protect, unprotect and search**
sensitive data through Kustodyan's contextual transform engine — so data is tokenized,
encrypted, anonymized or masked according to *who* is asking (a role) and *what*
operation is requested, with every call auditable.

It speaks two transports from one binary:

- **stdio** (default) — for local use, e.g. `npx kustodyan-mcp`
- **streamable HTTP** — for hosting behind a reverse proxy (set `KUSTODYAN_MCP_TRANSPORT=http`)

## What it does

The Kustodyan Engine exposes a single `transform` operation; behaviour is selected by
**evidence** you send — a `Role` (who) and an `Action` (`Protect` / `Unprotect` / `Search`)
— plus the `(className, propertyName)` of each value. The transformation technique
(encryption, tokenization, anonymization, masking) is configured server-side, never chosen
by the caller. This server wraps that model in ergonomic tools.

### Tools

| Tool | Purpose |
|------|---------|
| `protect` | Protect field values for a role (encrypt / tokenize / anonymize per config). |
| `unprotect` | Reverse a protection to recover the original — **returns cleartext, treat as sensitive**. |
| `search` | Get a search token to match against a stored protected value. |
| `transform` | Low-level escape hatch: send a full Engine transform payload. |
| `validate_transform` | Statically validate a transform payload before sending. |
| `whoami` | Confirm credentials and the configured environment (decoded token claims). |
| `health` | Check Identity + Engine reachability. |
| `list_data_model` | Discover the configured classes, properties, roles and actions. |

### Resources & prompts

- `kustodyan://guide/contextualisation` — how Role/Action evidence drives transforms.
- `kustodyan://guide/best-practices` — safe, effective use of protect/unprotect.
- `kustodyan://data-model` — the configured data-model manifest.
- Prompt `protect_record` — guides an assistant to protect a record's PII safely.

## Configuration (environment)

| Variable | Required | Description |
|----------|----------|-------------|
| `KUSTODYAN_IDENTITY_URL` | yes | e.g. `https://<env>.kustodyan.io/api/identity` |
| `KUSTODYAN_ENGINE_URL` | yes | e.g. `https://<env>.kustodyan.io/api/engine` |
| `KUSTODYAN_CLIENT_ID` | yes | Engine API client id (from the CoreAdmin portal) |
| `KUSTODYAN_CLIENT_SECRET` | yes | Engine API client secret |
| `KUSTODYAN_DATA_MODEL` | no | Path to a data-model manifest JSON (classes/properties/roles) |
| `KUSTODYAN_MCP_TRANSPORT` | no | `stdio` (default) or `http` |
| `KUSTODYAN_HTTP_HOST` / `KUSTODYAN_HTTP_PORT` | no | HTTP bind (default `127.0.0.1` / `9090`) |

## Run locally (stdio)

```bash
KUSTODYAN_IDENTITY_URL=https://<env>.kustodyan.io/api/identity \
KUSTODYAN_ENGINE_URL=https://<env>.kustodyan.io/api/engine \
KUSTODYAN_CLIENT_ID=... KUSTODYAN_CLIENT_SECRET=... \
npx kustodyan-mcp
```

MCP client config (stdio):

```json
{
  "mcpServers": {
    "kustodyan": {
      "command": "npx",
      "args": ["-y", "kustodyan-mcp"],
      "env": {
        "KUSTODYAN_IDENTITY_URL": "https://<env>.kustodyan.io/api/identity",
        "KUSTODYAN_ENGINE_URL": "https://<env>.kustodyan.io/api/engine",
        "KUSTODYAN_CLIENT_ID": "...",
        "KUSTODYAN_CLIENT_SECRET": "..."
      }
    }
  }
}
```

## Run hosted (HTTP, token-gated image)

The container serves streamable HTTP behind an nginx bearer-token gate.

```bash
docker run -d -p 8080:8080 \
  -e MCP_BEARER_TOKEN=<a long random secret> \
  -e KUSTODYAN_IDENTITY_URL=https://<env>.kustodyan.io/api/identity \
  -e KUSTODYAN_ENGINE_URL=https://<env>.kustodyan.io/api/engine \
  -e KUSTODYAN_CLIENT_ID=... -e KUSTODYAN_CLIENT_SECRET=... \
  <image>
```

Point your MCP client at `https://<host>/mcp`, sending `Authorization: Bearer <MCP_BEARER_TOKEN>`
(or `?token=<MCP_BEARER_TOKEN>`). `GET /healthz` is unauthenticated for probes.

## Build

```bash
npm install
npm run build      # -> dist/
npm start          # stdio
```

## Safety notes

- `unprotect` returns cleartext. Never log it, persist it, or call it for an unauthorised
  role. Prefer a masking role when a partial value suffices.
- Discover the data model (`list_data_model`) instead of guessing `propertyName`s.
- Transform calls can succeed (HTTP 200) while individual fields carry a per-field `error` —
  always inspect per-field results.

## License

MIT
