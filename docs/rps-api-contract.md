# RegData RPS (Protection Suite) — Identity & Engine API Contract

> Research target: build an MCP server wrapping the RPS **Identity** (OAuth2) and **Engine** (Transform) APIs.
> Sources (all public GitHub): `RegdataSA/rps-engine-client-js` (TypeScript, **v5.0.1**, primary), `RegdataSA/rps-engine-client-python` (**v1.0.8**, Sept 2025), `RegdataSA/rps-engine-client-dotnet` (C#, v3.10.0, older). Docs: `community.rpsprod.ch` → `https://demo.rpsprod.ch/community` (JS-rendered SPA, no static text extractable).

All field names below are quoted **verbatim** from source. Where a fact could not be confirmed in source, it is marked **[UNCONFIRMED]**.

---

## 0. TL;DR

- **Auth:** `POST {identityUrl}/connect/token`, `Content-Type: application/x-www-form-urlencoded`, body `grant_type=client_credentials&client_id=…&client_secret=…` (OAuth2 client-credentials, **no scope sent**). Response is standard OAuth: `access_token`, `token_type`, `expires_in`. Default auth path = `'connect/token'`.
- **Transform:** `POST {engineUrl}/transform` (JS) — equivalently `POST {engineHostName}api/transform` (Python). Headers: `Authorization: Bearer <token>` + `Content-Type: application/json`.
- **Request body** (`ITransformInput` / `RequestBody`): `{ rightsContexts[], processingContexts[], requests[] }` (+ optional top-level `loggingContext`). Each request references contexts **by GUID** and carries `instances[]` of `{ className, propertyName, value }`.
- **Response body** (`ITransformOutput` / `ResponseBody`): `{ responses[], error }`; each response `{ request, rightsContext, processingContext, instances[] }`; each instance `{ className, propertyName, value, error? }`.

---

## 1. Identity / Auth

### 1.1 Base URL convention
- The client is configured with a separate **Identity** base URL and **Engine** base URL.
  - JS (`RPSAgent`): `identityUrl` and `engineUrl` constructor options.
  - Python (`settings.rps`): `identityServiceHostName` and `engineHostName`.
- Example identity URLs seen in source: `https://identity.rpsprod.ch`, and `https://develop.rps.net/api/identity` (i.e. the base URL itself may already include an `/api/identity` path prefix; the client just appends the auth path).

### 1.2 Token endpoint
- **Path (default `authPath`):** `connect/token`
  - JS: `public authPath = 'connect/token'` (overridable via `identity.authPath`). Request: `this.#httpIdentity.post(this.authPath, data)`.
  - Python: `url = f'{self.client_options.identity_server_host_name}connect/token'` (note: host name expected to end with `/`).
- **HTTP method:** `POST`
- **Grant type:** `client_credentials` (OAuth 2.0 Client Credentials flow)
- **Content-Type:** `application/x-www-form-urlencoded`
  - JS sends a raw urlencoded string; Python sends a dict via `requests` `data=` (urlencoded by default).

### 1.3 Exact request body params
JS builds the body string literally:
```
grant_type=client_credentials&client_id=${clientId}&client_secret=${clientSecret}
```
Python builds the equivalent dict:
```python
{
    'grant_type': 'client_credentials',
    'client_id':  '<clientId>',
    'client_secret': '<clientSecret>',
}
```
- Params sent: **`grant_type`, `client_id`, `client_secret`**.
- **`scope` is NOT sent** by either client.

### 1.4 Token response shape
Standard OpenID-Connect / IdentityServer token response. The JS parser reads these fields (tolerant of snake_case *and* camelCase):
```ts
const {
  access_token, token,
  expires_in, expiresIn,
  token_type, tokenType,
  scope,
} = tokenInfo || {}
// normalized → { token, expiresIn, tokenType, scope }
```
- Canonical server JSON fields: **`access_token`**, **`token_type`** (e.g. `"Bearer"`), **`expires_in`**, optional **`scope`**.
- Python reads only `response_body["access_token"]`.
- The Engine `Authorization` header is built as `` `${tokenType} ${token}` `` (JS) / `f"Bearer {access_token}"` (Python) — i.e. **`Authorization: Bearer <access_token>`**.

### 1.5 JS `ITokenInfo` type
```ts
export interface ITokenInfo {
  token: string
  tokenType: string
}
```
(The JS `#parseTokenInfo` actually returns `{ token, expiresIn, tokenType, scope }`, a superset of `ITokenInfo`.)

---

## 2. Engine Transform API

### 2.1 Endpoint
| Client | Method | Path string in source | Effective URL |
|---|---|---|---|
| JS v5.0.1 | `POST` | `'transform'` | `{engineUrl}/transform` |
| Python v1.0.8 | `POST` | `f'{self.host_name}api/transform'` → `'api/transform'` | `{engineHostName}api/transform` |

- The two clients use **different base-URL conventions**, so the literal path differs (`transform` vs `api/transform`). With JS the `/api/engine` part is expected to be inside `engineUrl` (e.g. `https://develop.rps.net/api/engine` + `transform`). The JS CHANGELOG explicitly notes: *"remove 'api' prefix for transform endpoint"* (v3.11.x). Python keeps an `api/` segment.
- **Recommendation for the MCP server:** make the engine transform path configurable; default to `{engineBase}/transform` and document that some deployments expose it as `{host}/api/transform`. **[Treat the exact prefix as deployment-dependent.]**

### 2.2 Required headers
```
Authorization: Bearer <access_token>
Content-Type:  application/json
```
- JS: `{ 'Content-Type': 'application/json', 'Authorization': `${tokenType} ${token}` }`
- Python: `{"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}`
- **No tenant/config header.** Configuration is selected *inside the body* by `className`/`propertyName`/contexts, plus an optional per-request `secretsManager` id — **not** via an HTTP header. (No `X-Tenant`, no `X-Config` header in any client.)
- JS auto-retries **once** on HTTP `401` (resets token, re-auths, replays).

### 2.3 Request body schema (`ITransformInput` / Python `RequestBody`)

JS interfaces (verbatim from `src/types.ts`):
```ts
export interface IEvidence {
  name: string
  value: string
}

export interface ITransformInputContext {
  guid: string
  evidences: IEvidence[]
}

export interface IInstance {
  className?: string
  propertyName?: string
  value: string
  dependencyContext?: { evidences: IEvidence[] }
  loggingContext?:    { evidences: IEvidence[] }
}

export interface IRequest {
  guid: string
  rightsContext: string          // GUID referencing a rightsContexts[].guid
  processingContext?: string     // GUID referencing a processingContexts[].guid (optional)
  secretsManager?: string        // optional secrets-manager id
  instances: IInstance[]
}

export interface ITransformInput {
  rightsContexts:     ITransformInputContext[]
  processingContexts: ITransformInputContext[]
  requests:           IRequest[]
}
```

Top-level field names (camelCase wire form): **`rightsContexts`**, **`processingContexts`**, **`requests`**, plus optional **`loggingContext`** (present in Python `RequestBody` and in the JSON-schema validator, omitted from the JS `ITransformInput` interface).

Python `RequestBody` (pydantic, `by_alias=True` → wire aliases shown):
```
loggingContext     (optional)  → Context
rightsContexts                 → list[Context]
processingContexts             → list[Context]
requests                       → list[Request]
```
Python `Request` aliases: `guid`, `rightsContext`, `processingContext`, `loggingContext` (opt), `secretsManager` (opt), `instances`.
Python `Instance` aliases: `className`, `propertyName`, `value`, `error` (opt), `loggingContext` (opt), `dependencyContext` (opt).
Python `Context`: `guid` (UUID), `evidences` (list).
Python `Evidence`: `name`, `value`.

**Validation rules** (from JS JSON-schema, `src/schema/index.ts`) — the validator accepts BOTH a **JS/camelCase** form and a **C#/PascalCase** form:
- `requests` — `minItems: 1`; each request requires **`guid`, `rightsContext`, `instances`** (`processingContext` + `secretsManager` optional).
- `rightsContexts` — `minItems: 1`; each context requires **`guid`, `evidences`**.
- `processingContexts` — `minItems: 0` (may be empty/absent).
- `instances` — `minItems: 1`; each instance requires **`value`** (`className`/`propertyName` optional).
- `evidences` — `minItems: 1`; each evidence requires **`name`, `value`** (both `minLength: 1`).
- Top-level `RequestData` requires **`rightsContexts`** and **`requests`**.
- C# casing variant: `ProcessingContexts`, `RightsContexts`, `Requests`, `Guid`, `RightsContext`, `Instances`, `ClassName`, `PropertyName`, `Value`, `Evidences`, `Name`, `Value`, `DependencyContext`, `LoggingContext`, `SecretsManager`.

### 2.4 Concrete example request (from `examples/base.ts`, verbatim)
```json
{
  "rightsContexts": [
    {
      "guid": "5e084dc7-91ed-4803-b72b-249871f7debf",
      "evidences": [ { "name": "Role", "value": "Admin" } ]
    }
  ],
  "processingContexts": [
    {
      "guid": "ffc6fc02-17d3-4e5c-95a5-234b35662169",
      "evidences": [ { "name": "Action", "value": "Protect" } ]
    }
  ],
  "requests": [
    {
      "guid": "b0cf56d2-c330-4890-ac11-307805279c19",
      "rightsContext": "5e084dc7-91ed-4803-b72b-249871f7debf",
      "processingContext": "ffc6fc02-17d3-4e5c-95a5-234b35662169",
      "instances": [
        { "className": "User", "propertyName": "FirstName", "value": "Jonny" },
        { "className": "User", "propertyName": "LastName",  "value": "Silverhand" },
        { "className": "User", "propertyName": "BirthDate", "value": "16.11.1988" }
      ]
    }
  ]
}
```
Note the **normalization model**: contexts are declared once in the top-level `rightsContexts`/`processingContexts` arrays (each with a `guid`), and each `request` references them **by guid string**. The JS `RPSCraft` helper de-duplicates identical contexts and assigns uuids automatically (`build()` emits exactly this shape).

### 2.5 Response body schema (`ITransformOutput` / Python `ResponseBody`)

JS (verbatim):
```ts
export interface IResponseInstance extends IInstance {
  error?: string
}

export interface IResponse {
  request: string            // echoes the request guid
  rightsContext: string      // guid
  processingContext: string  // guid
  instances: IResponseInstance[]
}

export interface ITransformOutput {
  duration: number           // added client-side by an axios interceptor (ms), NOT from server
  responses: IResponse[]
  status: number             // HTTP status, added client-side
  error: {
    error?: any
    errors?: any
  }
}
```
- Wire JSON from the engine contains **`responses`** and (on failure) **`error`**. `duration` and `status` are injected by the JS client, not returned by the server.
- Each response object wire fields: **`request`**, **`rightsContext`**, **`processingContext`**, **`instances`** (Python `Response` also carries `secretsManager`).
- Each response instance wire fields: **`className`**, **`propertyName`**, **`value`** (the transformed value), and optional **`error`**.
  - In JS the instance `error` is typed `string`; in Python an instance error is a structured object `{ code (UUID), message (string) }` (`RPSValueError`). **The Python source is authoritative on the real wire shape: per-instance `error` is `{ "code": <uuid>, "message": <string> }`.**

Python `ResponseBody.from_json` reads exactly:
```
json["responses"]                      → list
  each: json_response["request"], ["rightsContext"], ["processingContext"], ["instances"]
    each instance: ["className"], ["propertyName"], ["value"], optional ["error"]
json["error"]                          → { "code": <uuid>, "message": <string> }  (top-level engine error)
```

### 2.6 Concrete example response (reconstructed from the source, shapes verbatim)
```json
{
  "responses": [
    {
      "request": "b0cf56d2-c330-4890-ac11-307805279c19",
      "rightsContext": "5e084dc7-91ed-4803-b72b-249871f7debf",
      "processingContext": "ffc6fc02-17d3-4e5c-95a5-234b35662169",
      "instances": [
        { "className": "User", "propertyName": "FirstName", "value": "<protected>" },
        { "className": "User", "propertyName": "LastName",  "value": "<protected>" },
        { "className": "User", "propertyName": "BirthDate", "value": "<protected>" }
      ]
    }
  ],
  "error": null
}
```
A per-instance error (partial failure) looks like:
```json
{ "className": "User", "propertyName": "FirstName", "value": null,
  "error": { "code": "f1e2d3c4-...", "message": "..." } }
```
A whole-request engine failure returns top-level:
```json
{ "responses": [], "error": { "code": "....-uuid", "message": "..." } }
```
**[UNCONFIRMED]** the exact server JSON keys for top-level error are taken from Python (`error.code`, `error.message`); the JS interface uses a looser `{ error?, errors? }` wrapper, suggesting some engine builds may return an `errors` array instead. Treat top-level error as possibly `error` (object) **or** `errors` (collection).

### 2.7 `transformAndReturnOriginal` / `returnOriginalTransformResponse`
- This is a **client-side convenience**, not a server flag. It does **not** change the request body or the HTTP call.
- JS: `RPSAgent` constructor accepts `engine.returnOriginalTransformResponse` (boolean, default `false`) per the README; method `transformAndReturnOriginal(input)` calls `transform(input)` then post-processes via static `RPSAgent.processTransformOutput(output, input)`.
- It joins each response instance back to its **original** input value (matched by request `guid` + instance index) and re-shapes the instances:
```ts
export interface IResponseInstanceWithOriginal extends Omit<IResponseInstance, 'value'> {
  original: string       // the ORIGINAL input value
  transformed?: string   // the engine-returned value (was `value`)
}
export interface IResponseWithOriginal extends Omit<IResponse, 'instances'> {
  instances: IResponseInstanceWithOriginal[]
}
export interface ITransformOutputWithOriginal {
  duration: number
  responses: IResponseWithOriginal[]
}
```
So with-original output replaces each instance's `value` with the pair **`original`** (input) + **`transformed`** (output), preserving `className`, `propertyName`, and optional `error`. (Note: `status` and `error` from `ITransformOutput` are spread through but not declared on `ITransformOutputWithOriginal`.)

---

## 3. Core concepts (grounded in source)

- **processingContext** — A named bag of `evidences` declaring **what operation to perform**. The canonical evidence is **`{ "name": "Action", "value": "Protect" }`** or **`{ "name": "Action", "value": "Deprotect" }`** (seen verbatim in `examples/base.ts`, the Python README `settings.json`, and `simple_usage_example.py`). `Protect` applies the configured transform (encrypt/tokenize/anonymize/pseudonymize); `Deprotect` reverses it (where reversible). `processingContexts` is optional (`minItems: 0`); a request may omit it.

- **rightsContext** — A named bag of `evidences` declaring **who/what is asking**, i.e. authorization/role for the operation. The canonical evidence is **`{ "name": "Role", "value": "Admin" }`** (same three sources). The engine uses the role to decide whether the caller is permitted to protect/deprotect (and may yield different results per role). `rightsContexts` is required (`minItems: 1`) and each must contain ≥1 evidence.

- **evidence** — The atomic `{ name, value }` string pair that populates a context. Both `name` and `value` are required, non-empty. Evidences are the inputs RPS matches against its CoreAdmin configuration to resolve role/action (and any other contextual keys). Both contexts and instances can carry evidence bags (`dependencyContext.evidences`, `loggingContext.evidences`).

- **instance** — One unit of data to transform: `{ className?, propertyName?, value }`. `value` is the only required field. Instances are batched in a request's `instances[]`; the engine returns them in the **same order** (the clients re-join responses to inputs by index). Instances may also carry `dependencyContext` (related-data evidences used by the transform, e.g. min/max bounds) and a per-instance `loggingContext` (audit data).

- **className** / **propertyName** — The **logical address of the data field** in the RPS data model configured in CoreAdmin (e.g. `className: "User"`, `propertyName: "FirstName"`/`"BirthDate"`). This pair is the key that selects **which transformation rule / sequence** the engine applies to the value. Both are optional on the wire but are how config-driven behavior is selected in practice.

- **configuration** — Not a request field. It is the server-side definition in the **RPS Core Admin** platform (a.k.a. CoreAdmin): "Enabled configuration … filled with Transformation sequences, instances, rights and processing contexts" (Python README). The active configuration is selected by the client's `clientId` (the OAuth client identifies the tenant/config) plus the `className`/`propertyName`/context evidences. There is **no `configId`/`configuration` body field** in any client. The only related body field is the optional per-request **`secretsManager`** GUID (selects which secrets/keys manager to use). **[There is no `configId` in the public clients — if the user expected one, it does not exist in this API surface.]**

### 3.1 What decides encrypt vs tokenize vs anonymize vs pseudonymize?
**It is configuration-driven on the server, keyed by `className` + `propertyName` (and the resolved contexts) — NOT chosen by the client request.** The client only says: *which field* (`className`/`propertyName`), *what value*, *what action* (`Action: Protect`/`Deprotect`), and *who* (`Role: …`). The actual transform type (encryption / tokenization / anonymization / pseudonymization) and its parameters live in the CoreAdmin "Transformation sequences" configuration bound to that class/property and selected via the contexts. The same `Protect` action yields encryption for one property and tokenization for another purely because of server config. (Grounded in: Python README "Enabled configuration … Transformation sequences"; the request schema carries no transform-type selector.)

---

## 4. Errors

| Layer | Shape |
|---|---|
| **OAuth token** | Standard HTTP; Python does `response.raise_for_status()`. Expect OAuth error JSON `{ "error": "...", "error_description": "..." }` on 400/401 **[UNCONFIRMED — not parsed by clients]**. |
| **Transform HTTP** | JS treats HTTP `401` specially: resets token, retries once. On other errors JS returns `{ responses: [], status: <code or 500>, error: <response.data or message>, duration }`. Python does `raise_for_status()` then parses the body. |
| **Top-level engine error** | Wire JSON `error` object: **`{ "code": <uuid>, "message": <string> }`** (Python `Error`). JS wraps as `{ error }` or `{ errors }` (some builds may return `errors`). When present, Python raises `RPSEngineError("Error received from RPS Engine API response. Code: '<code>'. Message: '<message>')`. |
| **Per-instance error** | On a response instance: **`error: { "code": <uuid>, "message": <string> }`** (Python `RPSValueError`). JS types it loosely as `error?: string`. Engine returns this for partial/value-level failures while other instances succeed. |
| **Client-side validation** | JS `validateTransformJson(input): IRpsJsonValidationResult` → `{ schemaResult, errors[], warns[] }`; each item `{ message, prettyPath, path[] }`. Runs the JSON-schema in §2.3 before sending. |

No other HTTP status codes are documented in the clients beyond generic `401` handling and `500` fallback.

---

## 5. Other endpoints

**There are effectively only two HTTP endpoints** exposed by these clients:
1. **`POST {identityUrl}/connect/token`** — OAuth2 token (Identity API).
2. **`POST {engineUrl}/transform`** (a.k.a. `…/api/transform`) — the Engine Transform API.

No client exposes any of: health/liveness, userinfo, config retrieval, validation (server-side), or discovery endpoints. Everything else is **client-side only**:
- JS `RPSCraft` — request builder (dedups contexts, assigns guids, `build()` → `ITransformInput`).
- JS `validateTransformJson` — local JSON-schema validation.
- JS `RPSAgent` helpers: `getToken`, `trySetClient`, `setClient`, `setEngineUrl`, `setIdentityUrl`, `resetAuth`, `resetClient`, `isIdentitySet`, `isEngineSet`, `isAuthenticated`, `transform`, `transformAndReturnOriginal`, static `processTransformOutput`.
- Python: `EngineFactory.get_engine`, `RPSEngine.transform*`, context resolvers that load rights/processing contexts from JSON files or settings (`ContextSource.JSON` / `ContextSource.SETTINGS`) — all client-side; resolution to GUID happens before the single `/transform` POST.

**[UNCONFIRMED]** The OIDC discovery doc (`{identityUrl}/.well-known/openid-configuration`) and any token-introspection/userinfo endpoints likely exist on the IdentityServer but are not referenced by any client; do not assume their presence.

---

## 6. Notes / caveats for the MCP implementer

- The repo's `examples/base.ts` imports `EngineClient` / `IdentityClient` from `../src/index`, **but those classes do not exist in `src/` and are not exported** (the shipped v5.0.1 API is `RPSAgent` + `RPSCraft`). That example is stale/aspirational — **do not model the client on it.** It does, however, reveal the real base-URL convention (`https://develop.rps.net/api/identity` and `…/api/engine`) and a real example payload.
- Identity base URL handling differs by client: Python expects the host string to **end with `/`** (`f'{host}connect/token'`), JS uses axios `baseURL` join. Normalize trailing slashes in the MCP server.
- `secretsManager` is a GUID (Python `default_factory=uuid.uuid4` — beware it defaults to a *random* uuid in the Python model rather than null; pass explicitly or omit).
- Build the `Authorization` header from the token response `token_type` (don't hardcode `Bearer` if you want to be faithful), but in practice it is `Bearer`.
- Per-instance and top-level `error` use a `{ code: uuid, message: string }` shape (Python, authoritative). Surface both in the MCP tool result.
- Transform path prefix (`/transform` vs `/api/transform`) is deployment-dependent — make it configurable.
