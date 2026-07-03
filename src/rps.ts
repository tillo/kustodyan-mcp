/**
 * Thin client for the Kustodyan / RegData Protection Suite (RPS) runtime APIs:
 *   - Identity API  (OAuth2 client-credentials -> bearer token)
 *   - Engine  API   (POST /transform)
 *
 * The transform *behaviour* (encrypt / tokenize / anonymize / mask / search) is
 * entirely server-configured and selected by the evidence you send (Role, Action,
 * …) plus the (className, propertyName) of each value. This client just speaks the
 * wire protocol and caches the token.
 */

export interface RpsConfig {
  identityUrl: string;
  engineUrl: string;
  clientId: string;
  clientSecret: string;
  authPath: string;       // default "connect/token"
  transformPath: string;  // default "transform"
}

export interface Evidence { name: string; value: string; }

export interface TransformContext {
  guid: string;
  evidences: Evidence[];
}

export interface TransformInstance {
  className?: string;
  propertyName?: string;
  value?: string;
  error?: { code: string; message: string };
}

export interface TransformRequest {
  guid: string;
  rightsContext: string;
  processingContext: string;
  instances: TransformInstance[];
}

export interface TransformInput {
  // The Engine validates loggingContext.evidences (the docs' `attributes` is wrong).
  loggingContext?: { evidences: Evidence[] };
  rightsContexts: TransformContext[];
  processingContexts: TransformContext[];
  requests: TransformRequest[];
}

export interface TransformResponse {
  request: string;
  rightsContext?: string;
  processingContext?: string;
  instances: TransformInstance[];
}

export interface TransformOutput {
  responses?: TransformResponse[];
  error?: { code: string; message: string };
}

export class RpsError extends Error {
  constructor(message: string, readonly status?: number, readonly body?: unknown) {
    super(message);
    this.name = "RpsError";
  }
}

function trimSlash(u: string) { return u.replace(/\/+$/, ""); }

export function loadConfigFromEnv(env = process.env): RpsConfig {
  const need = (k: string) => {
    const v = env[k];
    if (!v) throw new Error(`Missing required env ${k}`);
    return v;
  };
  return {
    identityUrl: trimSlash(need("KUSTODYAN_IDENTITY_URL")),
    engineUrl: trimSlash(need("KUSTODYAN_ENGINE_URL")),
    clientId: need("KUSTODYAN_CLIENT_ID"),
    clientSecret: need("KUSTODYAN_CLIENT_SECRET"),
    authPath: env.KUSTODYAN_AUTH_PATH || "connect/token",
    transformPath: env.KUSTODYAN_TRANSFORM_PATH || "transform",
  };
}

/** Decode a JWT payload without verifying the signature (claims display only). */
export function decodeJwt(token: string): Record<string, unknown> {
  const part = token.split(".")[1];
  if (!part) return {};
  const b64 = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(part.length + (4 - (part.length % 4)) % 4, "=");
  try { return JSON.parse(Buffer.from(b64, "base64").toString("utf8")); }
  catch { return {}; }
}

export class RpsClient {
  private token?: string;
  private tokenExp = 0; // epoch seconds
  constructor(private cfg: RpsConfig) {}

  get config() { return this.cfg; }

  /** Fetch (and cache) a client-credentials access token. */
  async getToken(force = false): Promise<{ token: string; scope?: string; expiresIn?: number }> {
    const now = Math.floor(Date.now() / 1000);
    if (!force && this.token && now < this.tokenExp - 30) {
      return { token: this.token };
    }
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.cfg.clientId,
      client_secret: this.cfg.clientSecret,
    });
    const res = await fetch(`${this.cfg.identityUrl}/${this.cfg.authPath}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new RpsError(`Token request failed (HTTP ${res.status})`, res.status, safeJson(text));
    }
    const data = JSON.parse(text);
    this.token = data.access_token;
    this.tokenExp = now + (Number(data.expires_in) || 1800);
    return { token: this.token!, scope: data.scope, expiresIn: Number(data.expires_in) };
  }

  /** POST a TransformInput to the Engine, refreshing the token once on 401. */
  async transform(input: TransformInput): Promise<TransformOutput & { httpStatus: number }> {
    const doCall = async (token: string) => {
      const res = await fetch(`${this.cfg.engineUrl}/${this.cfg.transformPath}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(input),
      });
      const text = await res.text();
      return { res, text };
    };

    let { token } = await this.getToken();
    let { res, text } = await doCall(token);
    if (res.status === 401) {
      ({ token } = await this.getToken(true));
      ({ res, text } = await doCall(token));
    }
    const parsed = (safeJson(text) ?? {}) as TransformOutput;
    if (res.status >= 400 && !parsed.error) {
      throw new RpsError(`Transform failed (HTTP ${res.status})`, res.status, parsed);
    }
    return { ...parsed, httpStatus: res.status };
  }
}

function safeJson(text: string): unknown {
  if (!text) return undefined;
  try { return JSON.parse(text); } catch { return text; }
}

import { randomUUID } from "node:crypto";
/**
 * In-request reference id. The Engine validates these as .NET System.Guid, so they
 * MUST be UUIDs (the docs' claim that they can be "any value" is not enforced-safe).
 */
export function guid(_prefix?: string): string {
  return randomUUID();
}
