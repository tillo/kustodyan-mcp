#!/usr/bin/env python3
"""
Kustodyan CoreAdmin admin-API client (dev.kustodyan.io).

INTERNAL provisioning tooling — talks to the *private* CoreAdmin API that the
SPA uses (no public/management API is documented). Reverse-engineered from the
KustodyanLimits JMeter plan, which the product owner provided. Not part of the
publishable MCP package (excluded from npm/docker builds).

Auth: headless authorization_code + PKCE against the OpenIddict identity server,
using the CoreAdmin admin credentials from env KUSTODYAN_COREADMIN_USERNAME / _PASSWORD.

Usage:
  python kc_admin.py recon            # read-only: list accounts, secrets-managers, users
  python kc_admin.py whoami           # print admin token claims (safe subset)
"""
import sys, json, base64, hashlib, secrets, subprocess, urllib.parse, urllib.request, urllib.error, http.cookiejar

import os as _os
BASE     = _os.environ.get("KUSTODYAN_BASE_URL", "https://dev.kustodyan.io")
IDENT    = f"{BASE}/api/identity"
COREADM  = f"{BASE}/api/coreadmin"
ENGINE   = f"{BASE}/api/engine"
REDIRECT = f"{BASE}/coreadmin/auth/callback"
SCOPE    = "openid profile rps_config_admin_api"


def _admin_creds():
    # CoreAdmin credentials from the environment (point this at your own secret store).
    import os
    return {"username": os.environ["KUSTODYAN_COREADMIN_USERNAME"],
            "password": os.environ["KUSTODYAN_COREADMIN_PASSWORD"]}


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt_claims(token):
    p = token.split(".")[1]; p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


class KustodyanAdmin:
    def __init__(self):
        self._token = None
        cj = http.cookiejar.CookieJar()
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k): return None
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj), _NoRedirect)
        self._cj = cj

    def _raw(self, url, data=None, headers=None, method=None):
        h = {"User-Agent": "kustodyan-mcp-provisioner", "Accept": "application/json"}
        if headers: h.update(headers)
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            r = self._opener.open(req, timeout=40)
            return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    # --- auth ---
    def login(self):
        cred = _admin_creds()
        st, _, body = self._raw(f"{COREADM}/config/frontend")
        client_id = json.loads(body)["oidc"]["clientId"]
        verifier = _b64url(secrets.token_bytes(32))
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        st, _, body = self._raw(f"{IDENT}/authenticate",
            data=json.dumps({"userName": cred["username"], "password": cred["password"]}).encode(),
            headers={"Content-Type": "application/json", "Origin": BASE,
                     "Referer": f"{BASE}/auth/login"})
        if st not in (200, 204):
            raise RuntimeError(f"authenticate failed HTTP {st}: {body[:200]!r}")
        q = urllib.parse.urlencode({
            "client_id": client_id, "redirect_uri": REDIRECT, "response_type": "code",
            "scope": SCOPE, "code_challenge": challenge, "code_challenge_method": "S256",
            "state": secrets.token_hex(16), "nonce": secrets.token_hex(16),
            "response_mode": "query"})
        st, hdrs, _ = self._raw(f"{IDENT}/connect/authorize?{q}",
                                headers={"Referer": f"{BASE}/auth/login"})
        loc = hdrs.get("Location", "")
        code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [None])[0]
        if not code:
            raise RuntimeError(f"authorize gave no code (HTTP {st}) loc={loc[:160]}")
        st, _, body = self._raw(f"{IDENT}/connect/token",
            data=urllib.parse.urlencode({
                "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                "code_verifier": verifier, "client_id": client_id}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        d = json.loads(body)
        self._token = d.get("access_token")
        if not self._token:
            raise RuntimeError(f"token exchange failed HTTP {st}: {body[:200]!r}")
        return self._token

    @property
    def token(self):
        if not self._token: self.login()
        return self._token

    # --- generic JSON API call against the CoreAdmin private API ---
    def api(self, method, path, body=None, base=COREADM, raw_token=None):
        url = path if path.startswith("http") else f"{base}{path}"
        headers = {"Authorization": f"Bearer {raw_token or self.token}",
                   "Origin": BASE, "Referer": f"{BASE}/coreadmin/"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        st, _, resp = self._raw(url, data=data, headers=headers, method=method)
        try:
            parsed = json.loads(resp) if resp else None
        except Exception:
            parsed = resp.decode("utf-8", "ignore")
        return st, parsed

    # --- multipart/form-data upload (e.g. config /import) ---
    def api_upload(self, method, path, field, filename, content, content_type="application/json", base=COREADM):
        url = path if path.startswith("http") else f"{base}{path}"
        boundary = "----kustodyanmcp" + secrets.token_hex(12)
        if isinstance(content, str): content = content.encode()
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
        headers = {"Authorization": f"Bearer {self.token}",
                   "Content-Type": f"multipart/form-data; boundary={boundary}",
                   "Origin": BASE, "Referer": f"{BASE}/coreadmin/"}
        st, _, resp = self._raw(url, data=body, headers=headers, method=method)
        try:
            return st, (json.loads(resp) if resp else None)
        except Exception:
            return st, resp.decode("utf-8", "ignore")

    # --- engine: client_credentials token + transform ---
    def engine_token(self, client_id, client_secret):
        st, _, body = self._raw(f"{IDENT}/connect/token",
            data=urllib.parse.urlencode({
                "grant_type": "client_credentials",
                "client_id": client_id, "client_secret": client_secret}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        return st, json.loads(body)

    def transform(self, engine_access_token, payload):
        st, _, body = self._raw(f"{ENGINE}/transform",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {engine_access_token}",
                     "Content-Type": "application/json"})
        try:
            return st, json.loads(body)
        except Exception:
            return st, body.decode("utf-8", "ignore")


def _print(label, st, data):
    s = json.dumps(data, indent=2) if not isinstance(data, str) else data
    print(f"\n### {label}  (HTTP {st})\n{s[:1800]}")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "whoami"
    a = KustodyanAdmin(); a.login()
    if cmd == "whoami":
        c = jwt_claims(a.token)
        print(json.dumps({k: c.get(k) for k in
            ("sub", "name", "email", "preferred_username", "scope", "exp", "client_id")}, indent=2))
        return
    if cmd == "recon":
        st, accounts = a.api("GET", "/accounts")
        _print("GET /accounts", st, accounts)
        # find martino-ish account ids to inspect
        ids = []
        if isinstance(accounts, list):
            for ac in accounts:
                if isinstance(ac, dict) and ac.get("id"):
                    ids.append((ac.get("id"), ac.get("name")))
        print("\naccounts:", ids[:10])
        for aid, nm in ids[:4]:
            st, sm = a.api("GET", f"/accounts/{aid}/secrets-managers")
            _print(f"secrets-managers [{nm} {aid}]", st, sm)
            st, us = a.api("GET", f"/accounts/{aid}/users")
            _print(f"users [{nm} {aid}]", st, us)
            st, tg = a.api("GET", f"/accounts/{aid}/targets")
            _print(f"targets [{nm} {aid}]", st, tg)
        return
    print("unknown command", cmd)


if __name__ == "__main__":
    main()
