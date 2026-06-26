# Searchable, role-contextual encryption for a document app

A working pattern for putting **RegData Protection Suite (RPS / Kustodyan)** in front of a real
document-management app (paperless-ngx) so that document content, title, tags and correspondents are
**encrypted at rest *and* in the search index**, **searchable without decrypting** (full-word *and*
begins-with), and **revealed differently per user** — all decided server-side by the configuration.

> Reference implementation: `paperless-kustodyan` (a paperless-ngx custom image + the standalone
> `paperless_kustodyan` add-on app) and the provisioning scripts in this repo (`provisioning/*.py`).

---

## 1. The idea in one picture

```
                    write (Protect)                        read (Unprotect, per role)
 "annual salary …" ───────────────────►  token stream  ───────────────────►  DATA_STEWARD  annual salary …
                    word-by-word          (also what the                      CASE_WORKER   annual s***** …
                    (det. or PROPE)        index stores)                      STAFF         <ciphertext tokens>
                                                                              (no role)     denied

 search "salary"  ── tokenize the query the SAME way ──►  match in the encrypted index   ✔
 search "sal*"    ── PROPE EqualSearch [min,max] band ──►  field:[lo TO hi] range query   ✔  (title/correspondent)
```

Cleartext exists only transiently inside the Engine during an authorized transform. The database
columns and the Whoosh full-text index hold **only ciphertext tokens**.

---

## 2. Searchability is a ladder — and each rung is a leakage trade

RPS exposes its transformer catalog at **`GET /api/coreadmin/transformers`** (85 transformers; each
has `id`, `name`, `description`, `applicableDataType`, `isSearchable`). Choosing the right one per
field *is* the design — and what each leaks is the price of what it can search:

| Scheme (transformer) | Searches | Leaks | Frequency | Pick for |
|---|---|---|---|---|
| **Probabilistic** (`AESProtector`) | nothing — same input → different ciphertext | nothing | hidden | high-secrecy fields you never search |
| **Deterministic** (`AESDeterministicProtector`) | equality / full-word | **frequency** (same word → same token) | exposed | searchable text where order must stay hidden — **and ML features** (see §5) |
| **OPE** (`ShiftedOPEStringToken…`) | equality + begins-with + range | **order + prefix** | exposed | short metadata where you'd otherwise need all three |
| **PROPE** (`PROPEStringToken…`) | equality + begins-with | **order** only | **hidden** | searchable fields where repetition is the threat |

**PROPE is the interesting one** and is the least documented. Its tokens are *non-deterministic*
(`PROPEStringTokenProtector("John")` twice → two different tokens → frequency hidden), yet still
searchable: **`PROPEStringTokenEqualSearchProtector`**, run under a **`Search`** action, returns its
result **in the response `dependencyContext`** (not in `value`): `{method:"between", min, max}`. Every
non-deterministic token for a word falls inside `[min,max]`, so equality search is an **order-preserving
range / `BETWEEN`** query that a plain sorted index evaluates with no decryption. **Begins-with is the
same call on a prefix** — `EqualSearch("emp")` returns a band that brackets every word starting with
`emp`. Two non-obvious requirements: the band lives in `dependencyContext`, and the token comparison is
**case-insensitive** (a range scan with the wrong collation silently returns nothing). The band is
also prefix-coarse, so it's a candidate filter. *(None of this is in the docs — `provisioning/prope_search_demo.py`
reproduces it end-to-end.)*

---

## 3. How it maps onto the app

### Field → scheme (built from scratch, `provisioning/ope_provision.py`)

| Field | At-rest | Searchable | Why |
|---|---|---|---|
| `content` | **deterministic** + probabilistic full copy | equality | keeps paperless's ML auto-classifier working (PROPE has no shared features to learn — see §5) |
| `title` | **PROPE** + probabilistic full copy | equality + begins-with | titles repeat (`Invoice`, `Patient`) → frequency-hiding matters; classifier doesn't use it |
| `correspondent` | **PROPE** + probabilistic full copy | equality + begins-with | same; searchable/filterable by prefix |
| `tag` | **deterministic** | equality | exact match; usage frequency is structural (the M2M) anyway |
| custom field | **probabilistic** | — | high-secrecy (e.g. IBAN), never searched |

Roles: **DATA_STEWARD** (full reveal), **CASE_WORKER** (mask), **STAFF** (read the stored token),
no role → denied. Rights contexts (Editors / Staff) and processing contexts (Apply / Reveal / Mask /
**Search**) encode exactly that. One **AES key per property** (key + domain separation) from the
account secrets-manager.

### Write (`signals.py`, `pre_save`)
Each searchable field stores a hybrid: a **probabilistic full-fidelity copy** (exact case/punctuation,
role-aware on read) as the first token, then the per-word search tokens. Deterministic tokens are
`k`+hex; PROPE tokens are `k`+hex of the **lower-cased** token (so a range query reproduces the engine's
case-insensitive collation), and the display copy is `h`+hex so it sorts *below* the `k…` range and a
`field:[lo TO hi]` query can never match it. Content words carry an app-held **suffix salt** (separate
from the engine key → reversing a token needs both). Fail-closed: a transform error aborts the save.

### Read (`serializers_patch.py`)
Monkeypatch paperless's **native** serializers so each value is deprotected **for the caller's role** on
the way out — no paperless source edited, no special client. Same stored ciphertext → full / masked /
token / denied. (`preview_patch.py` renders a deprotected PDF on the fly for reveal-capable roles, with
`Cache-Control: no-store`.)

### Search (`search_patch.py`)
Rewrite the query before paperless parses it: `content` → its deterministic token (exact term);
`title`/`correspondent` → the PROPE `EqualSearch` band as a `field:[lo TO hi]` **range** clause. One
query fans out to `(content:<det> OR title:[…] OR correspondent:[…])`; a `word*` prefix drops the
content clause (deterministic has no begins-with) and keeps the PROPE ranges.

---

## 4. What the user sees (the showcase)

One encrypted copy of each document, four accounts:

| role (Django group → RPS role) | content | title | correspondent |
|---|---|---|---|
| **steward** → DATA_STEWARD | full cleartext | `Discharge summary - J. Doe` | `Acme Corp Billing` |
| **worker** → CASE_WORKER | masked | `Dis****…` | `Acm***` |
| **clerk** → STAFF | `CF_…` token | `TF_…` token | `CO_…` token |
| **nobody** | denied | denied | denied |

Search over the encrypted index (as steward): content `salary`→3 / `hypertension`→2; title
`discharge`, `invoice`, and begins-with `emp*` / `invoice*`; correspondent `acme`→5, `zurich`→3 and
`acm*` / `zur*`. Auto-classification still predicts the correspondent + tags from the (deterministic)
content. Seed/render: `demo/showcase_seed.py`, `demo/render_showcase.py`.

---

## 5. Honest trade-offs (say these out loud when presenting)

- **Searchability isn't free — it's a leakage dial.** Deterministic leaks *frequency* (vulnerable to
  frequency analysis on natural-language text); OPE leaks *order + prefix*; PROPE leaks *order* but
  hides *frequency*; probabilistic leaks nothing but can't be searched. Pick per field.
- **PROPE breaks ML — so content stays deterministic.** paperless's classifier trains on the content
  tokens; deterministic tokens give shared features across documents, but PROPE's non-deterministic
  tokens are unique per occurrence → nothing to learn. So PROPE goes on title/correspondent (the
  classifier doesn't use them) and content stays deterministic.
- **No token cache.** A persistent word→token map would be a cleartext vocabulary *and* a rainbow table
  that reverses the index without the key. Protect calls are de-duplicated per request only.
- **Display fidelity is preserved** by storing a probabilistic full copy alongside the (lower-cased)
  search tokens; reads return exact case/punctuation, role-aware.
- **Cost.** One Engine round-trip per field write/read (batched over its words) and per query term
  (the PROPE `Search` band call). Fine for interactive use; the same calls the RPS Proxy makes.

---

## 6. Gotchas (hard-won)

- Secrets-manager must be **enabled** on the account before keys/clients can be minted
  (`SECRETS_MANAGER_NOT_FOUND` otherwise) — undocumented.
- `guid`s in a transform must be real UUIDs; `loggingContext.evidences` (not the documented
  `attributes`) and it **rejects empty values**.
- The transformer catalog exposes no per-transformer **argument schema**; `validateSequenceArguments:false`
  lets you pass minimal args (`{keyId}`) while you reverse-engineer.
- **PROPE search contract is undocumented:** the band is in `dependencyContext` (`{method,min,max}`),
  not `value`; the token collation is **case-insensitive** (wrong collation → silently empty). `StartWith`
  returns a bare value and is superseded by `EqualSearch`-on-a-prefix for an index-backed search.
- Tokens must be **analyzer-safe** — hex-encode so Whoosh keeps each as one term. For PROPE ranges,
  hex the *lower-cased* token (CI order) and prefix the display copy with `h` so it sorts below the
  `k…` range.
- paperless **recomputes md5-looking checksums** in a `pre_save`, so an ORM seed must use a non-hex
  checksum or it collides.

---

## 7. Talking points for a demo / pitch

1. "Your most sensitive document field, encrypted at rest and in the index — and you can still search
   it." (Type `salary`; open the doc as three users, see three renderings.)
2. "No fork. No plugin API needed." A standalone Django add-on (signals + serializer/search
   monkeypatches) — paperless source untouched, activated by one env var.
3. "The policy lives in the config, not the code." Who sees what is the RPS configuration; the app
   just forwards the caller's role.
4. "Searchability is a dial — and so is leakage." probabilistic → deterministic (equality, leaks
   frequency) → PROPE (equality + begins-with, hides frequency) → OPE (adds range, leaks order+prefix),
   per field, by changing one transformer.
5. "An app can do what the gateway does." The PROPE range search runs over the same `/transform` API
   the RPS Proxy uses — no gateway required for an in-app integration.
