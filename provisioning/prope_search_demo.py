#!/usr/bin/env python3
"""End-to-end proof that the APPLICATION can do PROPE searchable encryption with NO gateway and NO
cleartext, using the same /transform API the RPS Proxy uses.

Mechanism (discovered by probing, undocumented): the PROPE *EqualSearch* transformer returns its
result in the response **dependencyContext** as {method:"between", min, max}. The stored PROPE tokens
are non-deterministic (each occurrence differs -> frequency hidden) but order-preserving, so every
token for a word falls inside [min,max]. Equality search == an order-preserving RANGE query, which a
plain sorted index (Whoosh/SQL `BETWEEN`) evaluates with no decryption.

Run: python3 prope_search_demo.py   (creates a throwaway config on dev.kustodyan.io, cleans up)
"""
import json, uuid
from kc_admin import KustodyanAdmin

ACCOUNT="paperles"; TARGET="046a5753-e87d-4729-b98f-d0d8a6a79d0b"; SM="fa265666-b2f8-4251-865b-041f049636a3"
CLASS="ch.tillo.demo.PropeSearch"; CONFIG="PropeSearchDemo"
def U(): return str(uuid.uuid4())
import re
WORD=re.compile(r"[a-z0-9]+")

DOCS={
  1:"patient hypertension discharge cardiology",
  2:"invoice acme consulting services",
  3:"payroll salary bonus confidential",
  4:"patient radiology imaging report",
}

def build():
    key=U(); inst={}; seqs=[]; sid={}
    def prop(n): inst[n]={"id":U(),"propertyType":"String","mapping":len(inst)+1,"className":CLASS,"propertyName":n}
    def seq(nm,tid): s=U(); seqs.append({"id":s,"name":nm,"transformers":[{"id":tid,"arguments":{"keyId":key},"disabledArguments":False}]}); return s
    prop("w"); prop("eq")
    sP=seq("P","PROPEStringTokenProtector"); sU=seq("U","PROPEStringTokenDeprotector"); sE=seq("E","PROPEStringTokenEqualSearchProtector")
    def es(a): return {"id":U(),"evidences":[{"name":"Action","value":a},{"name":"Role","value":"T"}]}
    rights=[{"id":U(),"name":"E","description":"","evidenceSets":[es("Protect"),es("Unprotect"),es("Search")],
             "properties":[{"propertyId":inst[p]["id"],"right":"CanTransform"} for p in inst]}]
    proc=[{"id":U(),"name":"A","description":"","evidenceSets":[es("Protect")],"properties":[{"propertyId":inst["w"]["id"],"sequenceId":sP}]},
          {"id":U(),"name":"R","description":"","evidenceSets":[es("Unprotect")],"properties":[{"propertyId":inst["w"]["id"],"sequenceId":sU}]},
          {"id":U(),"name":"S","description":"","evidenceSets":[es("Search")],"properties":[{"propertyId":inst["eq"]["id"],"sequenceId":sE}]}]
    return {"configurationName":CONFIG,"instances":[inst[p] for p in inst],"transformerSequences":seqs,"rightsContexts":rights,
            "processingContexts":proc,"secrets":[{"id":key,"name":"k","description":"","group":"","type":"SingleKey"}],"dataSets":[]}

a=KustodyanAdmin(); a.login()
base=f"/accounts/{ACCOUNT}/targets/{TARGET}"
ex=next((c for c in (a.api("GET",f"{base}/configurations")[1] or []) if c.get("name")==CONFIG),None)
cid=ex["id"] if ex else a.api("POST",f"{base}/configurations",{"name":CONFIG,"secretsManagerIds":[SM]})[1]["id"]
cb=f"{base}/configurations/{cid}"
a.api_upload("POST",f"{cb}/import",field="file",filename="c.json",content=json.dumps(build()))
for s in (a.api("GET",f"{cb}/secrets")[1] or []): a.api("PUT",f"{cb}/secrets/{s['id']}/value",{SM:{"generateValueOptions":{"valuesCount":1}}})
cl=a.api("POST",f"{cb}/clients",{"name":"PS","type":"Global","rightsContexts":[],"processingContexts":[],"secretsManagers":[SM]})[1]
eat=a.engine_token(cl["clientId"],cl["clientSecret"])[1]["access_token"]
def tx(act,prop,vals):
    ev=[{"name":"Action","value":act},{"name":"Role","value":"T"}]; g=[U(),U(),U()]
    return a.transform(eat,{"rightsContexts":[{"guid":g[0],"evidences":ev}],"processingContexts":[{"guid":g[1],"evidences":ev}],
      "requests":[{"guid":g[2],"rightsContext":g[0],"processingContext":g[1],"instances":[{"className":CLASS,"propertyName":prop,"value":v} for v in vals]}]})[1]["responses"][0]["instances"]

# ---- WRITE: store each doc's words as non-deterministic PROPE tokens (the encrypted index) ----
index={}  # doc_id -> [tokens]
for did,text in DOCS.items():
    words=WORD.findall(text)
    index[did]=[i["value"] for i in tx("Protect","w",words)]
print("=== ENCRYPTED INDEX AT REST (non-deterministic — same word in two docs = different tokens) ===")
for did,toks in index.items(): print(f"  doc{did}: {toks}")
dup_patient=[index[1][0], index[4][0]]  # 'patient' appears in doc1 and doc4
print(f"\n  'patient' in doc1 vs doc4: {dup_patient[0]} vs {dup_patient[1]}  -> identical? {dup_patient[0]==dup_patient[1]} (frequency hidden)")

# ---- SEARCH: EqualSearch -> [min,max] band -> range scan (no decryption) ----
# the engine's OPE token comparison is CASE-INSENSITIVE lexicographic (a==A). A range-scan must use
# the same collation; in a DB index you'd declare the column with a CI collation (what the RPS Proxy
# relies on too), here we lower-case before comparing.
def ckey(s): return s.lower()
def search(word):
    inst=tx("Search","eq",[word])[0]
    band={e["name"]:e["value"] for e in inst.get("dependencyContext",{}).get("evidences",[])}
    lo,hi=ckey(band.get("min","")),ckey(band.get("max",""))
    hits=[did for did,toks in index.items() if any(lo<=ckey(t)<=hi for t in toks)]
    return band.get("min"),band.get("max"),sorted(hits)
print("\n=== EQUALITY search (EqualSearch on the full word -> [min,max] -> range scan) ===")
for q in ["hypertension","patient","salary","acme","zebra"]:
    lo,hi,hits=search(q); print(f"  '{q:13}' band[{(lo or '')[:10]}..{(hi or '')[:10]}] -> docs {hits}")
# BEGINS-WITH is the SAME mechanism: EqualSearch on a PREFIX returns a band that brackets every word
# starting with it (the band is prefix-granular). No separate StartWith needed.
print("\n=== BEGINS-WITH search (EqualSearch on a prefix -> band brackets all prefix matches) ===")
for q in ["card","radio","consul","pay"]:
    lo,hi,hits=search(q); print(f"  '{q:13}*' band[{(lo or '')[:10]}..{(hi or '')[:10]}] -> docs {hits}")

# ---- REVEAL: role-gated deprotect of a stored token (the only place cleartext appears) ----
print("\n=== REVEAL (deprotect, role-gated) ===")
print("  doc3 word[1] token", index[3][1], "->", tx("Unprotect","w",[index[3][1]])[0]["value"])

for c in (a.api("GET",f"{cb}/clients")[1] or []): a.api("DELETE",f"{cb}/clients/{c.get('id') or c.get('clientId')}")
a.api("DELETE",f"{base}/configurations",[cid]); print("\n[cleaned up throwaway config]")
