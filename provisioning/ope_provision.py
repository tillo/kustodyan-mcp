#!/usr/bin/env python3
"""From-scratch searchable config `PaperlessOPE` (class ch.tillo.paperless.OpeDocument).

**title** uses **PROPE** (`PROPEStringTokenProtector`): non-deterministic tokens that hide word
frequency, searchable via `PROPEStringTokenEqualSearchProtector` which returns a `[min,max]`
order-preserving band (in the response `dependencyContext`) covering equality AND begins-with. The
PROPE tokens are write-only for search; display comes from a probabilistic full-fidelity copy
(title_full). **content** stays **deterministic** (`AESDeterministicProtector`) — equality search +
keeps paperless's ML auto-classifier working, which PROPE's non-deterministic tokens would break
(no shared features across docs). tag deterministic; correspondent / customfield probabilistic.
Roles: DATA_STEWARD full / CASE_WORKER mask / STAFF token. The engine client is printed; set it as env on the app.
"""
import json, subprocess, uuid
from kc_admin import KustodyanAdmin, IDENT, ENGINE

import os as _os
ACCOUNT=_os.environ.get("KUSTODYAN_ACCOUNT","paperles")
TARGET =_os.environ["KUSTODYAN_TARGET_ID"]   # your RPS target uuid
SM     =_os.environ["KUSTODYAN_SM_ID"]       # your secrets-manager uuid
CONFIG="PaperlessOPE"; CLASS="ch.tillo.paperless.OpeDocument"
MASK={"content":"X"+"*"*60,"tag":"XXX"+"*"*60}
ROLES={"steward":"DATA_STEWARD","worker":"CASE_WORKER","staff":"STAFF"}
def U(): return str(uuid.uuid4())

def build():
    inst={}; seqs=[]; sid={}
    keys={g:U() for g in ["content","title_search","correspondent_search","tag","content_full","title_full","correspondent","customfield"]}
    def K(tid,k): return {"id":tid,"arguments":{"keyId":k},"disabledArguments":False}            # PROPE (keyId only)
    def DET(tid,k): return {"id":tid,"arguments":{"keyLength":32,"encoding":"Base64","inputEncoded":False,"keyId":k},"disabledArguments":False}
    def AES(tid,k): return {"id":tid,"arguments":{"useHashKey":False,"keyLength":32,"ivKeyLength":32,"mode":"CBC","encoding":"Base64","inputEncoded":False,"keyId":k},"disabledArguments":False}
    def w(p): return {"id":"SimpleWrapper","arguments":{"prefix":p,"postfix":"_"},"disabledArguments":False}
    def uw(p): return {"id":"SimpleUnwrapper","arguments":{"prefix":p,"postfix":"_"},"disabledArguments":False}
    def m(pat): return {"id":"MaskingStringProtector","arguments":{"pattern":pat},"disabledArguments":False}
    i=0
    def prop(name):
        nonlocal i; i+=1; inst[name]={"id":U(),"propertyType":"String","mapping":i,"className":CLASS,"propertyName":name}
    def triple(name, pseq, useq, mseq):
        sp,su,sm=U(),U(),U(); sid[(name,"p")],sid[(name,"u")],sid[(name,"m")]=sp,su,sm
        seqs.append({"id":sp,"reverseSequenceId":su,"name":f"P_{name}","transformers":pseq})
        seqs.append({"id":su,"reverseSequenceId":sp,"name":f"U_{name}","transformers":useq})
        seqs.append({"id":sm,"name":f"M_{name}","transformers":mseq})

    # PROPE searchable title + correspondent (non-deterministic -> hides frequency). protect on write;
    # EqualSearch on query returns a [min,max] band (equality AND begins-with). Write-only -> no
    # unprotect/mask (display is the *_full / correspondent probabilistic copy below).
    for f in ["title_search","correspondent_search"]:
        prop(f); k=keys[f]; sp,ss=U(),U(); sid[(f,"p")],sid[(f,"s")]=sp,ss
        seqs.append({"id":sp,"name":f"P_{f}","transformers":[K("PROPEStringTokenProtector",k)]})
        seqs.append({"id":ss,"name":f"S_{f}","transformers":[K("PROPEStringTokenEqualSearchProtector",k)]})

    # Deterministic searchable (equality; ML-classifier-compatible): content, tag
    for f in ["content","tag"]:
        prop(f); k=keys[f]
        triple(f, [DET("AESDeterministicProtector",k)], [DET("AESDeterministicDeprotector",k)],
               [DET("AESDeterministicDeprotector",k), m(MASK[f])])

    # Full-fidelity display fields (probabilistic AES -> exact case/punctuation on read, role-aware)
    FMASK={"content_full":"X"*8+"*"*600,"title_full":"X"*3+"*"*120,"correspondent":"X"*3+"*"*120,"customfield":"X"*2+"*"*120}
    for f,pfx in [("content_full","CF_"),("title_full","TF_"),("correspondent","CO_"),("customfield","XF_")]:
        prop(f); k=keys[f]
        triple(f, [AES("AESProtector",k), w(pfx)], [uw(pfx), AES("AESDeprotector",k)],
               [uw(pfx), AES("AESDeprotector",k), m(FMASK[f])])

    def es(act,role): return {"id":U(),"evidences":[{"name":"Action","value":act},{"name":"Role","value":role}]}
    props_all=list(inst.keys())
    rights=[{"id":U(),"name":"Editors","description":"","evidenceSets":[es("Protect",ROLES["steward"]),es("Search",ROLES["steward"]),es("Unprotect",ROLES["steward"]),es("Unprotect",ROLES["worker"])],
             "properties":[{"propertyId":inst[p]["id"],"right":"CanTransform"} for p in props_all]},
            {"id":U(),"name":"Staff","description":"","evidenceSets":[es("Unprotect",ROLES["staff"])],
             "properties":[{"propertyId":inst[p]["id"],"right":"CanRead"} for p in props_all]}]
    proc=[{"id":U(),"name":"Apply","description":"","evidenceSets":[es("Protect",ROLES["steward"])],
           "properties":[{"propertyId":inst[p]["id"],"sequenceId":sid[(p,"p")]} for p in props_all if (p,"p") in sid]},
          {"id":U(),"name":"Search","description":"","evidenceSets":[es("Search",ROLES["steward"])],
           "properties":[{"propertyId":inst[p]["id"],"sequenceId":sid[(p,"s")]} for p in props_all if (p,"s") in sid]},
          {"id":U(),"name":"Reveal","description":"","evidenceSets":[es("Unprotect",ROLES["steward"])],
           "properties":[{"propertyId":inst[p]["id"],"sequenceId":sid[(p,"u")]} for p in props_all if (p,"u") in sid]},
          {"id":U(),"name":"Mask","description":"","evidenceSets":[es("Unprotect",ROLES["worker"])],
           "properties":[{"propertyId":inst[p]["id"],"sequenceId":sid[(p,"m")]} for p in props_all if (p,"m") in sid]}]
    return {"configurationName":CONFIG,"instances":[inst[p] for p in props_all],"transformerSequences":seqs,
            "rightsContexts":rights,"processingContexts":proc,
            "secrets":[{"id":k,"name":f"key-{g}","description":"","group":"","type":"SingleKey"} for g,k in keys.items()],"dataSets":[]}

a=KustodyanAdmin(); a.login(); print("[login] ok")
base=f"/accounts/{ACCOUNT}/targets/{TARGET}"
st,cfgs=a.api("GET",f"{base}/configurations")
ex=next((c for c in (cfgs or []) if c.get("name")==CONFIG),None)
cid=ex["id"] if ex else a.api("POST",f"{base}/configurations",{"name":CONFIG,"secretsManagerIds":[SM]})[1]["id"]
cb=f"{base}/configurations/{cid}"; print("[config]",cid)
print("[import]",a.api_upload("POST",f"{cb}/import",field="file",filename="c.json",content=json.dumps(build()))[0])
st,secs=a.api("GET",f"{cb}/secrets")
for s in secs: print("[secret]",a.api("PUT",f"{cb}/secrets/{s['id']}/value",{SM:{"generateValueOptions":{"valuesCount":1}}})[0])
st,cl=a.api("POST",f"{cb}/clients",{"name":"OpeClient","type":"Global","rightsContexts":[],"processingContexts":[],"secretsManagers":[SM]})
if isinstance(cl,dict) and cl.get("clientId"):
    cid_,csec=cl["clientId"],cl["clientSecret"]; print("[client] created",cid_)
else:
    cid_,csec=_os.environ["KUSTODYAN_CLIENT_ID"],_os.environ["KUSTODYAN_CLIENT_SECRET"]; print("[client] reuse from env",cid_)
payload={"identityUrl":IDENT,"engineUrl":ENGINE,"clientId":cid_,"clientSecret":csec,"scope":"rps_engine_api",
         "accountId":ACCOUNT,"targetId":TARGET,"configurationId":cid,"configName":CONFIG,"className":CLASS}
def akl(n,v):
    # Print the engine client; set KUSTODYAN_CLIENT_ID / KUSTODYAN_CLIENT_SECRET on the app from these.
    print(f"[engine-client] {n} = {v}")
akl("engine-client (json)",json.dumps(payload)); akl("KUSTODYAN_CLIENT_ID",cid_); akl("KUSTODYAN_CLIENT_SECRET",csec)
print("[client] printed above — set as env on the app")
st,tok=a.engine_token(cid_,csec); eat=tok["access_token"]
def txi(act,role,prop,word):
    ev=[{"name":"Action","value":act},{"name":"Role","value":role}]; g1,g2,g3=U(),U(),U()
    st,r=a.transform(eat,{"rightsContexts":[{"guid":g1,"evidences":ev}],"processingContexts":[{"guid":g2,"evidences":ev}],
      "requests":[{"guid":g3,"rightsContext":g1,"processingContext":g2,"instances":[{"className":CLASS,"propertyName":prop,"value":word}]}]})
    return r["responses"][0]["instances"][0] if isinstance(r,dict) and r.get("responses") else {"value":str(r)}
def band(prop,word):
    d=txi("Search",ROLES["steward"],prop,word).get("dependencyContext",{}).get("evidences",[]); m={e["name"]:e["value"] for e in d}; return m.get("min"),m.get("max")
ci=lambda s:(s or "").lower()
print("\n=== verify content = DETERMINISTIC (equality; classifier-compatible) ===")
c1=txi("Protect",ROLES["steward"],"content","salary")["value"]; c2=txi("Protect",ROLES["steward"],"content","salary")["value"]
print("deterministic (same token):", c1==c2, "| token:", c1, "| reversible:", txi("Unprotect",ROLES["steward"],"content",c1)["value"])
print("\n=== verify title = PROPE (non-deterministic -> frequency hidden; EqualSearch range) ===")
t=[txi("Protect",ROLES["steward"],"title_search","salary")["value"] for _ in range(3)]
print("tokens for 'salary' x3:", t, "| all distinct:", len(set(t))==3)
lo,hi=band("title_search","salary"); print(f"EqualSearch('salary') band [{lo}..{hi}]")
print("salary tokens in band (CI):", all(ci(lo)<=ci(x)<=ci(hi) for x in t))
ph=txi("Protect",ROLES["steward"],"title_search","payroll")["value"]; print("'payroll' token in 'salary' band:", ci(lo)<=ci(ph)<=ci(hi), "(want False)")
plo,phi=band("title_search","emp"); te=txi("Protect",ROLES["steward"],"title_search","employment")["value"]
print(f"begins-with 'emp' band covers an 'employment' token:", ci(plo)<=ci(te)<=ci(phi))
print("\n=== verify full-fidelity (content_full, probabilistic, exact case) ===")
orig="Anna Smith — annual salary CHF 145'000."
ft=txi("Protect",ROLES["steward"],"content_full",orig)["value"]
print("reversible EXACT (steward):", txi("Unprotect",ROLES["steward"],"content_full",ft)["value"], "| mask (worker):", txi("Unprotect",ROLES["worker"],"content_full",ft)["value"])
