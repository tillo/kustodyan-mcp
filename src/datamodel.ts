/**
 * Optional data-model manifest.
 *
 * The Kustodyan/RPS runtime API has no catalog endpoint to discover which
 * classes/properties/roles/actions a configuration exposes — so an operator can
 * supply a small manifest (via KUSTODYAN_DATA_MODEL=/path/to.json) that the MCP
 * surfaces as a resource and uses for light validation and agent hints. If none
 * is supplied, a built-in default describing the reference "ch.kyos.Contact"
 * configuration is used so the tools are useful out of the box.
 */
import { readFileSync } from "node:fs";

export interface DataProperty {
  propertyName: string;
  description?: string;
  technique?: string; // human note, e.g. "email tokenization"
}

export interface DataClass {
  className: string;
  description?: string;
  properties: DataProperty[];
}

export interface RoleInfo {
  role: string;
  summary: string;
}

export interface DataModel {
  configuration?: string;
  defaultClassName?: string;
  defaultRole?: string;
  roleEvidenceName: string;   // usually "Role"
  actionEvidenceName: string; // usually "Action"
  protectAction: string;      // usually "Protect"
  unprotectAction: string;    // usually "Unprotect"
  searchAction: string;       // usually "Search"
  classes: DataClass[];
  roles: RoleInfo[];
}

const DEFAULT_MODEL: DataModel = {
  configuration: "PaperlessDemo",
  defaultClassName: "ch.kyos.Contact",
  defaultRole: "R_MANAGER",
  roleEvidenceName: "Role",
  actionEvidenceName: "Action",
  protectAction: "Protect",
  unprotectAction: "Unprotect",
  searchAction: "Search",
  classes: [
    {
      className: "ch.kyos.Contact",
      description: "Reference contact record used by the demo configuration.",
      properties: [
        { propertyName: "emailAddress", technique: "email tokenization (reversible)" },
        { propertyName: "phoneNumber", technique: "E.164 phone tokenization (reversible)" },
        { propertyName: "creditCard", technique: "AES deterministic encryption + wrap (reversible)" },
        { propertyName: "unstructuredDocument", technique: "AES encryption of free text/base64 (reversible)" },
      ],
    },
  ],
  roles: [
    { role: "R_MANAGER", summary: "Transform: may protect and unprotect to cleartext." },
    { role: "R_OPERATOR", summary: "Unprotect-then-mask: sees a masked partial value only." },
    { role: "R_ADMINISTRATOR", summary: "Read: receives the stored protected value, cannot unprotect." },
    { role: "R_GUEST", summary: "Read: receives the stored protected value, cannot unprotect." },
  ],
};

export function loadDataModel(env = process.env): DataModel {
  const path = env.KUSTODYAN_DATA_MODEL;
  if (!path) return DEFAULT_MODEL;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8"));
    return { ...DEFAULT_MODEL, ...raw };
  } catch (e) {
    // Fall back to default but don't crash the server over a bad manifest.
    process.stderr.write(`[kustodyan-mcp] could not read KUSTODYAN_DATA_MODEL=${path}: ${e}\n`);
    return DEFAULT_MODEL;
  }
}

export function knownProperty(model: DataModel, className: string, propertyName: string): boolean {
  const c = model.classes.find((c) => c.className === className);
  if (!c) return false;
  return c.properties.some((p) => p.propertyName === propertyName);
}
