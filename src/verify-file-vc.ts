#!/usr/bin/env node
/**
 * verify-file-vc.ts
 *
 * Verifies:
 * 1) VC-JWT signature + VC semantics (IOTA Identity WASM)
 * 2) File hash matches VC claim (SHA-256)
 * 3) Fetches an Object from IOTA via getObject (RPC)
 * 4) Extracts owner DID from object fields (owner_did / ownerDid / ownerDID)
 * 5) Resolves the owner DID Document from IOTA (RPC)
 * 6) Checks for LinkedDomains service (DLVC signal)
 * 7) Validates DLVC and prints linked domain(s)
 *
 * Notes:
 * - ONLINE is required for resolving DIDs + getObject.
 * - Works with identity-wasm "node" entrypoint.
 *
 * Windows ESM:
 * - Import from "@iota/identity-wasm/node/index.js" (not "@iota/identity-wasm/node").
 */

import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

import { IotaClient, type IotaObjectData, type IotaObjectResponse } from "@iota/iota-sdk/client";
import * as identity from "@iota/identity-wasm/node/index.js";

type Json = Record<string, unknown>;
type DidDocJson = Json & { id?: string; service?: unknown; verificationMethod?: unknown; alsoKnownAs?: unknown };

function usageAndExit(code: number): never {
  console.error(
    `Usage:
  node dist/verify-file-vc.js --file <path> --bundle <bundle.json> --rpc <url> [--oid <objectId>]
  node dist/verify-file-vc.js --file <path> --jwt <vcJwt> --rpc <url> [--oid <objectId>]

Options:
  --rpc <url>                 IOTA RPC endpoint (required)
  --bundle <bundle.json>      bundle produced by issuer (contains vcJwt)
  --jwt <vcJwt>               VC-JWT string (alternative to --bundle)
  --oid <objectId>            object id to fetch (0x...)
  --dlvc-proxy <url>          optional proxy (POST {did,network} -> {didConfiguration})
  --no-validate               skip VC-JWT signature/semantic validation (hash-only)
`
  );
  process.exit(code);
}

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
function flag(name: string): boolean {
  return process.argv.includes(name);
}

function sha256Hex(data: Uint8Array): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

async function readJsonFile(filePath: string): Promise<unknown> {
  const raw = await fs.readFile(path.resolve(filePath), "utf8");
  return JSON.parse(raw) as unknown;
}

function ensureRecord(v: unknown, name: string): Json {
  if (!v || typeof v !== "object" || Array.isArray(v)) {
    throw new Error(`${name} must be an object`);
  }
  return v as Json;
}

function must<T>(value: T | undefined | null, name: string): T {
  if (value === undefined || value === null) {
    throw new Error(`Missing required export: ${name}`);
  }
  return value;
}

function extractIssFromJwt(jwt: string): string {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as unknown;
  const p = ensureRecord(payload, "JWT payload");
  const iss = p["iss"];
  if (typeof iss !== "string" || !iss.startsWith("did:")) throw new Error("JWT payload missing valid 'iss'");
  return iss;
}

function extractVcFromJwtPayload(jwt: string): Json {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as unknown;
  const p = ensureRecord(payload, "JWT payload");
  const vc = p["vc"];
  return ensureRecord(vc, "JWT payload.vc");
}

function extractClaimedFileHash(vc: Json): string {
  const cs = ensureRecord(vc["credentialSubject"], "vc.credentialSubject");
  const file = ensureRecord(cs["file"], "vc.credentialSubject.file");
  const h = file["sha256"];
  if (typeof h !== "string" || h.length === 0) throw new Error("VC missing credentialSubject.file.sha256");
  return h;
}

function toJwtInstance(jwtStr: string): unknown {
  const JwtCtor = (identity as unknown as Json)["Jwt"];
  if (!JwtCtor) return jwtStr;

  const JwtObj = JwtCtor as unknown;
  if (typeof JwtObj !== "function" && typeof JwtObj !== "object") return jwtStr;

  // try static fromString
  const fromString = (JwtObj as Json)["fromString"];
  if (typeof fromString === "function") {
    return (fromString as (s: string) => unknown)(jwtStr);
  }

  // try constructor
  try {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call
    return new (JwtCtor as unknown as { new (s: string): unknown })(jwtStr);
  } catch {
    return jwtStr;
  }
}

async function resolveDidDocument(rpcUrl: string, did: string): Promise<unknown> {
  const client = new IotaClient({ url: rpcUrl });

  // IdentityClientReadOnly.create(client)
  const roCtor = (identity as unknown as Json)["IdentityClientReadOnly"];
  if (!roCtor || typeof roCtor !== "function") {
    throw new Error("identity-wasm missing IdentityClientReadOnly");
  }
  const create = (roCtor as unknown as Json)["create"];
  if (typeof create !== "function") {
    throw new Error("IdentityClientReadOnly.create is not available");
  }
  const ro = await (create as (c: IotaClient) => Promise<unknown>)(client);

  // build DID instance if possible, else pass string
  let didArg: unknown = did;

  const IotaDID = (identity as unknown as Json)["IotaDID"];
  if (IotaDID && (typeof IotaDID === "function" || typeof IotaDID === "object")) {
    const fromString = (IotaDID as Json)["fromString"];
    const parse = (IotaDID as Json)["parse"];
    if (typeof fromString === "function") {
      didArg = (fromString as (s: string) => unknown)(did);
    } else if (typeof parse === "function") {
      didArg = (parse as (s: string) => unknown)(did);
    }
  }

  const roObj = ro as unknown as { resolveDid: (d: unknown) => Promise<unknown> };
  return await roObj.resolveDid(didArg);
}

function didDocToJson(resolved: unknown): DidDocJson {
  // resolved can be:
  // - { doc, meta }
  // - a Document instance with toJSON() returning either plain DID doc OR {doc,meta}
  // - a plain DID doc object
  if (!resolved || typeof resolved !== "object") {
    throw new Error("Unexpected DID resolution result");
  }

  const r = resolved as Json;

  // { doc, meta } format already
  if (r["doc"] && typeof r["doc"] === "object") {
    return ensureRecord(r["doc"], "resolved.doc") as DidDocJson;
  }

  // Document instance (WASM). IMPORTANT: call toJSON with correct `this`.
  if (typeof (resolved as any).toJSON === "function") {
    const j = (resolved as any).toJSON();
    const jr = ensureRecord(j, "resolved.toJSON()");
    if (jr["doc"] && typeof jr["doc"] === "object") {
      return ensureRecord(jr["doc"], "resolved.toJSON().doc") as DidDocJson;
    }
    return jr as DidDocJson;
  }

  // already a plain object
  return ensureRecord(resolved, "resolved") as DidDocJson;
}

async function getObject(client: IotaClient, id: string): Promise<IotaObjectData> {
  const { data } = await client.getObject({
    id,
    options: {
      showType: true,
      showOwner: true,
      showPreviousTransaction: false,
      showDisplay: true,
      showContent: true,
      showBcs: true,
      showStorageRebate: false,
    },
  });
  if (!data) throw new Error("Object not found");
  return data as IotaObjectData;
}

function extractFields(obj: IotaObjectData): Record<string, unknown> | undefined {
  // SDK structure: data.content.fields
  const content = (obj as unknown as Json)["content"];
  if (!content || typeof content !== "object") return undefined;
  const fields = (content as Json)["fields"];
  if (!fields || typeof fields !== "object" || Array.isArray(fields)) return undefined;
  return fields as Record<string, unknown>;
}

function extractOwnerDidFromFields(fields: Record<string, unknown>): string | undefined {
  const candidates = [fields["owner_did"], fields["ownerDid"], fields["ownerDID"], fields["owner"]].filter(
    (v) => typeof v === "string"
  ) as string[];
  for (const c of candidates) {
    if (c.startsWith("did:")) return c;
  }
  return undefined;
}

function extractObjectIdFromIssuerDidDoc(didDoc: DidDocJson): string | undefined {
  // alsoKnownAs: ["urn:oid:testnet:0x..."]
  const aka = didDoc["alsoKnownAs"];
  if (Array.isArray(aka)) {
    for (const v of aka) {
      if (typeof v !== "string") continue;
      const m = v.match(/urn:oid:(?:testnet:|mainnet:|iota:)?(0x[0-9a-fA-F]{16,})/);
      if (m?.[1]) return m[1];
    }
  }

  // serviceEndpoint URL: https://.../oid=0x...
  const service = didDoc["service"];
  if (Array.isArray(service)) {
    for (const s of service) {
      if (!s || typeof s !== "object") continue;
      const se = (s as Json)["serviceEndpoint"];
      const endpoints: string[] =
        typeof se === "string" ? [se] : Array.isArray(se) ? se.filter((x): x is string => typeof x === "string") : [];
      for (const ep of endpoints) {
        try {
          const u = new URL(ep);
          const oid = u.searchParams.get("oid");
          if (oid && oid.startsWith("0x")) return oid;
        } catch {}
      }
    }
  }
  return undefined;
}

function extractLinkedDomains(didDoc: DidDocJson): string[] {
  const service = didDoc["service"];
  if (!Array.isArray(service)) return [];
  const out: string[] = [];
  for (const s of service) {
    if (!s || typeof s !== "object") continue;
    const t = (s as Json)["type"];
    const typeStr = Array.isArray(t)
      ? t.filter((x): x is string => typeof x === "string").join(",")
      : typeof t === "string"
      ? t
      : "";
    if (!typeStr.includes("LinkedDomains")) continue;

    const se = (s as Json)["serviceEndpoint"];
    const endpoints: string[] =
      typeof se === "string" ? [se] : Array.isArray(se) ? se.filter((x): x is string => typeof x === "string") : [];
    for (const ep of endpoints) {
      try {
        const u = new URL(ep);
        out.push(u.origin + "/");
      } catch {}
    }
  }
  return Array.from(new Set(out));
}

function didNetwork(did: string): "testnet" | "mainnet" {
  return did.includes(":testnet:") ? "testnet" : "mainnet";
}

async function fetchDidConfiguration(origin: string): Promise<unknown> {
  const url = origin.replace(/\/$/, "/") + ".well-known/did-configuration.json";
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching did-configuration`);
  return (await res.json()) as unknown;
}

async function fetchDidConfigurationViaProxy(proxyUrl: string, did: string, network: string): Promise<unknown> {
  const res = await fetch(proxyUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ did, network }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from proxy`);
  const j = (await res.json()) as unknown;
  const obj = ensureRecord(j, "proxy response");
  const dc = obj["didConfiguration"];
  return dc ?? j;
}

async function validateDlvc(
  ownerDid: string,
  ownerResolved: unknown,
  ownerDidDocJson: DidDocJson,
  proxyUrl?: string
): Promise<{ valid: boolean; domains: string[]; error?: string }> {
  const domains = extractLinkedDomains(ownerDidDocJson);
  if (domains.length === 0)
    return { valid: false, domains: [], error: "No LinkedDomains service in owner DID Document" };

  const DomainLinkageConfiguration = (identity as unknown as Json)["DomainLinkageConfiguration"];
  const JwtDomainLinkageValidator = (identity as unknown as Json)["JwtDomainLinkageValidator"];
  const EdDSAJwsVerifier = (identity as unknown as Json)["EdDSAJwsVerifier"];
  const JwtCredentialValidationOptions = (identity as unknown as Json)["JwtCredentialValidationOptions"];
  if (
    !DomainLinkageConfiguration ||
    !JwtDomainLinkageValidator ||
    !EdDSAJwsVerifier ||
    !JwtCredentialValidationOptions
  ) {
    return { valid: false, domains, error: "identity-wasm missing DLVC validator exports" };
  }

  // ownerResolved must be a Document instance for validateLinkage (we pass the resolved object from identity)
  const ownerDoc = ownerResolved;

  for (const origin of domains) {
    try {
      const cfgJson = proxyUrl
        ? await fetchDidConfigurationViaProxy(proxyUrl, ownerDid, didNetwork(ownerDid))
        : await fetchDidConfiguration(origin);

      const cfg = (DomainLinkageConfiguration as Json)["fromJSON"];
      if (typeof cfg !== "function") throw new Error("DomainLinkageConfiguration.fromJSON not available");
      const cfgObj = (cfg as (j: unknown) => unknown)(cfgJson);

      const validator = new (JwtDomainLinkageValidator as unknown as {
        new (v: unknown): { validateLinkage: (...args: unknown[]) => void };
      })(new (EdDSAJwsVerifier as unknown as { new (): unknown })());

      // DID linked url: any LinkedDomains serviceEndpoint string
      const didLinkedUrl = origin; // good enough for validator in most builds
      const opts = new (JwtCredentialValidationOptions as unknown as { new (): unknown })();

      validator.validateLinkage(ownerDoc, cfgObj, didLinkedUrl, opts);
      return { valid: true, domains };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      // try next domain
      if (origin === domains[domains.length - 1]) return { valid: false, domains, error: msg };
    }
  }

  return { valid: false, domains, error: "DLVC validation failed" };
}

async function main(): Promise<void> {
  const filePath = arg("--file");
  const bundlePath = arg("--bundle");
  const jwtStr = arg("--jwt");
  const rpcUrl = arg("--rpc");
  const oidArg = arg("--oid");
  const proxyUrl = arg("--dlvc-proxy");
  const noValidate = flag("--no-validate");

  if (!filePath || !rpcUrl || (!bundlePath && !jwtStr)) usageAndExit(1);

  // VC-JWT
  let vcJwt: string;
  let bundleJson: Json | undefined;

  if (bundlePath) {
    const b = await readJsonFile(bundlePath);
    bundleJson = ensureRecord(b, "bundle");
    const v = bundleJson["vcJwt"];
    if (typeof v !== "string" || v.length === 0) throw new Error("Bundle missing vcJwt");
    vcJwt = v;
  } else {
    vcJwt = String(jwtStr);
  }

  const issuerDid = extractIssFromJwt(vcJwt);

  // Resolve issuer DID doc (ONLINE, because you said issuer DID isn't in bundle)
  const issuerResolved = await resolveDidDocument(rpcUrl, issuerDid);
  const issuerDidDocJson = didDocToJson(issuerResolved);

  // Validate VC-JWT signature + semantics
  let signatureValid: boolean | undefined = undefined;
  let validationError: string | undefined = undefined;
  let vcJson: Json;

  if (!noValidate) {
    try {
      const JwtCredentialValidator = must(
        (identity as unknown as Json)["JwtCredentialValidator"],
        "JwtCredentialValidator"
      );
      const EdDSAJwsVerifier = must((identity as unknown as Json)["EdDSAJwsVerifier"], "EdDSAJwsVerifier");
      const JwtCredentialValidationOptions = must(
        (identity as unknown as Json)["JwtCredentialValidationOptions"],
        "JwtCredentialValidationOptions"
      );
      const FailFast = must((identity as unknown as Json)["FailFast"], "FailFast");

      const jwtObj = toJwtInstance(vcJwt);

      const decoded = new (JwtCredentialValidator as unknown as {
        new (v: unknown): { validate: (...args: unknown[]) => { intoCredential: () => { toJSON: () => unknown } } };
      })(new (EdDSAJwsVerifier as unknown as { new (): unknown })()).validate(
        jwtObj,
        issuerResolved,
        new (JwtCredentialValidationOptions as unknown as { new (): unknown })(),
        (FailFast as Json)["FirstError"]
      );

      const decodedJson = decoded.intoCredential().toJSON();
      vcJson = ensureRecord(decodedJson, "decoded VC");
      signatureValid = true;
    } catch (e: unknown) {
      signatureValid = false;
      validationError = e instanceof Error ? e.message : String(e);
      vcJson = extractVcFromJwtPayload(vcJwt);
    }
  } else {
    vcJson = extractVcFromJwtPayload(vcJwt);
  }

  // File hash
  const fileAbs = path.resolve(filePath);
  const fileBytes = new Uint8Array(await fs.readFile(fileAbs));
  const fileHash = sha256Hex(fileBytes);
  const claimedHash = extractClaimedFileHash(vcJson);
  const hashMatch = fileHash.toLowerCase() === claimedHash.toLowerCase();

  // Object fetch
  const iota = new IotaClient({ url: rpcUrl });
  const oid = oidArg ?? extractObjectIdFromIssuerDidDoc(issuerDidDocJson);
  let object: IotaObjectData | undefined = undefined;
  let ownerDid: string | undefined = undefined;

  if (oid) {
    object = await getObject(iota, oid);
    const fields = extractFields(object);
    if (fields) ownerDid = extractOwnerDidFromFields(fields);
  }

  // Resolve owner DID + DLVC
  let ownerDidDocJson: DidDocJson | undefined = undefined;
  let dlvc: { valid: boolean; domains: string[]; error?: string } | undefined = undefined;

  if (ownerDid) {
    const ownerResolved = await resolveDidDocument(rpcUrl, ownerDid);
    ownerDidDocJson = didDocToJson(ownerResolved);
    dlvc = await validateDlvc(ownerDid, ownerResolved, ownerDidDocJson, proxyUrl);
  }

  const ok = (noValidate ? true : signatureValid === true) && hashMatch && (ownerDid ? dlvc?.valid === true : true);

  const result = {
    ok,
    vc: {
      issuerDid,
      signatureValid: noValidate ? undefined : signatureValid,
      validationError: noValidate ? undefined : validationError,
      hashMatch,
      vcClaimedHash: claimedHash,
      file: { path: fileAbs, sha256: fileHash },
    },
    issuerDidDocument: {
      id: issuerDidDocJson.id ?? null,
      alsoKnownAs: issuerDidDocJson.alsoKnownAs ?? null,
      services: issuerDidDocJson.service ?? null,
    },
    object: oid
      ? {
          oid,
          type: object?.type ?? null,
          ownerDid: ownerDid ?? null,
          fields: object ? extractFields(object) ?? null : null,
        }
      : { oid: null, ownerDid: null, note: "Provide --oid or add alsoKnownAs/service in issuer DID doc" },
    owner: ownerDid
      ? {
          did: ownerDid,
          linkedDomains: dlvc?.domains ?? [],
          dlvcValid: dlvc?.valid ?? false,
          dlvcError: dlvc?.error,
        }
      : null,
  };

  console.log(JSON.stringify(result, null, 2));
  process.exit(ok ? 0 : 2);
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.stack : String(e));
  process.exit(1);
});
