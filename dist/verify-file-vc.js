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
import { IotaClient } from "@iota/iota-sdk/client";
import * as identity from "@iota/identity-wasm/node/index.js";
function usageAndExit(code) {
    console.error(`Usage:
  node dist/verify-file-vc.js --file <path> --bundle <bundle.json> --rpc <url> [--oid <objectId>]
  node dist/verify-file-vc.js --file <path> --jwt <vcJwt> --rpc <url> [--oid <objectId>]

Options:
  --rpc <url>                 IOTA RPC endpoint (required)
  --bundle <bundle.json>      bundle produced by issuer (contains vcJwt)
  --jwt <vcJwt>               VC-JWT string (alternative to --bundle)
  --oid <objectId>            object id to fetch (0x...)
  --dlvc-proxy <url>          optional proxy (POST {did,network} -> {didConfiguration})
  --no-validate               skip VC-JWT signature/semantic validation (hash-only)
`);
    process.exit(code);
}
function arg(name) {
    const i = process.argv.indexOf(name);
    return i >= 0 ? process.argv[i + 1] : undefined;
}
function flag(name) {
    return process.argv.includes(name);
}
function sha256Hex(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}
async function readJsonFile(filePath) {
    const raw = await fs.readFile(path.resolve(filePath), "utf8");
    return JSON.parse(raw);
}
function ensureRecord(v, name) {
    if (!v || typeof v !== "object" || Array.isArray(v)) {
        throw new Error(`${name} must be an object`);
    }
    return v;
}
function must(value, name) {
    if (value === undefined || value === null) {
        throw new Error(`Missing required export: ${name}`);
    }
    return value;
}
function extractIssFromJwt(jwt) {
    const parts = jwt.split(".");
    if (parts.length !== 3)
        throw new Error("Invalid JWT format");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    const p = ensureRecord(payload, "JWT payload");
    const iss = p["iss"];
    if (typeof iss !== "string" || !iss.startsWith("did:"))
        throw new Error("JWT payload missing valid 'iss'");
    return iss;
}
function extractVcFromJwtPayload(jwt) {
    const parts = jwt.split(".");
    if (parts.length !== 3)
        throw new Error("Invalid JWT format");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    const p = ensureRecord(payload, "JWT payload");
    const vc = p["vc"];
    return ensureRecord(vc, "JWT payload.vc");
}
function extractClaimedFileHash(vc) {
    const cs = ensureRecord(vc["credentialSubject"], "vc.credentialSubject");
    const file = ensureRecord(cs["file"], "vc.credentialSubject.file");
    const h = file["sha256"];
    if (typeof h !== "string" || h.length === 0)
        throw new Error("VC missing credentialSubject.file.sha256");
    return h;
}
function toJwtInstance(jwtStr) {
    const JwtCtor = identity["Jwt"];
    if (!JwtCtor)
        return jwtStr;
    const JwtObj = JwtCtor;
    if (typeof JwtObj !== "function" && typeof JwtObj !== "object")
        return jwtStr;
    // try static fromString
    const fromString = JwtObj["fromString"];
    if (typeof fromString === "function") {
        return fromString(jwtStr);
    }
    // try constructor
    try {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call
        return new JwtCtor(jwtStr);
    }
    catch {
        return jwtStr;
    }
}
async function resolveDidDocument(rpcUrl, did) {
    const client = new IotaClient({ url: rpcUrl });
    // IdentityClientReadOnly.create(client)
    const roCtor = identity["IdentityClientReadOnly"];
    if (!roCtor || typeof roCtor !== "function") {
        throw new Error("identity-wasm missing IdentityClientReadOnly");
    }
    const create = roCtor["create"];
    if (typeof create !== "function") {
        throw new Error("IdentityClientReadOnly.create is not available");
    }
    const ro = await create(client);
    // build DID instance if possible, else pass string
    let didArg = did;
    const IotaDID = identity["IotaDID"];
    if (IotaDID && (typeof IotaDID === "function" || typeof IotaDID === "object")) {
        const fromString = IotaDID["fromString"];
        const parse = IotaDID["parse"];
        if (typeof fromString === "function") {
            didArg = fromString(did);
        }
        else if (typeof parse === "function") {
            didArg = parse(did);
        }
    }
    const roObj = ro;
    return await roObj.resolveDid(didArg);
}
function didDocToJson(resolved) {
    // resolved can be:
    // - { doc, meta }
    // - a Document instance with toJSON() returning either plain DID doc OR {doc,meta}
    // - a plain DID doc object
    if (!resolved || typeof resolved !== "object") {
        throw new Error("Unexpected DID resolution result");
    }
    const r = resolved;
    // { doc, meta } format already
    if (r["doc"] && typeof r["doc"] === "object") {
        return ensureRecord(r["doc"], "resolved.doc");
    }
    // Document instance (WASM). IMPORTANT: call toJSON with correct `this`.
    if (typeof resolved.toJSON === "function") {
        const j = resolved.toJSON();
        const jr = ensureRecord(j, "resolved.toJSON()");
        if (jr["doc"] && typeof jr["doc"] === "object") {
            return ensureRecord(jr["doc"], "resolved.toJSON().doc");
        }
        return jr;
    }
    // already a plain object
    return ensureRecord(resolved, "resolved");
}
async function getObject(client, id) {
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
    if (!data)
        throw new Error("Object not found");
    return data;
}
function extractFields(obj) {
    // SDK structure: data.content.fields
    const content = obj["content"];
    if (!content || typeof content !== "object")
        return undefined;
    const fields = content["fields"];
    if (!fields || typeof fields !== "object" || Array.isArray(fields))
        return undefined;
    return fields;
}
function extractOwnerDidFromFields(fields) {
    const candidates = [fields["owner_did"], fields["ownerDid"], fields["ownerDID"], fields["owner"]].filter((v) => typeof v === "string");
    for (const c of candidates) {
        if (c.startsWith("did:"))
            return c;
    }
    return undefined;
}
function extractObjectIdFromIssuerDidDoc(didDoc) {
    // alsoKnownAs: ["urn:oid:testnet:0x..."]
    const aka = didDoc["alsoKnownAs"];
    if (Array.isArray(aka)) {
        for (const v of aka) {
            if (typeof v !== "string")
                continue;
            const m = v.match(/urn:oid:(?:testnet:|mainnet:|iota:)?(0x[0-9a-fA-F]{16,})/);
            if (m?.[1])
                return m[1];
        }
    }
    // serviceEndpoint URL: https://.../oid=0x...
    const service = didDoc["service"];
    if (Array.isArray(service)) {
        for (const s of service) {
            if (!s || typeof s !== "object")
                continue;
            const se = s["serviceEndpoint"];
            const endpoints = typeof se === "string" ? [se] : Array.isArray(se) ? se.filter((x) => typeof x === "string") : [];
            for (const ep of endpoints) {
                try {
                    const u = new URL(ep);
                    const oid = u.searchParams.get("oid");
                    if (oid && oid.startsWith("0x"))
                        return oid;
                }
                catch { }
            }
        }
    }
    return undefined;
}
function extractLinkedDomains(didDoc) {
    const service = didDoc["service"];
    if (!Array.isArray(service))
        return [];
    const out = [];
    for (const s of service) {
        if (!s || typeof s !== "object")
            continue;
        const t = s["type"];
        const typeStr = Array.isArray(t)
            ? t.filter((x) => typeof x === "string").join(",")
            : typeof t === "string"
                ? t
                : "";
        if (!typeStr.includes("LinkedDomains"))
            continue;
        const se = s["serviceEndpoint"];
        const endpoints = typeof se === "string" ? [se] : Array.isArray(se) ? se.filter((x) => typeof x === "string") : [];
        for (const ep of endpoints) {
            try {
                const u = new URL(ep);
                out.push(u.origin + "/");
            }
            catch { }
        }
    }
    return Array.from(new Set(out));
}
function didNetwork(did) {
    return did.includes(":testnet:") ? "testnet" : "mainnet";
}
async function fetchDidConfiguration(origin) {
    const url = origin.replace(/\/$/, "/") + ".well-known/did-configuration.json";
    const res = await fetch(url);
    if (!res.ok)
        throw new Error(`HTTP ${res.status} fetching did-configuration`);
    return (await res.json());
}
async function fetchDidConfigurationViaProxy(proxyUrl, did, network) {
    const res = await fetch(proxyUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ did, network }),
    });
    if (!res.ok)
        throw new Error(`HTTP ${res.status} from proxy`);
    const j = (await res.json());
    const obj = ensureRecord(j, "proxy response");
    const dc = obj["didConfiguration"];
    return dc ?? j;
}
async function validateDlvc(ownerDid, ownerResolved, ownerDidDocJson, proxyUrl) {
    const domains = extractLinkedDomains(ownerDidDocJson);
    if (domains.length === 0)
        return { valid: false, domains: [], error: "No LinkedDomains service in owner DID Document" };
    const DomainLinkageConfiguration = identity["DomainLinkageConfiguration"];
    const JwtDomainLinkageValidator = identity["JwtDomainLinkageValidator"];
    const EdDSAJwsVerifier = identity["EdDSAJwsVerifier"];
    const JwtCredentialValidationOptions = identity["JwtCredentialValidationOptions"];
    if (!DomainLinkageConfiguration ||
        !JwtDomainLinkageValidator ||
        !EdDSAJwsVerifier ||
        !JwtCredentialValidationOptions) {
        return { valid: false, domains, error: "identity-wasm missing DLVC validator exports" };
    }
    // ownerResolved must be a Document instance for validateLinkage (we pass the resolved object from identity)
    const ownerDoc = ownerResolved;
    for (const origin of domains) {
        try {
            const cfgJson = proxyUrl
                ? await fetchDidConfigurationViaProxy(proxyUrl, ownerDid, didNetwork(ownerDid))
                : await fetchDidConfiguration(origin);
            const cfg = DomainLinkageConfiguration["fromJSON"];
            if (typeof cfg !== "function")
                throw new Error("DomainLinkageConfiguration.fromJSON not available");
            const cfgObj = cfg(cfgJson);
            const validator = new JwtDomainLinkageValidator(new EdDSAJwsVerifier());
            // DID linked url: any LinkedDomains serviceEndpoint string
            const didLinkedUrl = origin; // good enough for validator in most builds
            const opts = new JwtCredentialValidationOptions();
            validator.validateLinkage(ownerDoc, cfgObj, didLinkedUrl, opts);
            return { valid: true, domains };
        }
        catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            // try next domain
            if (origin === domains[domains.length - 1])
                return { valid: false, domains, error: msg };
        }
    }
    return { valid: false, domains, error: "DLVC validation failed" };
}
async function main() {
    const filePath = arg("--file");
    const bundlePath = arg("--bundle");
    const jwtStr = arg("--jwt");
    const rpcUrl = arg("--rpc");
    const oidArg = arg("--oid");
    const proxyUrl = arg("--dlvc-proxy");
    const noValidate = flag("--no-validate");
    if (!filePath || !rpcUrl || (!bundlePath && !jwtStr))
        usageAndExit(1);
    // VC-JWT
    let vcJwt;
    let bundleJson;
    if (bundlePath) {
        const b = await readJsonFile(bundlePath);
        bundleJson = ensureRecord(b, "bundle");
        const v = bundleJson["vcJwt"];
        if (typeof v !== "string" || v.length === 0)
            throw new Error("Bundle missing vcJwt");
        vcJwt = v;
    }
    else {
        vcJwt = String(jwtStr);
    }
    const issuerDid = extractIssFromJwt(vcJwt);
    // Resolve issuer DID doc (ONLINE, because you said issuer DID isn't in bundle)
    const issuerResolved = await resolveDidDocument(rpcUrl, issuerDid);
    const issuerDidDocJson = didDocToJson(issuerResolved);
    // Validate VC-JWT signature + semantics
    let signatureValid = undefined;
    let validationError = undefined;
    let vcJson;
    if (!noValidate) {
        try {
            const JwtCredentialValidator = must(identity["JwtCredentialValidator"], "JwtCredentialValidator");
            const EdDSAJwsVerifier = must(identity["EdDSAJwsVerifier"], "EdDSAJwsVerifier");
            const JwtCredentialValidationOptions = must(identity["JwtCredentialValidationOptions"], "JwtCredentialValidationOptions");
            const FailFast = must(identity["FailFast"], "FailFast");
            const jwtObj = toJwtInstance(vcJwt);
            const decoded = new JwtCredentialValidator(new EdDSAJwsVerifier()).validate(jwtObj, issuerResolved, new JwtCredentialValidationOptions(), FailFast["FirstError"]);
            const decodedJson = decoded.intoCredential().toJSON();
            vcJson = ensureRecord(decodedJson, "decoded VC");
            signatureValid = true;
        }
        catch (e) {
            signatureValid = false;
            validationError = e instanceof Error ? e.message : String(e);
            vcJson = extractVcFromJwtPayload(vcJwt);
        }
    }
    else {
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
    let object = undefined;
    let ownerDid = undefined;
    if (oid) {
        object = await getObject(iota, oid);
        const fields = extractFields(object);
        if (fields)
            ownerDid = extractOwnerDidFromFields(fields);
    }
    // Resolve owner DID + DLVC
    let ownerDidDocJson = undefined;
    let dlvc = undefined;
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
main().catch((e) => {
    console.error(e instanceof Error ? e.stack : String(e));
    process.exit(1);
});
