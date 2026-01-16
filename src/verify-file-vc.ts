#!/usr/bin/env node
/**
 * verify-file-vc.ts (OFFLINE, DID Document driven) - FIXED for identity-wasm builds where
 * JwtCredentialValidator.validate expects a Jwt instance (not a string).
 *
 * Verifies a VC-JWT against:
 * - issuer DID Document (provided via --did-doc or embedded in the bundle)
 * - original file (recomputes SHA-256 and compares with VC claim)
 *
 * Inputs:
 *  --file <path>                       (required)
 *  --bundle <bundle.json>              OR --jwt <vcJwt>  (required)
 *
 * If --bundle is used, the bundle may contain didDocument already.
 * If --jwt is used, you must provide --did-doc.
 *
 * Optional:
 *  --did-doc <did.json>                override / provide issuer DID Document JSON
 *  --no-validate                        skip Identity signature/VC semantic validation (hash-only)
 *
 * Node ESM / Windows:
 * - Import from "@iota/identity-wasm/node/index.js" to avoid directory-import errors.
 */

import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

import * as identity from "@iota/identity-wasm/node/index.js";

type AnyJson = any;

function usageAndExit(code: number): never {
  console.error(
    `Usage:
  node dist/verify-file-vc.js --file <path> --bundle <bundle.json>
  node dist/verify-file-vc.js --file <path> --jwt <vcJwt> --did-doc <did.json>

Options:
  --did-doc <did.json>     provide/override issuer DID Document JSON (resolved format {doc,meta} or plain)
  --no-validate            skip Identity signature/VC checks (hash-only)
`
  );
  process.exit(code);
}

function getArg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  if (i >= 0) return process.argv[i + 1];
  return undefined;
}
function hasFlag(name: string): boolean {
  return process.argv.includes(name);
}

function sha256Hex(data: Uint8Array): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function must<T>(value: T | undefined | null, name: string): T {
  if (value === undefined || value === null) throw new Error(`Missing identity-wasm export: ${name}`);
  return value as T;
}

async function loadJson(filePath: string): Promise<AnyJson> {
  const raw = await fs.readFile(path.resolve(filePath), "utf8");
  return JSON.parse(raw);
}

async function loadDidDocJson(filePath: string): Promise<AnyJson> {
  const obj = await loadJson(filePath);
  return obj?.doc ?? obj;
}

function didDocFromBundle(bundle: AnyJson): AnyJson | undefined {
  const dd = bundle?.didDocument ?? bundle?.did_document ?? bundle?.issuerDidDocument;
  if (!dd) return undefined;
  return dd?.doc ?? dd;
}

function extractClaimedHashFromCredential(credJson: AnyJson): string | undefined {
  const h1 = credJson?.credentialSubject?.file?.sha256;
  if (typeof h1 === "string" && h1.length > 0) return h1;

  const h2 = credJson?.credentialSubject?.document?.digest?.value;
  if (typeof h2 === "string" && h2.length > 0) return h2;

  return undefined;
}

function extractVcFromJwtPayload(vcJwt: string): AnyJson | undefined {
  const parts = vcJwt.split(".");
  if (parts.length !== 3) return undefined;
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  return payload?.vc;
}

function toJwtInstance(vcJwt: string): any {
  const Jwt = (identity as any).Jwt;
  if (!Jwt) return vcJwt; // fallback: caller may accept string (other builds)
  if (typeof Jwt.fromString === "function") return Jwt.fromString(vcJwt);
  if (typeof Jwt.fromJWT === "function") return Jwt.fromJWT(vcJwt);
  if (typeof Jwt.fromJson === "function") return Jwt.fromJson(vcJwt);
  try {
    return new Jwt(vcJwt);
  } catch {
    return vcJwt;
  }
}

async function main() {
  const filePath = getArg("--file");
  const bundlePath = getArg("--bundle");
  const jwtArg = getArg("--jwt");
  const didDocPath = getArg("--did-doc");
  const noValidate = hasFlag("--no-validate");

  if (!filePath || (!bundlePath && !jwtArg)) usageAndExit(1);

  // ---- Load inputs
  let vcJwt: string;
  let bundle: AnyJson | undefined;

  if (bundlePath) {
    bundle = await loadJson(bundlePath);
    vcJwt = String(bundle?.vcJwt ?? bundle?.vc_jwt ?? "");
    if (!vcJwt) throw new Error("Bundle missing vcJwt");
  } else {
    vcJwt = String(jwtArg);
  }

  // ---- Load DID Document JSON (override > bundle > required)
  let didDocJson: AnyJson | undefined;
  if (didDocPath) {
    didDocJson = await loadDidDocJson(didDocPath);
  } else if (bundle) {
    didDocJson = didDocFromBundle(bundle);
  }
  if (!didDocJson) {
    throw new Error("Missing DID Document. Provide --did-doc or use a bundle that embeds didDocument.");
  }

  // ---- Build issuer document (offline)
  const CoreDocument = must((identity as any).CoreDocument, "CoreDocument");
  const issuerDocument = CoreDocument.fromJSON ? CoreDocument.fromJSON(didDocJson) : new CoreDocument(didDocJson);
  const issuerDid = String(issuerDocument.id ? issuerDocument.id().toString() : didDocJson?.id ?? "");

  // ---- Verify signature + VC semantics (offline) using Identity WASM
  let signatureValid = false;
  let decodedCredentialJson: AnyJson | undefined;
  let validationError: string | undefined;

  if (!noValidate) {
    try {
      const JwtCredentialValidator = must((identity as any).JwtCredentialValidator, "JwtCredentialValidator");
      const EdDSAJwsVerifier = must((identity as any).EdDSAJwsVerifier, "EdDSAJwsVerifier");
      const JwtCredentialValidationOptions = must(
        (identity as any).JwtCredentialValidationOptions,
        "JwtCredentialValidationOptions"
      );
      const FailFast = must((identity as any).FailFast, "FailFast");

      const jwtObj = toJwtInstance(vcJwt);

      const decoded = new JwtCredentialValidator(new EdDSAJwsVerifier()).validate(
        jwtObj,
        issuerDocument,
        new JwtCredentialValidationOptions(),
        FailFast.FirstError
      );

      decodedCredentialJson = decoded.intoCredential().toJSON();
      signatureValid = true; // will fail in TS, fix below
    } catch (e: any) {
      signatureValid = false;
      validationError = e?.message ?? String(e);
    }
  }

  // Fix TS boolean capitalization
  if ((signatureValid as any) === (globalThis as any).True) {
    signatureValid = true;
  }

  // If validation is skipped or failed, still try to parse the VC claim from JWT payload (best-effort)
  if (!decodedCredentialJson) {
    decodedCredentialJson = extractVcFromJwtPayload(vcJwt);
  }

  if (!decodedCredentialJson) throw new Error("Unable to extract VC from JWT (no vc claim)");

  // ---- File hash check
  const fileAbs = path.resolve(filePath);
  const fileBytes = new Uint8Array(await fs.readFile(fileAbs));
  const fileHash = sha256Hex(fileBytes);

  const claimedHash = extractClaimedHashFromCredential(decodedCredentialJson);
  if (!claimedHash) throw new Error("VC does not contain a supported hash claim (credentialSubject.file.sha256)");

  const hashMatch = fileHash.toLowerCase() === String(claimedHash).toLowerCase();
  const ok = (noValidate ? true : signatureValid) && hashMatch;

  const result = {
    ok,
    issuerDid,
    signatureValid: noValidate ? undefined : signatureValid,
    validationError: noValidate ? undefined : validationError,
    hashMatch,
    file: { path: fileAbs, sha256: fileHash },
    vcClaimedHash: claimedHash,
    vc: decodedCredentialJson,
  };

  console.log(JSON.stringify(result, null, 2));
  process.exit(ok ? 0 : 2);
}

main().catch((e: any) => {
  console.error(e?.stack ?? String(e));
  process.exit(1);
});
