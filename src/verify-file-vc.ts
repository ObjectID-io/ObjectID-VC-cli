// src/verify-file-vc.ts

import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import * as ed25519 from "@noble/ed25519";

function usageAndExit(code: number): never {
  console.error(
    `Usage:
  node dist/verify-file-vc.js --bundle <bundle.json> --file <path>
or:
  node dist/verify-file-vc.js --jwt <vcJwt> --file <path>

Options:
  --bundle <path>   Bundle produced by issuer (contains vcJwt/did/etc)
  --jwt <string>    VC-JWT string (alternative to --bundle)
  --file <path>     File to hash and compare (required)
  --now <iso>       Override current time (ISO 8601), optional
`
  );
  process.exit(code);
}

function getArg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  if (i >= 0) return process.argv[i + 1];
  return undefined;
}

function b64urlToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
function b64urlToJson(s: string): any {
  return JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
}
function sha256Hex(data: Uint8Array): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * Extract public JWK from did:jwk:<base64url(json)>
 * did:jwk method id is base64url of a JWK JSON. We decode and read 'x' (Ed25519).
 */
function publicKeyFromDidJwk(did: string): Uint8Array {
  if (!did.startsWith("did:jwk:")) throw new Error(`Unsupported DID (expected did:jwk): ${did}`);
  const enc = did.slice("did:jwk:".length);
  const jwkJson = JSON.parse(Buffer.from(enc, "base64url").toString("utf8"));
  if (jwkJson?.kty !== "OKP" || jwkJson?.crv !== "Ed25519" || typeof jwkJson?.x !== "string") {
    throw new Error("Invalid did:jwk JWK payload (expected OKP/Ed25519 with x)");
  }
  return b64urlToBytes(jwkJson.x);
}

function parseVcFromJwtPayload(payload: any): any {
  // VC-JWT commonly stores the VC object in `vc`
  const vc = payload?.vc ?? payload?.["https://www.w3.org/2018/credentials/v1"]?.vc;
  if (!vc) throw new Error("JWT payload does not contain `vc` claim");
  return vc;
}

function getIssuerDidFromJwt(payload: any, vc: any): string {
  // Prefer JWT `iss`, fallback to vc.issuer
  const iss = payload?.iss ?? vc?.issuer;
  if (!iss || typeof iss !== "string") throw new Error("Missing issuer DID (iss / vc.issuer)");
  return iss;
}

function checkTimeClaims(payload: any, nowSec: number): { ok: boolean; reason?: string } {
  // Standard JWT time claims: nbf, exp
  if (typeof payload?.nbf === "number" && nowSec < payload.nbf) {
    return { ok: false, reason: `nbf not satisfied (now=${nowSec} < nbf=${payload.nbf})` };
  }
  if (typeof payload?.exp === "number" && nowSec >= payload.exp) {
    return { ok: false, reason: `token expired (now=${nowSec} >= exp=${payload.exp})` };
  }
  return { ok: true };
}

async function main() {
  const bundlePath = getArg("--bundle");
  const jwtArg = getArg("--jwt");
  const filePath = getArg("--file");
  const nowIso = getArg("--now");

  if (!filePath || (!bundlePath && !jwtArg)) usageAndExit(1);

  // Load VC-JWT
  let vcJwt: string;
  let bundle: any | undefined;

  if (bundlePath) {
    const raw = await fs.readFile(path.resolve(bundlePath), "utf8");
    bundle = JSON.parse(raw);
    vcJwt = String(bundle?.vcJwt ?? "");
    if (!vcJwt) throw new Error("Bundle missing `vcJwt`");
  } else {
    vcJwt = String(jwtArg);
  }

  // Parse JWT parts
  const parts = vcJwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format (expected 3 parts)");
  const [h64, p64, s64] = parts;

  const header = b64urlToJson(h64);
  const payload = b64urlToJson(p64);
  const signature = b64urlToBytes(s64);

  if (header?.alg !== "EdDSA") throw new Error(`Unsupported alg: ${header?.alg}`);

  // Extract VC and issuer DID
  const vc = parseVcFromJwtPayload(payload);
  const issuerDid = getIssuerDidFromJwt(payload, vc);

  // Verify signature (JWS signing input is ASCII of "<h64>.<p64>")
  const signingInput = new TextEncoder().encode(`${h64}.${p64}`);
  const pubKey = publicKeyFromDidJwk(issuerDid);

  const signatureValid = await ed25519.verify(signature, signingInput, pubKey);

  // Verify file hash matches VC subject
  const fileAbs = path.resolve(filePath);
  const fileBytes = new Uint8Array(await fs.readFile(fileAbs));
  const fileHash = sha256Hex(fileBytes);

  const claimedHash = vc?.credentialSubject?.file?.sha256 ?? vc?.credentialSubject?.document?.digest?.value ?? null;

  if (!claimedHash || typeof claimedHash !== "string") {
    throw new Error(
      "VC does not contain a supported hash field (credentialSubject.file.sha256 or document.digest.value)"
    );
  }

  const hashMatch = fileHash.toLowerCase() === claimedHash.toLowerCase();

  // Time validation (optional)
  const nowSec = nowIso ? Math.floor(new Date(nowIso).getTime() / 1000) : Math.floor(Date.now() / 1000);
  const time = checkTimeClaims(payload, nowSec);

  const result = {
    ok: signatureValid && hashMatch && time.ok,
    signatureValid,
    hashMatch,
    timeValid: time.ok,
    timeReason: time.ok ? undefined : time.reason,
    issuerDid,
    header,
    // Minimal useful payload fields
    claims: {
      iss: payload?.iss,
      sub: payload?.sub,
      nbf: payload?.nbf,
      exp: payload?.exp,
    },
    file: {
      path: fileAbs,
      sha256: fileHash,
    },
    vcClaimedHash: claimedHash,
  };

  console.log(JSON.stringify(result, null, 2));

  if (!result.ok) process.exit(2);
}

main().catch((e) => {
  console.error(e?.stack ?? String(e));
  process.exit(1);
});
