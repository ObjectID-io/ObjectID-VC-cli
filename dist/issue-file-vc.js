#!/usr/bin/env node
/**
 * issue-file-vc.ts (OFFLINE, DID extracted from DID Document produced by ObjectID)
 *
 * Signs a VC-JWT attesting a file SHA-256 hash, using an EXISTING verificationMethod
 * from a provided DID Document JSON.
 *
 * Inputs:
 *  --file <path>
 *  --seed <seedHex>            (64 hex chars, EXACT same value used when creating the DID)
 *  --did-doc <did.json>        (resolved DID doc JSON: either {doc, meta} or doc-only)
 *
 * Optional:
 *  --method-id <full|#frag|frag>   choose a specific verificationMethod (default: first)
 *  --out <dir|file.json>           default "."; if ends with .json -> exact output file, else directory
 *  --vc-id <string>                default urn:uuid:...
 *  --no-validate                   skip local self-validation
 *
 * IMPORTANT:
 * - Key derivation matches your DID creation code:
 *     Ed25519Keypair.deriveKeypairFromSeed(seedHex)
 * - JWK.d uses the raw 32-byte secretKey extracted from keypair using decodeIotaPrivateKey().
 *
 * Node ESM / Windows:
 * - Import from "@iota/identity-wasm/node/index.js" to avoid directory-import errors.
 */
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import * as identity from "@iota/identity-wasm/node/index.js";
import { Ed25519Keypair } from "@iota/iota-sdk/keypairs/ed25519";
import { decodeIotaPrivateKey } from "@iota/iota-sdk/cryptography";
function usageAndExit(code) {
    console.error(`Usage:
  node dist/issue-file-vc.js --file <path> --seed <64-hex> --did-doc <didDoc.json>

Options:
  --method-id <id|#fragment>   (default: first verificationMethod in DID doc)
  --out <dir|file.json>        (default: .) if ends with .json -> exact output file, else directory
  --vc-id <string>             (default: urn:uuid:...)
  --no-validate                skip self-validation
`);
    process.exit(code);
}
function getArg(name) {
    const i = process.argv.indexOf(name);
    if (i >= 0)
        return process.argv[i + 1];
    return undefined;
}
function hasFlag(name) {
    return process.argv.includes(name);
}
function assertSeedHex64(seedHex) {
    const s = seedHex.trim().toLowerCase().replace(/^0x/, "");
    if (s.length !== 64)
        throw new Error("SEED must have 64 hex characters (32 bytes).");
    if (!/^[0-9a-f]+$/.test(s))
        throw new Error("SEED must be hex.");
    return s;
}
function sha256Hex(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}
function toB64Url(bytes) {
    return Buffer.from(bytes).toString("base64url");
}
function uuidLike() {
    return `urn:uuid:${crypto.randomUUID()}`;
}
function must(value, name) {
    if (value === undefined || value === null)
        throw new Error(`Missing identity-wasm export: ${name}`);
    return value;
}
async function loadDidDocJson(filePath) {
    const raw = await fs.readFile(path.resolve(filePath), "utf8");
    const obj = JSON.parse(raw);
    return obj?.doc ?? obj;
}
function normalizeMethodId(input, did) {
    if (input.startsWith(did + "#")) {
        const fragment = input.slice(did.length); // includes "#"
        return { methodId: input, fragment };
    }
    if (input.startsWith("#"))
        return { methodId: did + input, fragment: input };
    return { methodId: `${did}#${input}`, fragment: `#${input}` };
}
function pickMethodFromDoc(didDoc, did, preferred) {
    const methods = Array.isArray(didDoc?.verificationMethod) ? didDoc.verificationMethod : [];
    if (methods.length === 0)
        throw new Error("DID Document has no verificationMethod[]");
    if (preferred) {
        const { methodId, fragment } = normalizeMethodId(preferred, did);
        const m = methods.find((x) => String(x?.id) === methodId);
        if (!m)
            throw new Error(`verificationMethod not found in DID doc: ${methodId}`);
        return { method: m, methodId, fragment };
    }
    const m0 = methods[0];
    const id0 = String(m0?.id || "");
    if (!id0)
        throw new Error("First verificationMethod has no id");
    const idx = id0.indexOf("#");
    const fragment = idx >= 0 ? id0.slice(idx) : "";
    return { method: m0, methodId: id0, fragment };
}
async function main() {
    const filePath = getArg("--file");
    const seedStr = getArg("--seed");
    const didDocPath = getArg("--did-doc");
    const methodIdArg = getArg("--method-id");
    const outArg = getArg("--out") ?? ".";
    const vcId = getArg("--vc-id") ?? uuidLike();
    const doValidate = !hasFlag("--no-validate");
    if (!filePath || !seedStr || !didDocPath)
        usageAndExit(1);
    const seedHex = assertSeedHex64(seedStr);
    // DID Document
    const didDocJson = await loadDidDocJson(didDocPath);
    const did = String(didDocJson?.id || "");
    if (!did)
        throw new Error("DID Document id missing (doc.id)");
    // Select verification method
    const picked = pickMethodFromDoc(didDocJson, did, methodIdArg);
    const vmJson = picked.method;
    const methodId = picked.methodId;
    const fragmentFromDoc = picked.fragment;
    if (!fragmentFromDoc)
        throw new Error("Selected method id has no #fragment");
    // Public key from DID doc
    const jwkFromDoc = vmJson?.publicKeyJwk;
    const xDoc = String(jwkFromDoc?.x || "");
    if (!xDoc)
        throw new Error("verificationMethod.publicKeyJwk.x missing in DID doc");
    // Derive keypair EXACTLY like DID creation code
    const keypair = Ed25519Keypair.deriveKeypairFromSeed(seedHex);
    const pkRaw = keypair.getPublicKey().toRawBytes();
    const pkX = toB64Url(pkRaw);
    if (pkX !== xDoc) {
        throw new Error(`Seed does NOT match DID Document publicKeyJwk.x\n` + `- derived x: ${pkX}\n` + `- doc x:     ${xDoc}`);
    }
    // Extract raw 32-byte secret key for JWK 'd'
    const { secretKey } = decodeIotaPrivateKey(keypair.getSecretKey());
    if (!secretKey || secretKey.length !== 32) {
        throw new Error("Unable to extract 32-byte secretKey from keypair.getSecretKey()");
    }
    // File hash (after DID check, so we fail fast for key mismatch)
    const fileAbs = path.resolve(filePath);
    const fileBytes = new Uint8Array(await fs.readFile(fileAbs));
    const fileHash = sha256Hex(fileBytes);
    const stat = await fs.stat(fileAbs);
    // Storage (official mem stores)
    const Storage = must(identity.Storage, "Storage");
    const JwkMemStore = must(identity.JwkMemStore, "JwkMemStore");
    const KeyIdMemStore = must(identity.KeyIdMemStore, "KeyIdMemStore");
    const storage = new Storage(new JwkMemStore(), new KeyIdMemStore());
    // Insert private key JWK (x from DID doc, d from secretKey)
    const Jwk = must(identity.Jwk, "Jwk");
    const jwkPriv = Jwk.fromJSON({
        kty: "OKP",
        crv: "Ed25519",
        alg: "EdDSA",
        x: xDoc,
        d: toB64Url(secretKey),
    });
    const keyId = await storage.keyStorage().insert(jwkPriv);
    // Build issuer document from provided DID doc JSON
    const CoreDocument = must(identity.CoreDocument, "CoreDocument");
    const issuerDocument = CoreDocument.fromJSON ? CoreDocument.fromJSON(didDocJson) : new CoreDocument(didDocJson);
    // Bind method digest -> keyId
    const MethodDigest = must(identity.MethodDigest, "MethodDigest");
    const VerificationMethod = must(identity.VerificationMethod, "VerificationMethod");
    const vmInst = VerificationMethod.fromJSON ? VerificationMethod.fromJSON(vmJson) : new VerificationMethod(vmJson);
    let digest;
    if (typeof MethodDigest.fromMethod === "function")
        digest = MethodDigest.fromMethod(vmInst);
    else if (typeof MethodDigest.fromVerificationMethod === "function")
        digest = MethodDigest.fromVerificationMethod(vmInst);
    else
        digest = new MethodDigest(vmInst);
    await storage.keyIdStorage().insertKeyId(digest, keyId);
    // Create unsigned VC
    const Credential = must(identity.Credential, "Credential");
    const unsignedVc = new Credential({
        id: vcId,
        type: "FileHashCredential",
        issuer: issuerDocument.id(),
        credentialSubject: {
            id: did,
            file: {
                name: path.basename(fileAbs),
                size: stat.size,
                sha256: fileHash,
            },
        },
    });
    // Sign VC-JWT using existing method fragment (from DID doc)
    const JwsSignatureOptions = must(identity.JwsSignatureOptions, "JwsSignatureOptions");
    const credentialJwt = await issuerDocument.createCredentialJwt(storage, fragmentFromDoc, unsignedVc, new JwsSignatureOptions());
    // Optional self-validation
    let vcJsonOut = unsignedVc.toJSON();
    if (doValidate) {
        const JwtCredentialValidator = must(identity.JwtCredentialValidator, "JwtCredentialValidator");
        const EdDSAJwsVerifier = must(identity.EdDSAJwsVerifier, "EdDSAJwsVerifier");
        const JwtCredentialValidationOptions = must(identity.JwtCredentialValidationOptions, "JwtCredentialValidationOptions");
        const FailFast = must(identity.FailFast, "FailFast");
        const decoded = new JwtCredentialValidator(new EdDSAJwsVerifier()).validate(credentialJwt, issuerDocument, new JwtCredentialValidationOptions(), FailFast.FirstError);
        vcJsonOut = decoded.intoCredential().toJSON();
    }
    // Output path: treat --out ending with .json as file, otherwise directory
    const outIsFile = outArg.toLowerCase().endsWith(".json");
    const outPath = outIsFile
        ? path.resolve(outArg)
        : path.join(path.resolve(outArg), `${path.basename(fileAbs)}.vc.bundle.json`);
    await fs.mkdir(path.dirname(outPath), { recursive: true });
    const outBundle = {
        did,
        didDocument: issuerDocument.toJSON(),
        verificationMethodId: methodId,
        methodFragment: fragmentFromDoc,
        vcJwt: credentialJwt.toString(),
        vc: vcJsonOut,
    };
    await fs.writeFile(outPath, JSON.stringify(outBundle, null, 2), "utf8");
    console.log(JSON.stringify(outBundle, null, 2));
    console.error(`\nOK: wrote ${outPath}`);
}
main().catch((e) => {
    console.error(e?.stack ?? String(e));
    process.exit(1);
});
