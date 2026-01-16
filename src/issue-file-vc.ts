#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import * as ed25519 from "@noble/ed25519";

/**
 * IOTA Identity WASM: i docs dicono di importare da '@iota/identity/node' vs '@iota/identity-wasm/node'
 * (dipende dalla versione/bundle). Qui facciamo fallback runtime senza dipendere dai typings.
 */
async function loadIdentity(): Promise<any> {
  const tries = ["@iota/identity/node", "@iota/identity-wasm/node", "@iota/identity-wasm/web"];
  for (const mod of tries) {
    try {
      return await import(mod);
    } catch {}
  }
  throw new Error(`Impossibile importare IOTA Identity (provati: ${tries.join(", ")})`);
}

function usageAndExit(code: number): never {
  console.error(
    `Uso:
  node dist/issue-file-vc.js --file <path> --seed <hex32|hex64|0x..>
Opzioni:
  --out <dir>       (default: .)
  --kid <string>    (default: key-1)
`
  );
  process.exit(code);
}

function getArg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  if (i >= 0) return process.argv[i + 1];
  return undefined;
}

function parseSeed32(seedStr: string): Uint8Array {
  // Accetta: 0x..., hex64 (32 bytes), hex32 (16 bytes -> espandiamo con sha256)
  let s = seedStr.trim().toLowerCase();
  if (s.startsWith("0x")) s = s.slice(2);
  if (!/^[0-9a-f]+$/.test(s)) throw new Error("Seed deve essere hex (es: 0x..., oppure hex64).");

  const bytes = Buffer.from(s, "hex");

  if (bytes.length === 32) return new Uint8Array(bytes);

  // Se non è 32 bytes, normalizziamo: sha256(seedBytes) -> 32 bytes
  return new Uint8Array(crypto.createHash("sha256").update(bytes).digest());
}

function sha256Hex(data: Uint8Array): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function b64urlEncode(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

function b64urlDecodeToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

/**
 * JwkStorage + KeyIdStorage “minimi” (in-memory) per far funzionare
 * generateMethod/createCredentialJwt (IOTA Identity usa MethodDigest -> keyId). :contentReference[oaicite:2]{index=2}
 */
class DeterministicJwkStorage {
  private keys = new Map<string, { sk: Uint8Array; pk: Uint8Array }>();
  private identity: any;
  private seed32: Uint8Array;

  constructor(identity: any, seed32: Uint8Array) {
    this.identity = identity;
    this.seed32 = seed32;
  }

  // JwkStorage.generate(keyType, algorithm) -> Promise<JwkGenOutput>
  generate = async (_keyType: string, _algorithm: any) => {
    // Chiave deterministica dal seed
    const sk = this.seed32;
    const pk = await ed25519.getPublicKey(sk);

    const keyId = sha256Hex(pk).slice(0, 32); // breve ma stabile
    this.keys.set(keyId, { sk, pk });

    // JWK pubblico (senza "d")
    const jwkPublicJson = {
      kty: "OKP",
      crv: "Ed25519",
      x: b64urlEncode(pk),
      alg: "EdDSA",
      kid: `#${keyId}`,
    };

    // In WASM: JwkGenOutput.fromJSON({ jwk, keyId }) :contentReference[oaicite:3]{index=3}
    return this.identity.JwkGenOutput.fromJSON({
      jwk: jwkPublicJson,
      keyId,
    });
  };

  // JwkStorage.insert(jwk) -> Promise<keyId>
  insert = async (jwk: any) => {
    const d = jwk?.d;
    const x = jwk?.x;
    if (!d || !x) throw new Error("insert(jwk): jwk deve contenere 'd' (privata) e 'x' (pubblica).");

    const sk = b64urlDecodeToBytes(String(d));
    const pk = b64urlDecodeToBytes(String(x));

    if (sk.length !== 32) throw new Error("insert(jwk): 'd' deve essere 32 bytes (Ed25519 seed).");

    const keyId = sha256Hex(pk).slice(0, 32);
    this.keys.set(keyId, { sk, pk });
    return keyId;
  };

  // JwkStorage.sign(keyId, data, publicKey) -> Promise<Uint8Array>
  sign = async (keyId: string, data: Uint8Array, _publicKey: any) => {
    const entry = this.keys.get(keyId);
    if (!entry) throw new Error(`sign: keyId non trovato: ${keyId}`);
    return await ed25519.sign(data, entry.sk);
  };

  delete = async (keyId: string) => {
    this.keys.delete(keyId);
  };

  exists = async (keyId: string) => {
    return this.keys.has(keyId);
  };
}

class InMemoryKeyIdStorage {
  private map = new Map<string, string>();

  insertKeyId = async (methodDigest: any, keyId: string) => {
    const k = String(methodDigest.toString());
    if (this.map.has(k)) throw new Error("insertKeyId: entry gia' esistente");
    this.map.set(k, keyId);
  };

  getKeyId = async (methodDigest: any) => {
    const k = String(methodDigest.toString());
    const v = this.map.get(k);
    if (!v) throw new Error("getKeyId: entry non trovata");
    return v;
  };

  deleteKeyId = async (methodDigest: any) => {
    const k = String(methodDigest.toString());
    if (!this.map.delete(k)) throw new Error("deleteKeyId: entry non trovata");
  };
}

function resolveMethodScope(identity: any): any {
  // Preferisci AssertionMethod, altrimenti VerificationMethod
  const ms = identity.MethodScope;
  if (ms?.AssertionMethod) return ms.AssertionMethod();
  if (ms?.VerificationMethod) return ms.VerificationMethod();
  // fallback: prova fromJSON con stringa W3C-ish
  if (ms?.fromJSON) return ms.fromJSON("assertionMethod");
  throw new Error("Impossibile creare MethodScope (AssertionMethod/VerificationMethod).");
}

async function main() {
  const filePath = getArg("--file");
  const seedStr = getArg("--seed");
  const outDir = getArg("--out") ?? ".";
  const kid = getArg("--kid") ?? "key-1";

  if (!filePath || !seedStr) usageAndExit(1);

  const identity = await loadIdentity();

  const seed32 = parseSeed32(seedStr);

  // File -> hash
  const fileAbs = path.resolve(filePath);
  const bytes = new Uint8Array(await fs.readFile(fileAbs));
  const fileHash = sha256Hex(bytes);
  const stat = await fs.stat(fileAbs);

  // Deriva DID:JWK dal JWK pubblico (solo x/crv/kty/alg).
  const pk = await ed25519.getPublicKey(seed32);
  const publicJwk = { kty: "OKP", crv: "Ed25519", x: b64urlEncode(pk), alg: "EdDSA" };
  const didMethodId = b64urlEncode(new TextEncoder().encode(JSON.stringify(publicJwk)));
  const did = `did:jwk:${didMethodId}`;

  // Storage + Doc
  const jwkStore = new DeterministicJwkStorage(identity, seed32);
  const keyIdStore = new InMemoryKeyIdStorage();
  const storage = new identity.Storage(jwkStore, keyIdStore);

  const doc = new identity.CoreDocument({ id: did });

  // Inserisce un verification method generato (deterministico, perché il JwkStorage.generate lo è)
  const scope = resolveMethodScope(identity);
  const alg = identity.JwsAlgorithm?.EdDSA ?? "EdDSA";
  const fragment = await doc.generateMethod(storage, "ed25519", alg, kid, scope);

  // Credential (VC Data Model v1.1) e firma come VC-JWT :contentReference[oaicite:4]{index=4}
  const now = new Date().toISOString();
  const vcJson = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential", "FileHashCredential"],
    issuer: did,
    issuanceDate: now,
    credentialSubject: {
      id: did,
      file: {
        name: path.basename(fileAbs),
        size: stat.size,
        sha256: fileHash,
      },
    },
  };

  const credential = identity.Credential.fromJSON(vcJson);

  // Signature options
  const sigOptions = identity.JwsSignatureOptions.fromJSON({ typ: "JWT" });

  const jwt = await doc.createCredentialJwt(storage, fragment, credential, sigOptions, {
    // claim extra opzionali
    iat: Math.floor(Date.now() / 1000),
  });

  // Output
  await fs.mkdir(outDir, { recursive: true });
  const base = path.basename(fileAbs);
  const outBundle = {
    did,
    methodFragment: fragment,
    didDocument: doc.toJSON(),
    vc: vcJson,
    vcJwt: jwt.toString(),
  };

  const outPath = path.join(outDir, `${base}.vc.bundle.json`);
  await fs.writeFile(outPath, JSON.stringify(outBundle, null, 2), "utf8");

  console.log(JSON.stringify(outBundle, null, 2));
  console.error(`\nOK: scritto ${outPath}`);
}

main().catch((e) => {
  console.error(e?.stack ?? String(e));
  process.exit(1);
});
