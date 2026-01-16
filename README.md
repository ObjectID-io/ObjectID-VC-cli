# iota-vc-cli

TypeScript (Node.js) CLI that generates a **Verifiable Credential (VC-JWT)** for a file by embedding its **SHA-256 hash**, and signs it with **EdDSA (Ed25519)** using **IOTA Identity WASM**.

This version is designed to work **offline** as long as you provide the **DID Document JSON** of the issuer:

- the script **extracts the issuer DID** from `didDocument.id`
- it selects a `verificationMethod` from the DID Document
- it imports the issuer private key from `--seed` into the in-memory JWK store
- it binds `verificationMethod` → keyId in the KeyId store
- it signs a VC-JWT via `createCredentialJwt(...)`
- (optional) it self-validates the JWT using the same DID Document (still offline)

> Important: the seed is interpreted exactly like your DID creation flow, using  
> `Ed25519Keypair.deriveKeypairFromSeed(seedHex)`.

---

## Requirements

- Node.js >= 20
- npm
- Bash environment (Linux/macOS/WSL/Windows PowerShell OK)

---

## Install

```bash
npm i
```

Dependencies needed:

```bash
npm i @iota/iota-sdk
npm i @iota/identity-wasm@beta
```

---

## Build

```bash
npm run build
```

---

## Prepare the DID Document file

Save the resolved DID document JSON to a file, e.g. `did.json`.

The tool accepts both:

- `{ "doc": { ... }, "meta": { ... } }` (IOTA resolve format), or
- `{ ... }` (plain DID Document)

It will automatically use `doc.id` (or `id`) as the issuer DID.

---

## Issue a VC-JWT for a file (offline)

```bash
node dist/issue-file-vc.js \
  --file "./test.txt" \
  --seed "c42c2d8a69456c66......." \
  --did-doc "./did.json" \
  --out "./out"
```

### Options

- `--file <path>`: file path to attest (required)
- `--seed <64-hex>`: issuer seed used to create the DID key (required)
- `--did-doc <path>`: DID Document JSON file (required)
- `--method-id <id|#fragment|fragment>`: choose a specific `verificationMethod` (default: first)
- `--out <dir|file.json>`: output directory (default: `.`). If it ends with `.json`, it’s treated as an exact output file.
- `--vc-id <string>`: credential id (default: `urn:uuid:<randomUUID>`)
- `--no-validate`: skip the self-validation step

### Output

By default (when `--out` is a directory), it writes:

`<filename>.vc.bundle.json`

The bundle contains:

- `did`: issuer DID extracted from DID Document
- `verificationMethodId`, `methodFragment`
- `didDocument` (as JSON)
- `vcJwt` (signed VC-JWT)
- `vc` (decoded credential JSON, if validation enabled)

---

## Verify a VC against the original file

If you have the verifier CLI from earlier, you can verify:

- signature (EdDSA) using the DID Document
- time claims (nbf/exp if present)
- SHA-256(file) matches the value embedded in the VC

Example (bundle mode):

```bash
node dist/verify-file-vc.js \
  --bundle "./out/test.txt.vc.bundle.json" \
  --file "./test.txt"
```

---

## Security notes

- Never commit the seed.
- Treat seeds as secrets (env vars / secret manager).
- The DID Document you provide is treated as the “truth” in offline mode.  
  If you need canonical verification, resolve the DID against the network in your verifier.

---

## Project layout

```
.
├─ package.json
├─ tsconfig.json
└─ src/
   ├─ issue-file-vc.ts
   ├─ verify-file-vc.ts
   └─ ...
```

---

## License

MIT (or set your preferred license).
