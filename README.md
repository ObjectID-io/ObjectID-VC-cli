# Objectid-vc-cli

TypeScript (Node.js) CLI that generates a **Verifiable Credential** for a file by embedding its **SHA-256 hash**, and signs it with **EdDSA (Ed25519)** using **IOTA Identity**.

What it does:

- reads an input file (`--file`)
- takes a seed (`--seed`)
- deterministically derives an Ed25519 keypair
- builds an **offline DID** (`did:jwk`)
- creates a DID Document with a verification method
- creates a VC (JSON) containing file metadata + hash
- outputs a signed **VC-JWT**

It also includes a verifier CLI that:

- takes the **same file** (`--file`) to recompute SHA-256
- takes either a **bundle** (`--bundle`) or a **raw VC-JWT** (`--jwt`)
- verifies **signature + hash match + time claims** (`nbf/exp`)

> Note: `did:iota` is not deterministically derivable from a seed alone without publishing on-chain. This CLI uses `did:jwk` because it’s fully offline and deterministic.

---

## Requirements

- Node.js >= 18
- npm
- Bash environment (Linux/macOS/WSL OK)

---

## Install

```bash
npm i
```

---

## Build

```bash
npm run build
```

---

## Issue a VC for a file

```bash
node dist/issue-file-vc.js --file "./eventi 23-12-2025.zip" --seed "0x0123...deadbeef"
```

Options:

- `--file <path>`: file path to attest (required)
- `--seed <hex|0xhex>`: seed in hex (required)
  - if it’s not exactly 32 bytes, it is normalized with `sha256(seedBytes)`
- `--out <dir>`: output directory (default: `.`)
- `--kid <string>`: method fragment (default: `key-1`)

Example with output dir:

```bash
node dist/issue-file-vc.js \
  --file "./eventi 23-12-2025.zip" \
  --seed "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  --out "./out" \
  --kid "key-1"
```

---

## Output (issuer)

The issuer CLI prints a JSON “bundle” to `stdout` and also writes a file:

`<filename>.vc.bundle.json`

Example:

`eventi 23-12-2025.zip.vc.bundle.json`

Typical bundle content:

- `did`: derived DID (did:jwk)
- `methodFragment`: e.g. `key-1`
- `didDocument`: generated DID Document
- `vc`: VC as JSON (includes SHA-256 hash of the file)
- `vcJwt`: the VC encoded as a signed JWT (EdDSA)

---

## Verify a VC against the original file

### Verifier CLI

You can verify either:

- a **bundle** produced by the issuer CLI (`--bundle`), or
- a **raw VC-JWT** string (`--jwt`)

You must also provide the **file** to recompute its SHA-256 hash (`--file`).

#### Verify using a bundle

```bash
node dist/verify-file-vc.js \
  --bundle "./out/eventi 23-12-2025.zip.vc.bundle.json" \
  --file "./eventi 23-12-2025.zip"
```

#### Verify using a raw VC-JWT

```bash
node dist/verify-file-vc.js \
  --jwt "eyJ..." \
  --file "./eventi 23-12-2025.zip"
```

#### Optional: override “now” for time-claim checks

The verifier checks JWT `nbf` and `exp` using the current time. You can override it:

```bash
node dist/verify-file-vc.js \
  --bundle "./out/eventi 23-12-2025.zip.vc.bundle.json" \
  --file "./eventi 23-12-2025.zip" \
  --now "2026-01-16T10:00:00Z"
```

---

## Verifier output and exit codes

The verifier prints a JSON result like:

- `signatureValid`: JWS signature valid (EdDSA)
- `hashMatch`: SHA-256(file) matches the hash claimed in the VC
- `timeValid`: `nbf`/`exp` satisfied
- `ok`: true only if all the above are true

Exit codes:

- `0` verification OK
- `2` verification failed (signature/hash/time)
- `1` runtime/input error (bad args, invalid JSON/JWT, etc.)

---

## Security

- **Never commit the seed.**
- Treat real seeds as secrets (env vars, secret manager, protected files).
- The DID is deterministic: same seed => same DID / key.

---

## Project layout

```
.
├─ package.json
├─ tsconfig.json
└─ src/
   ├─ issue-file-vc.ts
   └─ verify-file-vc.ts
```

---

## Limitations / notes

- The VC is designed to “attest a file” via its hash. No on-chain anchoring is performed.
- The verifier assumes the issuer DID is `did:jwk` and extracts the Ed25519 public key from it to verify the VC-JWT signature.
- To produce a `did:iota` you need a different flow: create/publish an Identity on the IOTA network (RPC endpoint, gas, faucet/mainnet, etc.).
- For ZIP files, if you need robustness against recompression/metadata changes, add a **manifest** with per-entry hashes (not included in this base CLI).

---

## License

MIT (or set your preferred license).
