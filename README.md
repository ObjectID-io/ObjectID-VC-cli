# iota-vc-cli

CLI TypeScript (Node.js) per generare una **Verifiable Credential** che attesta un file tramite **hash SHA-256**, firmata con **EdDSA (Ed25519)** usando **IOTA Identity**.

La CLI:

- legge un file (`--file`)
- prende un seed (`--seed`)
- deriva deterministicamente una chiave Ed25519
- costruisce un **DID offline** (`did:jwk`)
- genera un DID Document con un verification method
- crea una VC (JSON) con metadati + hash del file
- produce anche la **VC-JWT** firmata

> Nota: `did:iota` non è deterministico “solo da seed” senza pubblicazione on-chain. Qui si usa `did:jwk` perché è derivabile offline.

---

## Requisiti

- Node.js >= 18
- npm
- Ambiente bash (Linux/macOS/WSL ok)

---

## Installazione

```bash
npm i
```
