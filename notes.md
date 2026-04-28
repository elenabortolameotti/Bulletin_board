# Bulletin Board project

## Fase 1
Append only architecture
## Fase 2
Access control: chi può scrivere cosa ecc...
## Fase 3
Voto
## Fase 4
Analisi di performance

## Da vedere:
Eddsa batch verification
hash che ricordano dove sono arrivata fino a quel momento

## The project
## Goal
Minimal CT-like append-only log for Bulletin Boards:
-signed states (checkpoints)
-client-side verification
-inclusion + consistency proofs

## Components
## Log
-stores entries
-maintains Merkle tree
-produces:
 -checkpoints (signed)
 -inclusion proofs
 -consistency proofs

## Client (verification logic)
-does NOT trust the log
 verifies:
 -checkpoint signature
 -entry inclusion
 -append-only consistency

## Witness
-observes checkpoints over time
-verifies consistency
-confirms valid log evolution

## Core objects
## Entry
-data submitted to the log
-hashed → becomes a leaf

## Checkpoint
Authenticated log state:
-TreeSize
-RootHash
-Signature
→ “this is the state of the log”

## Receipt
Returned on append:
-EntryID
-Index
-LeafHash
-Checkpoint
no inclusion proof (requested separately)

## Merkle tree
HashLeaf = H(0x00 || data)
HashNode = H(0x01 || left || right)
Supports:
-root computation
-inclusion proof + verify
-consistency proof + verify

## Core operations
## Append
-adds entry
-updates tree
-returns receipt

## Checkpoint
-signs (TreeSize, RootHash)
-authenticates log state

## VerifyCheckpoint
✔ checkpoint signed by log
❌ does NOT guarantee append-only over time

## VerifyEntryInCheckpoint
✔ entry ∈ checkpoint
✔ checkpoint is authentic

## VerifyConsistencyProof
✔ new checkpoint extends old one (append-only)

## Guarantees
## ✔ Provided
-append-only structure (via consistency proofs)
-authenticated log states
-verifiable inclusion of entries
## ❌ Not yet
-witness / cosigning
-fork detection (split view)
-network layer (API, tiles)

## Conceptual flow
## Inclusion
-append entry
-get receipt (with checkpoint)
-get inclusion proof
-verify

## Consistency
-old checkpoint
-new checkpoint
-get consistency proof
-verify

## Trust model
client trusts only:
-hash function
-signature verification
-log alone is not enough → needs witness for stronger guarantees

## Witness / anti-equivocation
### Possiede
- propria chiave di firma
- chiave pubblica del log
- ultimo checkpoint accettato

### Verifica
- firma del log sul nuovo checkpoint
- consistency rispetto all’ultimo checkpoint visto

### Firma
- il checkpoint del log (cosignature)

### Rifiuta se
- firma del log invalida
- new checkpoint più piccolo del precedente
- stessa size ma root diversa
- new checkpoint non consistente col precedente

### Obiettivo
- ridurre l’equivocation del log
- aggiungere una seconda entità che conferma l’evoluzione append-only


git add .
git commit -m "messaggio"
git push