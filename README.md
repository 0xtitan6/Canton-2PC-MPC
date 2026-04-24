# Canton 2PC-MPC

**Research implementation of [2PC-MPC](https://eprint.iacr.org/2024/253) threshold ECDSA, targeting Canton Network as the broadcast channel.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Crypto: CC-BY-NC-ND-4.0](https://img.shields.io/badge/Crypto%20deps-CC--BY--NC--ND--4.0-red.svg)](#licensing-and-scope)

This is a **personal research project** exploring how far the 2PC-MPC protocol — published by [dWallet Labs](https://dwalletlabs.com) and implemented in their open-source [inkrypto](https://github.com/dwallet-labs/inkrypto) library — can be pushed toward a Canton Network deployment. It is explicitly **not a product** and not suitable for any commercial use (see [licensing](#licensing-and-scope)).

## What this actually is

A thin Rust wrapper that embeds `dwallet-labs/inkrypto` (pinned to rev `abd7f010`) and drives its 2PC-MPC state machine, working up toward using **Canton 3.4 as the broadcast channel** through which MPC parties exchange messages.

The 2PC-MPC protocol produces standard ECDSA signatures over secp256k1, so any signature this project emits is verifiable by stock `k256` — and by extension, by every Bitcoin / Ethereum / EVM node on the planet.

## Current status

| Phase | Scope | Status |
|---|---|---|
| **0** | In-process ceremony: DKG → presign → sign, verified by both inkrypto and k256 | ✅ [`tests/local_ceremony.rs`](crates/mpc-protocol/tests/local_ceremony.rs) |
| **1** | Actor-per-party multi-task ceremony over an in-process broadcast bus | ✅ [`tests/multiparty_ceremony.rs`](crates/mpc-protocol/tests/multiparty_ceremony.rs) |
| **2** | Replace the in-process bus with the Canton 3.4 Ledger API v2 (DAR + tonic client + session driver) | 🏗️ next |
| **3** | Broadcast a real ECDSA transaction on a chain testnet (Ethereum Sepolia first) | ⏳ |

## Demo

```bash
# Phase 0: single-process ceremony, 2-of-2 weighted threshold
cargo test -p mpc-protocol --test local_ceremony --release -- --nocapture

# Phase 1: actor-per-party over tokio::broadcast bus, same topology
cargo test -p mpc-protocol --test multiparty_ceremony --release -- --nocapture
```

Sample output (Phase 1):

```
Phase 1 multi-actor ceremony OK:
  public_key (SEC1) = 0242f8e84a3c1e6a79f8a1a8678a857bf3cec975a05fc58040ee152a7c51f3445f
  signature r||s    = fd89bb2bfff7a4fbe0aa6b9740c0592c9b4f84bb7b9b713efece153d6b64e180...
  (verifies under both inkrypto and stock k256)
test ... ok   finished in 8.70s
```

## Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                  Phase 1 — current (in-process)                   │
│                                                                   │
│   ┌──────────────┐    ┌──────────────────────────────────────┐    │
│   │ Orchestrator │    │  InProcessBus (tokio::broadcast)     │    │
│   │              │    │                                      │    │
│   │ • DKG client │    │                                      │    │
│   │ • Sign client│    │                                      │    │
│   └──────┬───────┘    └──────▲───────────▲───────────▲──────┘    │
│          │                   │           │           │           │
│          │ kicks off         │ pub/sub   │ pub/sub   │ pub/sub   │
│          ▼                   │           │           │           │
│   ┌──────────────┐    ┌──────┴──────┐ ┌──┴──────────┐ ┌───────┐  │
│   │ (one tokio   │───▶│  Actor P1   │ │  Actor P2   │ │  ...  │  │
│   │  task per    │    │  (inkrypto  │ │  (inkrypto  │ │       │  │
│   │  party)      │    │   state m.) │ │   state m.) │ │       │  │
│   └──────────────┘    └─────────────┘ └─────────────┘ └───────┘  │
└───────────────────────────────────────────────────────────────────┘

                              ▼ (Phase 2)

┌───────────────────────────────────────────────────────────────────┐
│                  Phase 2 — Canton as broadcast                    │
│                                                                   │
│   ┌──────────────┐             ┌────────────────────────────┐     │
│   │ Orchestrator │             │    Canton 3.4 Ledger API   │     │
│   │              │ submit      │       (CommandService +    │     │
│   │              │──────────▶  │        UpdateService)      │     │
│   │              │             │                            │     │
│   │              │ ◀───────────│  `MpcSession` / `RoundMsg` │     │
│   └──────────────┘ tx stream   │   Daml templates           │     │
│                                └────────────────────────────┘     │
│                                                                   │
│   CantonBus just swaps InProcessBus — actors are unchanged.       │
└───────────────────────────────────────────────────────────────────┘
```

Key crates (workspace):

| Path | Role |
|---|---|
| [`crates/mpc-protocol`](crates/mpc-protocol) | Phase 0 & 1 implementation — thin wrapper over inkrypto + actor model |
| [`daml`](daml) | Daml templates (placeholder — will be ported to Canton 3.4 in Phase 2) |
| `crates/{crypto-core,chains/*,dwallet,canton-integration}` | **Currently excluded from workspace.** These were placeholder scaffolding from an earlier iteration and depend on an older k256 line that is incompatible with inkrypto's pre-release crypto deps. They'll be ported back crate-by-crate as the real control/signing plane grows. |

## How the protocol runs (Phase 1)

One ceremony has five stages. Centralized (client) rounds are one-shot synchronous calls made by the orchestrator; decentralized (network) rounds are driven by actors.

1. **DKG centralized** — client generates its key share + proof of knowledge locally.
2. **DKG decentralized** — one round. Each network party runs `advance()`, publishes its message, collects quorum, finalizes into the joint DKG output.
3. **Presign decentralized** — four rounds, same actor loop.
4. **Sign centralized** — client generates its partial signature from the presign + message digest.
5. **Sign decentralized** — two rounds. Decrypter subset advances, final round yields a full ECDSA signature.

The 2-of-2 unit-weight topology that Phase 1 targets has every tangible party in every round's subset, so the actor assumes uniform participation. Weighted topologies with per-round decrypter subsets (e.g. the `(4, {1:2, 2:1, 3:3})` case inkrypto tests) need the actor to route by `parties_per_round` — a Phase 1.5 follow-up.

## Building

```bash
# Rust 1.85+ required (edition 2024 in inkrypto transitive deps)
rustc --version
cargo build --release
cargo test --release -- --nocapture
```

Expect the first build to take ~5–10 min — inkrypto pulls in ~20 pre-release crypto crates pinned to its lockfile versions.

## Licensing and scope

This repository is dual-concern:

- **This project's original code** (everything under this repo that isn't `inkrypto`): Apache-2.0.
- **`dwallet-labs/inkrypto`** (via git dep): **[CC-BY-NC-ND-4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/)**. That license **forbids commercial use and derivative works**. This project uses it strictly for personal non-distributed research. You may not build a product on this repo without first obtaining a commercial license from dWallet Labs (`dev@dwalletlabs.com`).

In plain terms: read it, run it locally, learn from it. Do not ship it.

## Non-goals

- Not a fork of inkrypto — inkrypto is used as-is via git dep, unmodified.
- Not a production implementation of 2PC-MPC — the upstream project ([Ika Network](https://ika.xyz/)) is.
- Not a Canton smart-contract framework — the Daml templates here exist only to carry MPC messages.

## Acknowledgements

- [dWallet Labs](https://dwalletlabs.com) — 2PC-MPC protocol + [inkrypto](https://github.com/dwallet-labs/inkrypto)
- [Ika Network](https://ika.xyz) — reference implementation
- [Canton Network](https://www.canton.network) / [Digital Asset](https://www.digitalasset.com) — ledger platform
