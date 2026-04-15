# Canton 2PC-MPC

**Bringing Native Bitcoin, Ethereum, Solana, and more to Canton Network**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Rust implementation of the 2PC-MPC (Two-Party Computation Multi-Party Computation) protocol for threshold signatures, enabling Canton Network smart contracts to natively control assets on Bitcoin, Ethereum, Solana, and other blockchains without bridges or wrapped tokens.

## Overview

Canton 2PC-MPC enables **true cross-chain interoperability** by allowing Daml smart contracts on Canton Network to sign transactions on any supported blockchain. Unlike traditional bridges that require trusting custodians or wrapped tokens, this system provides **zero-trust security** through cryptographic guarantees.

### Key Features

- **Native Asset Control**: Control real BTC, ETH, SOL directly from Canton smart contracts
- **Zero-Trust Security**: Neither the user nor the network can sign alone
- **Multi-Chain Support**: Bitcoin, Ethereum, Solana, and EVM-compatible chains
- **High Performance**: Sub-second signature generation with massive parallelism
- **Canton Integration**: Deep integration with Daml smart contracts and Canton Ledger API

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Canton Network                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                 Daml Smart Contracts                     │   │
│  │     (DeFi, Custody, Tokenization, Trading, etc.)        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Canton Integration Layer                    │   │
│  │         (Ledger API, Daml Templates, Events)            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
└──────────────────────────────┼──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    2PC-MPC Protocol Layer                       │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────┐   │
│  │      DKG      │  │    Signing    │  │  dWallet Manager  │   │
│  │  (Key Gen)    │  │   Protocol    │  │                   │   │
│  └───────────────┘  └───────────────┘  └───────────────────┘   │
│                              │                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Cryptographic Primitives                    │   │
│  │  ┌─────────┐  ┌─────────────┐  ┌───────────────────┐    │   │
│  │  │  ECDSA  │  │   EdDSA     │  │     Schnorr       │    │   │
│  │  │secp256k1│  │  Ed25519    │  │  (BIP-340)        │    │   │
│  │  └─────────┘  └─────────────┘  └───────────────────┘    │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                               │
           ┌───────────────────┼───────────────────┐
           ▼                   ▼                   ▼
     ┌──────────┐        ┌──────────┐        ┌──────────┐
     │  Bitcoin │        │ Ethereum │        │  Solana  │
     │   BTC    │        │ ETH/ERC20│        │ SOL/SPL  │
     └──────────┘        └──────────┘        └──────────┘
```

## Supported Chains

| Chain | Signature Scheme | Address Types | Tokens |
|-------|-----------------|---------------|--------|
| **Bitcoin** | ECDSA secp256k1 | P2PKH, P2WPKH | BTC |
| **Bitcoin (Taproot)** | Schnorr | P2TR | BTC |
| **Ethereum** | ECDSA secp256k1 | EOA | ETH, ERC-20 |
| **Polygon** | ECDSA secp256k1 | EOA | MATIC, ERC-20 |
| **Arbitrum** | ECDSA secp256k1 | EOA | ETH, ERC-20 |
| **Optimism** | ECDSA secp256k1 | EOA | ETH, ERC-20 |
| **Base** | ECDSA secp256k1 | EOA | ETH, ERC-20 |
| **Avalanche** | ECDSA secp256k1 | EOA | AVAX, ERC-20 |
| **BNB Chain** | ECDSA secp256k1 | EOA | BNB, BEP-20 |
| **Solana** | EdDSA Ed25519 | Pubkey | SOL, SPL |

## Project Structure

```
Canton-2PC-MPC/
├── Cargo.toml                    # Workspace configuration
├── crates/
│   ├── crypto-core/              # Cryptographic primitives
│   │   ├── ecdsa.rs              # ECDSA secp256k1
│   │   ├── eddsa.rs              # EdDSA Ed25519
│   │   ├── schnorr.rs            # Schnorr (BIP-340)
│   │   └── hash.rs               # Hash functions
│   │
│   ├── mpc-protocol/             # 2PC-MPC protocol implementation
│   │   ├── protocol.rs           # Core protocol coordinator
│   │   ├── dkg.rs                # Distributed Key Generation
│   │   ├── signing.rs            # Threshold signing
│   │   ├── participant.rs        # MPC participant
│   │   └── network.rs            # Network layer
│   │
│   ├── chains/
│   │   ├── bitcoin/              # Bitcoin support
│   │   │   ├── address.rs        # Address generation
│   │   │   ├── transaction.rs    # TX building
│   │   │   ├── psbt.rs           # PSBT support
│   │   │   └── signer.rs         # Signing utilities
│   │   │
│   │   ├── ethereum/             # Ethereum/EVM support
│   │   │   ├── address.rs        # Address derivation
│   │   │   ├── transaction.rs    # TX building (legacy/EIP-1559)
│   │   │   ├── signer.rs         # Signing utilities
│   │   │   └── erc20.rs          # ERC-20 interactions
│   │   │
│   │   └── solana/               # Solana support
│   │       ├── address.rs        # Pubkey handling
│   │       ├── transaction.rs    # TX building
│   │       ├── signer.rs         # Signing utilities
│   │       └── spl_token.rs      # SPL token support
│   │
│   ├── dwallet/                  # dWallet management
│   │   ├── wallet.rs             # dWallet abstraction
│   │   ├── manager.rs            # Wallet manager
│   │   └── chain_adapter.rs      # Chain adapters
│   │
│   └── canton-integration/       # Canton Network integration
│       ├── ledger_api.rs         # Canton Ledger API client
│       ├── daml_types.rs         # Daml type definitions
│       ├── service.rs            # Main service
│       └── events.rs             # Event handling
```

## How It Works

### 1. Two-Party Computation (2PC)

The system ensures that **both the user AND the network** must participate in every signature. This is the "2PC" part:

- **User**: Holds one share of the private key
- **Network**: Holds the other share, distributed among nodes via MPC

Neither party can sign alone, providing zero-trust security.

### 2. Multi-Party Computation (MPC)

The network's share is itself distributed across multiple nodes using threshold cryptography:

- **Threshold**: t-of-n nodes must participate
- **No single point of failure**: No single node can reconstruct the key
- **Byzantine fault tolerance**: Tolerates malicious nodes

### 3. Distributed Key Generation (DKG)

When creating a new dWallet:

1. User generates their secret share locally
2. Network nodes run FROST DKG to generate the network's share
3. Public key is computed without revealing any private key

### 4. Signing Protocol

When signing a transaction:

1. User generates nonce commitment
2. Network nodes generate their nonce commitments
3. All commitments are broadcast
4. Partial signatures are computed
5. Final signature is aggregated

## Usage

### Creating a dWallet

```rust
use canton_2pc_mpc::dwallet::{DWalletConfig, DWalletManager};

// Create manager
let manager = DWalletManager::new();

// Create a wallet for Bitcoin/Ethereum (ECDSA)
let config = DWalletConfig::for_bitcoin_ethereum(2, 3)
    .with_name("My Cross-Chain Wallet");

let wallet_id = manager.create_wallet(config).await?;

// Get derived addresses
let wallet = manager.get_wallet(&wallet_id).await?;
println!("Bitcoin: {}", wallet.address("bitcoin").unwrap());
println!("Ethereum: {}", wallet.address("ethereum").unwrap());
```

### Signing a Transaction

```rust
// Sign a message
let message = b"Hello, Canton!";
let signature = manager.sign(&wallet_id, "ethereum", message).await?;

// Build and sign a transaction
let params = TransactionParams {
    chain: "ethereum".to_string(),
    to: "0x742d35Cc6634C0532925a3b844Bc9e7595f1".to_string(),
    amount: 1_000_000_000_000_000_000, // 1 ETH
    data: None,
    fee_params: None,
};

let signed_tx = manager.build_and_sign_transaction(
    &wallet_id,
    ChainType::Ethereum,
    params,
).await?;

println!("TX Hash: {}", signed_tx.tx_hash);
```

### Canton Integration

```rust
use canton_integration::{CantonConfig, CantonMpcService};

// Configure Canton connection
let config = CantonConfig {
    ledger_host: "localhost".to_string(),
    ledger_port: 6865,
    party_id: "participant1".to_string(),
    application_id: "my-app".to_string(),
    use_tls: false,
};

// Start service
let service = CantonMpcService::new(config, dwallet_manager);
service.start().await?;

// Create dWallet via Canton
let contract = service.create_dwallet("ecdsa_secp256k1", 2).await?;

// Execute cross-chain transfer
let transfer = service.transfer(
    &contract.dwallet_id,
    "ethereum",
    "0x742d35Cc6634C0532925a3b844Bc9e7595f1",
    "1000000000000000000",
    "ETH",
).await?;
```

## Building

### Prerequisites

- Rust 1.75+
- Cargo

### Build

```bash
# Clone the repository
git clone https://github.com/example/canton-2pc-mpc
cd canton-2pc-mpc

# Build all crates
cargo build --release

# Run tests
cargo test

# Build documentation
cargo doc --open
```

## Configuration

### MPC Protocol

```rust
let config = ProtocolConfig {
    signature_type: SignatureType::EcdsaSecp256k1,
    threshold: 2,           // 2-of-3 threshold
    total_participants: 3,
    round_timeout_ms: 30_000,
    max_concurrent_sessions: 100,
    proactive_security: false,
};
```

### Canton Connection

```rust
let config = CantonConfig {
    ledger_host: "canton-node.example.com".to_string(),
    ledger_port: 6865,
    party_id: "my-party".to_string(),
    application_id: "canton-2pc-mpc".to_string(),
    use_tls: true,
};
```

## Security Considerations

1. **Key Material**: Private key shares are never combined; signing happens distributively
2. **Network Security**: Use TLS for all network communication
3. **Threshold Selection**: Choose threshold based on your trust model (e.g., 2-of-3, 3-of-5)
4. **Proactive Security**: Consider enabling key refresh for long-lived wallets

## Comparison with Alternatives

| Feature | Canton 2PC-MPC | Traditional Bridges | Wrapped Tokens |
|---------|---------------|---------------------|----------------|
| **Native Assets** | ✅ Yes | ❌ No | ❌ No |
| **Custody** | Decentralized | Centralized | Varies |
| **Trust Assumptions** | Cryptographic | Operational | Varies |
| **Smart Contract Control** | ✅ Full | Limited | ✅ Yes |
| **Single Point of Failure** | ❌ None | ✅ Yes | Varies |

## Inspired By

This project is inspired by [Ika](https://ika.xyz/), the fastest parallel MPC network on Sui, which pioneered the 2PC-MPC approach for cross-chain asset control.

## License

Apache-2.0

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## Acknowledgments

- [Ika Network](https://ika.xyz/) for the 2PC-MPC protocol design
- [Canton Network](https://www.canton.network/) for the enterprise blockchain infrastructure
- [Digital Asset](https://www.digitalasset.com/) for Daml and Canton
- [FROST](https://eprint.iacr.org/2020/852) for threshold signature research
