//! Phase 0/1 scaffold: thin wrapper that embeds the dwallet-labs/inkrypto 2PC-MPC stack.
//!
//! **License note:** the `twopc_mpc` / `inkrypto` crates we depend on are licensed
//! CC-BY-NC-ND-4.0 (non-commercial, no-derivatives). This project uses them for
//! personal research only and does not distribute modifications. Do not repurpose
//! this crate for commercial use without obtaining a commercial license from
//! dWallet Labs (dev@dwalletlabs.com).

pub mod actor;
pub mod bus;
pub mod ceremony;
pub mod session;

pub use ceremony::{run_local_ecdsa_ceremony, CeremonyError, CeremonyOutput};
pub use session::{run_multiparty_ecdsa_ceremony, SessionError, SessionOutput};
