//! Daml type definitions for dWallet contracts
//!
//! These types mirror the Daml templates that would be deployed on Canton
//! for managing dWallets and cross-chain operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// dWallet contract state on Canton ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DWalletContract {
    /// Contract ID
    pub contract_id: String,
    /// dWallet ID
    pub dwallet_id: String,
    /// Owner party
    pub owner: String,
    /// Operators (MPC network nodes)
    pub operators: Vec<String>,
    /// Signature type
    pub signature_type: String,
    /// Threshold
    pub threshold: u32,
    /// Total participants
    pub total_participants: u32,
    /// Public key (hex encoded)
    pub public_key: String,
    /// Derived addresses
    pub addresses: HashMap<String, String>,
    /// Status
    pub status: DWalletStatus,
    /// Creation time
    pub created_at: String,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// dWallet status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DWalletStatus {
    /// DKG in progress
    Creating,
    /// Active and ready for signing
    Active,
    /// Temporarily suspended
    Suspended,
    /// Permanently archived
    Archived,
}

/// Request to create a new dWallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDWalletRequest {
    /// Owner party
    pub owner: String,
    /// Requested signature type
    pub signature_type: String,
    /// Requested threshold
    pub threshold: u32,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Sign request contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// Request ID
    pub request_id: String,
    /// dWallet ID
    pub dwallet_id: String,
    /// Requestor party
    pub requestor: String,
    /// Target chain
    pub chain: String,
    /// Message to sign (hex encoded)
    pub message: String,
    /// Request status
    pub status: SignRequestStatus,
    /// Signature (when complete)
    pub signature: Option<String>,
    /// Creation time
    pub created_at: String,
}

/// Sign request status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignRequestStatus {
    /// Pending approval
    Pending,
    /// Approved, signing in progress
    Approved,
    /// Signing complete
    Complete,
    /// Rejected
    Rejected,
    /// Failed
    Failed,
    /// Expired
    Expired,
}

/// Cross-chain transfer request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    /// Request ID
    pub request_id: String,
    /// dWallet ID
    pub dwallet_id: String,
    /// Requestor party
    pub requestor: String,
    /// Source chain
    pub source_chain: String,
    /// Destination address
    pub destination: String,
    /// Amount (as string for precision)
    pub amount: String,
    /// Token/asset identifier
    pub asset: String,
    /// Status
    pub status: TransferStatus,
    /// Transaction hash (when broadcast)
    pub tx_hash: Option<String>,
}

/// Transfer status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferStatus {
    /// Pending approval
    Pending,
    /// Building transaction
    Building,
    /// Signing transaction
    Signing,
    /// Broadcasting transaction
    Broadcasting,
    /// Confirming on chain
    Confirming,
    /// Complete
    Complete,
    /// Failed
    Failed,
}

/// Daml template definitions (as strings for reference)
pub mod templates {
    /// DWallet template
    pub const DWALLET_TEMPLATE: &str = r#"
template DWallet
  with
    owner : Party
    operators : [Party]
    dwalletId : Text
    signatureType : Text
    threshold : Int
    totalParticipants : Int
    publicKey : Text
    addresses : [(Text, Text)]
    status : DWalletStatus
    metadata : [(Text, Text)]
  where
    signatory owner
    observer operators

    choice Sign : ContractId SignRequest
      with
        requestId : Text
        chain : Text
        message : Text
      controller owner
      do
        create SignRequest with
          requestId
          dwalletId
          requestor = owner
          chain
          message
          status = Pending
          signature = None
          createdAt = "now"

    choice Archive : ()
      controller owner
      do
        return ()
"#;

    /// SignRequest template
    pub const SIGN_REQUEST_TEMPLATE: &str = r#"
template SignRequest
  with
    requestId : Text
    dwalletId : Text
    requestor : Party
    chain : Text
    message : Text
    status : SignRequestStatus
    signature : Optional Text
    createdAt : Text
  where
    signatory requestor

    choice Approve : ContractId SignRequest
      with
        newStatus : SignRequestStatus
      controller requestor
      do
        create this with status = newStatus

    choice Complete : ContractId SignRequest
      with
        sig : Text
      controller requestor
      do
        create this with
          status = Complete
          signature = Some sig

    choice Reject : ContractId SignRequest
      controller requestor
      do
        create this with status = Rejected
"#;

    /// TransferRequest template
    pub const TRANSFER_REQUEST_TEMPLATE: &str = r#"
template TransferRequest
  with
    requestId : Text
    dwalletId : Text
    requestor : Party
    sourceChain : Text
    destination : Text
    amount : Text
    asset : Text
    status : TransferStatus
    txHash : Optional Text
  where
    signatory requestor

    choice ExecuteTransfer : ContractId TransferRequest
      with
        hash : Text
      controller requestor
      do
        create this with
          status = Complete
          txHash = Some hash
"#;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dwallet_contract_serialization() {
        let contract = DWalletContract {
            contract_id: "contract123".to_string(),
            dwallet_id: "dwallet456".to_string(),
            owner: "party1".to_string(),
            operators: vec!["op1".to_string(), "op2".to_string()],
            signature_type: "ecdsa_secp256k1".to_string(),
            threshold: 2,
            total_participants: 3,
            public_key: "02abcd...".to_string(),
            addresses: HashMap::from([
                ("bitcoin".to_string(), "bc1q...".to_string()),
                ("ethereum".to_string(), "0x123...".to_string()),
            ]),
            status: DWalletStatus::Active,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            metadata: HashMap::new(),
        };

        let json = serde_json::to_string(&contract).unwrap();
        let recovered: DWalletContract = serde_json::from_str(&json).unwrap();

        assert_eq!(contract.dwallet_id, recovered.dwallet_id);
        assert_eq!(contract.status, recovered.status);
    }
}
