//! Multisig configuration transaction utilities.
//!
//! Functions for building transactions that modify the multisig configuration
//! (signers, threshold, etc.).

mod config;

pub(crate) use config::build_update_procedure_threshold_transaction_request_for_root;
pub use config::{
    build_update_procedure_threshold_transaction_request, build_update_signers_transaction_request,
};
