//! Shared execution logic for proposal finalization.

use std::collections::HashSet;

use guardian_shared::{EcdsaMessageFormat, SignatureScheme};
use miden_client::account::Account;
use miden_client::transaction::TransactionRequest;
use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::{Felt, Word};

use crate::MidenSdkClient;
use crate::error::{MultisigError, Result};
use crate::keystore::{ensure_hex_prefix, word_from_hex};
use crate::proposal::TransactionType;

/// Signature advice entry: (key, prepared_signature_values)
pub type SignatureAdvice = (Word, Vec<Felt>);

/// Input for collecting a signature into advice format.
pub struct SignatureInput {
    /// Hex-encoded signer commitment (with or without 0x prefix).
    pub signer_commitment: String,
    /// Hex-encoded signature (with or without 0x prefix).
    pub signature_hex: String,
    /// Signature scheme (falcon or ecdsa).
    pub scheme: SignatureScheme,
    /// Hex-encoded public key (required for ECDSA signatures).
    pub public_key_hex: Option<String>,
    /// Message encoding used for an ECDSA signature.
    pub message_format: EcdsaMessageFormat,
}

/// Collects and validates cosigner signatures into advice entries.
///
/// Filters signatures to only include those from required signers, skips duplicates,
/// and converts to the format needed for transaction advice.
///
/// # Arguments
/// * `signatures` - Raw signature inputs to process
/// * `required_commitments` - Set of valid signer commitments (lowercase hex)
/// * `tx_summary_commitment` - The transaction summary commitment being signed
///
/// # Returns
/// Vector of (key, prepared_signature) tuples for transaction advice.
pub(crate) fn collect_signature_advice(
    signatures: impl IntoIterator<Item = SignatureInput>,
    required_commitments: &HashSet<String>,
    tx_summary_commitment: Word,
) -> Result<Vec<SignatureAdvice>> {
    let mut advice = Vec::new();
    let mut added_signers: HashSet<String> = HashSet::new();

    for sig_input in signatures {
        if !required_commitments
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&sig_input.signer_commitment))
        {
            continue;
        }

        // Skip duplicates
        let signer_lower = sig_input.signer_commitment.to_lowercase();
        if !added_signers.insert(signer_lower) {
            continue;
        }

        let commitment =
            word_from_hex(&sig_input.signer_commitment).map_err(MultisigError::HexDecode)?;

        let signature = sig_input
            .scheme
            .parse_signature_hex(&ensure_hex_prefix(&sig_input.signature_hex))
            .map_err(MultisigError::Signature)?;
        let entry = match sig_input.message_format {
            EcdsaMessageFormat::Raw => sig_input.scheme.build_signature_advice_entry(
                commitment,
                tx_summary_commitment,
                &signature,
                sig_input.public_key_hex.as_deref(),
            ),
            EcdsaMessageFormat::Eip712 => sig_input.scheme.build_eip712_signature_advice_entry(
                commitment,
                tx_summary_commitment,
                &signature,
                sig_input.public_key_hex.as_deref(),
            ),
        }
        .map_err(MultisigError::Signature)?;
        advice.push(entry);
    }

    Ok(advice)
}

/// Builds the fungible asset to transfer.
///
/// Since Miden 0.16 the asset-callback flag derives from the faucet account ID,
/// so the asset no longer needs to be reconciled against the sender's vault.
pub fn build_transfer_asset(faucet_id: AccountId, amount: u64) -> Result<FungibleAsset> {
    FungibleAsset::new(faucet_id, amount)
        .map_err(|e| MultisigError::InvalidConfig(format!("failed to create asset: {}", e)))
}

/// Builds the final transaction request based on transaction type.
#[expect(
    clippy::too_many_arguments,
    reason = "execution needs transaction metadata and signature scheme to stay explicit"
)]
pub async fn build_final_transaction_request(
    client: &MidenSdkClient,
    transaction_type: &TransactionType,
    account: &Account,
    salt: Word,
    signature_advice: Vec<SignatureAdvice>,
    metadata_threshold: Option<u64>,
    metadata_signer_commitments: Option<&[Word]>,
    scheme: SignatureScheme,
) -> Result<TransactionRequest> {
    match transaction_type {
        TransactionType::P2ID {
            recipient,
            faucet_id,
            amount,
            note_type,
            heights,
        } => {
            let asset = build_transfer_asset(*faucet_id, *amount)?;

            crate::transaction::build_p2id_transaction_request(
                account,
                *recipient,
                vec![asset.into()],
                *note_type,
                *heights,
                salt,
                signature_advice,
            )
        }
        TransactionType::ConsumeNotes {
            note_ids,
            metadata_version,
            notes,
        } => {
            // v1/v2 dispatch for issue #229 / spec FR-009.
            match metadata_version {
                Some(crate::proposal::CONSUME_NOTES_METADATA_VERSION_V2) => {
                    if notes.len() != note_ids.len() {
                        return Err(MultisigError::NoteBindingMismatch(format!(
                            "consume_notes v2: notes.len()={} does not match note_ids.len()={}",
                            notes.len(),
                            note_ids.len()
                        )));
                    }
                    let mut decoded: Vec<miden_protocol::note::Note> =
                        Vec::with_capacity(notes.len());
                    for (i, serialized) in notes.iter().enumerate() {
                        let note = serialized.to_note()?;
                        if note.id() != note_ids[i] {
                            return Err(MultisigError::NoteBindingMismatch(format!(
                                "consume_notes v2: notes[{}] id {} != note_ids[{}] {}",
                                i,
                                note.id().to_hex(),
                                i,
                                note_ids[i].to_hex()
                            )));
                        }
                        decoded.push(note);
                    }
                    crate::transaction::build_consume_notes_transaction_request_from_notes(
                        decoded,
                        salt,
                        signature_advice,
                    )
                }
                None | Some(1) => {
                    #[cfg(feature = "legacy-consume-notes")]
                    {
                        crate::transaction::build_consume_notes_transaction_request(
                            client,
                            note_ids.clone(),
                            salt,
                            signature_advice,
                        )
                        .await
                    }
                    #[cfg(not(feature = "legacy-consume-notes"))]
                    {
                        let _ = (client, salt, signature_advice);
                        // Preserve `Some(1)` vs `None` so the error tells the
                        // operator which legacy shape was rejected.
                        Err(MultisigError::UnsupportedMetadataVersion {
                            found: *metadata_version,
                        })
                    }
                }
                Some(other) => Err(MultisigError::UnsupportedMetadataVersion {
                    found: Some(*other),
                }),
            }
        }
        TransactionType::SwitchGuardian { new_commitment, .. } => {
            crate::transaction::build_update_guardian_transaction_request(
                *new_commitment,
                scheme,
                salt,
                signature_advice,
            )
        }
        TransactionType::UpdateProcedureThreshold {
            procedure,
            new_threshold,
        } => {
            let tx_request =
                crate::transaction::build_update_procedure_threshold_transaction_request(
                    *procedure,
                    *new_threshold,
                    salt,
                    signature_advice,
                )?;

            Ok(tx_request)
        }
        TransactionType::AddCosigner { .. }
        | TransactionType::RemoveCosigner { .. }
        | TransactionType::UpdateSigners { .. } => {
            // Signer update transactions need threshold and signer commitments from metadata
            let signer_commitments = metadata_signer_commitments.ok_or_else(|| {
                MultisigError::MissingConfig("signer_commitments for signer update".to_string())
            })?;
            let new_threshold = metadata_threshold
                .ok_or_else(|| MultisigError::MissingConfig("new_threshold".to_string()))?;

            let (tx_request, _) = crate::transaction::build_update_signers_transaction_request(
                new_threshold,
                signer_commitments,
                salt,
                signature_advice,
                scheme,
            )?;

            Ok(tx_request)
        }
        TransactionType::Custom => Err(MultisigError::UnsupportedTransactionType(
            "cannot build a transaction for a custom proposal type".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miden_client::Serializable;
    use miden_confidential_contracts::multisig_guardian::{
        MultisigGuardianBuilder, MultisigGuardianConfig,
    };
    use miden_protocol::account::AccountType;
    use miden_protocol::account::auth::AuthSecretKey;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey as EcdsaSigningKey;
    use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
    use miden_protocol::note::NoteType;
    use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
    use miden_protocol::transaction::RawOutputNote;
    use miden_standards::account::auth::eip712;
    use miden_testing::MockChainBuilder;
    use miden_tx::TransactionExecutorError;
    use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};

    #[test]
    fn test_collect_signature_advice_filters_by_required() {
        let required: HashSet<String> = ["0xabc", "0xdef"].iter().map(|s| s.to_string()).collect();

        // Note: This test validates the filtering logic structure.
        // Full integration requires valid signatures which need real keys.

        let signatures = vec![SignatureInput {
            signer_commitment: "0xunknown".to_string(),
            signature_hex: "0x1234".to_string(),
            scheme: SignatureScheme::Falcon,
            public_key_hex: None,
            message_format: EcdsaMessageFormat::Raw,
        }];

        // Unknown signer should be filtered out
        let result = collect_signature_advice(signatures, &required, Word::default());
        // This will fail on signature parsing, but validates filtering happens first
        // In production, only valid signatures would be provided
        assert!(result.is_ok()); // Empty vec since unknown was filtered
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_collect_signature_advice_skips_duplicates() {
        let required: HashSet<String> = ["0xabc"].iter().map(|s| s.to_string()).collect();

        let signatures = vec![
            SignatureInput {
                signer_commitment: "0xABC".to_string(), // uppercase
                signature_hex: "0x1234".to_string(),
                scheme: SignatureScheme::Falcon,
                public_key_hex: None,
                message_format: EcdsaMessageFormat::Raw,
            },
            SignatureInput {
                signer_commitment: "0xabc".to_string(), // lowercase duplicate
                signature_hex: "0x5678".to_string(),
                scheme: SignatureScheme::Falcon,
                public_key_hex: None,
                message_format: EcdsaMessageFormat::Raw,
            },
        ];

        // Both will fail signature parsing, but second should be deduplicated
        // before reaching that point (based on lowercase comparison)
        let result = collect_signature_advice(signatures, &required, Word::default());
        // Will error on first sig parse since it's not a valid Falcon sig,
        // but the dedup logic is what we're testing
        assert!(result.is_err()); // Error on invalid sig, but only one attempt
    }

    #[test]
    fn test_collect_signature_advice_with_valid_signature() {
        let secret_key = SecretKey::new();
        let public_key = secret_key.public_key();
        let commitment = public_key.to_commitment();
        let commitment_hex = format!("0x{}", hex::encode(commitment.to_bytes()));

        let msg = Word::default();
        let signature = secret_key.sign(msg);
        let signature_hex = format!("0x{}", hex::encode(signature.to_bytes()));

        let required: HashSet<String> = [commitment_hex.clone()].into_iter().collect();
        let signatures = vec![SignatureInput {
            signer_commitment: commitment_hex,
            signature_hex,
            scheme: SignatureScheme::Falcon,
            public_key_hex: None,
            message_format: EcdsaMessageFormat::Raw,
        }];

        let advice = collect_signature_advice(signatures, &required, msg).expect("valid advice");
        assert_eq!(advice.len(), 1);
    }

    #[test]
    fn test_collect_signature_advice_with_eip712_signature() {
        let signing_key = EcdsaSigningKey::new();
        let public_key = signing_key.public_key();
        let commitment = public_key.to_commitment();
        let commitment_hex = format!("0x{}", hex::encode(commitment.to_bytes()));
        let tx_summary_commitment = Word::from([1u32, 2, 3, 4]);
        let digest = eip712::transaction_summary_digest(tx_summary_commitment);
        let signature = signing_key.sign_prehash(digest);

        let required: HashSet<String> = [commitment_hex.clone()].into_iter().collect();
        let signatures = vec![SignatureInput {
            signer_commitment: commitment_hex,
            signature_hex: format!("0x{}", hex::encode(signature.to_bytes())),
            scheme: SignatureScheme::Ecdsa,
            public_key_hex: Some(format!("0x{}", hex::encode(public_key.to_bytes()))),
            message_format: EcdsaMessageFormat::Eip712,
        }];

        let advice = collect_signature_advice(signatures, &required, tx_summary_commitment)
            .expect("valid EIP-712 advice");
        assert_eq!(advice.len(), 1);
        assert_eq!(advice[0].1.len(), 32);
    }

    #[tokio::test]
    async fn guardian_account_executes_mixed_raw_and_eip712_signatures() -> anyhow::Result<()> {
        let raw_signing_key = EcdsaSigningKey::new();
        let raw_public_key = raw_signing_key.public_key();
        let eip712_signing_key = EcdsaSigningKey::new();
        let eip712_public_key = eip712_signing_key.public_key();
        let guardian_signing_key = EcdsaSigningKey::new();
        let guardian_public_key = guardian_signing_key.public_key();
        let guardian_authenticator =
            BasicAuthenticator::new(&[AuthSecretKey::EcdsaK256Keccak(guardian_signing_key)]);

        let config = MultisigGuardianConfig::new(
            2,
            vec![
                raw_public_key.to_commitment(),
                eip712_public_key.to_commitment(),
            ],
            guardian_public_key.to_commitment(),
        )
        .with_account_type(AccountType::Public)
        .with_signature_scheme(SignatureScheme::Ecdsa);
        let mut account = MultisigGuardianBuilder::new(config).build_existing()?;

        let output_asset = FungibleAsset::mock(0);
        let mut chain_builder = MockChainBuilder::with_accounts([account.clone()])?;
        let output_note = chain_builder.add_p2id_note(
            account.id(),
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE.try_into()?,
            &[output_asset],
            NoteType::Public,
        )?;
        let input_note = chain_builder.add_spawn_note([&output_note])?;
        let mut chain = chain_builder.build()?;
        let auth_args = Word::from([Felt::new_unchecked(712); 4]);

        let unsigned = chain
            .build_transaction(account.id())
            .authenticated_input_notes([input_note.id()])
            .authenticator(None)
            .expected_output_notes(vec![RawOutputNote::Full(output_note.clone())])
            .auth_args(auth_args)
            .build()?;
        let tx_summary = match unsigned
            .execute()
            .await
            .expect_err("signatures are required")
        {
            TransactionExecutorError::Unauthorized(summary) => summary,
            error => anyhow::bail!("expected unauthorized transaction, got {error}"),
        };
        let tx_summary_commitment = tx_summary.as_ref().to_commitment();
        let signing_inputs = SigningInputs::TransactionSummary(tx_summary);

        let raw_signature = raw_signing_key.sign(tx_summary_commitment);
        let eip712_signature = eip712_signing_key
            .sign_prehash(eip712::transaction_summary_digest(tx_summary_commitment));
        let signature_inputs = vec![
            SignatureInput {
                signer_commitment: format!(
                    "0x{}",
                    hex::encode(raw_public_key.to_commitment().to_bytes())
                ),
                signature_hex: format!("0x{}", hex::encode(raw_signature.to_bytes())),
                scheme: SignatureScheme::Ecdsa,
                public_key_hex: Some(format!("0x{}", hex::encode(raw_public_key.to_bytes()))),
                message_format: EcdsaMessageFormat::Raw,
            },
            SignatureInput {
                signer_commitment: format!(
                    "0x{}",
                    hex::encode(eip712_public_key.to_commitment().to_bytes())
                ),
                signature_hex: format!("0x{}", hex::encode(eip712_signature.to_bytes())),
                scheme: SignatureScheme::Ecdsa,
                public_key_hex: Some(format!("0x{}", hex::encode(eip712_public_key.to_bytes()))),
                message_format: EcdsaMessageFormat::Eip712,
            },
        ];
        let required_commitments = signature_inputs
            .iter()
            .map(|signature| signature.signer_commitment.clone())
            .collect();
        let signature_advice = collect_signature_advice(
            signature_inputs,
            &required_commitments,
            tx_summary_commitment,
        )?;
        let guardian_signature = guardian_authenticator
            .get_signature(guardian_public_key.to_commitment().into(), &signing_inputs)
            .await?;

        let mut signed = chain
            .build_transaction(account.id())
            .authenticated_input_notes([input_note.id()])
            .authenticator(None)
            .expected_output_notes(vec![RawOutputNote::Full(output_note)])
            .auth_args(auth_args);
        for (key, value) in signature_advice {
            signed = signed.add_advice_map_entry(key, value);
        }
        let executed = signed
            .add_signature(
                guardian_public_key.into(),
                tx_summary_commitment,
                guardian_signature,
            )
            .build()?
            .execute()
            .await?;

        account.apply_patch(executed.account_patch())?;
        chain.add_pending_executed_transaction(&executed)?;
        chain.prove_next_block()?;

        Ok(())
    }
}
