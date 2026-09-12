use base64::Engine;
use miden_protocol::account::Account;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::auth::Signature as AccountSignature;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak;
use miden_protocol::crypto::dsa::falcon512_poseidon2::Signature as FalconSignature;
use miden_protocol::transaction::TransactionSummary;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Felt, Hasher, Word};
use serde::{Deserialize, Serialize};

pub mod account_delta;
pub mod auth;
pub mod auth_request_message;
pub mod auth_request_payload;
pub mod felt;
pub mod hex;
pub mod lookup_auth_message;
pub mod retry;

use crate::hex::FromHex;

/// Supported signature schemes
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    Falcon,
    Ecdsa,
}

/// Message encoding used by an ECDSA proposal signature.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EcdsaMessageFormat {
    /// Sign the transaction-summary commitment directly.
    #[default]
    Raw,
    /// Sign the EIP-712 `MidenTransaction` object containing the summary commitment.
    Eip712,
}

impl EcdsaMessageFormat {
    pub fn from(value: &str) -> Result<Self, String> {
        match value {
            value if value.eq_ignore_ascii_case("raw") => Ok(Self::Raw),
            value if value.eq_ignore_ascii_case("eip712") => Ok(Self::Eip712),
            value => Err(format!("unsupported ECDSA message format: {value}")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Eip712 => "eip712",
        }
    }
}

impl SignatureScheme {
    pub fn from(ack_scheme: &str) -> Result<Self, String> {
        match ack_scheme {
            value if value.eq_ignore_ascii_case("falcon") => Ok(Self::Falcon),
            value if value.eq_ignore_ascii_case("ecdsa") => Ok(Self::Ecdsa),
            value => Err(format!("unsupported signature scheme: {}", value)),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Falcon => "falcon",
            Self::Ecdsa => "ecdsa",
        }
    }

    /// Maps to the upstream `AuthScheme` used by the `AuthGuardedMultisig` component.
    pub const fn auth_scheme(self) -> AuthScheme {
        match self {
            Self::Falcon => AuthScheme::Falcon512Poseidon2,
            Self::Ecdsa => AuthScheme::EcdsaK256Keccak,
        }
    }

    /// Numeric identifier the guarded-multisig MASM stores alongside each public key.
    pub const fn auth_scheme_id(self) -> u64 {
        self.auth_scheme() as u64
    }

    pub fn parse_signature_hex(self, signature_hex: &str) -> Result<AccountSignature, String> {
        match self {
            Self::Falcon => {
                let signature = FalconSignature::from_hex(&ensure_hex_prefix(signature_hex))
                    .map_err(|e| format!("failed to parse Falcon signature: {}", e))?;
                Ok(AccountSignature::from(signature))
            }
            Self::Ecdsa => {
                let mut signature_bytes = ::hex::decode(signature_hex.trim_start_matches("0x"))
                    .map_err(|e| format!("invalid ECDSA signature hex: {}", e))?;
                if signature_bytes.len() != 65 {
                    return Err("ECDSA signature must be 65 bytes".to_string());
                }
                if matches!(signature_bytes[64], 27 | 28) {
                    signature_bytes[64] -= 27;
                }
                let signature = ecdsa_k256_keccak::Signature::read_from_bytes(&signature_bytes)
                    .map_err(|e| format!("failed to parse ECDSA signature: {}", e))?;
                Ok(AccountSignature::EcdsaK256Keccak(signature))
            }
        }
    }

    pub fn build_signature_advice_entry(
        self,
        pubkey_commitment: Word,
        message: Word,
        signature: &AccountSignature,
        public_key_hex: Option<&str>,
    ) -> Result<(Word, Vec<Felt>), String> {
        let key = signature_advice_key(pubkey_commitment, message);

        let values = match (self, signature) {
            (Self::Falcon, AccountSignature::Falcon512Poseidon2(_)) => {
                signature.to_encoded_signature(message)
            }
            (Self::Falcon, _) => {
                return Err("expected Falcon signature for falcon scheme".to_string());
            }
            (Self::Ecdsa, AccountSignature::EcdsaK256Keccak(ecdsa_signature)) => {
                let public_key_hex = public_key_hex.ok_or_else(|| {
                    "ECDSA signature requires public key for advice preparation".to_string()
                })?;
                let public_key = parse_ecdsa_public_key_hex(public_key_hex)?;
                let actual_commitment = public_key.to_commitment();
                if actual_commitment != pubkey_commitment {
                    return Err(format!(
                        "ECDSA public key commitment mismatch: expected {}, got {}",
                        word_to_hex(pubkey_commitment),
                        word_to_hex(actual_commitment)
                    ));
                }
                AccountSignature::EcdsaK256Keccak(ecdsa_signature.clone())
                    .to_encoded_signature(message)
            }
            (Self::Ecdsa, _) => {
                return Err("expected ECDSA signature for ecdsa scheme".to_string());
            }
        };

        Ok((key, values))
    }

    /// Builds the advice entry for an EIP-712 transaction-summary signature.
    pub fn build_eip712_signature_advice_entry(
        self,
        pubkey_commitment: Word,
        tx_summary_commitment: Word,
        signature: &AccountSignature,
        public_key_hex: Option<&str>,
    ) -> Result<(Word, Vec<Felt>), String> {
        let AccountSignature::EcdsaK256Keccak(ecdsa_signature) = signature else {
            return Err("EIP-712 message format requires an ECDSA signature".to_string());
        };
        if self != Self::Ecdsa {
            return Err("EIP-712 message format requires the ecdsa scheme".to_string());
        }

        let public_key_hex = public_key_hex.ok_or_else(|| {
            "ECDSA signature requires public key for advice preparation".to_string()
        })?;
        let public_key = parse_ecdsa_public_key_hex(public_key_hex)?;
        let actual_commitment = public_key.to_commitment();
        if actual_commitment != pubkey_commitment {
            return Err(format!(
                "ECDSA public key commitment mismatch: expected {}, got {}",
                word_to_hex(pubkey_commitment),
                word_to_hex(actual_commitment)
            ));
        }

        let digest = miden_standards::account::auth::eip712::transaction_summary_digest(
            tx_summary_commitment,
        );
        if !public_key.verify_prehash(digest, ecdsa_signature) {
            return Err("invalid EIP-712 transaction-summary signature".to_string());
        }

        let key = miden_standards::account::auth::eip712::transaction_summary_signature_key(
            pubkey_commitment.into(),
            tx_summary_commitment,
        );
        let values =
            miden_core_lib::dsa::ecdsa_k256_keccak::encode_signature(&public_key, ecdsa_signature);

        Ok((key, values))
    }
}

impl std::fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn ensure_hex_prefix(hex: &str) -> String {
    if hex.starts_with("0x") {
        hex.to_string()
    } else {
        format!("0x{}", hex)
    }
}

fn word_to_hex(word: Word) -> String {
    format!("0x{}", ::hex::encode(word.to_bytes()))
}

fn signature_advice_key(pubkey_commitment: Word, message: Word) -> Word {
    let mut elements = Vec::with_capacity(8);
    elements.extend_from_slice(pubkey_commitment.as_elements());
    elements.extend_from_slice(message.as_elements());
    Hasher::hash_elements(&elements)
}

/// Parses a compressed or uncompressed SEC1 ECDSA public key.
pub fn parse_ecdsa_public_key_hex(
    public_key_hex: &str,
) -> Result<ecdsa_k256_keccak::PublicKey, String> {
    let public_key_bytes = ::hex::decode(public_key_hex.trim_start_matches("0x"))
        .map_err(|e| format!("invalid ECDSA public key hex: {}", e))?;
    match public_key_bytes.len() {
        33 => {}
        65 if public_key_bytes[0] == 0x04 => {}
        65 => return Err("uncompressed ECDSA public key must start with 0x04".to_string()),
        _ => return Err("ECDSA public key must be 33 or 65 bytes".to_string()),
    }

    let public_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|e| format!("invalid ECDSA public key: {e}"))?;
    let compressed = public_key.to_sec1_point(true);
    ecdsa_k256_keccak::PublicKey::read_from_bytes(compressed.as_bytes())
        .map_err(|e| format!("failed to deserialize ECDSA public key: {}", e))
}

/// Signature type for delta proposals
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, utoipa::ToSchema)]
#[serde(tag = "scheme", rename_all = "snake_case")]
pub enum ProposalSignature {
    Falcon {
        /// Hex-encoded Falcon signature
        signature: String,
    },
    Ecdsa {
        /// Hex-encoded ECDSA secp256k1 signature
        signature: String,
        /// Hex-encoded ECDSA public key (required for signature preparation)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
        /// Encoding of the message presented to the ECDSA signer.
        #[serde(default, skip_serializing_if = "is_raw_message_format")]
        message_format: EcdsaMessageFormat,
    },
}

impl ProposalSignature {
    /// Creates a ProposalSignature from a scheme, hex-encoded signature, and optional public key.
    pub fn from_scheme(
        scheme: SignatureScheme,
        signature: String,
        public_key: Option<String>,
    ) -> Self {
        match scheme {
            SignatureScheme::Falcon => ProposalSignature::Falcon { signature },
            SignatureScheme::Ecdsa => ProposalSignature::Ecdsa {
                signature,
                public_key,
                message_format: EcdsaMessageFormat::Raw,
            },
        }
    }

    /// Creates an ECDSA signature with an explicit message format.
    pub fn ecdsa(
        signature: String,
        public_key: Option<String>,
        message_format: EcdsaMessageFormat,
    ) -> Self {
        Self::Ecdsa {
            signature,
            public_key,
            message_format,
        }
    }

    /// Returns the public key hex if this is an ECDSA signature with a public key.
    pub fn public_key(&self) -> Option<&str> {
        match self {
            ProposalSignature::Ecdsa { public_key, .. } => public_key.as_deref(),
            _ => None,
        }
    }

    /// Returns the ECDSA message format. Falcon signatures always use the raw Miden word format.
    pub const fn message_format(&self) -> EcdsaMessageFormat {
        match self {
            Self::Falcon { .. } => EcdsaMessageFormat::Raw,
            Self::Ecdsa { message_format, .. } => *message_format,
        }
    }
}

const fn is_raw_message_format(format: &EcdsaMessageFormat) -> bool {
    matches!(format, EcdsaMessageFormat::Raw)
}

/// Delta payload structure containing transaction summary and signatures
/// This is the standard format for delta_payload in proposals
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeltaPayload {
    pub tx_summary: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<DeltaSignature>,
}

impl DeltaPayload {
    pub fn new(tx_summary: serde_json::Value) -> Self {
        Self {
            tx_summary,
            signatures: Vec::new(),
        }
    }

    pub fn with_signature(mut self, signature: DeltaSignature) -> Self {
        self.signatures.push(signature);
        self
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("DeltaPayload should always serialize")
    }
}

/// Signature entry in delta payload
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeltaSignature {
    pub signer_id: String,
    pub signature: ProposalSignature,
}

pub trait ToJson {
    fn to_json(&self) -> serde_json::Value;
}

pub trait FromJson: Sized {
    fn from_json(json: &serde_json::Value) -> Result<Self, String>;
}

impl ToJson for Account {
    fn to_json(&self) -> serde_json::Value {
        let bytes = self.to_bytes();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        serde_json::json!({
          "data": encoded,
          "account_id": self.id().to_hex(),
        })
    }
}

impl FromJson for Account {
    fn from_json(json: &serde_json::Value) -> Result<Self, String> {
        let encoded = json
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'data' field")?;

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("Base64 decode error: {e}"))?;

        Account::read_from_bytes(&bytes).map_err(|e| format!("Deserialization error: {e}"))
    }
}

impl ToJson for TransactionSummary {
    fn to_json(&self) -> serde_json::Value {
        let bytes = self.to_bytes();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        serde_json::json!({
          "data": encoded,
        })
    }
}

impl FromJson for TransactionSummary {
    fn from_json(json: &serde_json::Value) -> Result<Self, String> {
        let encoded = json
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid 'data' field in delta payload")?;

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("Base64 decode error: {e}"))?;

        TransactionSummary::read_from_bytes(&bytes)
            .map_err(|e| format!("AccountDelta deserialization error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miden_protocol::{
        account::auth::{AuthScheme, Signature as AccountSignature},
        account::{AccountBuilder, auth::PublicKeyCommitment},
        crypto::dsa::ecdsa_k256_keccak::SigningKey as EcdsaSecretKey,
        crypto::dsa::falcon512_poseidon2::SecretKey,
    };
    use miden_standards::account::{
        auth::{Approver, AuthSingleSig},
        wallets::BasicWallet,
    };

    #[test]
    fn test_account_json_round_trip() {
        // Create a test account
        let secret_key = SecretKey::new();
        let public_key_commitment =
            PublicKeyCommitment::from(secret_key.public_key().to_commitment());
        let account = AccountBuilder::new([0xff; 32])
            .with_component(AuthSingleSig::new(Approver::new(
                public_key_commitment,
                AuthScheme::Falcon512Poseidon2,
            )))
            .with_component(BasicWallet)
            .build()
            .unwrap();

        // Serialize to JSON
        let json = account.to_json();

        // Deserialize from JSON
        let deserialized_account =
            Account::from_json(&json).expect("Failed to deserialize account");

        // Verify round-trip
        assert_eq!(account.id(), deserialized_account.id());
        assert_eq!(account.nonce(), deserialized_account.nonce());
        assert_eq!(
            account.to_commitment(),
            deserialized_account.to_commitment()
        );
        assert_eq!(
            account.storage().to_commitment(),
            deserialized_account.storage().to_commitment()
        );
        assert_eq!(
            account.code().commitment(),
            deserialized_account.code().commitment()
        );
    }

    #[test]
    fn signature_scheme_from_accepts_known_values_case_insensitively() {
        assert_eq!(
            SignatureScheme::from("falcon").unwrap(),
            SignatureScheme::Falcon
        );
        assert_eq!(
            SignatureScheme::from("ECDSA").unwrap(),
            SignatureScheme::Ecdsa
        );
    }

    #[test]
    fn signature_scheme_from_rejects_unknown_values() {
        let error = SignatureScheme::from("unknown").unwrap_err();

        assert!(error.contains("unsupported signature scheme"));
    }

    #[test]
    fn signature_scheme_parse_signature_hex_accepts_falcon_signatures() {
        let secret_key = SecretKey::new();
        let message = Word::from([1u32, 2, 3, 4]);
        let signature = secret_key.sign(message);
        let signature_hex = format!("0x{}", ::hex::encode(signature.to_bytes()));

        let parsed = SignatureScheme::Falcon
            .parse_signature_hex(&signature_hex)
            .unwrap();

        assert!(matches!(parsed, AccountSignature::Falcon512Poseidon2(_)));
    }

    #[test]
    fn signature_scheme_parse_signature_hex_accepts_ecdsa_signatures() {
        let secret_key = EcdsaSecretKey::new();
        let message = Word::from([1u32, 2, 3, 4]);
        let signature = secret_key.sign(message);
        let signature_hex = format!("0x{}", ::hex::encode(signature.to_bytes()));

        let parsed = SignatureScheme::Ecdsa
            .parse_signature_hex(&signature_hex)
            .unwrap();

        assert!(matches!(parsed, AccountSignature::EcdsaK256Keccak(_)));
    }

    #[test]
    fn ecdsa_public_key_parser_accepts_uncompressed_sec1() {
        let compressed = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let uncompressed = concat!(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );

        let compressed_key = parse_ecdsa_public_key_hex(compressed).unwrap();
        let uncompressed_key = parse_ecdsa_public_key_hex(uncompressed).unwrap();

        assert_eq!(compressed_key, uncompressed_key);
    }

    #[test]
    fn ecdsa_public_key_parser_rejects_trailing_bytes() {
        let key = concat!(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "00"
        );

        let error = parse_ecdsa_public_key_hex(key).expect_err("trailing bytes must fail");

        assert_eq!(error, "ECDSA public key must be 33 or 65 bytes");
    }

    #[test]
    fn ecdsa_public_key_parser_rejects_invalid_uncompressed_point() {
        let key = concat!(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        let error = parse_ecdsa_public_key_hex(key).expect_err("invalid point must fail");

        assert!(error.contains("invalid ECDSA public key"));
    }

    #[test]
    fn signature_scheme_normalizes_ethereum_recovery_ids() {
        let secret_key = EcdsaSecretKey::new();
        let signature = secret_key.sign(Word::from([1u32, 2, 3, 4]));

        for recovery_id in [27, 28] {
            let mut signature_bytes = signature.to_bytes();
            signature_bytes[64] = recovery_id;
            let signature_hex = format!("0x{}", ::hex::encode(signature_bytes));

            let parsed = SignatureScheme::Ecdsa
                .parse_signature_hex(&signature_hex)
                .expect("Ethereum recovery ID should be accepted");
            let AccountSignature::EcdsaK256Keccak(parsed) = parsed else {
                panic!("expected ECDSA signature");
            };

            assert_eq!(parsed.v(), recovery_id - 27);
        }
    }

    #[test]
    fn signature_scheme_rejects_trailing_ecdsa_signature_bytes() {
        let secret_key = EcdsaSecretKey::new();
        let mut signature = secret_key.sign(Word::from([1u32, 2, 3, 4])).to_bytes();
        signature.push(0);

        let error = SignatureScheme::Ecdsa
            .parse_signature_hex(&::hex::encode(signature))
            .expect_err("trailing bytes must fail");

        assert_eq!(error, "ECDSA signature must be 65 bytes");
    }

    #[test]
    fn signature_scheme_build_signature_advice_entry_accepts_falcon_signatures() {
        let secret_key = SecretKey::new();
        let message = Word::from([1u32, 2, 3, 4]);
        let commitment = Word::from([5u32, 6, 7, 8]);
        let signature = AccountSignature::from(secret_key.sign(message));

        let (key, values) = SignatureScheme::Falcon
            .build_signature_advice_entry(commitment, message, &signature, None)
            .unwrap();

        let mut elements = Vec::with_capacity(8);
        elements.extend_from_slice(commitment.as_elements());
        elements.extend_from_slice(message.as_elements());

        assert_eq!(key, Hasher::hash_elements(&elements));
        assert!(!values.is_empty());
    }

    #[test]
    fn signature_scheme_build_signature_advice_entry_accepts_ecdsa_signatures() {
        let secret_key = EcdsaSecretKey::new();
        let public_key = secret_key.public_key();
        let public_key_hex = format!("0x{}", ::hex::encode(public_key.to_bytes()));
        let message = Word::from([1u32, 2, 3, 4]);
        let commitment = public_key.to_commitment();
        let signature = AccountSignature::EcdsaK256Keccak(secret_key.sign(message));

        let (key, values) = SignatureScheme::Ecdsa
            .build_signature_advice_entry(commitment, message, &signature, Some(&public_key_hex))
            .unwrap();

        let mut elements = Vec::with_capacity(8);
        elements.extend_from_slice(commitment.as_elements());
        elements.extend_from_slice(message.as_elements());

        assert_eq!(key, Hasher::hash_elements(&elements));
        assert!(!values.is_empty());
    }

    #[test]
    fn signature_scheme_builds_domain_separated_eip712_advice_entry() {
        let secret_key = EcdsaSecretKey::new();
        let public_key = secret_key.public_key();
        let public_key_hex = format!("0x{}", ::hex::encode(public_key.to_bytes()));
        let commitment = public_key.to_commitment();
        let tx_summary_commitment = Word::from([1u32, 2, 3, 4]);
        let digest = miden_standards::account::auth::eip712::transaction_summary_digest(
            tx_summary_commitment,
        );
        let signature = AccountSignature::EcdsaK256Keccak(secret_key.sign_prehash(digest));

        let (key, values) = SignatureScheme::Ecdsa
            .build_eip712_signature_advice_entry(
                commitment,
                tx_summary_commitment,
                &signature,
                Some(&public_key_hex),
            )
            .unwrap();

        let raw_key = signature_advice_key(commitment, tx_summary_commitment);
        let domain = Word::new([
            Felt::new_unchecked(0x3231_3750_4945),
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ]);
        let expected_key = Hasher::merge(&[raw_key, domain]);
        assert_eq!(key, expected_key);
        assert_ne!(key, raw_key);
        assert_eq!(values.len(), 32);
    }

    #[test]
    fn signature_scheme_accepts_ledger_eip712_signature() {
        let public_key_hex = concat!(
            "0x0437b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299",
            "a6179912b7451c09896c4098eca7ce6b2e58330672795e847c4d6af44e024230"
        );
        let signature_hex = concat!(
            "0x3a260929a57fc23dc0b35b3bd41aa66df2d6cf0aff4914e5caf25f65f2f9f15b",
            "2fedb745401497982d8ee305c490af99440edabfd17ada7acfd527b7342f54b41b"
        );
        let public_key = parse_ecdsa_public_key_hex(public_key_hex).unwrap();
        let signature = SignatureScheme::Ecdsa
            .parse_signature_hex(signature_hex)
            .unwrap();
        let tx_summary_limb = Felt::new(0xefcd_ab89_6745_2301).unwrap();
        let tx_summary_commitment = Word::new([tx_summary_limb; 4]);

        let (_, values) = SignatureScheme::Ecdsa
            .build_eip712_signature_advice_entry(
                public_key.to_commitment(),
                tx_summary_commitment,
                &signature,
                Some(public_key_hex),
            )
            .unwrap();

        assert_eq!(values.len(), 32);
    }

    #[test]
    fn signature_scheme_rejects_invalid_eip712_signature() {
        let secret_key = EcdsaSecretKey::new();
        let public_key = secret_key.public_key();
        let public_key_hex = format!("0x{}", ::hex::encode(public_key.to_bytes()));
        let signature = AccountSignature::EcdsaK256Keccak(secret_key.sign_prehash([7u8; 32]));

        let error = SignatureScheme::Ecdsa
            .build_eip712_signature_advice_entry(
                public_key.to_commitment(),
                Word::from([1u32, 2, 3, 4]),
                &signature,
                Some(&public_key_hex),
            )
            .expect_err("signature for another digest must fail");

        assert_eq!(error, "invalid EIP-712 transaction-summary signature");
    }

    #[test]
    fn proposal_signature_message_format_is_backward_compatible() {
        let raw: ProposalSignature = serde_json::from_value(serde_json::json!({
            "scheme": "ecdsa",
            "signature": "0x01",
            "public_key": "0x02"
        }))
        .unwrap();
        assert_eq!(raw.message_format(), EcdsaMessageFormat::Raw);

        let eip712: ProposalSignature = serde_json::from_value(serde_json::json!({
            "scheme": "ecdsa",
            "signature": "0x01",
            "public_key": "0x02",
            "message_format": "eip712"
        }))
        .unwrap();
        assert_eq!(eip712.message_format(), EcdsaMessageFormat::Eip712);
    }

    #[test]
    fn signature_scheme_build_signature_advice_entry_requires_ecdsa_public_key() {
        let secret_key = EcdsaSecretKey::new();
        let message = Word::from([1u32, 2, 3, 4]);
        let commitment = secret_key.public_key().to_commitment();
        let signature = AccountSignature::EcdsaK256Keccak(secret_key.sign(message));

        let error = SignatureScheme::Ecdsa
            .build_signature_advice_entry(commitment, message, &signature, None)
            .unwrap_err();

        assert!(error.contains("requires public key"));
    }

    #[test]
    fn signature_scheme_build_signature_advice_entry_rejects_mismatched_ecdsa_public_key() {
        let secret_key = EcdsaSecretKey::new();
        let other_secret_key = EcdsaSecretKey::new();
        let other_public_key = other_secret_key.public_key();
        let other_public_key_hex = format!("0x{}", ::hex::encode(other_public_key.to_bytes()));
        let message = Word::from([1u32, 2, 3, 4]);
        let commitment = secret_key.public_key().to_commitment();
        let signature = AccountSignature::EcdsaK256Keccak(secret_key.sign(message));

        let error = SignatureScheme::Ecdsa
            .build_signature_advice_entry(
                commitment,
                message,
                &signature,
                Some(&other_public_key_hex),
            )
            .unwrap_err();

        assert!(error.contains("ECDSA public key commitment mismatch"));
    }
}
