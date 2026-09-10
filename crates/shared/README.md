## GUARDIAN Shared Crate

This crate contains shared types and utilities for the GUARDIAN project.

On the EIP-712 prototype branch, standalone consumers must also add the
[protocol patches](../miden-multisig-client/README.md#eip-712-prototype-setup)
to their workspace root.

### Features

- `auth`: Authentication utilities for Miden Falcon RPO-512
- `hex`: Hex utilities for converting between types and hex strings
- `retry`: Transient-failure classification, jittered backoff, and the retry
  policy types shared by the Guardian server and the Miden SDK clients
- `account_delta`: Applying a Miden `AccountDelta` to an account, with or
  without an additional storage patch, and reconstructing an account from a
  full-state delta. Shared so the server and the multisig client agree
  byte-for-byte on the resulting state commitment
- `ProposalSignature`: Miden ECDSA proposal signatures may select the `raw`
  (default) or `eip712` message format. Falcon signatures are always raw.
