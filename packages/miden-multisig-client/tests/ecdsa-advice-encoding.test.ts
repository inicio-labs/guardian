import { Felt, FeltArray, Poseidon2, PublicKey, Signature, Word } from '@miden-sdk/miden-sdk';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { describe, expect, it } from 'vitest';

import {
  assertEcdsaPrehashSignatureRecoverable,
  assertEcdsaSignatureRecoverable,
  buildEip712SignatureAdviceEntry,
  buildSignatureAdviceEntry,
  eip712TransactionSummaryDigest,
} from '../src/utils/signature.js';
import { bytesToHex, hexToBytes } from '../src/utils/encoding.js';

const ECDSA_AUTH_SCHEME_ID = 1;
const PRIVATE_KEY_HEX = '0x' + '11'.repeat(32);
const MESSAGE_HEX = '0x' + 'ab'.repeat(32);

/**
 * Sign `MESSAGE_HEX` the way an `ecdsa_k256_keccak` signer does: keccak256 over
 * the message word's bytes, then secp256k1 over that digest. Returns the SDK
 * `Signature` plus the compressed public key.
 */
function signEcdsa(): { signature: Signature; publicKeyHex: string } {
  const priv = hexToBytes(PRIVATE_KEY_HEX);
  const digest = keccak_256(hexToBytes(MESSAGE_HEX));
  const sig = secp256k1.sign(digest, priv, { prehash: false });

  const serialized = new Uint8Array(66);
  serialized[0] = ECDSA_AUTH_SCHEME_ID;
  serialized.set(sig.toCompactRawBytes(), 1);
  serialized[65] = sig.recovery;

  return {
    signature: Signature.deserialize(serialized),
    publicKeyHex: bytesToHex(secp256k1.getPublicKey(priv, true)),
  };
}

function commitmentHex(compressedPublicKeyHex: string): string {
  const bytes = hexToBytes(compressedPublicKeyHex);
  const serialized = new Uint8Array(bytes.length + 1);
  serialized[0] = ECDSA_AUTH_SCHEME_ID;
  serialized.set(bytes, 1);
  return PublicKey.deserialize(serialized).toCommitment().toHex();
}

describe('ECDSA advice payload comes from the SDK, not from local packing', () => {
  it('emits the 32-element QX||QY||SIG_R||SIG_S payload', () => {
    const { signature } = signEcdsa();

    const { values } = buildSignatureAdviceEntry(
      Word.fromHex(commitmentHex(signEcdsa().publicKeyHex)),
      Word.fromHex(MESSAGE_HEX),
      signature,
    );

    expect(values).toHaveLength(32);
  });

  it("first 16 elements hash to the verifier's expected PK_COMM", () => {
    // This is the invariant `ecdsa_k256_keccak::verify` asserts before checking
    // the signature: Poseidon2::hash_elements(QX[8] || QY[8]) == PK_COMM. It is
    // the assertion that fired ("invalid public key commitment") when this
    // client still packed the pre-miden-crypto-0.28 compressed-key encoding.
    const { signature, publicKeyHex } = signEcdsa();

    const { values } = buildSignatureAdviceEntry(
      Word.fromHex(commitmentHex(publicKeyHex)),
      Word.fromHex(MESSAGE_HEX),
      signature,
    );
    const publicKeyElements = values.slice(0, 16).map((f) => new Felt(BigInt(f.toString())));

    expect(Poseidon2.hashElements(new FeltArray(publicKeyElements)).toHex()).toBe(
      commitmentHex(publicKeyHex),
    );
  });

  it('keys the advice entry on the commitment and message', () => {
    const { signature, publicKeyHex } = signEcdsa();
    const commitment = commitmentHex(publicKeyHex);

    // `Word.toFelts()` consumes the Word, and the helper consumes both of its
    // Words, so the expected value needs its own instances.
    const { key } = buildSignatureAdviceEntry(
      Word.fromHex(commitment),
      Word.fromHex(MESSAGE_HEX),
      signature,
    );
    const expected = Poseidon2.hashElements(
      new FeltArray([
        ...Word.fromHex(commitment).toFelts(),
        ...Word.fromHex(MESSAGE_HEX).toFelts(),
      ]),
    );

    expect(key.toHex()).toBe(expected.toHex());
  });
});

describe('ECDSA recoverability guard', () => {
  const priv = hexToBytes(PRIVATE_KEY_HEX);
  const publicKeyHex = bytesToHex(secp256k1.getPublicKey(priv, true));

  function signatureHex(): string {
    const digest = keccak_256(hexToBytes(MESSAGE_HEX));
    const sig = secp256k1.sign(digest, priv, { prehash: false });
    const withV = new Uint8Array(65);
    withV.set(sig.toCompactRawBytes(), 0);
    withV[64] = sig.recovery;
    return bytesToHex(withV);
  }

  it('accepts a signature that recovers the expected key', () => {
    expect(() =>
      assertEcdsaSignatureRecoverable(signatureHex(), MESSAGE_HEX, publicKeyHex),
    ).not.toThrow();
  });

  it('rejects an unrecoverable signature instead of letting WASM abort', () => {
    const unrecoverable = `0x${'00'.repeat(32)}${'11'.repeat(32)}00`;

    expect(() =>
      assertEcdsaSignatureRecoverable(unrecoverable, MESSAGE_HEX, publicKeyHex),
    ).toThrow(/does not recover a public key/);
  });

  it('rejects a signature that recovers a different key', () => {
    const otherKey = bytesToHex(secp256k1.getPublicKey(hexToBytes('0x' + '22'.repeat(32)), true));

    expect(() => assertEcdsaSignatureRecoverable(signatureHex(), MESSAGE_HEX, otherKey)).toThrow(
      /does not match the expected/,
    );
  });

  it('rejects a wrong recovery byte', () => {
    const flipped = signatureHex().slice(0, -2) + (signatureHex().endsWith('00') ? '01' : '00');

    expect(() => assertEcdsaSignatureRecoverable(flipped, MESSAGE_HEX, publicKeyHex)).toThrow();
  });
});

describe('EIP-712 transaction-summary advice', () => {
  const txSummaryHash = () =>
    new Word(
      new BigUint64Array([
        0x0123_4567_89ab_cdefn,
        0x1020_3040_5060_7080n,
        0x0f1e_2d3c_4b5a_6978n,
        0x1122_3344_5566_7788n,
      ]),
    );

  it('matches the protocol digest vector', () => {
    expect(bytesToHex(eip712TransactionSummaryDigest(txSummaryHash()))).toBe(
      '0x03bc3b7d14f9c81dfa715b49b2297f070f91b4223adb2f6afe7d68b91122451d',
    );
  });

  it('accepts the Ledger Speculos prehash signature without hashing it again', () => {
    const publicKeyHex =
      '0x0437b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299a6179912b7451c09896c4098eca7ce6b2e58330672795e847c4d6af44e024230';
    const signatureHex =
      '0x3a260929a57fc23dc0b35b3bd41aa66df2d6cf0aff4914e5caf25f65f2f9f15b2fedb745401497982d8ee305c490af99440edabfd17ada7acfd527b7342f54b400';
    const digestHex = '0xe24fddd9b9535fa24adf94097b68c4f00bbed14ee6970cd41d62a62b5b6a07b3';

    expect(() =>
      assertEcdsaPrehashSignatureRecoverable(signatureHex, digestHex, publicKeyHex),
    ).not.toThrow();
    expect(() => assertEcdsaSignatureRecoverable(signatureHex, digestHex, publicKeyHex)).toThrow();
  });

  it('builds the domain-separated key and prepared ECDSA witness', () => {
    const privateKey = hexToBytes(PRIVATE_KEY_HEX);
    const digest = eip712TransactionSummaryDigest(txSummaryHash());
    const compact = secp256k1.sign(digest, privateKey, { prehash: false });
    const serialized = new Uint8Array(66);
    serialized[0] = ECDSA_AUTH_SCHEME_ID;
    serialized.set(compact.toCompactRawBytes(), 1);
    serialized[65] = compact.recovery;

    const publicKeyHex = bytesToHex(secp256k1.getPublicKey(privateKey, true));
    expect(() =>
      assertEcdsaPrehashSignatureRecoverable(
        bytesToHex(serialized.slice(1)),
        bytesToHex(digest),
        publicKeyHex,
      ),
    ).not.toThrow();
    const commitment = Word.fromHex(commitmentHex(publicKeyHex));
    const { key, values } = buildEip712SignatureAdviceEntry(
      commitment,
      txSummaryHash(),
      Signature.deserialize(serialized),
    );

    const rawKey = Poseidon2.hashElements(
      new FeltArray([...Word.fromHex(commitmentHex(publicKeyHex)).toFelts(), ...txSummaryHash().toFelts()]),
    );
    const domain = new Word(new BigUint64Array([0x3231_3750_4945n, 0n, 0n, 0n]));
    const expectedKey = Poseidon2.hashElements(
      new FeltArray([...rawKey.toFelts(), ...domain.toFelts()]),
    );

    expect(key.toHex()).toBe(expectedKey.toHex());
    expect(values).toHaveLength(32);
  });
});
