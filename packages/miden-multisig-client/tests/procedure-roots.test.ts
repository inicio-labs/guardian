import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { Account } from '@miden-sdk/miden-sdk';
import { describe, expect, it } from 'vitest';

import {
  BROWSER_AUTH_TX_ROOT,
  PROCEDURE_ROOTS,
  assertSupportedMultisigAccount,
  getProcedureRoot,
} from '../src/procedures.js';

interface GeneratedProcedureRoot {
  name: keyof typeof PROCEDURE_ROOTS;
  rust_hex: string;
  typescript_hex: string;
}

interface GeneratedProcedureRoots {
  procedure_roots: GeneratedProcedureRoot[];
}

let cachedRoots: GeneratedProcedureRoots | null = null;

function loadGeneratedProcedureRoots(): GeneratedProcedureRoots {
  if (cachedRoots) {
    return cachedRoots;
  }

  const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
  const output = execFileSync(
    'cargo',
    ['run', '--quiet', '--example', 'procedure_roots', '-p', 'miden-multisig-client', '--', '--json'],
    {
      cwd: repoRoot,
      encoding: 'utf8',
    },
  );

  cachedRoots = JSON.parse(output) as GeneratedProcedureRoots;
  return cachedRoots;
}

function accountWithProcedureRoots(...roots: string[]): Account {
  return {
    code: () => ({
      hasProcedure: (root: { toHex(): string }) => roots.includes(root.toHex()),
    }),
  } as unknown as Account;
}

describe('procedure roots', () => {
  it('match the compiled account procedure hashes in SDK hex format', () => {
    const generated = loadGeneratedProcedureRoots();

    for (const procedure of generated.procedure_roots) {
      expect(getProcedureRoot(procedure.name)).toBe(procedure.typescript_hex);
    }
  });

  it('do not use the Rust display encoding', () => {
    const generated = loadGeneratedProcedureRoots();
    const sendAsset = generated.procedure_roots.find(
      (procedure) => procedure.name === 'send_asset',
    );

    expect(sendAsset).toBeDefined();
    expect(PROCEDURE_ROOTS.send_asset).toBe(sendAsset?.typescript_hex);
    expect(PROCEDURE_ROOTS.send_asset).not.toBe(sendAsset?.rust_hex);
  });

  it('uses only the EIP-712-capable authentication root', () => {
    expect(getProcedureRoot('auth_tx')).toBe(
      '0x27446960c72463d647d560c573980568fdf50463752fc0d9a111eda3760d74b9',
    );
    expect(getProcedureRoot('auth_tx')).toBe(PROCEDURE_ROOTS.auth_tx);
    expect(BROWSER_AUTH_TX_ROOT).toBe(
      '0x723addb596afd2b56c09ecde616daeacca3280a146db8a8e7708db4bae143fc6',
    );
  });

  it('accepts accounts created by either current SDK builder', () => {
    expect(() =>
      assertSupportedMultisigAccount(accountWithProcedureRoots(PROCEDURE_ROOTS.auth_tx)),
    ).not.toThrow();
    expect(() =>
      assertSupportedMultisigAccount(accountWithProcedureRoots(BROWSER_AUTH_TX_ROOT)),
    ).not.toThrow();
  });

  it('rejects the legacy raw-only authenticator', () => {
    const legacyRoot = '0xa6aa6f69d9358535272ba433cd48d20628a5c69598e00c6dd01a22e83a5f15df';
    expect(() => assertSupportedMultisigAccount(accountWithProcedureRoots(legacyRoot))).toThrow(
      'EIP-712-capable guarded-multisig authenticator',
    );
  });
});
