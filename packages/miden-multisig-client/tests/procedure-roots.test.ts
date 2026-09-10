import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { PROCEDURE_ROOTS, getProcedureRoot } from '../src/procedures.js';

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

describe('procedure roots', () => {
  it('match the compiled account procedure hashes in SDK hex format', () => {
    const generated = loadGeneratedProcedureRoots();

    for (const procedure of generated.procedure_roots) {
      const version = procedure.name === 'auth_tx' ? 'miden-0.16-eip712' : 'miden-0.16-raw';
      expect(getProcedureRoot(procedure.name, version)).toBe(procedure.typescript_hex);
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

  it('keeps the original 0.16 raw auth root in the compatibility registry', () => {
    expect(getProcedureRoot('auth_tx')).toBe(PROCEDURE_ROOTS.auth_tx);
    expect(getProcedureRoot('auth_tx', 'miden-0.16-raw')).toBe(
      '0xa6aa6f69d9358535272ba433cd48d20628a5c69598e00c6dd01a22e83a5f15df',
    );
    expect(getProcedureRoot('send_asset', 'miden-0.16-raw')).toBe(
      PROCEDURE_ROOTS.send_asset,
    );
  });
});
