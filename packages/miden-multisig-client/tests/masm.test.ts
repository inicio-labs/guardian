import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { AccountComponent, MockWasmWebClient } from '@miden-sdk/miden-sdk';

import { GUARDED_MULTISIG_ACCOUNT_COMPONENT_MASM } from '../src/account/masm/account-components/auth.js';
import {
  EIP712_LIBRARY_MASM,
  MULTISIG_LIBRARY_MASM,
  SIGNATURE_LIBRARY_MASM,
} from '../src/account/masm/libraries/auth.js';
import { PROCEDURE_ROOTS } from '../src/procedures.js';

describe('generated MASM constants', () => {
  it.each([
    {
      name: 'guarded multisig component',
      generated: GUARDED_MULTISIG_ACCOUNT_COMPONENT_MASM,
      sourcePath: '../masm/account_components/auth/guarded_multisig.masm',
    },
    {
      name: 'EIP-712 library',
      generated: EIP712_LIBRARY_MASM,
      sourcePath: '../masm/libraries/auth/eip712.masm',
    },
    {
      name: 'signature library',
      generated: SIGNATURE_LIBRARY_MASM,
      sourcePath: '../masm/libraries/auth/signature.masm',
    },
    {
      name: 'multisig library',
      generated: MULTISIG_LIBRARY_MASM,
      sourcePath: '../masm/libraries/auth/multisig.masm',
    },
  ])('matches the vendored $name source', ({ generated, sourcePath }) => {
    expect(generated).toBe(readFileSync(new URL(sourcePath, import.meta.url), 'utf8'));
  });

  it('compiles to the Rust guarded-multisig procedure roots', async () => {
    const client = await MockWasmWebClient.createClient();
    const builder = await client.createCodeBuilder();
    const libraries = [
      ['guardian_sdk::auth::eip712', EIP712_LIBRARY_MASM],
      ['guardian_sdk::auth::signature', SIGNATURE_LIBRARY_MASM],
      ['guardian_sdk::auth::multisig', MULTISIG_LIBRARY_MASM],
    ] as const;

    for (const [namespace, source] of libraries) {
      builder.linkStaticLibrary(builder.buildLibrary(namespace, source));
    }

    const code = builder.compileAccountComponentCode(GUARDED_MULTISIG_ACCOUNT_COMPONENT_MASM);
    const component = AccountComponent.compile(code, []);

    expect(component.getProcedureHash('update_signers_and_threshold')).toBe(
      PROCEDURE_ROOTS.update_signers,
    );
    expect(component.getProcedureHash('set_procedure_threshold')).toBe(
      PROCEDURE_ROOTS.update_procedure_threshold,
    );
    expect(component.getProcedureHash('auth_tx_guarded_multisig')).toBe(
      PROCEDURE_ROOTS.auth_tx,
    );
    expect(component.getProcedureHash('update_guardian_public_key')).toBe(
      PROCEDURE_ROOTS.update_guardian,
    );
  });
});
