import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { nitroIncludes, root, skipUnless } from './helpers/native';

const hasClang = spawnSync('clang++', ['--version']).status === 0;
const hasSodium =
  hasClang &&
  spawnSync('clang++', ['-fsyntax-only', '-x', 'c++', '-'], { input: '#include <sodium.h>\n' })
    .status === 0;
const skip = skipUnless(
  hasClang && hasSodium,
  'clang++ or <sodium.h>',
  'Nitro bridge compile check'
);

describe.skipIf(skip)('Nitro bridge compile check (clang++ -fsyntax-only)', () => {
  let dir: string;
  let includes: string[];

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'nitro-headers-'));
    includes = nitroIncludes(dir);
  });

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  /** install.cpp instantiates HybridConcealCrypto, so it fails if any spec getter is unimplemented. */
  for (const file of ['cpp/HybridCypher.cpp', 'cpp/HybridConcealCrypto.cpp', 'cpp/install.cpp']) {
    it(`${file} compiles`, { timeout: 60_000 }, () => {
      const r = spawnSync(
        'clang++',
        [
          '-std=c++20',
          '-fsyntax-only',
          ...includes.map((i) => `-I${i}`),
          `-I${join(root, 'cpp')}`,
          join(root, file),
        ],
        { encoding: 'utf8' }
      );
      expect(r.status, r.stderr).toBe(0);
    });
  }
});
