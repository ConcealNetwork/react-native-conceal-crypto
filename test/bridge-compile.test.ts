import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { root } from './helpers/native';

const hasClang = spawnSync('clang++', ['--version']).status === 0;
const hasSodium =
  hasClang &&
  spawnSync('clang++', ['-fsyntax-only', '-x', 'c++', '-'], { input: '#include <sodium.h>\n' })
    .status === 0;
/** Skipped only locally; in CI a missing clang++ or libsodium fails the test. */
const skip = !(hasClang && hasSodium) && !process.env.CI;
if (skip) console.warn('clang++ or <sodium.h> not found: Nitro bridge compile check SKIPPED');

/** Nitro headers include `<NitroModules/X.hpp>` but ship them in sub-directories; flatten them. */
function listHeaders(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return listHeaders(p);
    return /\.h(pp)?$/.test(e.name) ? [p] : [];
  });
}

describe.skipIf(skip)('Nitro bridge compile check (clang++ -fsyntax-only)', () => {
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'nitro-headers-'));
    mkdirSync(join(dir, 'NitroModules'));
    for (const h of listHeaders(join(root, 'node_modules/react-native-nitro-modules/cpp'))) {
      symlinkSync(h, join(dir, 'NitroModules', basename(h)));
    }
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
          `-I${dir}`,
          `-I${join(root, 'node_modules/react-native/ReactCommon/jsi')}`,
          `-I${join(root, 'node_modules/react-native/ReactCommon')}`,
          `-I${join(root, 'cpp')}`,
          join(root, file),
        ],
        { encoding: 'utf8' }
      );
      expect(r.status, r.stderr).toBe(0);
    });
  }
});
