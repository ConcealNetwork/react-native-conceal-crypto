import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const hasCc = spawnSync('cc', ['--version']).status === 0;
/** Native tests are skipped only locally; in CI a missing `cc` fails the build step. */
export const skipNative = !hasCc && !process.env.CI;
if (skipNative) console.warn('cc not found: native ChaCha parity/interop tests SKIPPED');

/** Compiles test/native/chacha_parity.c with cpp/chacha8.c + cpp/chacha12.c + cpp/chacha_ietf.c (no Nitro). */
export function buildNative() {
  const dir = mkdtempSync(join(tmpdir(), 'chacha-parity-'));
  const bin = join(dir, 'chacha_parity');
  const build = spawnSync(
    'cc',
    [
      '-std=c11',
      '-O2',
      `-I${join(root, 'cpp')}`,
      join(root, 'test/native/chacha_parity.c'),
      join(root, 'cpp/chacha8.c'),
      join(root, 'cpp/chacha12.c'),
      join(root, 'cpp/chacha_ietf.c'),
      '-o',
      bin,
    ],
    { encoding: 'utf8' }
  );
  if (build.status !== 0) throw new Error(`native build failed:\n${build.stderr}`);
  return {
    run: (rounds: 8 | 12, keyHex: string, ivHex: string, dataHex: string) =>
      spawnSync(bin, [String(rounds), keyHex, ivHex, dataHex], { encoding: 'utf8' }),
    exec: (...args: string[]) => spawnSync(bin, args, { encoding: 'utf8' }),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}
