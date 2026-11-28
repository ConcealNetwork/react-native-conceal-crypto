import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const cppDir = join(root, 'cpp');

/** Native suites are skipped only locally; in CI a missing toolchain fails the build step. */
export function skipUnless(available: boolean, missing: string, suite: string): boolean {
  const skip = !available && !process.env.CI;
  if (skip) console.warn(`${missing} not found: ${suite} SKIPPED`);
  return skip;
}

export const hasCc = spawnSync('cc', ['--version']).status === 0;
export const skipNative = skipUnless(hasCc, 'cc', 'native ChaCha parity/interop tests');

export const hasSodium =
  hasCc &&
  spawnSync('cc', ['-x', 'c', '-', '-lsodium', '-o', '/dev/null'], {
    input: '#include <sodium.h>\nint main(void) { return sodium_init() < 0; }\n',
  }).status === 0;
export const skipArgon2id = skipUnless(
  hasCc && hasSodium,
  'cc or libsodium',
  'native Argon2id tests'
);

export const hasCxx = spawnSync('c++', ['--version']).status === 0;
export const skipCxx = skipUnless(hasCxx, 'c++', 'native mnemonic/HMAC tests');

type RunnerSpec = {
  /** Binary name; also prefixes the temp build dir. */
  name: string;
  compiler: string;
  std: string;
  /** Include dirs, or a function of the freshly created build dir. */
  includes: string[] | ((dir: string) => string[]);
  /** Repo-relative source files. */
  sources: string[];
  libs?: string[];
};

/** Compiles one test/native runner into a fresh temp dir. */
function compileRunner({ name, compiler, std, includes, sources, libs = [] }: RunnerSpec) {
  const dir = mkdtempSync(join(tmpdir(), `${name}-`));
  const includeDirs = typeof includes === 'function' ? includes(dir) : includes;
  const bin = join(dir, name);
  const build = spawnSync(
    compiler,
    [
      `-std=${std}`,
      '-O2',
      ...includeDirs.map((i) => `-I${i}`),
      ...sources.map((f) => join(root, f)),
      '-o',
      bin,
      ...libs,
    ],
    { encoding: 'utf8' }
  );
  if (build.status !== 0) throw new Error(`native ${name} build failed:\n${build.stderr}`);
  return {
    exec: (...args: string[]) => spawnSync(bin, args, { encoding: 'utf8' }),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** Compiles test/native/chacha_parity.c with cpp/chacha8.c + cpp/chacha12.c + cpp/chacha_ietf.c (no Nitro). */
export function buildNative() {
  const { exec, cleanup } = compileRunner({
    name: 'chacha_parity',
    compiler: 'cc',
    std: 'c11',
    includes: [cppDir],
    sources: [
      'test/native/chacha_parity.c',
      'cpp/chacha8.c',
      'cpp/chacha12.c',
      'cpp/chacha_ietf.c',
    ],
  });
  return {
    run: (rounds: 8 | 12, keyHex: string, ivHex: string, dataHex: string) =>
      exec(String(rounds), keyHex, ivHex, dataHex),
    exec,
    cleanup,
  };
}

/** Compiles test/native/argon2id_runner.c with cpp/argon2id_kdf.c against libsodium (no Nitro). */
export function buildArgon2id() {
  return compileRunner({
    name: 'argon2id_runner',
    compiler: 'cc',
    std: 'c11',
    includes: [cppDir],
    sources: ['test/native/argon2id_runner.c', 'cpp/argon2id_kdf.c'],
    libs: ['-lsodium'],
  });
}

/** Nitro headers include `<NitroModules/X.hpp>` but ship them in sub-directories; flatten them. */
export function listHeaders(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return listHeaders(p);
    return /\.h(pp)?$/.test(e.name) ? [p] : [];
  });
}

const nitroCpp = join(root, 'node_modules/react-native-nitro-modules/cpp');
const rnCommon = join(root, 'node_modules/react-native/ReactCommon');

/**
 * Symlinks the flattened `NitroModules/` dir into `dir` and returns the include paths needed to compile against
 * Nitro headers and the jsi bits they drag in (no Nitro runtime).
 */
export function nitroIncludes(dir: string): string[] {
  mkdirSync(join(dir, 'NitroModules'));
  for (const h of listHeaders(nitroCpp)) {
    symlinkSync(h, join(dir, 'NitroModules', basename(h)));
  }
  return [dir, join(nitroCpp, 'utils'), join(nitroCpp, 'core'), join(rnCommon, 'jsi'), rnCommon];
}

/** Compiles test/native/hmac_runner.cpp with cpp/Hmac.cpp + Nitro ArrayBuffer + the jsi bits it drags in (no Nitro runtime). */
export function buildHmac() {
  return compileRunner({
    name: 'hmac_runner',
    compiler: 'c++',
    std: 'c++20',
    includes: (dir) => [cppDir, ...nitroIncludes(dir)],
    sources: [
      'test/native/hmac_runner.cpp',
      'cpp/Hmac.cpp',
      'node_modules/react-native-nitro-modules/cpp/core/ArrayBuffer.cpp',
      'node_modules/react-native/ReactCommon/jsi/jsi/jsi.cpp',
    ],
  });
}

/** Compiles test/native/mnemonic_runner.cpp with cpp/Mnemonics (no Nitro). */
export function buildMnemonic() {
  return compileRunner({
    name: 'mnemonic_runner',
    compiler: 'c++',
    std: 'c++17',
    includes: [cppDir],
    sources: [
      'test/native/mnemonic_runner.cpp',
      'cpp/Mnemonics/Mnemonics.cpp',
      'cpp/Mnemonics/CRC32.cpp',
    ],
  });
}
