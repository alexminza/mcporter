// Usage: pnpm build && node scripts/test-vault-downgrade.mjs <installed-mcporter-0.15.0>
// All credentials and homes are synthetic; no provider or account is contacted.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const current = path.resolve(process.argv[3] ?? fileURLToPath(new URL('..', import.meta.url)));
const previous = path.resolve(process.argv[2] ?? 'missing-previous-package');
assert.equal(JSON.parse(await fs.readFile(path.join(previous, 'package.json'))).version, '0.15.0');
const root = await fs.mkdtemp(path.join(os.tmpdir(), 'mcporter-downgrade-'));
const password = 'synthetic-downgrade-test-password-only';
const token = 'synthetic-downgrade-access-token';
const config = path.join(root, 'config.json');
await fs.writeFile(config, JSON.stringify({ mcpServers: { demo: { baseUrl: 'https://example.com/mcp' } } }));

function environment(profile, encrypted) {
  const home = path.join(root, profile);
  const env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: path.join(home, 'config'),
    XDG_DATA_HOME: path.join(home, 'data'),
    XDG_STATE_HOME: path.join(home, 'state'),
    XDG_CACHE_HOME: path.join(home, 'cache'),
    MCPORTER_DAEMON_DIR: path.join(home, 'daemon'),
  };
  delete env.MCPORTER_VAULT_ENCRYPTION;
  delete env.MCPORTER_VAULT_PASSWORD;
  if (encrypted) env.MCPORTER_VAULT_PASSWORD = password;
  return env;
}
function runCli(pkg, profile, encrypted, args, input) {
  const result = spawnSync(process.execPath, [path.join(pkg, 'dist/cli.js'), '--config', config, ...args], {
    env: environment(profile, encrypted),
    input,
    encoding: 'utf8',
    timeout: 30_000,
  });
  return result;
}
function writeVault(pkg, profile, encrypted) {
  const result = runCli(
    pkg,
    profile,
    encrypted,
    ['vault', 'set', 'demo', '--stdin'],
    JSON.stringify({
      tokens: { access_token: token, refresh_token: 'synthetic-refresh-token', token_type: 'Bearer' },
    })
  );
  assert.equal(result.status, 0, result.stderr);
}
const vaultPath = (profile) => path.join(environment(profile, false).XDG_DATA_HOME, 'mcporter', 'credentials.json');
const bytes = (profile) => fs.readFile(vaultPath(profile), 'utf8');
function writeCache(pkg, profile, encrypted) {
  const program = `
    import { pathToFileURL } from 'node:url';
    const { DirectoryPersistence } = await import(pathToFileURL(process.argv[1]));
    await new DirectoryPersistence(process.argv[2]).saveTokens({ access_token: process.argv[3], token_type: 'Bearer' });
  `;
  const result = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      program,
      path.join(pkg, 'dist/oauth-persistence-stores.js'),
      path.join(root, profile, 'token-cache'),
      token,
    ],
    {
      env: environment(profile, encrypted),
      encoding: 'utf8',
      timeout: 30_000,
    }
  );
  assert.equal(result.status, 0, result.stderr);
}
const cacheBytes = (profile) => fs.readFile(path.join(root, profile, 'token-cache/tokens.json'), 'utf8');
try {
  writeVault(previous, 'protected', false);
  assert.ok((await bytes('protected')).includes(token));
  writeVault(current, 'protected', true);
  const sealed = await bytes('protected');
  assert.ok(!sealed.includes(token));
  assert.deepEqual(JSON.parse(sealed).encryption, { version: 1 });
  const refused = runCli(
    current,
    'protected',
    false,
    ['vault', 'set', 'demo', '--stdin'],
    JSON.stringify({ tokens: { access_token: token, token_type: 'Bearer' } })
  );
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /MCPORTER_VAULT_PASSWORD/);
  assert.equal(await bytes('protected'), sealed);
  console.log('PASS: released plaintext migrates; missing password preserves encrypted bytes');

  writeVault(previous, 'rollback', false);
  assert.ok((await bytes('rollback')).includes(token));
  assert.equal(await bytes('protected'), sealed);
  writeVault(current, 'protected', true);
  assert.ok(!(await bytes('protected')).includes(token));
  console.log('PASS: isolated downgrade and return preserve the encrypted profile');

  writeVault(previous, 'protected', false);
  assert.ok((await bytes('protected')).includes(token));
  writeVault(current, 'protected', true);
  assert.ok(!(await bytes('protected')).includes(token));
  console.log('PASS: reproduced unsafe shared-profile downgrade; supporting writer re-seals residue');

  writeCache(previous, 'protected', false);
  writeCache(current, 'protected', true);
  const sealedCache = await cacheBytes('protected');
  assert.ok(!sealedCache.includes(token));
  writeCache(previous, 'rollback', false);
  assert.equal(await cacheBytes('protected'), sealedCache);
  writeCache(previous, 'protected', false);
  assert.ok((await cacheBytes('protected')).includes(token));
  writeCache(current, 'protected', true);
  assert.ok(!(await cacheBytes('protected')).includes(token));
  console.log('PASS: tokenCacheDir migration, isolated rollback, downgrade residue and recovery');
} finally {
  await fs.rm(root, { recursive: true, force: true });
}
