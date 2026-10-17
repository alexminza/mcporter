import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServerDefinition } from '../src/config.js';
import { DirectoryPersistence } from '../src/oauth-persistence-stores.js';
import { clearVaultEntry, getOAuthVaultPath, loadVaultEntry, saveVaultEntry } from '../src/oauth-vault.js';

const PASSWORD = 'synthetic-vault-format-test-password';
const definition: ServerDefinition = {
  name: 'format-test',
  command: { kind: 'http', url: new URL('https://example.com/mcp') },
};
const tokens = { access_token: 'synthetic-access-token', token_type: 'Bearer' };

// A cleared encrypted store must not silently become plaintext when the next
// process loses its environment. The marker records that choice independently
// of whether there are currently any secret values to detect.
describe('persistent encryption format', () => {
  let root: string;
  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'mcporter-vault-format-'));
    vi.stubEnv('XDG_DATA_HOME', root);
    vi.stubEnv('MCPORTER_VAULT_PASSWORD', PASSWORD);
  });
  afterEach(async () => {
    vi.unstubAllEnvs();
    await fs.rm(root, { recursive: true, force: true });
  });

  it('keeps the vault encrypted after clearing its last entry', async () => {
    await saveVaultEntry(definition, { tokens });
    await clearVaultEntry(definition, 'all');
    const before = await fs.readFile(getOAuthVaultPath(), 'utf8');
    expect(JSON.parse(before).encryption).toEqual({ version: 1 });
    vi.stubEnv('MCPORTER_VAULT_PASSWORD', undefined);
    await expect(saveVaultEntry(definition, { tokens })).rejects.toMatchObject({ code: 'password_missing' });
    expect(await fs.readFile(getOAuthVaultPath(), 'utf8')).toBe(before);
    vi.stubEnv('MCPORTER_VAULT_PASSWORD', PASSWORD);
    await saveVaultEntry(definition, { tokens });
    expect((await loadVaultEntry(definition))?.tokens?.access_token).toBe(tokens.access_token);
  });

  it('refuses an unknown vault encryption version without repairing it', async () => {
    await saveVaultEntry(definition, { tokens });
    const document = JSON.parse(await fs.readFile(getOAuthVaultPath(), 'utf8'));
    document.encryption = { version: 2 };
    const before = JSON.stringify(document);
    await fs.writeFile(getOAuthVaultPath(), before);
    await expect(loadVaultEntry(definition)).rejects.toMatchObject({ code: 'payload_invalid' });
    await expect(saveVaultEntry(definition, { tokens })).rejects.toMatchObject({ code: 'payload_invalid' });
    expect(await fs.readFile(getOAuthVaultPath(), 'utf8')).toBe(before);
  });

  it('keeps an empty token cache encrypted across process environments', async () => {
    const cache = path.join(root, 'cache');
    const store = new DirectoryPersistence(cache);
    await store.saveTokens(tokens);
    await store.clear('all');
    const marker = path.join(cache, 'encryption.json');
    expect(JSON.parse(await fs.readFile(marker, 'utf8'))).toEqual({ version: 1 });
    vi.stubEnv('MCPORTER_VAULT_PASSWORD', undefined);
    await expect(new DirectoryPersistence(cache).saveTokens(tokens)).rejects.toMatchObject({
      code: 'password_missing',
    });
    await expect(fs.access(path.join(cache, 'tokens.json'))).rejects.toMatchObject({ code: 'ENOENT' });
    vi.stubEnv('MCPORTER_VAULT_PASSWORD', PASSWORD);
    await new DirectoryPersistence(cache).saveTokens(tokens);
    expect((await store.readTokens())?.access_token).toBe(tokens.access_token);
  });

  it.each(['all', 'rejected'] as const)(
    'remembers opt-in when first clearing plaintext credentials (%s)',
    async (scope) => {
      const cache = path.join(root, 'plaintext-cache');
      const store = new DirectoryPersistence(cache);
      vi.stubEnv('MCPORTER_VAULT_PASSWORD', undefined);
      await store.saveTokens(tokens);
      await store.saveClientInfo({ client_id: 'synthetic-client', client_secret: 'synthetic-client-secret' });
      const cached = await store.readSnapshot();
      vi.stubEnv('MCPORTER_VAULT_PASSWORD', PASSWORD);
      if (scope === 'all') await store.clear('all');
      else await store.clearRejectedCredentials(cached.tokens, cached.clientInfo);
      expect(JSON.parse(await fs.readFile(path.join(cache, 'encryption.json'), 'utf8'))).toEqual({ version: 1 });
      vi.stubEnv('MCPORTER_VAULT_PASSWORD', undefined);
      await expect(store.saveTokens(tokens)).rejects.toMatchObject({ code: 'password_missing' });
      await expect(fs.access(path.join(cache, 'tokens.json'))).rejects.toMatchObject({ code: 'ENOENT' });
    }
  );

  it('refuses an unknown token-cache marker without overwriting it', async () => {
    const cache = path.join(root, 'cache');
    await fs.mkdir(cache);
    const marker = path.join(cache, 'encryption.json');
    await fs.writeFile(marker, '{"version":2}');
    const store = new DirectoryPersistence(cache);
    await expect(store.readTokens()).rejects.toMatchObject({ code: 'payload_invalid' });
    await expect(store.saveTokens(tokens)).rejects.toMatchObject({ code: 'payload_invalid' });
    expect(await fs.readFile(marker, 'utf8')).toBe('{"version":2}');
  });
});
