import path from 'node:path';
import { loadConfigSnapshot } from '../../config.js';
import { readJsonFile } from '../../fs-json.js';
import { getOAuthVaultPath } from '../../oauth-vault.js';
import {
  VAULT_ENCRYPTION_POLICY_ENV,
  VAULT_PASSWORD_ENV,
  VaultEncryptionError,
  describeVaultSecrets,
  readVaultEncryptionSettings,
} from '../../oauth-vault-encryption.js';
import { MCPORTER_VERSION } from '../../version.js';
import { logConfigLocations, resolveConfigLocations } from './shared.js';
import type { ConfigCliOptions } from './types.js';

async function reportVault(issues: string[], configuredPolicy: 'optional' | 'required' | undefined): Promise<void> {
  const vaultPath = getOAuthVaultPath();
  let stats: ReturnType<typeof describeVaultSecrets> | 'absent' | 'unreadable';
  try {
    const document = await readJsonFile<{ entries?: unknown }>(vaultPath);
    stats = document === undefined ? 'absent' : describeVaultSecrets(document.entries);
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    stats = 'unreadable';
  }
  const label =
    typeof stats === 'string'
      ? stats
      : `${stats.entries} entries, ${stats.sealed} sealed values, ${stats.plaintext} plaintext values`;
  console.log(`OAuth vault: ${vaultPath} (${label})`);
  if (stats === 'unreadable') {
    issues.push('The OAuth vault is not valid JSON; mcporter will rewrite it on the next credential write.');
  }
  try {
    const settings = readVaultEncryptionSettings(process.env, configuredPolicy);
    console.log(
      `Vault encryption: policy ${settings.policy}, ${VAULT_PASSWORD_ENV} ${settings.password === undefined ? 'unset' : 'set'}`
    );
    if (typeof stats === 'string') return;
    if (stats.sealed > 0 && settings.password === undefined) {
      issues.push(
        `The OAuth vault holds ${stats.sealed} sealed values but ${VAULT_PASSWORD_ENV} is unset; OAuth-backed servers will fail until it is set.`
      );
    }
    if (stats.plaintext > 0 && settings.password !== undefined) {
      const source = process.env[VAULT_ENCRYPTION_POLICY_ENV]
        ? `${VAULT_ENCRYPTION_POLICY_ENV}=required`
        : 'oauthVaultEncryption "required"';
      issues.push(
        `The OAuth vault holds ${stats.plaintext} plaintext secret values${settings.policy === 'required' ? ` under ${source}` : ''}; they are sealed on the next vault write.`
      );
    }
  } catch (error) {
    if (!(error instanceof VaultEncryptionError)) throw error;
    issues.push(error.message);
  }
}

export async function handleDoctorCommand(options: ConfigCliOptions, _args: string[]): Promise<void> {
  console.log(`MCPorter ${MCPORTER_VERSION}`);
  logConfigLocations(await resolveConfigLocations(options.loadOptions), { leadingNewline: false });
  console.log('');
  const issues: string[] = [];
  const snapshot = await loadConfigSnapshot(options.loadOptions);
  for (const server of snapshot.servers) {
    if (server.command.kind === 'stdio' && !path.isAbsolute(server.command.cwd)) {
      issues.push(`Server '${server.name}' has a non-absolute working directory.`);
    }
  }
  await reportVault(issues, snapshot.vaultEncryption);
  if (issues.length === 0) {
    console.log('Config looks good.');
    return;
  }
  console.log('Config issues detected:');
  for (const issue of issues) console.log(`  - ${issue}`);
}
