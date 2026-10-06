const crypto = require("crypto");

const pool = require("../config/database");

/*
 * Envelope encryption for portal secrets (FIX-02).
 *
 * - VAULT_MASTER_KEY (32 bytes, base64; only this service holds it) wraps one
 *   random data key per organization, stored in vault_keys.
 * - Each credential's secret fields are sealed with that data key,
 *   AES-256-GCM, a fresh IV each time, and additional data naming the
 *   organization, client and portal — so a ciphertext copied onto another
 *   row does not decrypt.
 *
 * Without a valid master key the vault refuses to store or reveal secrets
 * (503) rather than storing them weakly; everything else still works.
 */

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;
const TAG_BYTES = 16;

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function masterKey() {
  const raw = process.env.VAULT_MASTER_KEY || "";
  const key = Buffer.from(raw, "base64");

  return key.length === 32 ? key : null;
}

const ready = () => masterKey() !== null;

function requireReady() {
  if (!ready()) {
    throw httpError(503, "The vault is not configured: VAULT_MASTER_KEY must be 32 bytes, base64");
  }
}

// seal: iv | tag | ciphertext, all in one buffer.
function seal(key, plaintext, aad) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  return { iv, sealed: Buffer.concat([ciphertext, cipher.getAuthTag()]) };
}

function open(key, iv, sealed, aad) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(sealed.subarray(sealed.length - TAG_BYTES));

  return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - TAG_BYTES)), decipher.final()]);
}

// The organization's data key, created (and wrapped) on first use.
async function dataKey(organizationId) {
  requireReady();
  const master = masterKey();
  const aad = `vault-key:${organizationId}`;

  let row = (await pool.query("SELECT wrapped_key, key_version FROM vault_keys WHERE organization_id = $1", [organizationId])).rows[0];

  if (!row) {
    const fresh = crypto.randomBytes(32);
    const { iv, sealed } = seal(master, fresh, aad);

    await pool.query(
      "INSERT INTO vault_keys (organization_id, wrapped_key) VALUES ($1, $2) ON CONFLICT (organization_id) DO NOTHING",
      [organizationId, Buffer.concat([iv, sealed])],
    );

    // Another request may have created it first: use whichever is stored.
    row = (await pool.query("SELECT wrapped_key, key_version FROM vault_keys WHERE organization_id = $1", [organizationId])).rows[0];
  }

  try {
    const wrapped = row.wrapped_key;
    return { key: open(master, wrapped.subarray(0, IV_BYTES), wrapped.subarray(IV_BYTES), aad), version: row.key_version };
  } catch {
    throw httpError(503, "The vault key does not open this organization's data key — is VAULT_MASTER_KEY the one it was created with?");
  }
}

const credentialAad = (organizationId, customerId, portalKey) => `credential:${organizationId}:${customerId}:${portalKey}`;

async function encryptSecrets(organizationId, customerId, portalKey, secrets) {
  const { key, version } = await dataKey(organizationId);
  const { iv, sealed } = seal(key, Buffer.from(JSON.stringify(secrets)), credentialAad(organizationId, customerId, portalKey));

  return { iv, ciphertext: sealed, version };
}

async function decryptSecrets(organizationId, customerId, portalKey, { iv, ciphertext }) {
  if (!iv || !ciphertext) return {};

  const { key } = await dataKey(organizationId);

  try {
    return JSON.parse(open(key, iv, ciphertext, credentialAad(organizationId, customerId, portalKey)).toString("utf8"));
  } catch {
    throw httpError(500, "This credential could not be decrypted");
  }
}

module.exports = { ready, requireReady, encryptSecrets, decryptSecrets, seal, open, httpError };
