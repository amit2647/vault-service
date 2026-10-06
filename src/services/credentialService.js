const { conditions } = require("bundle-sdk");

const pool = require("../config/database");
const { customized, decide, optionsFor } = require("./bundleSync");
const keys = require("./keyService");

const { httpError } = keys;

/*
 * Client portal credentials (CD-10, FIX-02).
 *
 * - Listing returns the fields that are not secret and whether a secret is
 *   stored — never a secret.
 * - Saving is refused until the client's signed authority (the bundle's
 *   consent file category) is on file. A secret left blank keeps the one
 *   stored, so changing a user ID does not wipe the password.
 * - Revealing needs vault.reveal and a reason, is rate limited, and is
 *   recorded in credential_reveals and audit_events.
 */

const REVEALS_PER_WINDOW = Number(process.env.VAULT_REVEALS_PER_WINDOW || 10);
const REVEAL_WINDOW_MS = Number(process.env.VAULT_REVEAL_WINDOW_MS || 10 * 60 * 1000);
const reveals = new Map();

// The part of a portal a checksum covers: what the bundle ships.
const content = (portal) => ({
  name: portal.name,
  url: portal.url || null,
  fields: portal.fields || [],
  enabledWhen: portal.enabledWhen || portal.enabled_when || null,
});

// The vault step of a bundle install: portals, and the consent category.
async function installVault(organizationId, bundleKey, version, vault = {}, choices = {}) {
  const portals = vault.portals || [];

  for (const portal of portals) {
    if (!portal?.key || !portal.name || !Array.isArray(portal.fields) || portal.fields.length === 0 || portal.fields.length > 4) {
      throw httpError(400, "Each portal needs a key, a name and one to four fields");
    }
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const summary = { inserted: 0, updated: 0, unchanged: 0, kept: 0, retired: 0, customized: [] };

    for (const [position, portal] of portals.entries()) {
      const shipped = content(portal);
      const row = (await client.query("SELECT * FROM portals WHERE organization_id = $1 AND key = $2", [organizationId, portal.key])).rows[0];
      const { action, shippedChecksum, flag, acknowledge } = decide(row && { content: content(row), sourceChecksum: row.source_checksum }, shipped, optionsFor(choices, "portal", portal.key));

      if (action === "insert") {
        await client.query(
          `INSERT INTO portals (organization_id, bundle_key, key, name, url, fields, enabled_when, position, source_version, source_checksum)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
          [organizationId, bundleKey, portal.key, shipped.name, shipped.url, JSON.stringify(shipped.fields), shipped.enabledWhen, position, version, shippedChecksum],
        );
        summary.inserted += 1;
        continue;
      }

      if (action === "keep") {
        await client.query(
          `UPDATE portals SET bundle_key = $1, retired_at = NULL, position = $2,
             update_available_version = CASE WHEN $6 THEN NULL WHEN $3 THEN $4 ELSE update_available_version END,
             source_checksum = CASE WHEN $6 THEN $7 ELSE source_checksum END
           WHERE id = $5`,
          [bundleKey, position, flag, version, row.id, Boolean(acknowledge), shippedChecksum],
        );
        summary.kept += 1;
        if (flag) summary.customized.push(customized("portal", portal.key, row.name, content(row), shipped, version));
        continue;
      }

      if (action === "update") {
        await client.query(
          "UPDATE portals SET name = $1, url = $2, fields = $3, enabled_when = $4, updated_at = NOW() WHERE id = $5",
          [shipped.name, shipped.url, JSON.stringify(shipped.fields), shipped.enabledWhen, row.id],
        );
      }

      await client.query(
        `UPDATE portals SET bundle_key = $1, position = $2, source_version = $3, source_checksum = $4, update_available_version = NULL, retired_at = NULL
         WHERE id = $5`,
        [bundleKey, position, version, shippedChecksum, row.id],
      );
      summary[action === "update" ? "updated" : "unchanged"] += 1;
    }

    const retired = await client.query(
      `UPDATE portals SET retired_at = NOW()
       WHERE organization_id = $1 AND bundle_key = $2 AND retired_at IS NULL AND key <> ALL($3::text[])`,
      [organizationId, bundleKey, portals.map((portal) => portal.key)],
    );
    summary.retired = retired.rowCount;

    await client.query(
      `INSERT INTO vault_settings (organization_id, bundle_key, consent_file_category, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (organization_id) DO UPDATE SET bundle_key = EXCLUDED.bundle_key, consent_file_category = EXCLUDED.consent_file_category, updated_at = NOW()`,
      [organizationId, bundleKey, vault.consentFileCategory || null],
    );

    // A dry run does all the work and rolls it back, to report what it would do.
    await client.query(choices.dryRun ? "ROLLBACK" : "COMMIT");
    return summary;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function clientOf(organizationId, customerId) {
  const row = (await pool.query("SELECT id, name, archived_at FROM customers WHERE id = $1 AND organization_id = $2", [customerId, organizationId])).rows[0];
  if (!row) throw httpError(404, "Client not found");
  return row;
}

async function consentOf(organizationId, customerId) {
  const settings = (await pool.query("SELECT consent_file_category FROM vault_settings WHERE organization_id = $1", [organizationId])).rows[0];
  const category = settings?.consent_file_category || null;

  if (!category) return { category: null, onFile: true };

  const file = await pool.query(
    "SELECT 1 FROM client_files WHERE organization_id = $1 AND customer_id = $2 AND category = $3 LIMIT 1",
    [organizationId, customerId, category],
  );

  return { category, onFile: file.rowCount > 0 };
}

// Services the client takes, in any period, for portals' enabledWhen.
async function engagedOf(customerId) {
  const result = await pool.query(
    `SELECT DISTINCT s.key FROM services s
     WHERE s.key IS NOT NULL AND s.id IN (
       SELECT service_id FROM customer_services WHERE customer_id = $1
       UNION SELECT l.service_id FROM engagement_lines l JOIN engagements e ON e.id = l.engagement_id WHERE e.customer_id = $1
     )`,
    [customerId],
  );
  return result.rows.map((row) => row.key);
}

async function list(organizationId, customerId) {
  await clientOf(organizationId, customerId);

  const rows = (
    await pool.query(
      `SELECT p.key, p.name, p.url, p.fields, p.enabled_when,
              c.id AS credential_id, c.public_fields, c.secret_ciphertext IS NOT NULL AS has_secret, c.updated_at, c.updated_by
       FROM portals p
       LEFT JOIN portal_credentials c ON c.portal_id = p.id AND c.customer_id = $2
       WHERE p.organization_id = $1 AND p.is_active AND p.retired_at IS NULL
       ORDER BY p.position, p.id`,
      [organizationId, customerId],
    )
  ).rows;

  const engaged = await engagedOf(customerId);

  return {
    vaultReady: keys.ready(),
    consent: await consentOf(organizationId, customerId),
    portals: rows.map((row) => ({
      key: row.key,
      name: row.name,
      url: row.url,
      fields: row.fields,
      // A portal the client's services do not call for is still listed, just not suggested.
      suggested: !row.enabled_when || Boolean(conditions.evaluate(row.enabled_when, { engaged })),
      credential: row.credential_id
        ? { id: row.credential_id, publicFields: row.public_fields || {}, hasSecret: row.has_secret, updatedAt: row.updated_at, updatedBy: row.updated_by }
        : null,
    })),
  };
}

async function portalOf(organizationId, portalKey) {
  const portal = (await pool.query("SELECT * FROM portals WHERE organization_id = $1 AND key = $2 AND retired_at IS NULL", [organizationId, portalKey])).rows[0];
  if (!portal) throw httpError(404, "Portal not found");
  return portal;
}

async function audit(organizationId, userId, action, credentialId, customerId, details) {
  await pool.query(
    `INSERT INTO audit_events (organization_id, actor_user_id, action, entity_type, entity_id, customer_id, details)
     VALUES ($1, $2, $3, 'credential', $4, $5, $6)`,
    [organizationId, userId, action, String(credentialId), customerId, details],
  );
}

async function save({ organizationId, userId }, customerId, portalKey, values) {
  if (!values || typeof values !== "object" || Array.isArray(values)) throw httpError(400, "fields must be an object");

  const client = await clientOf(organizationId, customerId);
  if (client.archived_at) throw httpError(409, "This client is archived; its credentials are read-only");

  const portal = await portalOf(organizationId, portalKey);
  const known = new Map(portal.fields.map((field) => [field.key, field]));

  for (const [key, value] of Object.entries(values)) {
    if (!known.has(key)) throw httpError(400, `${key} is not a field of ${portal.name}`);
    if (value !== null && value !== undefined && (typeof value !== "string" || value.length > 500)) {
      throw httpError(400, `${known.get(key).label} must be text of at most 500 characters`);
    }
  }

  const consent = await consentOf(organizationId, customerId);
  if (!consent.onFile) {
    const error = httpError(409, "Upload the client's signed consent and power of attorney before saving portal credentials");
    error.details = { consent: consent.category };
    throw error;
  }

  const existing = (await pool.query("SELECT * FROM portal_credentials WHERE customer_id = $1 AND portal_id = $2", [customerId, portal.id])).rows[0];

  const publicFields = {};
  const secretInput = {};
  for (const field of portal.fields) {
    const value = values[field.key];
    if (field.secret) {
      if (typeof value === "string" && value !== "") secretInput[field.key] = value;
    } else if (typeof value === "string") {
      publicFields[field.key] = value;
    } else if (existing?.public_fields?.[field.key] !== undefined) {
      publicFields[field.key] = existing.public_fields[field.key];
    }
  }

  let sealed = existing ? { iv: existing.secret_iv, ciphertext: existing.secret_ciphertext, version: existing.key_version } : { iv: null, ciphertext: null, version: null };

  if (Object.keys(secretInput).length > 0) {
    // Secrets left blank keep what is stored.
    const kept = existing?.secret_ciphertext
      ? await keys.decryptSecrets(organizationId, customerId, portal.key, { iv: existing.secret_iv, ciphertext: existing.secret_ciphertext })
      : {};
    sealed = await keys.encryptSecrets(organizationId, customerId, portal.key, { ...kept, ...secretInput });
  }

  const saved = (
    await pool.query(
      `INSERT INTO portal_credentials (organization_id, customer_id, portal_id, public_fields, secret_ciphertext, secret_iv, key_version, updated_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (customer_id, portal_id) DO UPDATE SET
         public_fields = EXCLUDED.public_fields, secret_ciphertext = EXCLUDED.secret_ciphertext, secret_iv = EXCLUDED.secret_iv,
         key_version = EXCLUDED.key_version, updated_by = EXCLUDED.updated_by, updated_at = NOW()
       RETURNING id`,
      [organizationId, customerId, portal.id, publicFields, sealed.ciphertext, sealed.iv, sealed.version, userId],
    )
  ).rows[0];

  // Which fields changed, never their values.
  await audit(organizationId, userId, "credential.saved", saved.id, customerId, { portal: portal.key, fields: Object.keys(values) });

  return list(organizationId, customerId);
}

function rateLimit(userId) {
  const now = Date.now();
  const recent = (reveals.get(userId) || []).filter((at) => now - at < REVEAL_WINDOW_MS);

  if (recent.length >= REVEALS_PER_WINDOW) {
    throw httpError(429, "Too many reveals in a short time; try again in a few minutes");
  }

  recent.push(now);
  reveals.set(userId, recent);
}

async function reveal({ organizationId, userId }, customerId, portalKey, reason) {
  if (typeof reason !== "string" || reason.trim().length < 5) {
    const error = httpError(400, "Say why you need the password (at least 5 characters)");
    error.details = { reason: "A reason is required" };
    throw error;
  }

  keys.requireReady();
  await clientOf(organizationId, customerId);
  const portal = await portalOf(organizationId, portalKey);

  const credential = (await pool.query("SELECT * FROM portal_credentials WHERE customer_id = $1 AND portal_id = $2", [customerId, portal.id])).rows[0];
  if (!credential?.secret_ciphertext) throw httpError(404, "No secret is stored for this portal");

  rateLimit(userId);

  const secrets = await keys.decryptSecrets(organizationId, customerId, portal.key, { iv: credential.secret_iv, ciphertext: credential.secret_ciphertext });

  await pool.query(
    `INSERT INTO credential_reveals (organization_id, credential_id, customer_id, portal_key, user_id, reason)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [organizationId, credential.id, customerId, portal.key, userId, reason.trim().slice(0, 1000)],
  );
  await audit(organizationId, userId, "credential.revealed", credential.id, customerId, { portal: portal.key, reason: reason.trim().slice(0, 1000) });

  return { portal: portal.key, secrets };
}

async function remove({ organizationId, userId }, customerId, portalKey) {
  const client = await clientOf(organizationId, customerId);
  if (client.archived_at) throw httpError(409, "This client is archived; its credentials are read-only");

  const portal = await portalOf(organizationId, portalKey);
  const removed = await pool.query("DELETE FROM portal_credentials WHERE customer_id = $1 AND portal_id = $2 RETURNING id", [customerId, portal.id]);

  if (removed.rowCount > 0) {
    await audit(organizationId, userId, "credential.removed", removed.rows[0].id, customerId, { portal: portal.key });
  }

  return list(organizationId, customerId);
}

// Reveals, newest first — who looked, at which portal, and why.
async function revealLog(organizationId, customerId) {
  await clientOf(organizationId, customerId);

  return (
    await pool.query(
      `SELECT r.id, r.portal_key, r.user_id, u.name AS user_name, r.reason, r.revealed_at
       FROM credential_reveals r LEFT JOIN users u ON u.id = r.user_id
       WHERE r.organization_id = $1 AND r.customer_id = $2 ORDER BY r.revealed_at DESC LIMIT 50`,
      [organizationId, customerId],
    )
  ).rows;
}

module.exports = { installVault, list, save, reveal, remove, revealLog, consentOf, clientOf, content, rateLimit };
