const crypto = require("crypto");
const { pipeline } = require("stream/promises");
const Busboy = require("busboy");
const { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } = require("@aws-sdk/client-s3");

const pool = require("../config/database");
const { httpError } = require("./keyService");
const { clientOf, consentOf } = require("./credentialService");

/*
 * Client files (CD-13), kept in the S3 store (SeaweedFS), metadata in
 * client_files.
 *
 * - The object key is random (org/<id>/<uuid>), never the file name.
 * - Uploads are capped at MAX_BYTES and hashed (sha256) as they arrive.
 * - Downloads are always attachments with nosniff, whatever the file claims
 *   to be, so nothing uploaded is ever rendered by the browser.
 * - A purged client's files lose their customer_id; the sweeper deletes the
 *   object, then the row.
 */

const MAX_BYTES = 25 * 1024 * 1024;
const BUCKET = process.env.S3_BUCKET || "client-files";
const CATEGORY = /^[a-z][a-z0-9_]{1,59}$/;

let s3 = null;

function store() {
  if (!s3) {
    s3 = new S3Client({
      endpoint: process.env.S3_ENDPOINT || "http://seaweedfs:8333",
      region: process.env.S3_REGION || "us-east-1",
      forcePathStyle: true,
      credentials: { accessKeyId: process.env.S3_ACCESS_KEY || "", secretAccessKey: process.env.S3_SECRET_KEY || "" },
    });
  }
  return s3;
}

// Tests replace the store.
function useStore(fake) {
  s3 = fake;
}

// The name as the person sees it: no path, no control characters.
function cleanName(name) {
  const base = String(name || "file").split(/[\\/]/).pop();
  // eslint-disable-next-line no-control-regex
  const cleaned = base.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  return (cleaned || "file").slice(0, 255);
}

const summaryColumns = "f.id, f.customer_id, f.engagement_id, f.category, f.file_name, f.content_type, f.size_bytes, f.sha256, f.uploaded_by, f.created_at";

async function list(organizationId, customerId) {
  await clientOf(organizationId, customerId);

  return {
    consent: await consentOf(organizationId, customerId),
    files: (
      await pool.query(
        `SELECT ${summaryColumns}, u.name AS uploaded_by_name
         FROM client_files f LEFT JOIN users u ON u.id = f.uploaded_by
         WHERE f.organization_id = $1 AND f.customer_id = $2 ORDER BY f.created_at DESC, f.id DESC`,
        [organizationId, customerId],
      )
    ).rows,
  };
}

// Reads one file from a multipart request into memory, within the cap.
function receive(req) {
  return new Promise((resolve, reject) => {
    let busboy;

    try {
      busboy = Busboy({ headers: req.headers, limits: { files: 1, fileSize: MAX_BYTES, fields: 5 } });
    } catch {
      reject(httpError(400, "Send the file as multipart/form-data"));
      return;
    }

    let received = null;

    busboy.on("file", (field, stream, info) => {
      const chunks = [];
      const hash = crypto.createHash("sha256");
      let size = 0;

      stream.on("data", (chunk) => {
        chunks.push(chunk);
        hash.update(chunk);
        size += chunk.length;
      });
      stream.on("limit", () => reject(httpError(413, `Files can be at most ${MAX_BYTES / (1024 * 1024)} MB`)));
      stream.on("end", () => {
        received = { name: cleanName(info.filename), type: String(info.mimeType || "application/octet-stream").slice(0, 150), body: Buffer.concat(chunks), size, sha256: hash.digest("hex") };
      });
    });
    busboy.on("error", () => reject(httpError(400, "The upload could not be read")));
    busboy.on("close", () => (received ? resolve(received) : reject(httpError(400, "No file was sent"))));

    req.pipe(busboy);
  });
}

async function upload({ organizationId, userId }, customerId, category, req) {
  const client = await clientOf(organizationId, customerId);
  if (client.archived_at) throw httpError(409, "This client is archived; its files are read-only");

  const kind = category || "general";
  if (!CATEGORY.test(kind)) throw httpError(400, "Invalid category");

  const file = await receive(req);
  if (file.size === 0) throw httpError(400, "The file is empty");

  const objectKey = `org/${organizationId}/${crypto.randomUUID()}`;

  await store().send(new PutObjectCommand({ Bucket: BUCKET, Key: objectKey, Body: file.body, ContentLength: file.size, ContentType: "application/octet-stream" }));

  try {
    const saved = (
      await pool.query(
        `INSERT INTO client_files (organization_id, customer_id, category, file_name, content_type, size_bytes, sha256, object_key, uploaded_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
        [organizationId, customerId, kind, file.name, file.type, file.size, file.sha256, objectKey, userId],
      )
    ).rows[0];

    return (await pool.query(`SELECT ${summaryColumns} FROM client_files f WHERE f.id = $1`, [saved.id])).rows[0];
  } catch (error) {
    // No row, no object.
    await store().send(new DeleteObjectCommand({ Bucket: BUCKET, Key: objectKey })).catch(() => {});
    throw error;
  }
}

async function fileOf(organizationId, fileId) {
  const file = (await pool.query("SELECT * FROM client_files WHERE id = $1 AND organization_id = $2 AND customer_id IS NOT NULL", [fileId, organizationId])).rows[0];
  if (!file) throw httpError(404, "File not found");
  return file;
}

// RFC 6266: an ASCII fallback plus the exact name, encoded.
function disposition(name) {
  const ascii = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

async function download(organizationId, fileId, res) {
  const file = await fileOf(organizationId, fileId);
  const object = await store().send(new GetObjectCommand({ Bucket: BUCKET, Key: file.object_key }));

  res.set({
    "Content-Type": "application/octet-stream",
    "Content-Disposition": disposition(file.file_name),
    "Content-Length": String(file.size_bytes),
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "private, no-store",
  });

  // Wait for the whole file: the route must not answer again while it streams.
  await pipeline(object.Body, res);
}

async function remove({ organizationId, userId }, fileId) {
  const file = await fileOf(organizationId, fileId);
  const client = await clientOf(organizationId, file.customer_id);
  if (client.archived_at) throw httpError(409, "This client is archived; its files are read-only");

  // The signed authority stays while credentials depend on it.
  const consent = await consentOf(organizationId, file.customer_id);
  if (consent.category && file.category === consent.category) {
    const others = await pool.query("SELECT 1 FROM client_files WHERE customer_id = $1 AND category = $2 AND id <> $3 LIMIT 1", [file.customer_id, consent.category, file.id]);
    const credentials = await pool.query("SELECT 1 FROM portal_credentials WHERE customer_id = $1 LIMIT 1", [file.customer_id]);

    if (others.rowCount === 0 && credentials.rowCount > 0) {
      throw httpError(409, "Portal credentials rely on this signed authority; remove them first");
    }
  }

  // The object first: a row without its object would offer a broken download.
  await store().send(new DeleteObjectCommand({ Bucket: BUCKET, Key: file.object_key }));
  await pool.query("DELETE FROM client_files WHERE id = $1", [file.id]);
  await pool.query(
    `INSERT INTO audit_events (organization_id, actor_user_id, action, entity_type, entity_id, customer_id, details)
     VALUES ($1, $2, 'file.deleted', 'file', $3, $4, $5)`,
    [organizationId, userId, String(file.id), file.customer_id, { name: file.file_name, category: file.category, sha256: file.sha256 }],
  );

  return { deleted: true };
}

/*
 * Deletes the objects (then rows) of files whose client was purged. One
 * transaction per batch, rows claimed with SKIP LOCKED so two runs never
 * fight over one. `organizationId` limits a run to one organization.
 */
async function sweep({ organizationId = null, batch = 100 } = {}) {
  const db = await pool.connect();
  let removed = 0;

  try {
    await db.query("BEGIN");
    const orphans = (
      await db.query(
        `SELECT id, object_key FROM client_files
         WHERE customer_id IS NULL ${organizationId ? "AND organization_id = $2" : ""}
         ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED`,
        organizationId ? [batch, organizationId] : [batch],
      )
    ).rows;

    for (const orphan of orphans) {
      try {
        await store().send(new DeleteObjectCommand({ Bucket: BUCKET, Key: orphan.object_key }));
        await db.query("DELETE FROM client_files WHERE id = $1", [orphan.id]);
        removed += 1;
      } catch (error) {
        // Left for the next run.
        console.error(`[Sweeper] file ${orphan.id}: ${error.message}`);
      }
    }

    await db.query("COMMIT");
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  } finally {
    db.release();
  }

  return { removed };
}

module.exports = { list, upload, download, remove, sweep, cleanName, disposition, useStore, MAX_BYTES };
