const { describe, test, before, after, beforeEach, mock } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

/*
 * The vault (CD-10, CD-13, FIX-02): envelope encryption, the gates on every
 * route, and uploads into a stand-in object store. Credentials, consent and
 * reveals run against a real database in the integration suite.
 */

process.env.JWT_SECRET = "unit-test-secret";
process.env.JWT_ISSUER = "unit-test-issuer";
process.env.BUNDLE_SERVICE_URL = "http://bundle-service.test";
process.env.VAULT_MASTER_KEY = crypto.randomBytes(32).toString("base64");

let installed;
let vaultKeys;
let rows;
const realFetch = global.fetch;

global.fetch = async (url, options) =>
  String(url).startsWith("http://bundle-service.test")
    ? new Response(JSON.stringify({ bundle: installed }), { status: 200 })
    : realFetch(url, options);

const pool = require("../src/config/database");

pool.query = async (text, params = []) => {
  const sql = text.replace(/\s+/g, " ").trim();

  if (/access_grants/.test(sql)) return { rows: [] };
  if (/^SELECT wrapped_key, key_version FROM vault_keys/.test(sql)) return { rows: vaultKeys[params[0]] ? [vaultKeys[params[0]]] : [] };
  if (/^INSERT INTO vault_keys/.test(sql)) {
    vaultKeys[params[0]] ??= { wrapped_key: params[1], key_version: 1 };
    return { rows: [] };
  }
  if (/^SELECT id, name, archived_at FROM customers/.test(sql)) return { rows: params[1] === 3 ? [{ id: params[0], name: "Acme", archived_at: null }] : [] };
  if (/^INSERT INTO client_files/.test(sql)) {
    rows.push({ id: rows.length + 1, file_name: params[3], content_type: params[4], size_bytes: params[5], sha256: params[6], object_key: params[7] });
    return { rows: [{ id: rows.length }] };
  }
  if (/FROM client_files f WHERE f.id/.test(sql)) return { rows: [rows[params[0] - 1]] };
  if (/^SELECT \* FROM client_files WHERE id = \$1/.test(sql)) {
    const row = rows[params[0] - 1];
    return { rows: row && params[1] === 3 ? [{ ...row, customer_id: 5 }] : [] };
  }

  throw new Error(`unexpected query: ${sql}`);
};

const keys = require("../src/services/keyService");
const files = require("../src/services/fileService");
const { rateLimit } = require("../src/services/credentialService");
const { forget } = require("../src/services/bundleContext");

let stored;
const objects = new Map();
files.useStore({
  send: async (command) => {
    stored.push(command.input);
    if (command.input.Body) objects.set(command.input.Key, Buffer.from(command.input.Body));
    if (command.constructor.name === "GetObjectCommand") return { Body: require("stream").Readable.from([objects.get(command.input.Key)]) };
    return {};
  },
});

beforeEach(() => {
  installed = { key: "ca-practice", capabilities: ["vault"] };
  vaultKeys = {};
  rows = [];
  stored = [];
  forget(3);
});

describe("envelope encryption", () => {
  test("a secret round-trips, and the stored form does not contain it", async () => {
    const sealed = await keys.encryptSecrets(3, 5, "gst", { password: "Very$ecret1" });

    assert.equal(sealed.ciphertext.includes(Buffer.from("Very$ecret1")), false);
    assert.deepEqual(await keys.decryptSecrets(3, 5, "gst", sealed), { password: "Very$ecret1" });
  });

  test("a ciphertext copied to another client or portal does not decrypt", async () => {
    const sealed = await keys.encryptSecrets(3, 5, "gst", { password: "x" });

    await assert.rejects(keys.decryptSecrets(3, 6, "gst", sealed), (error) => error.statusCode === 500);
    await assert.rejects(keys.decryptSecrets(3, 5, "income_tax", sealed), (error) => error.statusCode === 500);
  });

  test("each organization has its own data key, wrapped — never stored in the clear", async () => {
    await keys.encryptSecrets(3, 5, "gst", { password: "x" });
    await keys.encryptSecrets(4, 5, "gst", { password: "x" });

    assert.ok(vaultKeys[3] && vaultKeys[4]);
    assert.notDeepEqual(vaultKeys[3].wrapped_key, vaultKeys[4].wrapped_key);
    assert.equal(vaultKeys[3].wrapped_key.length, 12 + 32 + 16);
  });

  test("another master key cannot open the data key", async () => {
    const sealed = await keys.encryptSecrets(3, 5, "gst", { password: "x" });
    const real = process.env.VAULT_MASTER_KEY;

    process.env.VAULT_MASTER_KEY = crypto.randomBytes(32).toString("base64");
    await assert.rejects(keys.decryptSecrets(3, 5, "gst", sealed), (error) => error.statusCode === 503);
    process.env.VAULT_MASTER_KEY = real;
  });

  test("with no master key the vault refuses instead of storing weakly", async () => {
    const real = process.env.VAULT_MASTER_KEY;

    process.env.VAULT_MASTER_KEY = "";
    assert.equal(keys.ready(), false);
    await assert.rejects(keys.encryptSecrets(3, 5, "gst", { password: "x" }), (error) => error.statusCode === 503);
    process.env.VAULT_MASTER_KEY = real;
  });
});

describe("files", () => {
  test("names lose their path and control characters", () => {
    assert.equal(files.cleanName("C:\\Users\\x\\POA signed.pdf"), "POA signed.pdf");
    assert.equal(files.cleanName("../../etc/passwd"), "passwd");
    assert.equal(files.cleanName("a\u0000b\nc.pdf"), "abc.pdf");
  });

  test("downloads are always attachments, with the exact name encoded", () => {
    assert.equal(files.disposition('reçu "final".pdf'), "attachment; filename=\"re_u _final_.pdf\"; filename*=UTF-8''re%C3%A7u%20%22final%22.pdf");
  });
});

describe("reveals", () => {
  test("are rate limited per person", () => {
    for (let index = 0; index < 10; index += 1) rateLimit(901);
    assert.throws(() => rateLimit(901), (error) => error.statusCode === 429);
    assert.doesNotThrow(() => rateLimit(902));
  });
});

const app = require("../src/app");
let server;
let base;

before(async () => {
  mock.method(console, "log", () => {});
  mock.method(console, "error", () => {});
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  global.fetch = realFetch;
});

const token = (permissions) => `Bearer ${jwt.sign({ sub: 7, organizationId: 3, role: "X", permissions }, process.env.JWT_SECRET, { issuer: process.env.JWT_ISSUER })}`;
const call = (method, path, permissions, body) =>
  realFetch(`${base}${path}`, { method, headers: { "Content-Type": "application/json", Authorization: token(permissions) }, body: body && JSON.stringify(body) });

function upload(permissions, bytes, name = "poa.pdf") {
  const form = new FormData();
  form.append("file", new Blob([bytes], { type: "application/pdf" }), name);
  return realFetch(`${base}/vault/customers/5/files?category=consent_poa_signed`, { method: "POST", headers: { Authorization: token(permissions) }, body: form });
}

describe("routes", () => {
  test("reading credentials needs vault.read, and a bundle", async () => {
    assert.equal((await call("GET", "/vault/customers/5/credentials", ["files.read"])).status, 403);

    installed = null;
    forget(3);
    assert.equal((await call("GET", "/vault/customers/5/credentials", ["vault.read"])).status, 404);
  });

  test("revealing needs vault.reveal; saving needs vault.update", async () => {
    assert.equal((await call("POST", "/vault/customers/5/credentials/gst/reveal", ["vault.read", "vault.update"], { reason: "Filing GSTR-3B" })).status, 403);
    assert.equal((await call("PUT", "/vault/customers/5/credentials/gst", ["vault.read"], { fields: {} })).status, 403);
  });

  test("a reveal without a reason is refused before anything is read", async () => {
    const response = await call("POST", "/vault/customers/5/credentials/gst/reveal", ["vault.reveal"], { reason: "" });
    assert.equal(response.status, 400);
  });

  test("an upload lands in the store under a random key, hashed", async () => {
    const bytes = Buffer.from("%PDF-1.4 signed consent");
    const response = await upload(["files.upload"], bytes);

    assert.equal(response.status, 201, await response.clone().text());
    const saved = await response.json();
    assert.equal(saved.sha256, crypto.createHash("sha256").update(bytes).digest("hex"));
    assert.equal(saved.file_name, "poa.pdf");
    assert.match(stored[0].Key, /^org\/3\/[0-9a-f-]{36}$/);
    assert.equal(stored[0].ContentType, "application/octet-stream");
  });

  test("a download returns exactly the bytes uploaded, as an attachment", async () => {
    const bytes = crypto.randomBytes(70000);
    const saved = await (await upload(["files.upload"], bytes)).json();

    const response = await realFetch(`${base}/vault/files/${saved.id}/download`, { headers: { Authorization: token(["files.read"]) } });
    const back = Buffer.from(await response.arrayBuffer());

    assert.equal(response.status, 200);
    assert.ok(back.equals(bytes), `got ${back.length} bytes`);
    assert.match(response.headers.get("content-disposition"), /^attachment;/);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  });

  test("an upload over the cap is refused, and nothing is stored", async () => {
    const response = await upload(["files.upload"], Buffer.alloc(files.MAX_BYTES + 1));

    assert.equal(response.status, 413);
    assert.equal(stored.length, 0);
  });

  test("uploading needs files.upload; another organization's client is not found", async () => {
    assert.equal((await upload(["files.read"], Buffer.from("x"))).status, 403);

    const other = await realFetch(`${base}/vault/customers/5/files`, {
      method: "POST",
      headers: { Authorization: `Bearer ${jwt.sign({ sub: 7, organizationId: 4, role: "X", permissions: ["files.upload"] }, process.env.JWT_SECRET, { issuer: process.env.JWT_ISSUER })}` },
      body: new FormData(),
    });
    assert.equal(other.status, 404);
  });

  test("the install step needs bundles.manage", async () => {
    assert.equal((await call("PUT", "/vault/bundles/ca-practice/0.6.0", ["vault.update"], { vault: { portals: [] } })).status, 403);
  });
});
