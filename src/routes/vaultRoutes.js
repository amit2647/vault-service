const express = require("express");

const authenticate = require("../middleware/authenticate");
const requirePermission = require("../middleware/requirePermission");
const requireBundle = require("../middleware/requireBundle");
const credentials = require("../services/credentialService");
const files = require("../services/fileService");

const router = express.Router();

/*
 * The vault (CD-10, CD-13). Every route but the install step answers only an
 * organization with a profession bundle. Secrets leave this service in one
 * place only: a reveal, with its reason, uncached.
 */

const KEY = /^[a-z][a-z0-9-]{1,59}$/;
const ITEM = /^[a-z][a-z0-9_]{1,59}$/;
const VERSION = /^\d+\.\d+\.\d+$/;

function respond(handler) {
  return async (req, res) => {
    try {
      const result = await handler(req, res);
      if (!res.headersSent) res.json(result ?? { ok: true });
    } catch (error) {
      if (!error.statusCode) console.error("[Vault]", error);
      if (res.headersSent) return;
      res.status(error.statusCode || 500).json({
        error: error.statusCode ? error.message : "The vault request failed",
        ...(error.details ? { details: error.details } : {}),
      });
    }
  };
}

function bad(message) {
  const error = new Error(message);
  error.statusCode = 400;
  return error;
}

function id(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number <= 0) throw bad("Invalid id");
  return number;
}

function portalKey(value) {
  if (!ITEM.test(String(value || ""))) throw bad("Invalid portal");
  return value;
}

const auth = (req) => ({ organizationId: req.auth.organizationId, userId: req.auth.userId });
const gated = (permission) => [authenticate, requirePermission(permission), requireBundle];

// The vault step of a bundle install (runs before the install has finished).
router.put(
  "/vault/bundles/:key/:version",
  authenticate,
  requirePermission("bundles.manage"),
  respond((req) => {
    if (!KEY.test(req.params.key) || !VERSION.test(req.params.version)) throw bad("Invalid bundle key or version");
    const vault = req.body?.vault;
    if (!vault || typeof vault !== "object") throw bad("vault is required");

    return credentials.installVault(req.auth.organizationId, req.params.key, req.params.version, vault);
  }),
);

// Portals with what is stored for this client — never a secret.
router.get(
  "/vault/customers/:customerId/credentials",
  ...gated("vault.read"),
  respond((req) => credentials.list(req.auth.organizationId, id(req.params.customerId))),
);

router.put(
  "/vault/customers/:customerId/credentials/:portalKey",
  ...gated("vault.update"),
  respond((req) => credentials.save(auth(req), id(req.params.customerId), portalKey(req.params.portalKey), req.body?.fields)),
);

router.delete(
  "/vault/customers/:customerId/credentials/:portalKey",
  ...gated("vault.update"),
  respond((req) => credentials.remove(auth(req), id(req.params.customerId), portalKey(req.params.portalKey))),
);

router.post(
  "/vault/customers/:customerId/credentials/:portalKey/reveal",
  ...gated("vault.reveal"),
  respond(async (req, res) => {
    res.set("Cache-Control", "no-store");
    return credentials.reveal(auth(req), id(req.params.customerId), portalKey(req.params.portalKey), req.body?.reason);
  }),
);

router.get(
  "/vault/customers/:customerId/reveals",
  ...gated("vault.reveal"),
  respond((req) => credentials.revealLog(req.auth.organizationId, id(req.params.customerId))),
);

router.get(
  "/vault/customers/:customerId/files",
  ...gated("files.read"),
  respond((req) => files.list(req.auth.organizationId, id(req.params.customerId))),
);

router.post(
  "/vault/customers/:customerId/files",
  ...gated("files.upload"),
  respond(async (req, res) => {
    const saved = await files.upload(auth(req), id(req.params.customerId), req.query.category, req);
    res.status(201);
    return saved;
  }),
);

router.get(
  "/vault/files/:id/download",
  ...gated("files.read"),
  respond((req, res) => files.download(req.auth.organizationId, id(req.params.id), res)),
);

router.delete(
  "/vault/files/:id",
  ...gated("files.delete"),
  respond((req) => files.remove(auth(req), id(req.params.id))),
);

// Runs the sweeper now, for this organization's purged clients.
router.post(
  "/vault/files/sweep",
  ...gated("system.settings"),
  respond((req) => files.sweep({ organizationId: req.auth.organizationId })),
);

module.exports = router;
