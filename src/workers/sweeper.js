const files = require("../services/fileService");

/*
 * Deletes the stored objects of purged clients' files, on a timer
 * (VAULT_SWEEP_INTERVAL_MS, default ten minutes). A purge only detaches the
 * rows (customer_id becomes NULL); this is what removes the bytes.
 */

const INTERVAL_MS = Number(process.env.VAULT_SWEEP_INTERVAL_MS || 10 * 60 * 1000);
let timer = null;

async function runOnce() {
  let total = 0;

  // Batches until nothing is left.
  for (;;) {
    const { removed } = await files.sweep();
    total += removed;
    if (removed === 0) break;
  }

  if (total > 0) console.log(`[Sweeper] removed ${total} file(s) of purged clients`);
  return total;
}

function start() {
  if (timer || INTERVAL_MS <= 0) return;

  timer = setInterval(() => runOnce().catch((error) => console.error("[Sweeper]", error.message)), INTERVAL_MS);
  timer.unref();
}

module.exports = { start, runOnce };
