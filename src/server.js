const app = require("./app");

const PORT = process.env.PORT || 4012;

async function startServer() {
  try {
    console.log("[SERVER] Starting vault-service...");

    app.listen(PORT, () => {
      console.log(`[SERVER] Vault service running on port ${PORT}`);
    });
  } catch (error) {
    console.error("[SERVER] Vault service startup failed");

    console.error(error);

    process.exit(1);
  }
}

startServer();
