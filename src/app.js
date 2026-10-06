const express = require("express");
const cors = require("cors");

const healthRoutes = require("./routes/healthRoutes");
const vaultRoutes = require("./routes/vaultRoutes");
const requestLogger = require("./middleware/requestLogger");

/*
 * Vault service — encrypted portal credentials (reveal is audited) and client files kept in the S3 store.
 *
 * A capability service of the profession-bundle platform: profession-neutral,
 * configured by the organization's installed bundle (milestone M6). Uploads
 * are multipart and read by the file route itself, not by express.json.
 */
const app = express();

app.use(cors());
app.use(express.json());

app.use(requestLogger);

app.use(healthRoutes);
app.use(vaultRoutes);

module.exports = app;
