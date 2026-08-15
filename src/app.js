require("dotenv").config();
const express = require("express");
const fs = require("fs");
const path = require("path");
const { PORT, APP_NAME } = require("./config/appConfig");
const { sessionMiddleware } = require("./middleware/session");
const { scrubFlagEnv } = require("./lib/envGuard");
const store = require("./store");
const apiRoutes = require("./routes/apiRoutes");
const webRoutes = require("./routes/webRoutes");

// Remove any leftover secret.txt from previous runs — we no longer plant
// flags to disk; scrubbing stale files closes the path-traversal vector.
try {
  fs.rmSync(path.join(__dirname, "..", "secret.txt"), { force: true });
} catch (err) {
  console.error("startup:", err.message);
}

store.initStore();
scrubFlagEnv();

const app = express();
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  next();
});
app.use(express.static(path.join(__dirname, "../public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(sessionMiddleware);
app.use(webRoutes);
app.use(apiRoutes);

const server = app.listen(PORT, () => {
  console.log(`${APP_NAME} listening on port ${PORT}`);
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(
      `Port ${PORT} is already in use. The devcontainer's postStartCommand already runs "npm start" automatically on Codespace boot — check the Ports tab, or run "fuser -k ${PORT}/tcp" before starting again.`
    );
    process.exit(1);
  }
  throw err;
});

module.exports = app;
