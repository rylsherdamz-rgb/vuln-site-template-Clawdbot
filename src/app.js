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

try {
  fs.rmSync(path.join(__dirname, "..", "secret.txt"), { force: true });
} catch (err) {
  console.error("startup:", err.message);
}

store.initStore();
scrubFlagEnv();

const app = express();
app.use(express.static(path.join(__dirname, "../public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(sessionMiddleware);
app.use(webRoutes);
app.use(apiRoutes);

app.listen(PORT, () => {
  console.log(`${APP_NAME} listening on port ${PORT}`);
});

module.exports = app;
