const flagService = require("./flagService");
const CryptoUtil = require("../lib/cryptoUtil");
const { GM_TOKEN } = require("../config/securityConfig");

const ADMIN_DASHBOARD = {
  status: "operational",
  activeUsers: 1284,
  revenue_today: "$14,322.88",
  last_deploy: "2026-08-10T02:00:00Z",
  internal_ops_token: flagService.getSlot("FLAG5"),
};

function verifyAdminToken(rawToken) {
  if (!rawToken) {
    return { status: 401, body: { error: "Authorization header required" } };
  }
  if (!CryptoUtil.verifyHs256Jwt(rawToken, GM_TOKEN)) {
    return { status: 403, body: { error: "Invalid token signature" } };
  }
  return { status: 200, body: ADMIN_DASHBOARD };
}

module.exports = { verifyAdminToken };
