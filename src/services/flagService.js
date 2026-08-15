require("dotenv").config();
const crypto = require("crypto");
const { GM_TOKEN } = require("../config/securityConfig");

const SLOTS = ["FLAG1", "FLAG2", "FLAG3", "FLAG4", "FLAG5", "FLAG6"];

const VALUES = Object.fromEntries(
  SLOTS.map((name) => [name, process.env[name] || ""])
);

const GRADER_KEYS = {
  FLAG1: "FLAG1",
  FLAG2: "FLAG2",
  FLAG3: "FLAG3",
  FLAG4: "FLAG4",
  FLAG5: "FLAG5",
  FLAG6: "FLAG6",
};

const PEPPER = crypto.randomBytes(32);

class FlagService {
  getSlot(name) {
    return VALUES[name] || "";
  }

  sha256(value) {
    return crypto.createHash("sha256").update(value || "").digest("hex");
  }

  stackedToken(name, label, encoding = "hex") {
    const flag = VALUES[name] || "";
    if (!flag) return "";
    const layer1 = crypto.createHash("sha256").update(flag).digest();
    const layer2 = crypto.createHmac("sha256", PEPPER).update(layer1).update(label).digest();
    return layer2.toString(encoding);
  }

  verifyFlagHash(authHeader, vulnId, submittedHash) {
    const token =
      authHeader && authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null;
    if (!token || token !== GM_TOKEN) {
      return { status: 401, data: { error: "Unauthorized request" } };
    }
    if (!vulnId || !submittedHash) {
      return { status: 400, data: { error: "Missing parameters" } };
    }
    const slot = GRADER_KEYS[vulnId] || vulnId;
    const currentFlag = VALUES[slot] || "";
    if (!currentFlag) {
      return { status: 200, data: { match: false } };
    }
    const expected = this.sha256(currentFlag);
    return { status: 200, data: { match: expected === submittedHash } };
  }
}

module.exports = new FlagService();
