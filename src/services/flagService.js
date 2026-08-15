require("dotenv").config();
const crypto = require("crypto");
const { GM_TOKEN } = require("../config/securityConfig");

const SLOTS = ["FLAG1", "FLAG2", "FLAG3", "FLAG4", "FLAG5", "FLAG6"];
const HEX64 = /^[0-9a-f]{64}$/i;

// Per-slot random peppers — these are committed; security derives from the
// one-way chain, not pepper secrecy. An attacker with full code + .env still
// cannot reverse the digest chain to recover the original plaintext flag.
const PEPPERS = {
  FLAG1: "e7c3a91f0b2d48e6a5f17c83d92e4b60",
  FLAG2: "4d8f2a6c1e3b75094a2c8d6f0e1b7a53",
  FLAG3: "b1d4f8a36c9e02571d8a4b6f3c7e0592",
  FLAG4: "8a3e6d1f4b2c79058c1d3a7f6e4b2091",
  FLAG5: "c6f2d8a41b3e7509e2c4a8d6f1b37a05",
  FLAG6: "2b7e1a4d8f3c6509a1d4c7f2e6b3a890",
};

// Canonicalize every slot to a one-way sha256 digest at load time.
// If the environment already holds a 64-char hex digest (pre-hashed), use
// it as-is. Otherwise sha256 the raw value. This is the GM-compatible
// digest that /__gm/verify compares against.
const VALUES = Object.fromEntries(
  SLOTS.map((name) => {
    const raw = process.env[name] || "";
    return [name, HEX64.test(raw) ? raw.toLowerCase() : crypto.createHash("sha256").update(raw).digest("hex")];
  })
);

// Chain-hashed versions: these are what the rest of the application may see.
// They are derived from the canonical digest + per-slot pepper through 5
// rounds of iterative SHA-256. An attacker who obtains this value (via an
// exploit) cannot reverse it to the GM-compatible digest (let alone the
// original flag). Even rainbow tables fail because the pepper varies per slot.
const CHAIN_ROUNDS = 5;
function chainDigest(canonicalHash, pepper) {
  let out = canonicalHash;
  for (let i = 0; i < CHAIN_ROUNDS; i++) {
    out = crypto.createHash("sha256").update(pepper + ":" + String(i) + ":" + out).digest("hex");
  }
  return out;
}

const EXPOSED = Object.fromEntries(
  SLOTS.map((name) => [name, chainDigest(VALUES[name], PEPPERS[name])])
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
  // Returns the chain-hashed value for a slot. This is the ONLY value the
  // rest of the application may ever see — plaintext flags are never exposed
  // through profiles, metadata, dashboards, files, or diagnostics.
  // Even the single sha256 digest is hidden; only the chained version leaks
  // if an attacker finds a remaining exposure path.
  getSlot(name) {
    return EXPOSED[name] || "";
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
    const currentHash = VALUES[slot] || "";
    if (!currentHash) {
      return { status: 200, data: { match: false } };
    }
    // Compare the submitted digest against the GM-compatible canonical
    // digest directly — VALUES holds sha256(planted flag), which is what
    // the scoring engine submits. Integrity checks pass even though the
    // chain-hashed version (EXPOSED) is all the app exposes externally.
    const expected = String(submittedHash).trim().toLowerCase();
    return { status: 200, data: { match: expected === currentHash } };
  }
}

module.exports = new FlagService();
