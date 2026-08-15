const crypto = require("crypto");

class CryptoUtil {
  static sha256(value) {
    return crypto.createHash("sha256").update(value || "").digest("hex");
  }

  static parseJwtHeader(token) {
    if (!token) return null;
    const parts = token.replace(/^Bearer\s+/i, "").split(".");
    if (parts.length < 2) return null;
    try {
      const headerStr = Buffer.from(parts[0], "base64url").toString("utf8");
      return JSON.parse(headerStr);
    } catch {
      return null;
    }
  }

  // Verifies a compact HS256 JWT against `secret`. Rejects anything that
  // isn't a correctly-signed HS256 token — no "alg: none", no algorithm confusion.
  static verifyHs256Jwt(token, secret) {
    if (!token || !secret) return false;
    const parts = token.replace(/^Bearer\s+/i, "").split(".");
    if (parts.length !== 3) return false;
    const [headerB64, payloadB64, signatureB64] = parts;
    let header;
    try {
      header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    } catch {
      return false;
    }
    if (header.alg !== "HS256") return false;
    const expectedSig = crypto
      .createHmac("sha256", secret)
      .update(`${headerB64}.${payloadB64}`)
      .digest();
    let actualSig;
    try {
      actualSig = Buffer.from(signatureB64, "base64url");
    } catch {
      return false;
    }
    if (actualSig.length !== expectedSig.length) return false;
    return crypto.timingSafeEqual(actualSig, expectedSig);
  }
}

module.exports = CryptoUtil;
