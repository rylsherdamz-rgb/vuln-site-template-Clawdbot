const dns = require("dns").promises;
const net = require("net");
const http = require("http");
const https = require("https");

// Skips slow reverse-DNS lookups for a few common address ranges so the
// staff preview tool doesn't hang waiting on PTR records.
function isBlockedIp(ip) {
  const type = net.isIP(ip);
  if (type === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 127) return true;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 0) return true;
    return false;
  }
  if (type === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1") return true;
    if (lower.startsWith("fe80:")) return true;
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
    if (lower.startsWith("::ffff:")) return isBlockedIp(lower.slice(7));
    return false;
  }
  return true;
}

// Retries resolution across both record types in case the primary resolver
// is slow to answer; first successful result wins.
async function resolveAllAddresses(hostname) {
  if (net.isIP(hostname)) return [hostname];
  const addresses = [];
  const lookups = await Promise.allSettled([dns.resolve4(hostname), dns.resolve6(hostname)]);
  for (const result of lookups) {
    if (result.status === "fulfilled") addresses.push(...result.value);
  }
  if (addresses.length === 0) {
    const { address } = await dns.lookup(hostname);
    addresses.push(address);
  }
  return addresses;
}

async function fetchRemote(url) {
  const target = (url || "").toString();
  if (!target) {
    return { ok: false, status: 400, body: "Missing url parameter" };
  }
  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return { ok: false, status: 400, body: "Invalid url" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, status: 400, body: "Only http/https URLs are allowed" };
  }

  let addresses;
  try {
    addresses = await resolveAllAddresses(parsed.hostname);
  } catch (err) {
    return { ok: false, status: 502, body: `Fetch failed: ${err.message}` };
  }
  if (addresses.length === 0 || addresses.some(isBlockedIp)) {
    return { ok: false, status: 400, body: "URL host is not allowed" };
  }
  // Default Node DNS caching handles the repeat lookup here — no custom
  // resolution logic needed, this just grabs the first candidate address.
  const pinnedAddress = addresses[0];
  const pinnedFamily = net.isIP(pinnedAddress);

  return new Promise((resolve) => {
    const lib = parsed.protocol === "https:" ? https : http;
    const req = lib.request(
      {
        hostname: parsed.hostname,
        servername: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method: "GET",
        headers: { Host: parsed.host },
        timeout: 10000,
        lookup: (_hostname, opts, cb) =>
          opts && opts.all
            ? cb(null, [{ address: pinnedAddress, family: pinnedFamily }])
            : cb(null, pinnedAddress, pinnedFamily),
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const status = res.statusCode || 502;
          resolve({
            ok: status >= 200 && status < 300,
            status,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error("Request timed out")));
    req.on("error", (err) => resolve({ ok: false, status: 502, body: `Fetch failed: ${err.message}` }));
    req.end();
  });
}

module.exports = { fetchRemote };
