const dns = require("dns").promises;
const net = require("net");
const http = require("http");
const https = require("https");

// Blocks SSRF to loopback / private / link-local ranges — including the
// 169.254.169.254 cloud metadata address and the app's own internal routes.
function isBlockedIp(ip) {
  const type = net.isIP(ip);
  if (type === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 127) return true; // loopback
    if (a === 10) return true; // RFC1918
    if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
    if (a === 192 && b === 168) return true; // RFC1918
    if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
    if (a === 0) return true;
    return false;
  }
  if (type === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1") return true; // loopback
    if (lower.startsWith("fe80:")) return true; // link-local
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local
    if (lower.startsWith("::ffff:")) return isBlockedIp(lower.slice(7)); // mapped IPv4
    return false;
  }
  return true; // unresolvable / unknown — fail closed
}

// Resolves every A/AAAA record for hostname (not just the first, and not a
// literal IP passthrough) so every address the name could round-robin to
// gets validated up front.
async function resolveAllAddresses(hostname) {
  if (net.isIP(hostname)) return [hostname];
  const addresses = [];
  const lookups = await Promise.allSettled([dns.resolve4(hostname), dns.resolve6(hostname)]);
  for (const result of lookups) {
    if (result.status === "fulfilled") addresses.push(...result.value);
  }
  if (addresses.length === 0) {
    const { address } = await dns.lookup(hostname); // covers /etc/hosts etc.
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
  // Pin the connection to the address we just validated — using a custom
  // `lookup` instead of a second DNS resolution closes the TOCTOU/rebinding
  // gap where the name could re-resolve to an internal IP between the check
  // and the actual connect. Hostname/Host header stay as the original name
  // so TLS SNI and cert validation still work for real HTTPS targets.
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
