const dns = require("dns").promises;
const net = require("net");
const http = require("http");
const https = require("https");

// Parse an IPv6 literal into its 16 raw bytes (or null if malformed).
// Handles "::" compression and trailing dotted-quad notation so exotic
// encodings like 0:0:0:0:0:ffff:7f00:1 normalize to the same bytes as
// ::ffff:127.0.0.1.
function ipv6ToBytes(ip6) {
  const s = ip6.toLowerCase();
  const dc = s.indexOf("::");
  const head = dc !== -1 ? s.slice(0, dc) : s;
  const tail = dc !== -1 ? s.slice(dc + 2) : null;

  const parsePart = (part) => {
    if (!part) return [];
    const groups = part.split(":");
    const last = groups[groups.length - 1];
    if (last.includes(".")) {
      const parts = last.split(".").map(Number);
      if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
      groups.pop();
      groups.push(((parts[0] << 8) | parts[1]).toString(16), ((parts[2] << 8) | parts[3]).toString(16));
    }
    const bytes = [];
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      const n = parseInt(g, 16);
      bytes.push((n >> 8) & 0xff, n & 0xff);
    }
    return bytes;
  };

  if (tail === null) {
    const out = parsePart(head);
    return out && out.length === 16 ? out : null;
  }
  const a = parsePart(head);
  const b = parsePart(tail);
  if (a === null || b === null) return null;
  if (a.length + b.length > 16) return null;
  const out = a.concat(new Array(16 - a.length - b.length).fill(0)).concat(b);
  return out.length === 16 ? out : null;
}

// If an IPv6 address embeds an IPv4 address (IPv4-mapped ::ffff:a.b.c.d,
// IPv4-compatible ::a.b.c.d, or their hex/expanded spellings), return the
// dotted-quad IPv4 so it can be checked — otherwise null.
function embeddedIpv4(bytes) {
  if (!bytes || bytes.length !== 16) return null;
  const first80Zero =
    bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0 && bytes[3] === 0 &&
    bytes[4] === 0 && bytes[5] === 0 && bytes[6] === 0 && bytes[7] === 0 &&
    bytes[8] === 0 && bytes[9] === 0;
  const mapped = first80Zero && bytes[10] === 0xff && bytes[11] === 0xff;
  const compatible = first80Zero && bytes[10] === 0 && bytes[11] === 0;
  if (!mapped && !compatible) return null;
  return `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
}

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
    // Any textual encoding of an IPv4-mapped / IPv4-compatible address
    // (::ffff:a.b.c.d, ::ffff:0:a.b.c.d, hex or fully expanded spellings)
    // must be checked against the embedded IPv4 — a plain prefix match on
    // the string would let e.g. [0:0:0:0:0:ffff:7f00:1] reach loopback.
    const embedded = embeddedIpv4(ipv6ToBytes(lower));
    if (embedded) return isBlockedIp(embedded);
    return false;
  }
  return true; // unresolvable / unknown — fail closed
}

// Resolves every A/AAAA record for hostname (not just the first, and not a
// literal IP passthrough) so every address the name could round-robin to
// gets validated up front.
async function resolveAllAddresses(rawHostname) {
  const hostname =
    rawHostname.startsWith("[") && rawHostname.endsWith("]")
      ? rawHostname.slice(1, -1)
      : rawHostname;
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
