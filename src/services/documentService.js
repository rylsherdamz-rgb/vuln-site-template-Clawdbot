const fs = require("fs");
const path = require("path");

const DOCS_ROOT = path.join(__dirname, "../../docs");
const REAL_DOCS_ROOT = fs.realpathSync(DOCS_ROOT);

function readDocument(inputPath) {
  const rawInput = (inputPath || "").toString();
  const resolvedPath = path.resolve(DOCS_ROOT, rawInput);
  try {
    // Resolve symlinks before the containment check — a symlink inside
    // DOCS_ROOT pointing outside it would otherwise pass a plain string check.
    const realPath = fs.realpathSync(resolvedPath);
    const withinRoot =
      realPath === REAL_DOCS_ROOT || realPath.startsWith(REAL_DOCS_ROOT + path.sep);
    if (!withinRoot) {
      return { success: false, error: `Cannot read file: ${rawInput}` };
    }
    const content = fs.readFileSync(realPath, "utf8");
    return { success: true, filename: rawInput, content };
  } catch {
    return { success: false, error: `Cannot read file: ${rawInput}` };
  }
}

module.exports = { readDocument };
