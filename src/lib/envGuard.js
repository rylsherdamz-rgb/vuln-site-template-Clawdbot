const SLOTS = ["FLAG1", "FLAG2", "FLAG3", "FLAG4", "FLAG5", "FLAG6", "GM_TOKEN"];

function scrubFlagEnv() {
  for (const name of SLOTS) {
    delete process.env[name];
  }
}

module.exports = { scrubFlagEnv };
