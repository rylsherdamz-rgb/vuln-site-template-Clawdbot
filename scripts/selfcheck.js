const assert = require("assert");

process.env.FLAG1 = "testflag1";
process.env.GM_TOKEN = "testtoken";

const flagService = require("../src/services/flagService");
const { scrubFlagEnv } = require("../src/lib/envGuard");

const rawFlag = "testflag1";
const rawHash = flagService.sha256(rawFlag);
const decoy = flagService.stackedToken("FLAG1", "order.accessToken");

assert.notStrictEqual(decoy, rawHash);
assert.strictEqual(flagService.stackedToken("FLAG2", "unset.slot"), "");

const goodSubmit = flagService.verifyFlagHash("Bearer testtoken", "FLAG1", rawHash);
assert.strictEqual(goodSubmit.data.match, true);

const decoySubmit = flagService.verifyFlagHash("Bearer testtoken", "FLAG1", decoy);
assert.strictEqual(decoySubmit.data.match, false);

const flagServicePath = require.resolve("../src/services/flagService");

process.env.FLAG2 = "testflag2";
process.env.FLAG3 = "testflag3";
process.env.FLAG4 = "testflag4";
process.env.FLAG5 = "testflag5";
delete require.cache[flagServicePath];
const chainA = require("../src/services/flagService").stackedToken("FLAG5", "admin.internal_ops_token");

process.env.FLAG1 = "different-flag1-value";
delete require.cache[flagServicePath];
const chainB = require("../src/services/flagService").stackedToken("FLAG5", "admin.internal_ops_token");

assert.notStrictEqual(chainA, chainB);

scrubFlagEnv();
assert.strictEqual(process.env.FLAG1, undefined);
assert.strictEqual(process.env.GM_TOKEN, undefined);

const postScrubSubmit = flagService.verifyFlagHash("Bearer testtoken", "FLAG1", rawHash);
assert.strictEqual(postScrubSubmit.data.match, true);

console.log("selfcheck ok");
