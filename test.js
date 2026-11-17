// Steal the VFY agent — test suite. Must be run with: node test.js
// Uses TEST-ONLY strategy values (public test salt from the reference
// build). The real deployment salt is NEVER in this file.
'use strict';

process.env.STEAL_VFY_PARAMS = '10,18,0,0,0,0,0,0';
process.env.STEAL_VFY_SALT = '12345678901234567890';
process.env.AGENT_GAMES_HMAC_SECRET = 'test_secret_32_bytes_1234567890';
process.env.PORT = '0';

const assert = require('assert');
const http = require('http');
const crypto = require('crypto');
const snarkjs = require('snarkjs');
const {
  decideMove, matchIdToField, publicInputsHash, computeCommitment,
  verifySignature, signatureFor, handleTurn, runSelfTest, server, ACTION_CODE,
} = require('./server.js');

const WASM = require('path').join(__dirname, 'circuits', 'vfy-policy.wasm');
const ZKEY = require('path').join(__dirname, 'circuits', 'vfy-policy_final.zkey');

let passed = 0;
let failed = 0;
const timings = [];
function pass(name, ms) {
  passed++;
  console.log(`[PASS] ${name}` + (ms != null ? ` (${ms}ms)` : ''));
  if (ms != null) timings.push({ name, ms });
}
function fail(name, err) {
  failed++;
  console.log(`[FAIL] ${name} :: ${err && err.message ? err.message : err}`);
}
async function check(name, fn) {
  const t0 = Date.now();
  try {
    await fn();
    pass(name, Date.now() - t0);
  } catch (e) {
    fail(name, e);
  }
}

function signBody(secret, raw) {
  return crypto.createHmac('sha256', secret).update(raw).digest('hex');
}
function httpReq(port, method, pathUrl, headers, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: pathUrl, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function main() {
  const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
  const PARAMS = [10n, 18n, 0n, 0n, 0n, 0n, 0n, 0n];
  const TEST_SALT = 12345678901234567890n;

  // ---- 1. HMAC -----------------------------------------------------------
  await check('HMAC sign+verify round-trip (bare hex)', async () => {
    const body = JSON.stringify({ hello: 'world' });
    const sig = signatureFor(SECRET, body);
    assert.strictEqual(verifySignature(SECRET, body, sig), true);
    assert.strictEqual(verifySignature(SECRET, body, 'sha256=' + sig), true);
    assert.strictEqual(verifySignature(SECRET, body, '0'.repeat(64)), false);
    assert.strictEqual(verifySignature(SECRET, body + 'x', sig), false);
    assert.strictEqual(verifySignature('wrong-secret', body, sig), false);
  });

  // ---- 2. Commitment vector (known-good Poseidon value) ------------------
  await check('Poseidon commitment matches known vector', async () => {
    const ref = await computeCommitment([8n, 18n, 8n, 0n, 0n, 0n, 0n, 0n], TEST_SALT);
    assert.strictEqual(ref.decimal, '18509752657592529527109630018603854483195680471699643211660232613401632907815');
    assert.strictEqual(ref.hex, '0x28ec26140d6d66210a6816b9caef250448cc76a6f5e440a0a23dea4ead032227');
    const mine = await computeCommitment(PARAMS, TEST_SALT);
    const again = await computeCommitment(PARAMS, TEST_SALT);
    assert.strictEqual(mine.decimal, again.decimal, 'commitment must be deterministic');
  });

  // ---- 3. decideMove matrix (circuit-exact rules, no proving) -----------
  await check('decideMove full state matrix (30 combos)', async () => {
    const cases = [];
    for (const self of [0, 10, 17, 18, 19, 100]) {
      for (const opp of [0, 1, 8, 9, 100]) {
        let expected;
        if (self < 18) expected = 'FORTIFY';
        else if (opp <= 0) expected = 'HOLD';
        else expected = 'EXTRACT';
        cases.push({ self, opp, expected });
      }
    }
    for (const c of cases) {
      const m = decideMove({ selfBalance: c.self, opponentBalance: c.opp }, PARAMS);
      assert.strictEqual(m.type, c.expected, `self=${c.self} opp=${c.opp}`);
      assert.strictEqual(m.amountNum, c.expected === 'EXTRACT' ? 10 : 0);
    }
  });

  // ---- setup for proof tests ---------------------------------------------
  const cfg = { params: PARAMS, salt: TEST_SALT };
  const commitment = await computeCommitment(PARAMS, TEST_SALT);
  const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);
  let proveCount = 0;

  async function fullTurnCase(name, matchId, turn, state) {
    await check(name, async () => {
      const t0 = Date.now();
      const { response } = await handleTurn(
        { matchId, turn, state, strategyCommitment: { hash: commitment.hex } },
        cfg, commitment
      );
      const ms = Date.now() - t0;
      proveCount++;
      assert.ok(ms < 60000, 'proof must be far under the 5-min deadline');
      // shape
      assert.strictEqual(response.matchId, matchId);
      assert.strictEqual(response.turn, turn);
      assert.ok(response.policyProof, 'policyProof present');
      assert.strictEqual(response.policyProof.circuitVersion, 'v1');
      assert.ok(response.policyProof.proof, 'proof present');
      assert.strictEqual(response.policyProof.public_signals.length, 9, 'nPublic=9');
      assert.ok(response.idempotencyKey, 'idempotencyKey present');
      assert.ok(response.agentTimestamp, 'agentTimestamp present');
      // amount rules
      if (response.action.type === 'EXTRACT') {
        assert.strictEqual(response.action.amount, 10);
      } else {
        assert.strictEqual('amount' in response.action, false, response.action.type + ' must omit amount');
      }
      // public signals [1..8] are the 8 hash inputs, in order
      const ps = response.policyProof.public_signals;
      const matchField = matchIdToField(matchId);
      assert.strictEqual(ps[1], commitment.decimal, 'signal[1]=commitment');
      assert.strictEqual(ps[2], matchField.toString(), 'signal[2]=matchId');
      assert.strictEqual(ps[3], String(turn), 'signal[3]=turn');
      assert.strictEqual(ps[4], String(state.selfBalance), 'signal[4]=selfBalance');
      assert.strictEqual(ps[5], String(state.opponentBalance), 'signal[5]=opponentBalance');
      assert.strictEqual(ps[6], String(ACTION_CODE[response.action.type]), 'signal[6]=action');
      assert.strictEqual(ps[7], String(response.action.type === 'EXTRACT' ? 10 : 0), 'signal[7]=amount');
      assert.strictEqual(ps[8], '1', 'signal[8]=circuitVersion');
      // publicInputsHash recomputes correctly
      const recomputed = publicInputsHash({
        commitment: BigInt(commitment.decimal),
        matchId: matchField,
        turn,
        selfBalance: state.selfBalance,
        opponentBalance: state.opponentBalance,
        action: ACTION_CODE[response.action.type],
        amount: response.action.type === 'EXTRACT' ? 10 : 0,
      });
      assert.strictEqual(response.policyProof.publicInputsHash, recomputed, 'publicInputsHash matches');
      // local Groth16 verification
      const ok = await snarkjs.groth16.verify(vk, ps, response.policyProof.proof);
      assert.strictEqual(ok, true, 'Groth16 proof must verify locally');
    });
  }

  // ---- 4. Full turn proofs (all actions + boundaries) --------------------
  const MID = '9f4e1b2a-1111-2222-3333-444455556666';
  await fullTurnCase('turn EXTRACT (self 100, opp 100) + proof verifies', MID, 1, { selfBalance: 100, opponentBalance: 100 });
  await fullTurnCase('turn FORTIFY (self 10, opp 100) + proof verifies', MID, 2, { selfBalance: 10, opponentBalance: 100 });
  await fullTurnCase('turn HOLD (self 100, opp 0) + proof verifies', MID, 3, { selfBalance: 100, opponentBalance: 0 });
  await fullTurnCase('turn EXTRACT boundary self=18', MID, 4, { selfBalance: 18, opponentBalance: 100 });
  await fullTurnCase('turn FORTIFY boundary self=17', MID, 5, { selfBalance: 17, opponentBalance: 100 });
  await fullTurnCase('turn EXTRACT boundary opp=1', MID, 6, { selfBalance: 100, opponentBalance: 1 });
  await fullTurnCase('turn FORTIFY self=0 (edge)', MID, 7, { selfBalance: 0, opponentBalance: 100 });

  // ---- 5. handleTurn behaviours ------------------------------------------
  await check('retry same (matchId,turn) returns IDENTICAL response', async () => {
    const payload = { matchId: MID, turn: 11, state: { selfBalance: 100, opponentBalance: 100 }, strategyCommitment: { hash: commitment.hex } };
    const r1 = (await handleTurn(payload, cfg, commitment)).response;
    const r2 = (await handleTurn(payload, cfg, commitment)).response;
    assert.deepStrictEqual(r2, r1, 'retry must return the cached identical response');
    assert.strictEqual(r1.idempotencyKey, r2.idempotencyKey);
  });
  await check('different turn gets a different idempotencyKey', async () => {
    const a = (await handleTurn({ matchId: MID, turn: 12, state: { selfBalance: 100, opponentBalance: 100 }, strategyCommitment: { hash: commitment.hex } }, cfg, commitment)).response;
    const b = (await handleTurn({ matchId: MID, turn: 13, state: { selfBalance: 100, opponentBalance: 100 }, strategyCommitment: { hash: commitment.hex } }, cfg, commitment)).response;
    assert.notStrictEqual(a.idempotencyKey, b.idempotencyKey);
    assert.notStrictEqual(a.policyProof.proof.pi_a[0], b.policyProof.proof.pi_a[0], 'proofs differ per turn');
  });
  await check('envelope with WRONG strategyCommitment hash still proves (uses computed)', async () => {
    const { response } = await handleTurn(
      { matchId: MID, turn: 14, state: { selfBalance: 100, opponentBalance: 100 }, strategyCommitment: { hash: '0x' + '11'.repeat(32) } },
      cfg, commitment
    );
    assert.strictEqual(response.action.type, 'EXTRACT');
    const ok = await snarkjs.groth16.verify(vk, response.policyProof.public_signals, response.policyProof.proof);
    assert.strictEqual(ok, true);
  });
  await check('expired deadline -> 410 error', async () => {
    try {
      await handleTurn({ matchId: MID, turn: 15, state: { selfBalance: 100, opponentBalance: 100 }, deadline: Date.now() - 10 * 60 * 1000 }, cfg, commitment);
      throw new Error('should have thrown');
    } catch (e) {
      assert.strictEqual(e.status, 410);
    }
  });
  await check('future deadline passes through', async () => {
    const { response } = await handleTurn({ matchId: MID, turn: 16, state: { selfBalance: 100, opponentBalance: 100 }, deadline: Date.now() + 5 * 60 * 1000 }, cfg, commitment);
    assert.strictEqual(response.action.type, 'EXTRACT');
  });
  await check('missing state -> 400 error', async () => {
    try {
      await handleTurn({ matchId: MID, turn: 17, state: {} }, cfg, commitment);
      throw new Error('should have thrown');
    } catch (e) {
      assert.strictEqual(e.status, 400);
    }
  });
  await check('non-hex matchId works via keccak fallback + proof verifies', async () => {
    const { response } = await handleTurn({ matchId: 'stv_12_4', turn: 1, state: { selfBalance: 100, opponentBalance: 100 }, strategyCommitment: { hash: commitment.hex } }, cfg, commitment);
    assert.strictEqual(response.matchId, 'stv_12_4');
    const ok = await snarkjs.groth16.verify(vk, response.policyProof.public_signals, response.policyProof.proof);
    assert.strictEqual(ok, true);
  });

  // ---- 6. HTTP end-to-end -------------------------------------------------
  await check('self-test passes at startup', async () => {
    await runSelfTest();
    const { _internals } = require('./server.js');
    assert.strictEqual(_internals.selfTest, 'PASS');
  });
  const port = await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
  try {
    await check('GET /health: 200, hmac on, selfTest PASS, no salt leak', async () => {
      const r = await httpReq(port, 'GET', '/health');
      assert.strictEqual(r.status, 200);
      const j = JSON.parse(r.body);
      assert.strictEqual(j.ok, true);
      assert.strictEqual(j.agent, 'steal-the-vfy');
      assert.strictEqual(j.hmacConfigured, true);
      assert.strictEqual(j.selfTest, 'PASS');
      assert.strictEqual(j.strategyCommitment, commitment.hex);
      assert.ok(!r.body.includes('12345678901234567890'), 'salt must not leak via /health');
    });
    await check('POST /steal without signature -> 401', async () => {
      const body = JSON.stringify({ matchId: MID, turn: 21, state: { selfBalance: 100, opponentBalance: 100 } });
      const r = await httpReq(port, 'POST', '/steal', { 'content-type': 'application/json' }, body);
      assert.strictEqual(r.status, 401);
    });
    await check('POST /steal with wrong signature -> 401', async () => {
      const body = JSON.stringify({ matchId: MID, turn: 21, state: { selfBalance: 100, opponentBalance: 100 } });
      const r = await httpReq(port, 'POST', '/steal', { 'content-type': 'application/json', 'x-agent-games-signature': '0'.repeat(64) }, body);
      assert.strictEqual(r.status, 401);
    });
    await check('POST /steal with valid signature -> 200 + signed response + proof verifies', async () => {
      const body = JSON.stringify({ matchId: MID, turn: 21, state: { selfBalance: 100, opponentBalance: 100 }, strategyCommitment: { hash: commitment.hex } });
      const t0 = Date.now();
      const r = await httpReq(port, 'POST', '/steal', { 'content-type': 'application/json', 'x-agent-games-signature': signBody(SECRET, body) }, body);
      const ms = Date.now() - t0;
      assert.strictEqual(r.status, 200);
      assert.ok(ms < 60000, 'turn answered far inside the 5-min deadline');
      const j = JSON.parse(r.body);
      assert.strictEqual(j.action.type, 'EXTRACT');
      assert.ok(r.headers['x-agent-games-signature'], 'response must carry HMAC header');
      assert.strictEqual(verifySignature(SECRET, r.body, r.headers['x-agent-games-signature']), true, 'response signature must verify');
      const ok = await snarkjs.groth16.verify(vk, j.policyProof.public_signals, j.policyProof.proof);
      assert.strictEqual(ok, true);
    });
    await check('POST /steal preflight -> {ok:true, protocolVersion:v1}', async () => {
      const body = JSON.stringify({ type: 'agent-games.preflight.v1' });
      const r = await httpReq(port, 'POST', '/steal', { 'content-type': 'application/json', 'x-agent-games-signature': signBody(SECRET, body) }, body);
      assert.strictEqual(r.status, 200);
      assert.deepStrictEqual(JSON.parse(r.body), { ok: true, protocolVersion: 'v1' });
    });
    await check('POST /steal invalid JSON (signed) -> 400', async () => {
      const body = '{not json';
      const r = await httpReq(port, 'POST', '/steal', { 'content-type': 'application/json', 'x-agent-games-signature': signBody(SECRET, body) }, body);
      assert.strictEqual(r.status, 400);
    });
    await check('GET /unknown -> 404', async () => {
      const r = await httpReq(port, 'GET', '/unknown');
      assert.strictEqual(r.status, 404);
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  // ---- summary -------------------------------------------------------------
  const slowest = timings.reduce((m, t) => Math.max(m, t.ms), 0);
  const totalProves = require('./server.js')._internals.proofsGenerated;
  console.log('\n----------------------------------------');
  console.log(`RESULT: ${passed} passed, ${failed} failed (${totalProves} Groth16 proofs generated + verified locally in total)`);
  console.log(`Slowest single check: ${slowest}ms (turn deadline is 300000ms)`);
  if (failed > 0) process.exit(1);
  console.log('ALL TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
