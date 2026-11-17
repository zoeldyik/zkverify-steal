// zkVerify Agent Games — Steal the VFY agent
//
// A 20-turn head-to-head match. Each turn the platform POSTs a signed turn
// envelope; the agent answers with EXTRACT / FORTIFY / HOLD plus a Groth16
// policy proof that the move follows the Poseidon-committed strategy.
//
// Facts verified 17 Nov 2026 (see README.md for sources):
// - Circuit: vfy-policy.wasm / vfy-policy_final.zkey, Groth16/BN128,
//   nPublic = 9, vkHash 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
//   (from https://agentgames.zkverify.io/api/circuit-info).
// - Public signals: [output, commitment, matchId, turnNumber, selfBalance,
//   opponentBalance, action, amount, circuitVersion]. Signals [1..8] are the
//   8 values hashed (keccak256, 32-byte big-endian each) into publicInputsHash.
// - Strategy commitment = Poseidon(strategyParams[0..7], salt), registered
//   in the dashboard before play; frozen mid-match.
// - Circuit-enforced policy (verified by direct proving, NOT just the docs):
//     selfBalance < params[1]            -> FORTIFY
//     opponentBalance <= params[2]       -> HOLD        (note: <= , not <)
//     otherwise                          -> EXTRACT params[0]
//   EXTRACT amount must equal params[0] exactly; params[0] in 1..10.
//   FORTIFY/HOLD must have amount 0 (and the response must OMIT the amount
//   field entirely for those two actions).
// - HMAC-SHA256 over the raw body, header x-agent-games-signature, both ways.
// - Response: { matchId, turn, action, policyProof: { circuitVersion: "v1",
//   proof, public_signals, publicInputsHash }, agentTimestamp, idempotencyKey }.
//   proof + public_signals MUST sit INSIDE policyProof.
// - Turn deadline 5 min; platform waits ~30 s per push. Proof time here is
//   ~1.5-3 s, far inside the deadline.
// - Preflight: {"type":"agent-games.preflight.v1"} -> {ok:true, protocolVersion:"v1"}.
//
// No wallet, seed or private key anywhere in this code. The HMAC secret and
// the strategy salt come from environment variables only.

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const snarkjs = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');
const { keccak_256 } = require('js-sha3');

// ---------------------------------------------------------------- config --

const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex'; // 'hex' or 'sha256='
const WASM = path.join(__dirname, 'circuits', 'vfy-policy.wasm');
const ZKEY = path.join(__dirname, 'circuits', 'vfy-policy_final.zkey');
const VK_HASH = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';
const CACHE_FILE = path.join(__dirname, 'data', 'responses.json');
const MAX_CACHE = 200;

const ACTION_CODE = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };
const ACTION_NAME = { 0: 'HOLD', 1: 'FORTIFY', 2: 'EXTRACT' };

// Minimal .env loader (no dependency): KEY=VALUE lines, # comments, trims
// surrounding quotes. Real deployments set real env vars (Railway); the
// loader only makes local runs convenient. Never commit a real .env.
function loadEnvFile() {
  try {
    const raw = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
    for (const line of raw.split('\n')) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (!m || line.trim().startsWith('#')) continue;
      const key = m[1];
      let val = m[2].trim().replace(/^['"]|['"]$/g, '');
      if (!(key in process.env)) process.env[key] = val;
    }
  } catch { /* no .env — env vars must be set another way */ }
}
loadEnvFile();

function getStrategyConfig() {
  const rawParams = process.env.STEAL_VFY_PARAMS || '';
  const parts = rawParams.split(',').map((x) => x.trim()).filter((x) => x !== '');
  if (parts.length !== 8) {
    throw new Error('STEAL_VFY_PARAMS must have exactly 8 comma-separated integers (e.g. "10,18,0,0,0,0,0,0")');
  }
  const params = parts.map((x) => {
    if (!/^\d+$/.test(x)) throw new Error('STEAL_VFY_PARAMS must be non-negative integers, got: ' + x);
    return BigInt(x);
  });
  if (params[0] < 1n || params[0] > 10n) {
    throw new Error('STEAL_VFY_PARAMS[0] (EXTRACT amount) must be in 1..10, got: ' + params[0]);
  }
  const saltRaw = (process.env.STEAL_VFY_SALT || '').trim();
  if (!saltRaw || !/^\d+$/.test(saltRaw)) {
    throw new Error('STEAL_VFY_SALT must be set to a decimal integer (run: npm run commitment)');
  }
  return { params, salt: BigInt(saltRaw) };
}

// ------------------------------------------------------------------ HMAC --

function signatureFor(secret, rawBody) {
  const hex = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  return HMAC_FORMAT === 'sha256=' ? 'sha256=' + hex : hex;
}

// Accepts bare hex or "sha256=<hex>" on input (the platform's exact prefix
// convention is undocumented; accepting both is strictly safer).
function verifySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue || typeof headerValue !== 'string') return false;
  const cleaned = headerValue.trim().replace(/^sha256=/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(cleaned)) return false;
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(cleaned, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

// -------------------------------------------------------------- Poseidon --

let poseidonPromise = null;
function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

async function computeCommitment(params, salt) {
  const poseidon = await getPoseidon();
  const h = poseidon.F.toObject(poseidon([...params, salt]));
  return { decimal: h.toString(), hex: '0x' + h.toString(16).padStart(64, '0') };
}

// -------------------------------------------------------------- strategy --

// Circuit-exact policy. Verified by direct proving against vfy-policy.wasm:
// - FORTIFY iff selfBalance < params[1]
// - HOLD iff opponentBalance <= params[2]   <-- <= , the reference build
//   used < here and its EXTRACT is REJECTED by the circuit when
//   opponentBalance == params[2] exactly (proven 17 Nov 2026).
// - otherwise EXTRACT params[0].
// - EXTRACT amount must equal params[0] exactly; params[0] in 1..10.
// - FORTIFY / HOLD carry amount 0 (and the response omits `amount`).
function decideMove(state, params) {
  const selfBalance = BigInt(state.selfBalance ?? 0);
  const opponentBalance = BigInt(state.opponentBalance ?? 0);
  if (selfBalance < params[1]) return { type: 'FORTIFY', amountNum: 0 };
  if (opponentBalance <= params[2]) return { type: 'HOLD', amountNum: 0 };
  return { type: 'EXTRACT', amountNum: Number(params[0]) };
}

// ------------------------------------------------------------ field maps --

// matchId is normally a UUID (hex with dashes). Parse it as hex. If the
// platform ever sends a non-hex id, fall back to keccak256(utf8(id)) mod p
// (same convention the gatekeeper agent uses for task ids) instead of
// crashing — flagged in README as an untested fallback.
function matchIdToField(matchId) {
  const stripped = String(matchId).replace(/^0x/i, '').replace(/-/g, '');
  if (/^[0-9a-fA-F]+$/.test(stripped)) return BigInt('0x' + stripped);
  const hex = keccak_256(Buffer.from(String(matchId), 'utf8'));
  return BigInt('0x' + hex) % FIELD_P;
}

function toBytes32BE(bi) {
  let h = BigInt(bi).toString(16);
  if (h.length % 2) h = '0' + h;
  const buf = Buffer.from(h, 'hex');
  if (buf.length > 32) throw new Error('value over 32 bytes: ' + bi);
  return Buffer.concat([Buffer.alloc(32 - buf.length), buf]);
}

// The platform independently recomputes this hash from the game state it
// knows and rejects proofs whose hashes diverge. Order (verified: it
// matches publicSignals[1..8] exactly): commitment, matchId, turn,
// selfBalance, opponentBalance, action, amount, circuitVersion(1).
function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount }) {
  const vals = [commitment, matchId, BigInt(turn), BigInt(selfBalance), BigInt(opponentBalance), BigInt(action), BigInt(amount), 1n];
  return '0x' + keccak_256(Buffer.concat(vals.map(toBytes32BE)));
}

// ----------------------------------------------------------------- proof --

async function proveTurn({ commitment, matchIdField, turn, selfBalance, opponentBalance, actionCode, amount, params, salt }) {
  const input = {
    commitment: commitment.toString(),
    matchId: matchIdField.toString(),
    turnNumber: String(turn),
    selfBalance: String(selfBalance),
    opponentBalance: String(opponentBalance),
    action: String(actionCode),
    amount: String(amount),
    circuitVersion: '1',
    salt: salt.toString(),
    strategyParams: params.map(String),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  proofsGenerated++;
  return { proof, publicSignals };
}

// Try the policy action first; on proving failure, try the other actions
// that could be policy-valid (FORTIFY, then HOLD) as a fallback; only give
// up with an error if no action proves. In practice the first attempt
// always succeeds because decideMove mirrors the circuit exactly.
async function proveWithFallback(ctx) {
  const attempts = [];
  const seen = new Set();
  const queue = [ctx.move, { type: 'FORTIFY', amountNum: 0 }, { type: 'HOLD', amountNum: 0 }];
  for (const m of queue) {
    if (seen.has(m.type)) continue;
    seen.add(m.type);
    attempts.push(m.type);
    try {
      const { proof, publicSignals } = await proveTurn({ ...ctx, actionCode: ACTION_CODE[m.type], amount: m.amountNum });
      return { move: m, proof, publicSignals, attempts };
    } catch (e) {
      ctx.lastError = e;
    }
  }
  const err = new Error('all proof attempts failed (' + attempts.join(',') + '): ' + (ctx.lastError && ctx.lastError.message));
  err.attempts = attempts;
  throw err;
}

// ------------------------------------------------------- response cache --
// A platform retry of the same (matchId, turn) must get the IDENTICAL
// response (same idempotencyKey, same proof) — the platform accepts only
// the first submission per idempotencyKey. Persisted to disk so a restart
// mid-match does not forget answered turns.

const responseCache = new Map();
try {
  const saved = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
  if (saved && typeof saved === 'object') {
    for (const [k, v] of Object.entries(saved)) responseCache.set(k, v);
  }
} catch { /* first run */ }

function persistCache() {
  try {
    fs.mkdirSync(path.dirname(CACHE_FILE), { recursive: true });
    const obj = {};
    for (const [k, v] of responseCache) obj[k] = v;
    fs.writeFileSync(CACHE_FILE, JSON.stringify(obj));
  } catch (e) { console.error('[cache] persist failed:', e.message); }
}

// ------------------------------------------------------------- deadlines --

// The turn envelope carries a deadline (field name undocumented — the
// reference build ignores it entirely). We only reject when a deadline is
// present, parseable, and already expired by MORE than 5 minutes, so clock
// skew or an unfamiliar format can never kill a live turn.
function findDeadline(payload) {
  for (const key of ['deadline', 'deadlineAt', 'expiresAt', 'expires', 'expiry']) {
    if (payload[key] == null) continue;
    const v = payload[key];
    if (typeof v === 'number' && Number.isFinite(v)) return v > 1e12 ? v : v * 1000;
    if (typeof v === 'string') {
      if (/^\d+$/.test(v.trim())) {
        const n = Number(v.trim());
        return n > 1e12 ? n : n * 1000;
      }
      const t = Date.parse(v);
      if (!Number.isNaN(t)) return t;
    }
  }
  return null;
}

// ------------------------------------------------------------ turn logic --

async function handleTurn(payload, cfg, commitment) {
  const body = (payload && typeof payload === 'object') ? payload : {};
  // The match-push envelope is documented, but practice deliveries have
  // varied in the wild (nested `data`, `turnNumber`, top-level balances).
  // Accept the common variants, defaulting balances to 0 like the public
  // reference build, and log the envelope keys on any remaining 400 so the
  // failure is diagnosable from the Railway log.
  const inner = (body.data && typeof body.data === 'object') ? body.data : body;
  const turnSrc = (inner.turn && typeof inner.turn === 'object') ? inner.turn : inner;
  const matchId = body.matchId ?? inner.matchId ?? body.match_id ?? body.id ?? null;
  const turnRaw = body.turn ?? body.turnNumber ?? inner.turn ?? inner.turnNumber ?? turnSrc.turn ?? turnSrc.turnNumber ?? null;
  const state = body.state ?? inner.state ?? body.gameState ?? inner.gameState ?? body.balances ?? inner.balances ?? turnSrc.state ?? {
    selfBalance: body.selfBalance ?? inner.selfBalance,
    opponentBalance: body.opponentBalance ?? inner.opponentBalance,
  };
  const fail = (msg) => {
    console.error('[steal] 400 ' + msg + ' — payload keys: ' + Object.keys(body).join(',') + ' — ' + JSON.stringify(body).slice(0, 500));
    throw Object.assign(new Error(msg), { status: 400 });
  };
  if (matchId == null || matchId === '') fail('missing matchId');
  if (turnRaw == null || !/^\d+$/.test(String(turnRaw))) fail('missing/invalid turn');
  const turn = turnRaw;
  if (!state || state.selfBalance == null || state.opponentBalance == null) {
    fail('missing state balances');
  }
  const selfBalance = BigInt(state.selfBalance);
  const opponentBalance = BigInt(state.opponentBalance);
  if (selfBalance < 0n || opponentBalance < 0n) fail('negative balance');

  const deadlineMs = findDeadline(payload);
  if (deadlineMs != null && deadlineMs < Date.now() - 5 * 60 * 1000) {
    const err = new Error('turn deadline expired');
    err.status = 410;
    throw err;
  }

  const cacheKey = `${matchId}:${turn}`;
  if (responseCache.has(cacheKey)) return { cached: true, response: responseCache.get(cacheKey) };

  // Config check: the envelope carries the frozen commitment hash. It MUST
  // equal our computed commitment, or our salt/params do not match what was
  // registered in the dashboard and no proof can ever verify. Warn loudly
  // but proceed with OUR computed commitment (the only one that can prove).
  const envHash = payload.strategyCommitment && payload.strategyCommitment.hash;
  if (envHash != null && BigInt(envHash).toString() !== commitment.decimal) {
    console.error('[commitment] WARNING: envelope strategyCommitment ' + envHash +
      ' != computed ' + commitment.hex + ' — dashboard commitment and server env disagree!');
  }

  const move = decideMove({ selfBalance, opponentBalance }, cfg.params);
  const matchIdField = matchIdToField(matchId);
  const started = Date.now();
  const { move: usedMove, proof, publicSignals, attempts } = await proveWithFallback({
    commitment: BigInt(commitment.decimal),
    matchIdField,
    turn,
    selfBalance,
    opponentBalance,
    move,
    params: cfg.params,
    salt: cfg.salt,
  });
  const proveMs = Date.now() - started;

  const actionObj = usedMove.type === 'EXTRACT'
    ? { type: 'EXTRACT', amount: usedMove.amountNum }
    : { type: usedMove.type }; // HOLD / FORTIFY MUST omit `amount` entirely
  const hash = publicInputsHash({
    commitment: BigInt(commitment.decimal),
    matchId: matchIdField,
    turn,
    selfBalance,
    opponentBalance,
    action: ACTION_CODE[usedMove.type],
    amount: usedMove.amountNum,
  });
  const response = {
    matchId,
    turn,
    action: actionObj,
    policyProof: {
      circuitVersion: 'v1',
      proof,
      public_signals: publicSignals,
      publicInputsHash: hash,
    },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: crypto.randomUUID(),
  };
  responseCache.set(cacheKey, response);
  if (responseCache.size > MAX_CACHE) responseCache.delete(responseCache.keys().next().value);
  persistCache();
  console.log('[steal]', matchId, 'turn', turn, usedMove.type,
    usedMove.type === 'EXTRACT' ? usedMove.amountNum : '', proveMs + 'ms',
    attempts.length > 1 ? '(fallback tried: ' + attempts.join(',') + ')' : '');
  return { cached: false, response, proveMs };
}

// ------------------------------------------------------------------ http --

function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (HMAC_SECRET) headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

let selfTest = 'NOT_RUN';
let cfg = null;
let commitment = null;
let proofsGenerated = 0;

async function runSelfTest() {
  try {
    cfg = getStrategyConfig();
    commitment = await computeCommitment(cfg.params, cfg.salt);
    const t0 = Date.now();
    const { response } = await handleTurn({
      matchId: '9f4e1b2a-1111-2222-3333-444455556666',
      turn: 0,
      state: { selfBalance: 100, opponentBalance: 100 },
      strategyCommitment: { hash: commitment.hex },
    }, cfg, commitment);
    const vk = await snarkjs.zKey.exportVerificationKey(ZKEY);
    const ok = await snarkjs.groth16.verify(vk, response.policyProof.public_signals, response.policyProof.proof);
    if (!ok) throw new Error('self-test proof did not verify locally');
    selfTest = 'PASS';
    console.log(`[self-test] PASS (${Date.now() - t0}ms, action ${response.action.type})`);
  } catch (e) {
    selfTest = 'FAIL: ' + e.message;
    console.error('[self-test] FAIL:', e.message);
  }
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return sendSigned(res, 200, {
      ok: true,
      agent: 'steal-the-vfy',
      hmacConfigured: Boolean(HMAC_SECRET),
      selfTest,
      strategyCommitment: commitment ? commitment.hex : null,
      vkHash: VK_HASH,
      cachedTurns: responseCache.size,
    });
  }

  if (req.method === 'POST' && (req.url === '/steal' || req.url === '/')) {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const raw = Buffer.concat(chunks);
      if (!HMAC_SECRET) {
        return sendSigned(res, 503, { ok: false, error: 'hmac not configured' });
      }
      if (!verifySignature(HMAC_SECRET, raw, req.headers['x-agent-games-signature'])) {
        return sendSigned(res, 401, { ok: false, error: 'bad signature' });
      }
      let payload;
      try { payload = JSON.parse(raw.toString('utf8')); }
      catch { return sendSigned(res, 400, { ok: false, error: 'invalid json' }); }

      if (payload && payload.type === 'agent-games.preflight.v1') {
        return sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
      }

      try {
        const { response } = await handleTurn(payload, cfg, commitment);
        return sendSigned(res, 200, response);
      } catch (e) {
        if (e.status) return sendSigned(res, e.status, { ok: false, error: e.message });
        console.error('[steal] handler error', e);
        return sendSigned(res, 500, { ok: false, error: 'handler error' });
      }
    });
    return;
  }

  return sendSigned(res, 404, { ok: false, error: 'not found' });
});

async function main() {
  try {
    cfg = getStrategyConfig();
  } catch (e) {
    console.error('[config] ' + e.message);
    console.error('[config] Set STEAL_VFY_PARAMS and STEAL_VFY_SALT (run: npm run commitment) and restart.');
    process.exit(1);
  }
  if (!fs.existsSync(WASM) || !fs.existsSync(ZKEY)) {
    console.error('[circuits] missing circuit artifacts in ./circuits — download vfy-policy.wasm and vfy-policy_final.zkey from https://agentgames.zkverify.io/circuits/');
    process.exit(1);
  }
  await runSelfTest();
  server.listen(PORT, HOST, () => {
    console.log(`[steal-vfy] listening on ${HOST}:${PORT} (hmac ${HMAC_SECRET ? 'on' : 'OFF — set AGENT_GAMES_HMAC_SECRET before going live'})`);
  });
}

if (require.main === module) main();

module.exports = {
  decideMove, matchIdToField, publicInputsHash, computeCommitment,
  getStrategyConfig, verifySignature, signatureFor, handleTurn, proveTurn,
  runSelfTest, ACTION_CODE, server,
  _internals: { get cfg() { return cfg; }, get commitment() { return commitment; }, get selfTest() { return selfTest; }, get proofsGenerated() { return proofsGenerated; }, responseCache },
};
