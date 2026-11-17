# zkVerify Agent Games — Steal the VFY agent

Built 17 Nov 2026 for the **Steal the VFY** track. A 20-turn head-to-head
match: both agents start at 100 (simulated) VFY, and every turn the agent
answers EXTRACT / FORTIFY / HOLD plus a Groth16 **policy proof** that the
move follows the Poseidon-committed strategy. Prize per track: 100,000 VFY
(1st 50,000 / 2nd 30,000 / 3rd 20,000).

> **Timing — read this first.** The Swiss stage runs **13–17 Nov 2026**
> (7 rounds, then a Top-16 knockout). Today, 17 Nov, is the last Swiss day:
> the event page says you can "register mid-tournament to join from the next
> Swiss round, until the final round is paired" — but another builder
> reported the track already locked once pairing started
> (medium.com/@xepetcisnumberone, "Skylar"). Whether this agent can still
> enter is decided by the dashboard, not by this code. If it accepts the
> registration, the agent is ready to play; if it refuses, nothing here is
> wasted — the same code is reusable for any future season.

## What was verified (17 Nov 2026, all from official sources or direct proving)

**Sources:** `agentgames.zkverify.io/build` (§06 tournament protocol),
`/events/steal-the-vfy`, `/api/circuit-info`, `/rules`. The exact circuit
semantics were verified by *proving* against the official artifacts, not
by trusting prose — and one published reference build was cross-checked
(`github.com/DaddyUnikii/zkverify-agent`, `src/stealVfy.js` + `test/test.js`).

- **Circuits** (downloaded from `agentgames.zkverify.io/circuits/`,
  URLs confirmed via `/api/circuit-info`):
  `vfy-policy.wasm` 2,991,212 bytes (sha256
  `bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2`),
  `vfy-policy_final.zkey` 810,586 bytes (sha256
  `f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41`),
  Groth16/BN128, **nPublic = 9** (verified by exporting the verification
  key), vkHash
  `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`
  (matches `/api/circuit-info`). `vfy-policy.vkey.json` in `circuits/` is
  the exported key, for offline verification.
- **Turn envelope** (per §06 + the reference build): a signed JSON POST with
  `eventId: "steal-the-vfy"`, `matchId`, `turn`, `state: { selfBalance,
  opponentBalance }`, `strategyCommitment: { hash }`, plus a deadline.
  The response echoes `matchId` and `turn` exactly.
- **Actions:** EXTRACT (free, takes a bounded amount from the opponent's
  exposed balance), FORTIFY (small fixed cost, protects part of your balance
  for the next resolution), HOLD (free, no movement). **HOLD and FORTIFY
  must OMIT `action.amount` entirely** — `amount: 0` is rejected.
- **Response:** `{ matchId, turn, action, policyProof: { circuitVersion:
  "v1", proof, public_signals, publicInputsHash }, agentTimestamp,
  idempotencyKey }`. `proof` and `public_signals` MUST sit **inside**
  `policyProof` (leaving them at top level is the #1 cause of lost turns).
  `idempotencyKey` is fresh per (matchId, turn); a retry of the same turn
  gets the identical cached response.
- **Policy proof inputs** (circuit `vfy-policy`): `commitment`,
  `matchId`, `turnNumber`, `selfBalance`, `opponentBalance`, `action`
  (HOLD=0, FORTIFY=1, EXTRACT=2), `amount`, `circuitVersion: "1"`,
  `salt`, `strategyParams[0..7]`. Public signals are
  `[output, commitment, matchId, turnNumber, selfBalance, opponentBalance,
  action, amount, circuitVersion]` — signals [1..8] are exactly the 8
  values hashed into `publicInputsHash`. The keccak hash is
  `keccak256(concat of the 8 values as 32-byte big-endian)`; the platform
  recomputes it from the game state it knows and rejects mismatches.
  (Signal [0] is an opaque circuit output — it is NOT the keccak hash;
  verified by direct computation. The agent passes `publicSignals`
  through untouched, so its meaning does not matter.)
- **Strategy commitment:** `Poseidon(strategyParams[0..7], salt)`,
  registered in the dashboard before play, frozen mid-match. Changing
  params or salt changes the commitment and requires re-registration.
- **Circuit-enforced policy** — verified by direct proving (see `test.js`
  and the probe notes below), this is the part the docs do NOT spell out:
  - `selfBalance < params[1]` → FORTIFY
  - `opponentBalance <= params[2]` → HOLD (**<=**, not <)
  - otherwise → EXTRACT `params[0]`
  - EXTRACT `amount` must equal `params[0]` **exactly**; `params[0]` must
    be in 1..10 (amounts 0, 1, 2, 5, 9, 10, 11 all fail witness
    generation when `params[0]=8`; `params[0]=11` fails the param range
    check; `params[0]=1` and `=10` pass).
  - A wrong commitment (salt+1, or `params[0]=7` with amount 8) fails
    witness generation — the Poseidon binding works.
  - **Boundary correction vs the published reference build:** its
    `decideMove` used `opponentBalance < params[2] → HOLD`, but the
    circuit REJECTS EXTRACT when `opponentBalance == params[2]` exactly
    (proven: opp=8 with params[2]=8 fails; opp=9 passes). This agent uses
    `<=`, so it never attempts an unprovable move. The `selfBalance`
    boundary matches the reference (`self=18` extracts, `self=17`
    fortifies).
- **HMAC:** `x-agent-games-signature`, HMAC-SHA256 over the raw body,
  verified before parsing anything (401 on failure). Incoming signatures
  are accepted as bare hex or `sha256=<hex>`; responses are signed bare
  hex by default, `AGENT_GAMES_HMAC_FORMAT=sha256=` switches the prefix.
- **Deadlines:** 5 min per turn, platform waits ~30 s per push. Proof time
  here is ~1.3–2.8 s. Timeout −1/turn, invalid proof −2/turn, win +18,
  draw +9, loss +3, reliability bonus +0..+2.
- **Preflight:** `{"type":"agent-games.preflight.v1"}` →
  `{ok:true, protocolVersion:"v1"}`, signed. Same shape as the Gatekeeper
  agent (which passed live preflight).

## The strategy (plain words)

Params `[10, 18, 0, 0, 0, 0, 0, 0]` — the first three matter, the rest are
unused zeros:

- **EXTRACT 10** whenever you are healthy (`self ≥ 18`) and the opponent
  has anything left (`opponent ≥ 1`). EXTRACT is free and the resolver caps
  the take at the opponent's exposed balance, so the maximum amount (10)
  dominates any smaller one — proven: amount need NOT be ≤ opponent
  balance (EXTRACT 10 against opponent 9 proves fine).
- **FORTIFY** when you are weak (`self < 18`): pay the small defence cost
  and protect what is left instead of feeding the opponent.
- **HOLD** only when the opponent is at 0 (nothing left to take) — with
  `params[2]=0` there is no other HOLD case. Finishing off a weak opponent
  (1–8 balance) instead of holding is strictly better: holding leaves
  them alive to extract from you.

This is a simple, aggressive, fully rule-based strategy — deliberately not
a clever game-theoretic optimum (the resolver's exact fortify-protection
amount and fortify cost are not published, so no finer tuning is honestly
possible from public data).

## Test results (17 Nov 2026, `node test.js`, ~27 s)

**25 passed, 0 failed — 15 Groth16 proofs generated and verified locally.**

- HMAC sign/verify round-trip (bare hex + `sha256=` prefix), wrong
  secret / tampered body rejected.
- Poseidon commitment matches a known vector (`[8,18,8,0,0,0,0,0]` +
  salt `12345678901234567890` → `0x28ec2614…032227`).
- `decideMove` full state matrix: 30 combinations of self × opponent
  balances, all circuit-exact.
- Full turn proofs with local Groth16 verification: EXTRACT, FORTIFY,
  HOLD, plus boundaries (self=18 EXTRACT, self=17 FORTIFY, opp=1
  EXTRACT, opp=0 HOLD, self=0 FORTIFY edge). Every proof verified;
  `publicSignals[1..8]` and `publicInputsHash` recomputation asserted.
- Retry of the same (matchId, turn) returns the IDENTICAL response
  (same idempotencyKey and proof); a different turn gets a fresh key.
- Envelope with a WRONG `strategyCommitment.hash` still proves using the
  server's computed commitment (with a loud warning logged).
- Expired deadline → 410; future deadline passes; missing state → 400;
  non-hex matchId works via the keccak fallback and proves.
- HTTP end-to-end: `GET /health` → 200, `hmacConfigured: true`,
  `selfTest: PASS`, commitment shown, **salt not leaked**; unsigned POST
  → 401; wrong signature → 401; valid signed POST → 200 with a signed
  response whose HMAC verifies and whose proof verifies; preflight →
  `{ok:true, protocolVersion:"v1"}`; invalid JSON → 400; unknown path
  → 404.
- Slowest single check: 2,570 ms. Turn deadline is 300,000 ms.

## Deploy (Railway — same pattern as the Gatekeeper agent)

1. **Generate the strategy identity** (once — the values are already
   generated for this agent; they are NOT in this repo):
   `npm run commitment` prints `STEAL_VFY_PARAMS`, `STEAL_VFY_SALT`,
   and the commitment hex. With the salt already set it reproduces the
   same commitment — use that to double-check before registering.
2. **Put this folder in a GitHub repo** (private is fine). Do NOT commit
   `node_modules/`, `.env`, or `data/` (`.gitignore` covers them).
   Circuit files in `circuits/` ARE committed (~3.8 MB).
3. **Railway → New Project → Deploy from GitHub repo** (separate service
   from the Gatekeeper agent — separate endpoint, separate HMAC secret).
4. **Set the env vars in Railway:**
   `AGENT_GAMES_HMAC_SECRET` = the secret shown once in the dashboard
   for THIS agent (Rotate Secret — a different secret from the Gatekeeper
   agent), `STEAL_VFY_PARAMS`, `STEAL_VFY_SALT`. Never paste any of them
   into any AI tool or chat. Optional: `AGENT_GAMES_HMAC_FORMAT=sha256=`
   if preflight complains about the signature format.
5. **Register in the dashboard:** register the agent for the Steal the
   VFY event, paste the **commitment hex** as your strategy commitment,
   and set the endpoint to `https://<your-app>.up.railway.app/steal`.
   Then run the signed preflight + at least 1 practice turn. Check
   `/health` first — it must say `selfTest: PASS`.
6. **Watch the first live turn.** Scores live on the dashboard; this
   agent cannot see them.

## Run locally

```
npm install
node test.js            # 25 checks, ~30 s, no network
npm run commitment      # print params / salt / commitment hex
PORT=8080 node server.js
curl http://127.0.0.1:8080/health
```

## Files

- `server.js` — the whole agent: HMAC, Poseidon commitment, policy,
  proving, HTTP (`POST /steal`, `GET /health`), idempotent response
  cache (persisted to `data/responses.json`).
- `test.js` — the 25-check suite above (uses test-only strategy values).
- `scripts/commitment.js` — `npm run commitment`.
- `circuits/` — `vfy-policy.wasm`, `vfy-policy_final.zkey`,
  `vfy-policy.vkey.json` (exported verification key).
- `.env.example`, `.gitignore`, `package.json` (start: `node server.js`).

## Honest gaps (what is NOT verified)

- **Entry may already be closed.** The dashboard decides. See the timing
  note at the top.
- **Deadline field name.** The envelope "contains the deadline" per the
  field guide, but its exact field name is undocumented and the reference
  build ignores it. This agent only rejects a deadline that is present,
  parseable, and already expired by > 5 minutes — clock skew or an
  unfamiliar format can never kill a live turn.
- **Non-hex matchId fallback.** Match IDs are UUIDs (hex) in every sample
  seen; if the platform ever sends a non-hex id, the agent falls back to
  `keccak256(utf8(id)) mod p`. That fallback path proves and verifies
  locally (tested), but it has not been confirmed against a live platform
  turn.
- **`publicInputsHash` formula.** Taken from the reference build and
  corroborated by the public-signal order (signals [1..8] are exactly the
  8 hashed values, in order) — but the platform's own recomputation can
  only be confirmed by a live practice turn. If a practice turn is
  rejected for a hash mismatch, the formula is the first thing to recheck.
- **Resolver numbers.** The exact EXTRACT cap, FORTIFY cost, and how much
  balance FORTIFY protects are not published; the strategy above is built
  only on what the circuit enforces, not on tuned game theory.
