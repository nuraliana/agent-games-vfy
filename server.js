// Steal the VFY agent server — zkVerify Agent Games
// Node.js stdlib only (+ snarkjs for local Groth16 proving).
// No frameworks. Secrets ONLY from env vars. Never log secrets.
//
// Protocol sources (public, 16 Nov 2026):
//   https://agentgames.zkverify.io/build   (section 05, Steal the VFY)
//   https://agentgames.zkverify.io/events/steal-the-vfy
//   https://agentgames.zkverify.io/api/circuit-info
//
// STRATEGY (committed, see ../notes/VFY_STRATEGY.md):
//   strategyParams = [10, 0, 0, 0, 0, 0, 0, 0]
//     p0 = extract amount (10 = max, per /build "EXTRACT N, max 10")
//     p1 = fortify threshold on OWN balance (0 = never fortify)
//     p2 = hold threshold on OPPONENT balance (0 = hold only when opp = 0)
//     p3 = default mode (0 = EXTRACT, 1 = HOLD)
//     p4..p7 = 0 (reserved by the v1 circuit — any nonzero value fails witness gen)
//   commitment = Poseidon(strategyParams, salt)  — registered on the dashboard.
//   Decision rule (reverse-engineered from vfy-policy.wasm, verified by witness
//   probing — see notes/VFY_CIRCUIT.md):
//     if selfBalance < p1            -> FORTIFY
//     else if opponentBalance <= p2  -> HOLD
//     else                           -> EXTRACT p0 (p3=0) / HOLD (p3=1)
//   Public signals: [Poseidon(matchId, turn, 1), commitment, matchId, turn,
//                    selfBalance, opponentBalance, action, amount, circuitVersion]
//   Why always-EXTRACT-10: the /build payoff table makes EXTRACT dominant —
//   vs HOLD +20 swing, vs FORTIFY +10, vs EXTRACT 0 (draw). FORTIFY is never
//   the best reply (it costs 2 and only blocks 6); HOLD is never the best
//   reply (it gives the opponent a free extraction window). Verified by a
//   20-turn round-robin simulator (notes/VFY_STRATEGY.md): AGGRO-10 ties the
//   best (117 pts, 4W 5D 0L) and beats every sub-10 extractor, fortifier and
//   holder. Worst case vs another always-extractor is a draw (+9), never a loss.
//
// Proof: local Groth16 via snarkjs. The platform re-verifies offline against
// its own VK (proofReference / publicInputsHash are OPTIONAL audit pointers
// and are omitted — no on-chain submission is needed for VFY).
'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const snarkjs = require('snarkjs');
const { keccak_256 } = require('js-sha3');

// ---------------------------------------------------------------- config
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const WASM_PATH = process.env.VFY_WASM || path.join(__dirname, 'circuits', 'vfy-policy.wasm');
const ZKEY_PATH = process.env.VFY_ZKEY || path.join(__dirname, 'circuits', 'vfy-policy_final.zkey');
const VK_PATH = process.env.VFY_VK || path.join(__dirname, 'circuits', 'vk.json');
const DECISIONS_PATH = process.env.VFY_DECISIONS_FILE || path.join(__dirname, 'decisions.json');
// Committed strategy (must match the dashboard commitment exactly).
const STRATEGY_PARAMS = (process.env.VFY_STRATEGY_PARAMS || '10,0,0,0,0,0,0,0').split(',').map((s) => s.trim());
const SALT_DEC = process.env.VFY_SALT_DEC || '';
const COMMITMENT_DEC = process.env.VFY_COMMITMENT_DEC || '';
const VK_HASH = process.env.VFY_VK_HASH || '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';
const FIELD_MODULUS = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const PROOF_TIMEOUT_MS = parseInt(process.env.VFY_PROOF_TIMEOUT_MS || '240000', 10);

if (!HMAC_SECRET) {
  console.warn('[vfy] WARNING: AGENT_GAMES_HMAC_SECRET is not set. ' +
    'Inbound HMAC verification and response signing are DISABLED until it is set. ' +
    'Set it from the dashboard (Rotate Secret on the VFY agent) and restart.');
}
if (!SALT_DEC || !COMMITMENT_DEC) {
  console.warn('[vfy] WARNING: VFY_SALT_DEC / VFY_COMMITMENT_DEC not set — proofs cannot be generated. ' +
    'Set them from the committed strategy (see .vfy_credentials) and restart.');
}

// ---------------------------------------------------------------- state
function loadJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function saveJson(file, obj) {
  try { fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n'); } catch (e) { console.error('[vfy] save failed', file, e.message); }
}
// "matchId:turn" -> last signed response body (idempotency: a retried turn returns the same response + idempotencyKey).
const decisionsByTurn = loadJson(DECISIONS_PATH, {});

let vk = null;
try { vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8')); } catch (e) { console.warn('[vfy] vk.json not found, local proof verification disabled:', e.message); }

// ---------------------------------------------------------------- HMAC
function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}
function verifySignature(rawBody, header) {
  if (!HMAC_SECRET) return false;
  if (!header) return false;
  let sig = String(header).trim();
  if (sig.toLowerCase().startsWith('sha256=')) sig = sig.slice(7);
  const digest = crypto.createHmac('sha256', HMAC_SECRET).update(rawBody).digest();
  const expectedHex = digest.toString('hex');
  const expectedB64 = digest.toString('base64');
  const a = Buffer.from(sig, 'utf8');
  for (const expected of [expectedHex, expectedB64]) {
    const b = Buffer.from(expected, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}
function signBody(rawBody) {
  if (!HMAC_SECRET) return '';
  return hmacHex(HMAC_SECRET, rawBody);
}

// ---------------------------------------------------------------- helpers
function toBigInt(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return BigInt(v);
  const s = String(v).trim();
  if (/^0x/i.test(s)) return BigInt(s);
  return BigInt(s);
}
// matchId is a UUID string ("9f4e1b2a-..."). The circuit takes it as a field
// element; the /build publicInputsHash uses BigInt("0x" + uuid without dashes).
// A UUID is 128 bits, well inside the BN128 scalar field.
function matchIdToField(matchId) {
  const hex = String(matchId || '').replace(/-/g, '').replace(/^0x/, '');
  if (!/^[0-9a-fA-F]+$/.test(hex)) return (BigInt('0x' + Buffer.from(String(matchId || ''), 'utf8').toString('hex')) % FIELD_MODULUS).toString();
  return (BigInt('0x' + hex) % FIELD_MODULUS).toString();
}

// ---------------------------------------------------------------- decision
// The circuit's decision rule (verified by witness probing — see header).
// p0 = extract amount, p1 = fortify threshold (own balance),
// p2 = hold threshold (opponent balance), p3 = default mode (0 = EXTRACT).
function decideAction(selfBalance, opponentBalance) {
  const p0 = Number(STRATEGY_PARAMS[0] || 0);
  const p1 = Number(STRATEGY_PARAMS[1] || 0);
  const p2 = Number(STRATEGY_PARAMS[2] || 0);
  const p3 = Number(STRATEGY_PARAMS[3] || 0);
  if (selfBalance < p1) return { type: 'FORTIFY' };
  if (opponentBalance <= p2) return { type: 'HOLD' };
  if (p3 === 1) return { type: 'HOLD' };
  return { type: 'EXTRACT', amount: p0 };
}

// ---------------------------------------------------------------- proof
function buildCircuitInput(turn, action) {
  const state = turn.state || {};
  const actionEnum = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 }[action.type];
  return {
    commitment: COMMITMENT_DEC,
    matchId: matchIdToField(turn.matchId),
    turnNumber: String(turn.turn),
    selfBalance: toBigInt(state.selfBalance).toString(),
    opponentBalance: toBigInt(state.opponentBalance).toString(),
    action: String(actionEnum),
    amount: String(action.type === 'EXTRACT' ? action.amount : 0),
    circuitVersion: '1',
    salt: SALT_DEC,
    strategyParams: STRATEGY_PARAMS.map(String),
  };
}

async function generateProof(turn, action) {
  const circuitInput = buildCircuitInput(turn, action);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);
  if (vk) {
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    if (!ok) throw new Error('local proof verification failed');
  }
  return { proof, public_signals: publicSignals };
}

// publicInputsHash — REQUIRED by the platform (practice rejects the turn
// without it). Exact definition from the official reference
// (smilewithkhushi/steal-the-vfy-reference src/protocol.ts):
// keccak256 over 8 uint256 ABI words (32-byte BE each), in /build order:
// [commitment, matchId (UUID bytes), turn, selfBalance, opponentBalance,
//  action enum (HOLD 0 / FORTIFY 1 / EXTRACT 2), amount, 1].
// Note: these are the raw uint256 words, NOT field-reduced values.
function publicInputsHash(turn, action) {
  const words = [
    BigInt(COMMITMENT_DEC),
    BigInt('0x' + String(turn.matchId).replace(/-/g, '')),
    BigInt(turn.turn),
    toBigInt(turn.state.selfBalance),
    toBigInt(turn.state.opponentBalance),
    BigInt({ HOLD: 0, FORTIFY: 1, EXTRACT: 2 }[action.type]),
    BigInt(action.type === 'EXTRACT' ? action.amount : 0),
    1n,
  ];
  const buf = Buffer.concat(words.map((w) => Buffer.from(w.toString(16).padStart(64, '0'), 'hex')));
  return '0x' + keccak_256(buf);
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label + ' timed out after ' + ms + 'ms')), ms);
  });
  return Promise.race([promise.finally(() => clearTimeout(timer)), timeout]);
}

// Warm up the prover once at startup: a cold fullProve takes ~40s on
// Railway (wasm compile), warm takes ~1.3s. Without this, the first real
// turn after a deploy pays the cold cost and can miss a short deadline.
// Runs in the background; the server already listens while it warms up.
async function warmUpProver() {
  if (!SALT_DEC || !COMMITMENT_DEC) return; // nothing valid to prove with
  try {
    const input = buildCircuitInput(
      { matchId: '00000000-0000-0000-0000-000000000001', turn: 1,
        state: { selfBalance: 100, opponentBalance: 100 } },
      { type: 'EXTRACT', amount: 10 });
    await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
    console.log('[vfy] prover warmed up (cold fullProve done)');
  } catch (e) {
    console.warn('[vfy] prover warm-up failed (first turn will be slow):', e.message);
  }
}

// ---------------------------------------------------------------- HTTP
function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { 'content-type': 'application/json', 'content-length': body.length };
  if (HMAC_SECRET) headers['x-agent-games-signature'] = signBody(body);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => {
      chunks.push(c);
      if (Buffer.concat(chunks).length > 1024 * 1024) { req.destroy(); reject(new Error('body too large')); }
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleTurn(req, res, rawBody) {
  // 1. Verify HMAC on the RAW body BEFORE parsing.
  if (!verifySignature(rawBody, req.headers['x-agent-games-signature'])) {
    console.warn('[vfy] bad/missing HMAC signature');
    return sendJson(res, 401, { error: 'invalid signature' });
  }
  let turn;
  try { turn = JSON.parse(rawBody.toString('utf8')); }
  catch { return sendJson(res, 400, { error: 'invalid json' }); }

  // 2. Preflight handshake.
  if (turn.type === 'agent-games.preflight.v1') {
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
  }
  if (!turn.matchId || turn.turn === undefined || !turn.state) {
    return sendJson(res, 400, { error: 'missing matchId/turn/state' });
  }
  if (turn.eventId && turn.eventId !== 'steal-the-vfy') {
    return sendJson(res, 400, { error: 'unknown eventId' });
  }

  // 3. Idempotency: same match+turn retried -> same signed response.
  const key = `${turn.matchId}:${turn.turn}`;
  if (decisionsByTurn[key]) {
    const cached = decisionsByTurn[key];
    const body = Buffer.from(JSON.stringify(cached));
    const headers = { 'content-type': 'application/json', 'content-length': body.length };
    if (HMAC_SECRET) headers['x-agent-games-signature'] = signBody(body);
    res.writeHead(200, headers);
    return res.end(body);
  }

  // 4. Past-deadline turns fail closed as HOLD (no proof — the turn is lost
  // either way, but a late EXTRACT proof would be invalid anyway).
  const deadlineMs = turn.deadlineAt ? Date.parse(turn.deadlineAt) : 0;
  if (deadlineMs && Date.now() > deadlineMs) {
    console.warn(`[vfy] ${key}: past deadlineAt, fail closed (HOLD, no proof)`);
    const response = {
      matchId: turn.matchId, turn: turn.turn,
      action: { type: 'HOLD' },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: crypto.randomUUID(),
    };
    decisionsByTurn[key] = response;
    saveJson(DECISIONS_PATH, decisionsByTurn);
    return sendJson(res, 200, response);
  }

  // 5. Deterministic decision from the committed strategy.
  const selfBalance = Number(toBigInt(turn.state.selfBalance));
  const opponentBalance = Number(toBigInt(turn.state.opponentBalance));
  const action = decideAction(selfBalance, opponentBalance);

  // 6. Proof (bounded by the turn deadline minus a safety buffer).
  const response = {
    matchId: turn.matchId,
    turn: turn.turn,
    action: action.type === 'EXTRACT' ? { type: 'EXTRACT', amount: action.amount } : { type: action.type },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: crypto.randomUUID(),
  };
  let proofBudget = PROOF_TIMEOUT_MS;
  // 3s buffer: warm proofs take ~1.3s, so the response still returns well
  // before the deadline. A 15s buffer skipped proof entirely on short
  // practice deadlines (verified 17 Nov: practice turn skipped at 42ms).
  if (deadlineMs) proofBudget = Math.min(proofBudget, deadlineMs - Date.now() - 3000);
  if (proofBudget > 0 && SALT_DEC && COMMITMENT_DEC) {
    try {
      const t0 = Date.now();
      const { proof, public_signals } = await withTimeout(
        generateProof(turn, action), proofBudget, 'proof generation');
      response.policyProof = {
        circuitVersion: 'v1', proof, public_signals,
        publicInputsHash: publicInputsHash(turn, action),
      };
      console.log(`[vfy] ${key} ${action.type}${action.type === 'EXTRACT' ? ' ' + action.amount : ''} proof ok in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
    } catch (e) {
      // A missing proof scores -2 and the turn becomes HOLD; a timeout scores
      // -1 and the turn is missed. Returning the decision without a proof is
      // still the better failure mode (the platform records the attempt).
      console.error(`[vfy] ${key} proof FAILED (decision still returned):`, e.message);
    }
  } else {
    console.error(`[vfy] ${key} proof skipped (no budget / no salt+commitment configured)`);
  }

  decisionsByTurn[key] = response;
  saveJson(DECISIONS_PATH, decisionsByTurn);
  return sendJson(res, 200, response);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/' || url.pathname === '/agent')) {
      return sendJson(res, 200, {
        ok: true, service: 'steal-the-vfy', protocolVersion: 'v1',
        uptime_s: Math.floor(process.uptime()),
        hmac_configured: Boolean(HMAC_SECRET),
        strategy_configured: Boolean(SALT_DEC && COMMITMENT_DEC),
        strategy_params: STRATEGY_PARAMS.join(','),
        commitment: COMMITMENT_DEC ? ('0x' + BigInt(COMMITMENT_DEC).toString(16).padStart(64, '0')) : null,
        turns_answered: Object.keys(decisionsByTurn).length,
      });
    }
    if (req.method === 'POST' && (url.pathname === '/agent' || url.pathname === '/')) {
      const rawBody = await readRawBody(req);
      return handleTurn(req, res, rawBody);
    }
    return sendJson(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('[vfy] handler error:', e.message);
    if (!res.headersSent) return sendJson(res, 500, { error: 'internal error' });
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`[vfy] listening on http://${HOST}:${PORT} (POST /agent, GET /health)`);
    console.log(`[vfy] hmac_configured=${Boolean(HMAC_SECRET)} strategy_configured=${Boolean(SALT_DEC && COMMITMENT_DEC)} params=${STRATEGY_PARAMS.join(',')}`);
    warmUpProver();
  });
}

module.exports = { server, decideAction, verifySignature, hmacHex, matchIdToField, buildCircuitInput };
