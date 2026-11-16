// Local tests for the VFY server (no network, no dashboard).
// Run: AGENT_GAMES_HMAC_SECRET=testsecret VFY_SALT_DEC=... VFY_COMMITMENT_DEC=... node test.js
'use strict';
const http = require('http');
const crypto = require('crypto');
const assert = require('assert');

const PORT = 3456;
process.env.PORT = String(PORT);
const { server, decideAction, matchIdToField } = require('./server.js');

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || 'testsecret';
function sign(body) { return crypto.createHmac('sha256', SECRET).update(body).digest('hex'); }

function req(method, path, bodyObj, signIt = true) {
  return new Promise((resolve, reject) => {
    const body = bodyObj ? Buffer.from(JSON.stringify(bodyObj)) : null;
    const headers = { 'content-type': 'application/json' };
    if (body) headers['content-length'] = body.length;
    if (signIt && body) headers['x-agent-games-signature'] = sign(body);
    const r = http.request({ host: '127.0.0.1', port: PORT, path, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

(async () => {
  await new Promise((r) => server.listen(PORT, '127.0.0.1', r));
  console.log('server up on', PORT);
  let pass = 0, fail = 0;
  const check = (label, cond) => { console.log((cond ? 'PASS' : 'FAIL') + ' ' + label); cond ? pass++ : fail++; };

  // 1. decision rule (unit)
  check('decide EXTRACT 10 (95/105)', JSON.stringify(decideAction(95, 105)) === JSON.stringify({ type: 'EXTRACT', amount: 10 }));
  check('decide HOLD when opp=0', decideAction(95, 0).type === 'HOLD');
  check('decide HOLD when opp=0, self=0', decideAction(0, 0).type === 'HOLD');
  check('decide EXTRACT when opp=1', decideAction(95, 1).type === 'EXTRACT');

  // 2. health
  const h = await req('GET', '/health');
  const hj = JSON.parse(h.body);
  check('health ok', h.status === 200 && hj.ok === true);
  check('health hmac_configured', hj.hmac_configured === true);
  check('health strategy_configured', hj.strategy_configured === true);
  console.log('  commitment:', hj.commitment);

  // 3. preflight
  const pf = await req('POST', '/agent', { type: 'agent-games.preflight.v1' });
  check('preflight 200 + ok', pf.status === 200 && JSON.parse(pf.body).ok === true);

  // 4. bad HMAC -> 401
  const bad = await req('POST', '/agent', { type: 'agent-games.preflight.v1' }, false);
  check('missing HMAC -> 401', bad.status === 401);

  // 5. a real turn: EXTRACT 10 with valid proof
  const matchId = '9f4e1b2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b';
  const turn = {
    protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'competition',
    matchId, turn: 3,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    state: { selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: hj.commitment },
    resolverVersion: 'v1', nonce: '3c2f1a',
  };
  const t0 = Date.now();
  const resp = await req('POST', '/agent', turn);
  const dt = ((Date.now() - t0) / 1000).toFixed(1);
  const rj = JSON.parse(resp.body);
  check(`turn 200 (in ${dt}s)`, resp.status === 200);
  check('turn action EXTRACT 10', rj.action && rj.action.type === 'EXTRACT' && rj.action.amount === 10);
  check('turn echo matchId+turn', rj.matchId === matchId && rj.turn === 3);
  check('turn has policyProof v1', rj.policyProof && rj.policyProof.circuitVersion === 'v1' && rj.policyProof.proof && rj.policyProof.public_signals);
  check('turn has idempotencyKey', typeof rj.idempotencyKey === 'string' && rj.idempotencyKey.length > 10);
  check('idempotencyKey is deterministic sha256(matchId:turn)',
    rj.idempotencyKey === '38c62bb8-13d3-4cde-82b7-4df8270de5b5');
  check('turn response has protocolVersion v1', rj.protocolVersion === 'v1');
  check('response no-store (cache-control)', String(resp.headers['cache-control'] || '').includes('no-store'));
  check('response signed (x-agent-games-signature)', typeof resp.headers['x-agent-games-signature'] === 'string');
  if (rj.policyProof) {
    const ps = rj.policyProof.public_signals;
    check('publicSignals[1] == commitment', ps[1] === process.env.VFY_COMMITMENT_DEC);
    check('publicSignals[2] == matchId field', ps[2] === matchIdToField(matchId));
    check('publicSignals[3] == turn', ps[3] === '3');
    check('publicSignals[4..6] == balances', ps[4] === '95' && ps[5] === '105');
    check('publicSignals[6..7] == action/amount', ps[6] === '2' && ps[7] === '10');
    check('publicSignals[8] == circuitVersion', ps[8] === '1');
    // local verify
    const snarkjs = require('snarkjs');
    const vk = require('./circuits/vk.json');
    const ok = await snarkjs.groth16.verify(vk, ps, rj.policyProof.proof);
    check('proof verifies locally', ok === true);
    // publicInputsHash must match an independent keccak computation
    // (Python pycryptodome, same words): this exact value pins the formula.
    check('publicInputsHash matches reference keccak',
      rj.policyProof.publicInputsHash === '0x325310dddd330f100711b166ad01128d7b6ee669270cb1a4de43ee64980f9d6b');
  }

  // 6. idempotency: same turn again -> same idempotencyKey + action
  const resp2 = await req('POST', '/agent', turn);
  const rj2 = JSON.parse(resp2.body);
  check('idempotent retry: same idempotencyKey', rj2.idempotencyKey === rj.idempotencyKey);
  check('idempotent retry: same action', JSON.stringify(rj2.action) === JSON.stringify(rj.action));

  // 7. HOLD turn (opp balance 0)
  const turn2 = { ...turn, matchId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', turn: 1, state: { selfBalance: '95', opponentBalance: '0', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null } };
  const resp3 = await req('POST', '/agent', turn2);
  const rj3 = JSON.parse(resp3.body);
  check('opp=0 -> HOLD', rj3.action && rj3.action.type === 'HOLD');
  check('HOLD turn has proof', !!rj3.policyProof);

  console.log(`\n${pass} passed, ${fail} failed`);
  server.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('TEST ERROR:', e); server.close(); process.exit(1); });
