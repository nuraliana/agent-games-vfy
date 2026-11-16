# Steal the VFY agent — cst-stealer (Agent Games / zkVerify)

An agent that plays Steal the VFY: a 20-turn head-to-head match over a simulated
100 VFY starting balance. Every move is proven with a Groth16 proof (vfy-policy
circuit) that the move follows the committed strategy.

## Strategy (committed)

`strategyParams = [10, 0, 0, 0, 0, 0, 0, 0]`, commitment =
`Poseidon(strategyParams, salt)` (registered on the dashboard).

| param | value | meaning |
|---|---|---|
| p0 | 10 | extract amount — the maximum the rules allow |
| p1 | 0 | fortify threshold on own balance — never fortify |
| p2 | 0 | hold threshold on opponent balance — hold only when opponent = 0 |
| p3 | 0 | default mode — EXTRACT (not HOLD) |
| p4–p7 | 0 | reserved by the v1 circuit (any nonzero value fails) |

Decision rule (recovered from the circuit by witness probing):
```
if selfBalance < p1           -> FORTIFY
else if opponentBalance <= p2 -> HOLD
else                          -> EXTRACT p0   (p3 = 0)
```

Why always-EXTRACT-10: the payoff table in the build guide makes EXTRACT
dominant — vs HOLD a +20 swing, vs FORTIFY +10, vs EXTRACT a draw. FORTIFY
costs 2 VFY and only blocks 6, so it is never the best reply; HOLD gives the
opponent a free extraction window. A 20-turn round-robin simulator (10
strategies) confirms it: AGGRO-10 ties the best at 117 pts (4W 5D 0L) and
beats every sub-10 extractor, fortifier and holder. Worst case against another
always-extractor is a draw (+9) — never a loss.

## Run

```sh
npm install
AGENT_GAMES_HMAC_SECRET=<from dashboard Rotate Secret> \
VFY_SALT_DEC=<salt decimal> \
VFY_COMMITMENT_DEC=<commitment decimal> \
PORT=3000 node server.js
```

Endpoints: `POST /agent` (turns + preflight), `GET /health`.

## Files

- `server.js` — the agent (Node stdlib + snarkjs).
- `circuits/` — vfy-policy.wasm, vfy-policy_final.zkey, vk.json
  (vkHash `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`).
- `decisions.json` — idempotency cache (matchId:turn -> response), created at runtime.
