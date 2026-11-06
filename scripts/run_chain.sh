#!/usr/bin/env bash
# P5 measurement chain, run detached (scripts/start_chain.ps1). Each step commits when it lands;
# progress in evals/results/chain.log; chain.done at the end. Budget-bounded.
cd "$(dirname "$0")/.." || exit 1
unset VIRTUAL_ENV
LOG=evals/results/chain.log
log() { echo "[$(date +%H:%M)] $*" >>"$LOG"; }
commit() {
  (cd .. && git add -A -- p5-agent-redteam/evals && git commit -q -m "P5: $1

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>" >/dev/null 2>&1)
  log "committed: $1"
}
run() {
  log "######## $*"
  timeout 7200 uv run python "$@" 2>&1 | grep -v "it/s\]\|s/it\]\|^\s*$\|atk\]\|task\]\|case\]" >>"$LOG"
  log "exit=${PIPESTATUS[0]}"
}
log "chain start"

# 1. static attack-success rate on the held-out split: careful and naive targets, no defences
run scripts/run_eval.py --stack D0 --split test --max-cost 4;                 commit "static D0 careful test"
run scripts/run_eval.py --stack D0 --naive --split test --max-cost 4;         commit "static D0 naive test"
# 2. detection: does provenance marking flag the attempts (ASR stays ~0 either way)
run scripts/run_eval.py --stack D2 --split test --max-cost 4;                 commit "static D2 detection test"
# 3. the recommended stack on attacks (confirm ASR stays 0 and nothing regresses)
run scripts/run_eval.py --stack stack --split test --max-cost 5;              commit "static recommended-stack test"
# 4. false-block cost of each defence on the benign + look-alike set (the real tradeoff)
for d in D0 D2 D3 D4 D5 D6 D7 stack; do
  run scripts/run_eval.py --stack $d --benign-only --split test --max-cost 3; commit "benign false-block $d"
done
# 5. adaptive attacker: deterministic escalation ladder, then the model engine (records refusals)
run scripts/run_adaptive.py --engine ladder --stack D0 --limit 40 --rounds 5 --max-cost 4;  commit "adaptive ladder D0"
run scripts/run_adaptive.py --engine model --stack D0 --limit 16 --rounds 4 --attacker-model claude-sonnet-5-5 --max-cost 4; commit "adaptive model D0"

log "chain done"
touch evals/results/chain.done
