# Agent Red Team

A measurement harness for **indirect prompt injection** against tool-using AI agents. It plants
injection attacks in every channel an agent reads - emails, attachments, files, web pages,
calendar invites, tool results - and scores what actually happened in the agent's systems (a
planted secret reaching an attacker inbox, a tool call the user never asked for), not whether the
reply looked safe. Defences are pluggable layers measured one at a time: attack success, detection,
and the legitimate work they block.

**Write-up:** [docs/REPORT.md](docs/REPORT.md) · **Architecture:** [docs/architecture.md](docs/architecture.md) · **Responsible use:** [SECURITY.md](SECURITY.md) · **Live demo:** _(Streamlit deployment pending)_

## The headline

Run against Claude Haiku 5.5 over an inbox-and-files workload, across 276 held-out attacks
(14 techniques x 7 channels x 4 goals):

1. **A careful agent with no defences was not induced to act on a single injected instruction
   (0.0% attack success).** Not an exfiltrated secret, not an unrequested send, not a
   disclosed system prompt.
2. **A deliberately naive "act on whatever you read" agent did no worse (0.0%).** The
   model's resistance to injection does not depend on a careful prompt.
3. **An adaptive attacker that stacks every technique and retries five times still got
   0.0%.** A model-driven attacker could not even be built: the frontier models decline
   to author injection payloads, and the harness records that rather than faking it.

So the suite is an honest **robustness benchmark**, and the defences are measured by what they
still buy - detection, and their cost in blocked legitimate work - not by reducing an attack rate
that was already zero. The project plan predicted the opposite; the report keeps that wrong
prediction visible.

## Results

| Target / stack | Attacks | Attack success | Detected | By goal (success %) |
|---|---|---|---|---|
| Careful agent, no defences (D0) | 276 | 0.0% | 0.0% | derail 0.0%, disclose_instructions 0.0%, exfiltrate 0.0%, unauthorised_action 0.0% |
| Naive agent, no defences | 276 | 0.0% | 0.0% | derail 0.0%, disclose_instructions 0.0%, exfiltrate 0.0%, unauthorised_action 0.0% |
| Provenance marking (D2) | 276 | 0.0% | 92.0% | derail 0.0%, disclose_instructions 0.0%, exfiltrate 0.0%, unauthorised_action 0.0% |
| Recommended stack | 276 | 0.0% | 93.8% | derail 0.0%, disclose_instructions 0.0%, exfiltrate 0.0%, unauthorised_action 0.0% |

**Defence cost on legitimate work** (benign + look-alike tasks; lower blocked is better):

| D0 - none | 92.0% | 0.0% |
| D2 - provenance marking | 88.0% | 0.0% |
| D3 - input quarantine | 82.0% | 0.0% |
| D4 - capability scoping | 84.0% | 6.0% |
| D5 - output DLP | 86.0% | 2.0% |
| D6 - action confirmation | 64.0% | 22.0% |
| D7 - task-scope judge | 86.0% | 0.0% |
| recommended stack (D1+D2+D4+D5+D7) | 82.0% | 4.0% |

Full tables, the adaptive rounds and the attacker-model refusal: [docs/REPORT.md](docs/REPORT.md).

## How it works

```
scenario (benign task + the untrusted content it reads)
   x attack (goal x channel x technique)  -> planted into the exact field the agent reads
   -> target agent (Claude, tool use) under defence stack D0..D7
   -> scorer reads the sinks + canaries + tool log:  attack success? detected? benign task still done?
   -> adaptive attacker escalates a failed payload over N rounds
```

- **Success is a state, not a judgement.** A secret is a planted canary; a leak is that exact
  string arriving at an attacker domain. The reply is never scored for compliance.
- **The scorer is independent of the defences.** It has its own view of the world and the
  scenario's pre-written expectations, and separates *detected* from *prevented* from *silent*.
- **Everything is synthetic.** The workspace, the secrets and the attacker sinks live in one
  SQLite world; no real system is touched. See [SECURITY.md](SECURITY.md).

## Repository

```
src/redteam/
  workspace/   the simulated workstation: schema, seeded mailbox/drive/contacts/calendar/web, canaries, tools
  scenarios/   23 benign task templates -> 50 scenarios, with the slots an attacker can write into
  attacks/     14 techniques, the attack-case generator, the planter, the adaptive attacker
  defences/    the seven layers and the stacks
  target/      the inbox-and-files agent (careful and naive prompts)
  scoring.py   state-based attack success, detection, benign completion
scripts/       build_corpus, run_eval, run_adaptive, run_chain
app/           Streamlit demo: the attack explorer and a live try-a-payload on the visitor's own key
```

## Run it

```bash
uv sync --group dev --extra app
cp .env.example .env                                    # ANTHROPIC_API_KEY
uv run python scripts/build_corpus.py
uv run pytest -q
uv run python scripts/run_eval.py --stack D0 --split test
uv run python scripts/run_adaptive.py --engine ladder --limit 40 --rounds 5
uv run streamlit run app/streamlit_app.py
```

## Notes

Synthetic workspace and attack corpus, the author's own; the techniques are public and target only
the in-repo simulation (see [SECURITY.md](SECURITY.md)). The model is Claude Haiku 5.5 (Sonnet 5.5
as a reference). Sister project: an ops-action agent whose guard removes policy violations by
construction - this suite attacks that agent too.

## License

MIT
