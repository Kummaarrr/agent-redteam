# Security and responsible use

This repository is a **defensive** evaluation harness. It measures whether a tool-using AI agent
can be made to act on instructions hidden in the content it reads (indirect prompt injection), and
which defences stop that at what cost. It exists so that people deploying agents can measure this
risk instead of guessing at it.

## What is and is not here

- **Every target, system and secret is synthetic.** The workspace, the mailbox, the documents,
  the "secrets" (planted canary tokens) and the "attacker" addresses and URL are all seeded inside
  this repository's SQLite world. Nothing here touches a real system, a real inbox or real data.
- **The attack payloads are generic injection techniques that are already public** (authority
  framing, delimiter spoofing, encodings, multi-step). They are included because the value of the
  suite is the *measurement* - the payloads carry no secrets and target only the in-repo
  simulation. They are parametrised test fixtures, not a toolkit aimed at any external service.
- **The adaptive attacker is confined to the simulation.** It only rewrites the payload text of an
  existing in-repo attack case; it cannot change the target, the tools or the sinks. The default
  engine is a deterministic ladder. A model-driven engine is offered, and the harness records that
  current frontier models decline to author injection text rather than pretending otherwise.

## Do not

- Point the targets or the payloads at any system, account or person you are not authorised to
  test. The harness ships with no real credentials and no network targets; keep it that way.
- Use the corpus to attack third-party agents or services. That is outside the purpose of this
  project and, depending on jurisdiction and target, may be unlawful.

## Reporting

This is a portfolio project with a synthetic target; there is no production deployment to report a
vulnerability in. If you find an error in the harness or the scorer, open an issue.

## Keys

The live demo and the eval use the visitor's or owner's own Anthropic API key, passed per call and
never stored or logged. No key is committed; `.env` is git-ignored.
