# How it was built

## AI tools

- **Claude Code with Claude Opus 5** was the main implementation assistant. The
  implementation history before the final documentation pass contains 32
  commits, all with a Claude co-author trailer. It was used across the C#
  agent, FastAPI control plane, Python driver, tests, installers and docs.
- **Codex** was used for the final requirement, security and documentation
  review. That review found execution-layer defects that were then fixed and
  covered by tests, including malformed signed results, output-limit handling,
  pre-execution script verification and concurrent WebSocket sends.
- **OpenAI `gpt-4.1`** is the runtime model used by the investigation and
  remediation planners. It sits behind the small `Model` interface in
  `driver/model.py`; it is a product dependency, not a coding assistant.

## How the work was split

I set the product direction, selected the architecture and security boundaries,
reviewed the generated changes, and ran the system against real Windows
endpoints. The coding assistants drafted implementations, tests and
documentation. I iterated on their work through test failures, live endpoint
runs and adversarial review rather than accepting the first generated version.

The main human decisions were:

- use an outbound WebSocket so managed devices need no inbound port;
- authenticate a device with a private key instead of trusting its device ID;
- separate diagnosis from remediation and expose only reviewed catalogue
  actions to each model;
- bind human approval to the device, proposal and rebuilt script; and
- decide repair success with a fresh device check rather than a model opinion.

Several review passes found concrete defects after features first worked. Each
fix added or updated regression coverage. Examples include preventing an
enrollment token from replacing an existing device key, escaping hostile
device data in the dashboard, rejecting insecure lookalike loopback hosts,
binding approval to a script rebuilt from the repair catalogue, rejecting
malformed signed results and scoring evals against evidence instead of phrases.

The broad build order was:

1. Windows agent, control plane, enrollment and job lifecycle
2. result attestation, TLS, revocation and reboot detection
3. diagnostic catalogue, API client and bounded investigation loop
4. remediation catalogue, proposal binding, human approval and verification
5. evals, dashboard integration, installer and operator CLI
6. restart and upgrade endpoints, adversarial review and final documentation

## Verification during development

Unit and integration tests cover all three components: 88 control-plane tests,
112 driver tests and 16 .NET agent tests. The driver suite uses a scripted model
and fake transport, so it checks the decision loop without depending on a model
provider or network.

The system was also exercised on Windows EC2 endpoints. Faults were planted out
of band through AWS Systems Manager using `scripts/plant-fault`, so the AI had
to infer the cause from device evidence. An early stopped-spooler evaluation
scored 1/3 because the planner received summaries instead of the collected
data. After that data-flow bug was fixed, the full evaluation set scored 12/12.

## Time

The Git history spans about 40 hours across September 17–18, 2026. Before this
documentation pass it contained 32 commits and roughly 13,500 added and 2,200
removed lines. Hands-on time was not tracked separately, so I cannot give a
more precise estimate without inventing one.
