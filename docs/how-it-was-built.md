# How it was built

## AI tools

- **Claude Code with Claude Opus 5** was the main implementation assistant. Of
  the 43 commits, 42 carry a Claude co-author trailer; the exception is a
  documentation commit I made myself. It was used across the C# agent, FastAPI
  control plane, Python driver, tests, installers and docs.
- **Codex** ran alongside Claude Code throughout. I took the same design
  questions to both, such as how the agents should be structured and what the
  WebSocket protocol should look like, and went back and forth between their
  answers before deciding. Codex also did the final requirement, security and
  documentation review. That review found execution-layer defects that were then
  fixed and covered by tests, including malformed signed results, output-limit
  handling, pre-execution script verification and concurrent WebSocket sends.
- **OpenAI `gpt-4.1`** is the runtime model used by the investigation and
  remediation planners. It sits behind the small `Model` interface in
  `driver/model.py`; it is a product dependency, not a coding assistant.

## How I built it

I worked with Claude Code on one side and Codex on the other, and built the
system in this order:

1. **Infrastructure.** I created EC2 instances: Windows Server machines I could
   reach remotely on AWS to act as managed devices, and a Linux instance for the
   backend server.
2. **The connection.** I wrote a small C# program for the Windows machine, which
   became the agent. It opens a WebSocket connection to the backend, so the
   device only ever connects out.
3. **Design and protocol.** I went back and forth between Claude and Codex on how
   the agents should be designed, and on the protocol: which messages go over the
   WebSocket, in what order, and what each one carries.
4. **A dashboard.** I built a small HTML dashboard so I could see what was going
   on: devices, jobs and their results.
5. **A diagnosis agent.** An AI agent that takes a plain-English problem, runs
   read-only checks on the machine, and reports what is wrong.
6. **A repair agent.** A second agent that acts on a diagnosis. It proposes a fix
   as a PowerShell script chosen from a reviewed list. Once a person approves it,
   the system runs the script and checks the machine again to confirm it worked.

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
6. restart and upgrade endpoints, inventory, filtered event logs, adversarial
   review and final documentation
7. network diagnostics, device inventory, event log queries and tracked restarts

## Verification during development

Local verification on September 19, 2026 passed 151 control-plane tests,
121 driver tests and 16 .NET agent tests. The driver suite uses a scripted model
and fake transport, so it checks the decision loop without depending on a model
provider or network.

The system was also exercised on Windows EC2 endpoints. Faults were planted out
of band through AWS Systems Manager using `scripts/plant-fault`, so the AI had
to infer the cause from device evidence. An early stopped-spooler evaluation
scored 1/3 because the planner received summaries instead of the collected
data. After that data-flow bug was fixed, a development evaluation run scored
12/12. This is a historical result, not a fresh model evaluation for this
submission. Evals are run manually against test endpoints; each approved
repair instead gets its own live verification diagnostic.

## Time

My hands-on time was about 17–20 hours, across 43 commits.
