# Squash RMM

Remote management for Windows, with an API and AI-assisted troubleshooting.
Run PowerShell, retrieve structured results, and investigate problems in plain
English. AI repairs require human approval and are verified after execution.

Built with **C# / .NET**, **Python / FastAPI**, **SQLite**, and **OpenAI**.
The Windows agent uses an authenticated outbound WebSocket connection.

## Get started

Follow the [setup guide](docs/setup_guide.md) to build the agent, start the
server, and enroll a Windows device. Use curl, Postman, or the included dashboard
to run commands and investigations.

The API also provides device inventory, reboot tracking, and filtered Windows
event logs.

## Documentation

- [API reference](docs/api.md) — endpoints and curl examples
- [Design](docs/design.md) — architecture and key decisions
- [Threat model](docs/threat-model.md) — security boundaries and known limitations
- [How it was built](docs/how_the_project_was_built.md) — tools, development process, and time

Source: `src/` for the Windows agent, `server/` for the control plane,
`driver/` for AI, and `installer/` for installation scripts.
