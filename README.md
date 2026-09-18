# Squash RMM

A remote management system for Windows, built so an AI can do the operator's
job. It has three parts:

- **Agent.** A C# Windows Service. It connects outbound to the control plane
  over a WebSocket and runs PowerShell jobs, returning structured, signed
  results.
- **Control plane.** FastAPI and SQLite. It handles enrollment, device identity,
  job dispatch, timeouts, the audit log, a dashboard and the REST API.
- **AI driver.** Python. It diagnoses a problem described in plain English, one
  check at a time, then proposes a repair from a reviewed catalogue. The repair
  runs only after a human approves it, and whether it worked is decided by
  re-checking the device, not by a model.

| Document | What it covers |
|---|---|
| This README | Setup: from the zip to an enrolled device |
| [docs/design.md](docs/design.md) | Connection model, job lifecycle, device identity, the AI layer, what's next |
| [docs/threat-model.md](docs/threat-model.md) | Trust boundaries, defences, and what is deferred |
| [docs/api.md](docs/api.md) | Every route, with curl examples |
| [docs/how-it-was-built.md](docs/how-it-was-built.md) | Tools, how the work was split, time spent |

## Layout

```
src/SquashRmm.Agent/      Windows agent (.NET 10 worker service)
src/SquashRmm.Protocol/   Wire types shared with the control plane
tests/SquashRmm.Agent.Tests/  Agent tests (xUnit)
server/                   Control plane: main.py (routes, WebSocket), store.py (SQLite)
server/static/index.html  Dashboard: devices, jobs, investigations
driver/                   AI driver: diagnostic and repair catalogues, model loop, evals
installer/                install.ps1 / uninstall.ps1 (unattended, run on the endpoint)
scripts/squashctl         Operator CLI
scripts/plant-fault       Creates a real fault on an EC2 endpoint for demos
```

## Setup: zip to enrolled device

This takes about 20 minutes. Most of it is the first `dotnet publish`
downloading the Windows runtime.

### What you need

- A machine to run the control plane (macOS or Linux) with **Python 3.10+** and
  the **.NET 10 SDK**. The agent cross-compiles for Windows from any OS.
- A **Windows 10/11 or Windows Server** machine where you have Administrator
  rights, and which can reach the control plane over the network.
- Optional: an **OpenAI API key**, for AI investigations. Devices, jobs and the
  rest of the API work without it.

### 1. Install the control plane

```bash
cd rmm-for-squash
python3 -m venv .venv
.venv/bin/pip install -r server/requirements.txt   # the driver uses only the standard library
```

### 2. Configure

```bash
cp .env.example .env
python3 -c 'import secrets; print("op_" + secrets.token_urlsafe(32))'   # run twice: one key for you, one for the AI driver
```

Edit `.env`:

- Put your key in the `operator:` entry of `SQUASH_OPERATOR_KEYS`, and the second
  key in both the `ai-driver:` entry and `SQUASH_DRIVER_KEY`.
- Set `OPENAI_API_KEY` if you want investigations.

### 3. Build the agent and put it where the server serves it

```bash
dotnet publish src/SquashRmm.Agent -c Release -r win-x64 --self-contained \
  -p:PublishSingleFile=true -o dist/build
mkdir -p dist/publish
cp dist/build/SquashRmm.Agent.exe installer/install.ps1 installer/uninstall.ps1 dist/publish/
(cd dist/publish && shasum -a 256 SquashRmm.Agent.exe | cut -d' ' -f1 > SquashRmm.Agent.exe.sha256)
```

The installer refuses a binary whose SHA-256 doesn't match the published one.
Regenerate the `.sha256` file whenever you rebuild.

### 4. Start the control plane

```bash
set -a; . ./.env; set +a          # operator keys are read from the environment at startup
cd server
SQUASH_DIST=../dist/publish ../.venv/bin/uvicorn main:app --host 0.0.0.0 --port 5200
```

`curl http://<host>:5200/health` should return `{"status":"ok"}`. The database
is created at `server/squash.db`.

**TLS.** The steps above use plain HTTP, which is fine on a private lab network.
Anywhere else, run uvicorn on `--host 127.0.0.1` and put Caddy in front of it.
The deployed instance does this with a certificate for an
[sslip.io](https://sslip.io) name, so it needs no domain:

```
# Caddyfile (ports 80 and 443 open)
203-0-113-10.sslip.io {
    reverse_proxy 127.0.0.1:5200
}
```

The agent then connects over `wss://` with ordinary certificate validation.
`squashctl` refuses to send your key over `http://` unless you set
`SQUASH_ALLOW_PLAINTEXT=1`.

### 5. Mint an enrollment token

```bash
export SQUASH_SERVER=http://<host>:5200   # or https://… behind Caddy
export SQUASH_KEY=<your operator key>
export SQUASH_ALLOW_PLAINTEXT=1           # only if SQUASH_SERVER is http://
scripts/squashctl install
```

This prints a single-use token (valid for one hour) and the exact command to
run on the endpoint. To mint a token without the CLI:
`curl -X POST -H "X-API-Key: $SQUASH_KEY" $SQUASH_SERVER/api/enrollment-tokens`.

### 6. Install on Windows

In an **Administrator** PowerShell on the endpoint:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
iwr http://<host>:5200/install.ps1 -OutFile i.ps1
.\i.ps1 -Server http://<host>:5200 -Token enr_...
```

The installer:

1. downloads the agent and verifies its hash
2. installs it to `C:\Program Files\SquashRmm`, readable only by SYSTEM and
   Administrators
3. registers the `SquashEndpoint` service (automatic start, restart on failure)
4. waits for enrollment to finish

It ends with **`Installed and enrolled.`**

### 7. Check that it works

```bash
scripts/squashctl devices                 # ONLINE should be True
scripts/squashctl run <hostname> 'Get-Service Spooler | Select Name,Status | ConvertTo-Json'
```

Or open `http://<host>:5200/` and paste your operator key into the key field.

### If enrollment fails

| Symptom | Cause |
|---|---|
| `enrolment has not completed within 45s` | The token expired (1 hour), was already used, or the server can't be reached. On the endpoint, check `Get-EventLog -LogName Application -Source SquashEndpoint -Newest 5` |
| `Device is already enrolled` (409) | This machine enrolled before and its key is gone. Uninstall it, then run `squashctl reinstall <host>` to get a recovery token for that one device |
| `Device is revoked` (403) | Run `squashctl restore <host>` first |
| Device offline right after install | Check that outbound TCP from the endpoint to the control plane's port is allowed |

To remove the agent, run `uninstall.ps1` from the same place. It deletes the
service, the files and the key. The server keeps the device record and its audit
history.

## Tests

```bash
(cd server && SQUASH_DB=/tmp/squash-test.db ../.venv/bin/python -m unittest discover)   # 88 tests
(cd driver && ../.venv/bin/python -m unittest discover)                                  # 112 tests
dotnet test SquashRmm.slnx                                                               # 16 agent tests
```

The driver tests use a scripted model and a fake transport, so they need no
network or API key. The agent tests run the capped output reader, the
pre-execution hash check and the socket sender on any OS; the process tests
use bash off Windows.

## Running the AI driver

There are two ways to run an investigation:

- **Dashboard.** Go to Investigations → New. You'll see progress, evidence and a
  proposed repair, and you approve or reject the repair there.
- **CLI.** Prints the timing of each step as it runs:

  ```bash
  cd driver
  SQUASH_SERVER=$SQUASH_SERVER SQUASH_DRIVER_KEY=<driver key> \
    ../.venv/bin/python diagnose.py <hostname> "nothing prints from this computer"
  ```

Two scripts support demos against an EC2 endpoint (they need the AWS CLI with
SSM access):

- `scripts/plant-fault printing|clock|display|memory|dns|firewall|reset` breaks
  something real out of band. `firewall` is the multi-step network demo: the
  AI checks the adapter, pings, resolves, tests the port, and finds the rule.
- `driver/evals.py <hostname> [repeats]` scores the driver against known faults.
