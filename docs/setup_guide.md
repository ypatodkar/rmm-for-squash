# Setup guide

Allow about 20–30 minutes with the prerequisites installed. The first
`dotnet publish` downloads the Windows runtime; download time varies.

## What you need

- A machine to run the control plane (macOS or Linux) with **Python 3.10+** and
  the **.NET 10 SDK**. The agent cross-compiles for Windows from any OS.
- A **Windows 10/11 or Windows Server** machine where you have Administrator
  rights, and which can reach the control plane over the network.
- Optional: an **OpenAI API key**, for AI investigations. Devices, jobs and the
  rest of the API work without it.

## 1. Install the control plane

```bash
cd rmm-for-squash
python3 -m venv .venv
.venv/bin/pip install -r server/requirements.txt   # the driver uses only the standard library
```

## 2. Configure

```bash
cp .env.example .env
python3 -c 'import secrets; print("op_" + secrets.token_urlsafe(32))'   # run twice: one key for you, one for the AI driver
```

Edit `.env`:

- Put your key in the `operator:` entry of `SQUASH_OPERATOR_KEYS`, and the second
  key in both the `ai-driver:` entry and `SQUASH_DRIVER_KEY`.
- Set `OPENAI_API_KEY` if you want investigations.
- Keep `SQUASH_SELF_URL=http://127.0.0.1:5200` for the server's own AI worker.
  Change it if you change the server port. The default model is `gpt-4.1`.

## 3. Build the agent and put it where the server serves it

```bash
dotnet publish src/SquashRmm.Agent -c Release -r win-x64 --self-contained \
  -p:PublishSingleFile=true -o dist/build
mkdir -p dist/publish
cp dist/build/SquashRmm.Agent.exe installer/install.ps1 installer/uninstall.ps1 dist/publish/
(cd dist/publish && shasum -a 256 SquashRmm.Agent.exe | cut -d' ' -f1 > SquashRmm.Agent.exe.sha256)
```

The installer refuses a binary whose SHA-256 doesn't match the published one.
Regenerate the `.sha256` file whenever you rebuild.

## 4. Start the control plane

```bash
set -a; . ./.env; set +a          # operator keys are read from the environment at startup
cd server
SQUASH_DIST=../dist/publish ../.venv/bin/uvicorn main:app --host 0.0.0.0 --port 5200
```

`curl "http://<host>:5200/health"` should return `{"status":"ok"}`. The database
is created at `server/squash.db`.

Run one uvicorn worker and one control-plane instance. Active device sockets
and jobs are held in process memory; multiple workers do not share them. Keep
the SQLite database on persistent storage so device identity and history survive.

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

Replace the example hostname with your server's public address. For HTTPS,
use that `https://` URL in all remaining examples, including the Windows
installer. Only the server needs inbound access; the Windows agent connects out.

## 5. Mint an enrollment token

Keep the server running. Open a second terminal in the project root. Replace
`<host>` with the server address reachable from Windows and enter your operator key.

```bash
export SQUASH_SERVER="http://<host>:5200"   # the address the Windows machine will use, not 127.0.0.1
export SQUASH_KEY="<your operator key>"
export SQUASH_ALLOW_PLAINTEXT=1           # only if SQUASH_SERVER is http://
scripts/squashctl install
```

This prints a single-use token (valid for one hour) and the exact command to
run on the endpoint. The command embeds `SQUASH_SERVER`, which is why it must
be an address the Windows machine can reach. To mint a token without the CLI:
`curl -X POST -H "X-API-Key: $SQUASH_KEY" "$SQUASH_SERVER/api/enrollment-tokens"`.

## 6. Install on Windows

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

## 7. Check that it works

```bash
scripts/squashctl devices                 # ONLINE should be True
scripts/squashctl run "<hostname>" 'Get-Service Spooler | Select Name,Status | ConvertTo-Json'
```

Or open `http://<host>:5200/` and paste your operator key into the key field.

For curl or Postman, see the [API reference](api.md). Use `GET /api/devices`
to obtain the device ID, `POST /api/devices/{id}/jobs` to dispatch a script,
and `GET /api/jobs/{jobId}` to retrieve its result.

## If enrollment fails

| Symptom | Cause |
|---|---|
| `enrolment has not completed within 45s` | The token expired (1 hour), was already used, or the server can't be reached. On the endpoint, inspect Windows Event Viewer → Application for agent/service errors and check `Get-Service SquashEndpoint` |
| `Device is already enrolled` (409) | This machine enrolled before and its key is gone. From the project root, run `scripts/squashctl reinstall "<hostname>"` to get a recovery token for that device, then run the printed installer command on Windows |
| `Device is revoked` (403) | Run `scripts/squashctl restore "<hostname>"` first |
| `iwr` can't connect, or times out | The Windows machine can't reach the control plane. Check that port 5200 (or 443 behind Caddy) accepts inbound connections: the host firewall, and the security group if it's a cloud VM |
| Device offline right after install | Check that outbound TCP from the endpoint to the control plane's port is allowed |

## Upgrade or uninstall

Publish a new agent binary and checksum using step 3, then run
`scripts/squashctl upgrade "<hostname>"` from the project root to reinstall
that build remotely. It preserves the device key and identity. A successful
scheduling response is not proof the upgrade finished; wait for reconnection
and check `agentVersion`.

To uninstall, run in Administrator PowerShell on Windows, replacing the server
address with the one used for installation:

```powershell
$Server = "http://<host>:5200"
Invoke-WebRequest "$Server/uninstall.ps1" -OutFile uninstall.ps1
.\uninstall.ps1
```

This removes the service, files, and device key. The server keeps the device
record and audit history. A later reinstall needs a device-bound recovery token.

## Tests

Run from the project root:

```bash
(cd server && SQUASH_DB=/tmp/squash-test.db ../.venv/bin/python -m unittest discover)
(cd driver && ../.venv/bin/python -m unittest discover)
dotnet test SquashRmm.slnx
```

The driver tests use a scripted model and a fake transport, so they need no
network or API key. The agent tests run the capped output reader, the
pre-execution hash check and the socket sender on any OS; the process tests
use bash off Windows.

## Running the AI driver

Investigations are available through the dashboard, API, and CLI:

- **Dashboard.** Go to Investigations → New. You'll see progress, evidence and a
  proposed repair, and you approve or reject the repair there.
- **API.** `POST /api/investigations`, followed by GET requests for progress
  and a POST to `/api/investigations/{id}/decision` for approval or rejection.
  See the [request examples](api.md#6-ai-diagnostics-investigations).
- **CLI.** Prints the timing of each step as it runs:

  ```bash
  # From the project root
  cd driver
  SQUASH_SERVER=$SQUASH_SERVER SQUASH_DRIVER_KEY="<driver key>" \
    ../.venv/bin/python diagnose.py "<hostname>" "nothing prints from this computer"
  ```

Optional development tools for testing against an EC2 endpoint (they need the
AWS CLI with SSM access):

- `scripts/plant-fault printing|clock|display|memory|dns|firewall|reset` breaks
  something real out of band. `firewall` is the multi-step network demo: the
  AI can choose network diagnostics to locate the blocking rule.
- `driver/evals.py <hostname> [repeats]` scores the driver against known faults.

These evals deliberately change a test endpoint through AWS SSM. Set
`SQUASH_EVAL_INSTANCE` and `AWS_REGION` to that endpoint's EC2 instance and region,
and use its matching hostname. They are run manually during development, not
after every command; approved repairs have their own live verification check.

## Submission contents

Include the source archive, the demo video, and the five documents linked from
the README: this setup guide, API reference, design notes, threat model, and
build notes. Keep `.git` in the source archive as requested by the assignment.
Exclude local secrets (`.env`, private keys), runtime databases, `.venv`, and
generated build outputs. Include `.env.example` so a reviewer can configure
their own credentials and build the agent from source.
