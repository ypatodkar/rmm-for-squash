using System.Net.WebSockets;
using System.Runtime.InteropServices;
using SquashRmm.Protocol;

namespace SquashRmm.Agent;

public sealed class AgentWorker(
    IConfiguration config,
    ScriptExecutor executor,
    Enrollment enrollment,
    ILogger<AgentWorker> log) : BackgroundService
{
    private const string AgentVersion = "0.2.0";
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var serverUrl = config["Server:Url"] ?? "ws://localhost:5200";
        var deviceId = DeviceIdentity.Resolve();
        var backoff = TimeSpan.FromSeconds(1);

        log.LogInformation("Agent starting. DeviceId={DeviceId} Server={Server}", deviceId, serverUrl);

        var keyPath = Path.Combine(Enrollment.StateDirectory(), "device.key");
        var credential = DeviceCredential.LoadOrCreate(keyPath, out var keyIsNew);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await enrollment.EnsureEnrolledAsync(deviceId, credential, AgentVersion, keyIsNew, stoppingToken);
                keyIsNew = false;
                await RunSessionAsync(serverUrl, deviceId, credential, stoppingToken);
                backoff = TimeSpan.FromSeconds(1);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                log.LogWarning("Connection lost: {Message}. Retrying in {Backoff}s", ex.Message, backoff.TotalSeconds);
            }

            try
            {
                await Task.Delay(backoff, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            backoff = TimeSpan.FromSeconds(Math.Min(backoff.TotalSeconds * 2, MaxBackoff.TotalSeconds));
        }
    }

    private async Task RunSessionAsync(string serverUrl, string deviceId,
        DeviceCredential credential, CancellationToken ct)
    {
        using var socket = new ClientWebSocket();
        await socket.ConnectAsync(new Uri($"{serverUrl.TrimEnd('/')}/agent/connect"), ct);

        var challenge = await WebSocketJson.ReceiveAsync<ServerMessage>(socket, ct) as ServerChallenge
            ?? throw new InvalidOperationException("Server did not issue a challenge.");

        await WebSocketJson.SendAsync(socket, (AgentMessage)new AgentHello
        {
            DeviceId = deviceId,
            Hostname = Environment.MachineName,
            OsVersion = RuntimeInformation.OSDescription,
            AgentVersion = AgentVersion,
            Signature = credential.Sign(Convert.FromBase64String(challenge.Nonce))
        }, ct);

        var ack = await WebSocketJson.ReceiveAsync<ServerMessage>(socket, ct) as ServerHelloAck
            ?? throw new InvalidOperationException("Server did not acknowledge enrollment.");

        log.LogInformation("Connected. Heartbeat every {Interval}s", ack.HeartbeatIntervalSeconds);

        using var session = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var heartbeat = HeartbeatLoopAsync(socket, ack.HeartbeatIntervalSeconds, session.Token);
        var receive = ReceiveLoopAsync(socket, session.Token);

        try
        {
            await Task.WhenAny(heartbeat, receive);
        }
        finally
        {
            await session.CancelAsync();
        }

        await receive.ContinueWith(_ => { }, CancellationToken.None);
    }

    private static async Task HeartbeatLoopAsync(ClientWebSocket socket, int intervalSeconds, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(intervalSeconds));
        while (await timer.WaitForNextTickAsync(ct))
        {
            await WebSocketJson.SendAsync(socket, (AgentMessage)new AgentHeartbeat
            {
                SentAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            }, ct);
        }
    }

    private async Task ReceiveLoopAsync(ClientWebSocket socket, CancellationToken ct)
    {
        while (socket.State == WebSocketState.Open && !ct.IsCancellationRequested)
        {
            var message = await WebSocketJson.ReceiveAsync<ServerMessage>(socket, ct);
            if (message is null) break;

            if (message is ServerJobDispatch dispatch)
                _ = RunJobAsync(socket, dispatch.Job, ct);
        }
    }

    private async Task RunJobAsync(ClientWebSocket socket, JobSpec job, CancellationToken ct)
    {
        log.LogInformation("Job {JobId} received", job.JobId);

        try
        {
            await WebSocketJson.SendAsync(socket, (AgentMessage)new AgentJobAccepted { JobId = job.JobId }, ct);
            var result = await executor.RunAsync(job, ct);
            await WebSocketJson.SendAsync(socket, (AgentMessage)new AgentJobResult { Result = result }, ct);
            log.LogInformation("Job {JobId} finished: {State} in {Ms}ms", job.JobId, result.State, result.DurationMs);
        }
        catch (Exception ex)
        {
            log.LogError(ex, "Failed to report result for job {JobId}", job.JobId);
        }
    }
}
