using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace SquashRmm.Agent;

public sealed class Enrollment(IConfiguration config, ILogger<Enrollment> log)
{
    private sealed record Request(
        string Token, string DeviceId, string PublicKey,
        string Hostname, string OsVersion, string AgentVersion);

    /// <summary>
    /// Redeems the single-use enrolment token. Runs once per machine; the
    /// marker file records that this key has already been registered.
    /// </summary>
    public async Task EnsureEnrolledAsync(string deviceId, DeviceCredential credential,
        string agentVersion, bool keyIsNew, CancellationToken ct)
    {
        var markerPath = Path.Combine(StateDirectory(), "enrolled");
        if (!keyIsNew && File.Exists(markerPath)) return;

        var token = config["Enrollment:Token"];
        if (string.IsNullOrWhiteSpace(token))
            throw new InvalidOperationException(
                "No enrolment token configured and this device is not yet enrolled.");

        var httpBase = (config["Server:Url"] ?? "").Replace("wss://", "https://").Replace("ws://", "http://");
        using var http = new HttpClient { BaseAddress = new Uri(httpBase.TrimEnd('/') + "/") };

        var response = await http.PostAsJsonAsync("api/enroll", new Request(
            token, deviceId, credential.PublicKeyBase64, Environment.MachineName,
            RuntimeInformation.OSDescription, agentVersion), ct);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Enrollment rejected ({(int)response.StatusCode}): {body}");
        }

        await File.WriteAllTextAsync(markerPath, DateTimeOffset.UtcNow.ToString("o"), ct);
        log.LogInformation("Enrolled device {DeviceId}", deviceId);
    }

    public static string StateDirectory()
    {
        var configured = Environment.GetEnvironmentVariable("SQUASH_STATE_DIR");
        var path = !string.IsNullOrWhiteSpace(configured)
            ? configured
            : OperatingSystem.IsWindows()
                ? @"C:\SquashRmm\state"
                : Path.Combine(Path.GetTempPath(), "squash-agent-state");
        Directory.CreateDirectory(path);
        return path;
    }
}
