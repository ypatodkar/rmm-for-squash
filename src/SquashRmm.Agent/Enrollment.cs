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

        var token = ReadToken();
        if (string.IsNullOrWhiteSpace(token))
            throw new InvalidOperationException(
                "No enrolment token available and this device is not yet enrolled.");

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
        DiscardToken();
        log.LogInformation("Enrolled device {DeviceId}", deviceId);
    }

    private static string TokenPath() => Path.Combine(StateDirectory(), "enroll.token");

    private string? ReadToken()
    {
        var path = TokenPath();
        if (File.Exists(path))
        {
            var fromFile = File.ReadAllText(path).Trim();
            if (fromFile.Length > 0) return fromFile;
        }
        return config["Enrollment:Token"];
    }

    /// <summary>A redeemed token is spent; leaving it on disk serves no purpose.</summary>
    private void DiscardToken()
    {
        try
        {
            if (File.Exists(TokenPath())) File.Delete(TokenPath());
        }
        catch (IOException ex)
        {
            log.LogWarning("Could not remove the spent enrolment token: {Message}", ex.Message);
        }
    }

    /// <summary>
    /// State sits beside the executable so it follows wherever the installer
    /// places the agent, rather than assuming a fixed path.
    /// </summary>
    public static string StateDirectory()
    {
        var configured = Environment.GetEnvironmentVariable("SQUASH_STATE_DIR");
        var path = !string.IsNullOrWhiteSpace(configured)
            ? configured
            : Path.Combine(AppContext.BaseDirectory, "state");
        Directory.CreateDirectory(path);
        return path;
    }
}
