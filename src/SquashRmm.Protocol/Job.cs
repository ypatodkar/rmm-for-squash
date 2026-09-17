namespace SquashRmm.Protocol;

public sealed record JobSpec
{
    public required string JobId { get; init; }
    public required string Script { get; init; }
    public int TimeoutSeconds { get; init; } = 30;
    public int MaxOutputBytes { get; init; } = 1_048_576;

    /// <summary>SHA-256 of <see cref="Script"/> as computed by the control plane.</summary>
    public string? ScriptSha256 { get; init; }
}

public sealed record JobResult
{
    public required string JobId { get; init; }
    public required JobState State { get; init; }
    public int? ExitCode { get; init; }
    public string Stdout { get; init; } = "";
    public string Stderr { get; init; } = "";
    public long DurationMs { get; init; }
    public bool StdoutTruncated { get; init; }
    public bool StderrTruncated { get; init; }
    public string? Error { get; init; }

    /// <summary>SHA-256 of the script this device actually executed.</summary>
    public string? ScriptSha256 { get; init; }

    /// <summary>
    /// Device signature over <see cref="Attestation"/>. Lets the control plane
    /// verify that this result came from the enrolled device and corresponds to
    /// the script that was dispatched, rather than merely claiming to.
    /// </summary>
    public string? Signature { get; init; }

    /// <summary>
    /// Canonical, unambiguous summary of the execution. Field order is fixed and
    /// the separator cannot appear in a hex digest, so distinct executions cannot
    /// produce the same string.
    /// </summary>
    public static string Attestation(string jobId, string scriptSha256, int? exitCode,
        long durationMs, string stdoutSha256, string stderrSha256) =>
        string.Join('|', "squash-rmm-result-v1", jobId, scriptSha256,
            exitCode?.ToString() ?? "null", durationMs.ToString(),
            stdoutSha256, stderrSha256);
}
