namespace SquashRmm.Protocol;

public sealed record JobSpec
{
    public required string JobId { get; init; }
    public required string Script { get; init; }
    public int TimeoutSeconds { get; init; } = 30;
    public int MaxOutputBytes { get; init; } = 1_048_576;
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
}
