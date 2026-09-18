using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging.Abstractions;
using SquashRmm.Agent;
using SquashRmm.Protocol;

namespace SquashRmm.Agent.Tests;

/// <summary>
/// "What executes must verifiably match what was dispatched." These run real
/// processes: off Windows the executor uses bash, which is enough to prove
/// whether anything started.
/// </summary>
public class ScriptExecutorTests : IDisposable
{
    private readonly string marker = Path.Combine(Path.GetTempPath(), $"squash-test-{Guid.NewGuid():N}");
    private readonly ScriptExecutor executor = new(NullLogger<ScriptExecutor>.Instance);

    public void Dispose()
    {
        if (File.Exists(marker)) File.Delete(marker);
    }

    private JobSpec Job(string script, string? sha, int maxOutputBytes = 1_048_576) => new()
    {
        JobId = "job-1",
        Script = script,
        ScriptSha256 = sha,
        TimeoutSeconds = 20,
        MaxOutputBytes = maxOutputBytes,
    };

    private string TouchMarker => $"touch '{marker}'";

    [SkippableUnlessUnixFact]
    public async Task A_script_whose_hash_does_not_match_never_starts()
    {
        var result = await executor.RunAsync(Job(TouchMarker, new string('0', 64)), CancellationToken.None);

        Assert.Equal(JobState.Failed, result.State);
        Assert.Contains("does not match", result.Error);
        Assert.False(File.Exists(marker), "the script ran despite a hash mismatch");
        // Reported with the hash of what was received, so the server can see
        // exactly what differed.
        Assert.Equal(ScriptExecutor.Sha256Hex(TouchMarker), result.ScriptSha256);
    }

    [SkippableUnlessUnixFact]
    public async Task A_script_dispatched_without_a_hash_never_starts()
    {
        var result = await executor.RunAsync(Job(TouchMarker, sha: null), CancellationToken.None);

        Assert.Equal(JobState.Failed, result.State);
        Assert.Contains("no script hash", result.Error);
        Assert.False(File.Exists(marker));
    }

    [SkippableUnlessUnixFact]
    public async Task A_script_whose_hash_matches_runs()
    {
        // Without this the two tests above could pass because nothing ever runs.
        var result = await executor.RunAsync(
            Job(TouchMarker, ScriptExecutor.Sha256Hex(TouchMarker)), CancellationToken.None);

        Assert.Equal(JobState.Completed, result.State);
        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(marker));
    }

    [SkippableUnlessUnixFact]
    public async Task Hash_comparison_ignores_hex_case()
    {
        var upper = ScriptExecutor.Sha256Hex(TouchMarker).ToUpperInvariant();
        var result = await executor.RunAsync(Job(TouchMarker, upper), CancellationToken.None);
        Assert.Equal(JobState.Completed, result.State);
    }

    [SkippableUnlessUnixFact]
    public async Task Real_process_output_is_capped_and_flagged()
    {
        const string script = "head -c 5000 /dev/zero | tr '\\0' x";
        var result = await executor.RunAsync(
            Job(script, ScriptExecutor.Sha256Hex(script), maxOutputBytes: 1024), CancellationToken.None);

        Assert.Equal(JobState.Completed, result.State);
        Assert.Equal(1024, result.Stdout.Length);
        Assert.True(result.StdoutTruncated);
    }
}

/// <summary>
/// These tests start processes through the non-Windows path of the executor.
/// The Windows path is exercised on a real endpoint.
/// </summary>
public sealed class SkippableUnlessUnixFactAttribute : FactAttribute
{
    public SkippableUnlessUnixFactAttribute()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            Skip = "Runs the non-Windows execution path.";
    }
}
