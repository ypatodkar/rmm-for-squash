using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using SquashRmm.Protocol;

namespace SquashRmm.Agent;

public sealed class ScriptExecutor(ILogger<ScriptExecutor> log)
{
    public async Task<JobResult> RunAsync(JobSpec job, CancellationToken ct)
    {
        var stopwatch = Stopwatch.StartNew();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(job.TimeoutSeconds));

        try
        {
            return await ExecuteAsync(job, stopwatch, timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new JobResult
            {
                JobId = job.JobId,
                State = JobState.TimedOut,
                DurationMs = stopwatch.ElapsedMilliseconds,
                Error = $"Script exceeded {job.TimeoutSeconds}s timeout."
            };
        }
        catch (Exception ex)
        {
            log.LogError(ex, "Job {JobId} failed to execute", job.JobId);
            return new JobResult
            {
                JobId = job.JobId,
                State = JobState.Failed,
                DurationMs = stopwatch.ElapsedMilliseconds,
                Error = ex.Message
            };
        }
    }

    private static async Task<JobResult> ExecuteAsync(JobSpec job, Stopwatch stopwatch, CancellationToken ct)
    {
        var startInfo = BuildStartInfo(job.Script);
        using var process = new Process { StartInfo = startInfo };
        process.Start();

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            await process.StandardInput.WriteAsync(job.Script);
            process.StandardInput.Close();
        }

        var stdoutTask = ReadCappedAsync(process.StandardOutput, job.MaxOutputBytes, ct);
        var stderrTask = ReadCappedAsync(process.StandardError, job.MaxOutputBytes, ct);

        try
        {
            await process.WaitForExitAsync(ct);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }

        var (stdout, stdoutTruncated) = await stdoutTask;
        var (rawStderr, stderrTruncated) = await stderrTask;
        var stderr = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? CliXml.Decode(rawStderr)
            : rawStderr;

        return new JobResult
        {
            JobId = job.JobId,
            State = JobState.Completed,
            ExitCode = process.ExitCode,
            Stdout = stdout,
            Stderr = stderr,
            DurationMs = stopwatch.ElapsedMilliseconds,
            StdoutTruncated = stdoutTruncated,
            StderrTruncated = stderrTruncated
        };
    }

    private static ProcessStartInfo BuildStartInfo(string script)
    {
        var info = new ProcessStartInfo
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Redirected stderr otherwise receives CLIXML-serialized progress records,
            // which downstream consumers misread as failure output.
            var preamble = "$ProgressPreference='SilentlyContinue';$InformationPreference='SilentlyContinue';";
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(preamble + script));
            info.FileName = "powershell.exe";
            info.ArgumentList.Add("-NoProfile");
            info.ArgumentList.Add("-NonInteractive");
            info.ArgumentList.Add("-ExecutionPolicy");
            info.ArgumentList.Add("Bypass");
            info.ArgumentList.Add("-EncodedCommand");
            info.ArgumentList.Add(encoded);
        }
        else
        {
            info.FileName = File.Exists("/usr/local/bin/pwsh") ? "/usr/local/bin/pwsh" : "/bin/bash";
            if (info.FileName.EndsWith("pwsh")) info.ArgumentList.Add("-Command");
            info.ArgumentList.Add("-");
        }

        return info;
    }

    private static async Task<(string Text, bool Truncated)> ReadCappedAsync(
        StreamReader reader, int maxBytes, CancellationToken ct)
    {
        var builder = new StringBuilder();
        var buffer = new char[4096];
        var truncated = false;

        while (true)
        {
            int read;
            try
            {
                read = await reader.ReadAsync(buffer, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (read == 0) break;

            if (builder.Length >= maxBytes)
            {
                truncated = true;
                continue;
            }

            builder.Append(buffer, 0, Math.Min(read, maxBytes - builder.Length));
        }

        return (builder.ToString(), truncated);
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) { }
        catch (NotSupportedException) { }
    }
}
