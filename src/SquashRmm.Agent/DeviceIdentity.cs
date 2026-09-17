using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SquashRmm.Agent;

public static class DeviceIdentity
{
    public static string Resolve()
    {
        var raw = ReadMachineIdentifier();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash)[..32].ToLowerInvariant();
    }

    private static string ReadMachineIdentifier()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var guid = ReadWindowsMachineGuid();
            if (!string.IsNullOrWhiteSpace(guid)) return guid;
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            var uuid = ReadMacHardwareUuid();
            if (!string.IsNullOrWhiteSpace(uuid)) return uuid;
        }

        return Environment.MachineName;
    }

    private static string? ReadWindowsMachineGuid()
    {
        if (!OperatingSystem.IsWindows()) return null;
        using var key = Microsoft.Win32.Registry.LocalMachine
            .OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
        return key?.GetValue("MachineGuid") as string;
    }

    private static string? ReadMacHardwareUuid()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "/usr/sbin/ioreg",
                ArgumentList = { "-rd1", "-c", "IOPlatformExpertDevice" },
                RedirectStandardOutput = true,
                UseShellExecute = false
            });

            var output = process!.StandardOutput.ReadToEnd();
            process.WaitForExit();

            var marker = "\"IOPlatformUUID\" = \"";
            var start = output.IndexOf(marker, StringComparison.Ordinal);
            if (start < 0) return null;

            start += marker.Length;
            var end = output.IndexOf('"', start);
            return end < 0 ? null : output[start..end];
        }
        catch
        {
            return null;
        }
    }
}
