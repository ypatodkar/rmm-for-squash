using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SquashRmm.Agent;

/// <summary>
/// The enrolment keypair. The private key never leaves the machine and is
/// sealed with DPAPI (machine scope) so a copied file is useless elsewhere.
/// </summary>
public sealed class DeviceCredential
{
    private readonly ECDsa _key;

    private DeviceCredential(ECDsa key) => _key = key;

    public string PublicKeyBase64 =>
        Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo());

    public string Sign(byte[] payload) =>
        Convert.ToBase64String(_key.SignData(payload, HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence));

    public static DeviceCredential LoadOrCreate(string path, out bool created)
    {
        if (File.Exists(path))
        {
            var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(Unprotect(File.ReadAllBytes(path)), out _);
            created = false;
            return new DeviceCredential(key);
        }

        var fresh = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        File.WriteAllBytes(path, Protect(fresh.ExportPkcs8PrivateKey()));
        RestrictToOwner(path);
        created = true;
        return new DeviceCredential(fresh);
    }

    private static byte[] Protect(byte[] plaintext) =>
        OperatingSystem.IsWindows()
            ? ProtectedData.Protect(plaintext, null, DataProtectionScope.LocalMachine)
            : plaintext;

    private static byte[] Unprotect(byte[] sealed_) =>
        OperatingSystem.IsWindows()
            ? ProtectedData.Unprotect(sealed_, null, DataProtectionScope.LocalMachine)
            : sealed_;

    private static void RestrictToOwner(string path)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
