using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace SquashRmm.Agent;

/// <summary>
/// powershell.exe serializes its error stream as CLIXML whenever stderr is redirected.
/// Consumers need the human-readable text, not the envelope.
/// </summary>
public static partial class CliXml
{
    private const string Marker = "#< CLIXML";

    public static string Decode(string stderr)
    {
        if (string.IsNullOrEmpty(stderr) || !stderr.TrimStart().StartsWith(Marker, StringComparison.Ordinal))
            return stderr;

        var xmlStart = stderr.IndexOf("<Objs", StringComparison.Ordinal);
        if (xmlStart < 0) return stderr;

        try
        {
            var root = XDocument.Parse(stderr[xmlStart..]).Root;
            if (root is null) return stderr;

            XNamespace ns = root.GetDefaultNamespace();
            var lines = root.Elements(ns + "S")
                .Where(e => (string?)e.Attribute("S") == "Error")
                .Select(e => Unescape(e.Value));

            var text = string.Concat(lines).Trim();
            return text.Length > 0 ? text : "";
        }
        catch (System.Xml.XmlException)
        {
            return stderr;
        }
    }

    private static string Unescape(string value) =>
        EscapePattern().Replace(value, m =>
            ((char)Convert.ToInt32(m.Groups[1].Value, 16)).ToString());

    [GeneratedRegex(@"_x([0-9A-Fa-f]{4})_")]
    private static partial Regex EscapePattern();
}
