using System.Text;

namespace SquashRmm.Agent;

/// <summary>
/// Reads a process stream to the end while keeping at most a fixed number of
/// UTF-8 bytes of it.
/// </summary>
/// <remarks>
/// Two properties matter, because callers decide from the result whether
/// output is safe to parse. The limit is in bytes as the text will be
/// encoded, not in UTF-16 characters, so non-ASCII output cannot exceed it.
/// And the truncation flag is set whenever anything at all is discarded,
/// including the tail of the read that crossed the limit -- a flag that is
/// only mostly right is worse than none.
///
/// The stream is always drained to the end. A child process writing to a
/// full pipe blocks, so stopping early would turn a bounded read into a hang.
/// </remarks>
public static class OutputCapture
{
    public static async Task<(string Text, bool Truncated)> ReadAsync(
        TextReader reader, int maxBytes, CancellationToken ct)
    {
        var kept = new Utf8Budget(maxBytes);
        var buffer = new char[4096];

        while (true)
        {
            int read;
            try
            {
                read = await reader.ReadAsync(buffer.AsMemory(), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (read == 0) break;
            kept.Append(buffer.AsSpan(0, read));
        }

        kept.Finish();
        return (kept.ToString(), kept.Truncated);
    }

    /// <summary>
    /// Accumulates characters until the next one would not fit. A surrogate
    /// pair is one four-byte character and is kept or dropped whole, even when
    /// a read ends between its halves.
    /// </summary>
    private sealed class Utf8Budget(int maxBytes)
    {
        private readonly StringBuilder text = new();
        private int bytes;
        private char? pendingHigh;

        public bool Truncated { get; private set; }

        public void Append(ReadOnlySpan<char> chunk)
        {
            foreach (var c in chunk)
            {
                if (Truncated) return;

                if (pendingHigh is { } high)
                {
                    pendingHigh = null;
                    if (char.IsLowSurrogate(c))
                    {
                        Keep(4, high, c);
                        continue;
                    }
                    // An unpaired high surrogate encodes as U+FFFD: three bytes.
                    Keep(3, high);
                    if (Truncated) return;
                }

                if (char.IsHighSurrogate(c))
                    pendingHigh = c;
                else
                    Keep(Utf8Length(c), c);
            }
        }

        public void Finish()
        {
            if (pendingHigh is { } high && !Truncated) Keep(3, high);
            pendingHigh = null;
        }

        public override string ToString() => text.ToString();

        private void Keep(int size, char first, char? second = null)
        {
            if (bytes + size > maxBytes)
            {
                Truncated = true;
                return;
            }
            bytes += size;
            text.Append(first);
            if (second is { } low) text.Append(low);
        }

        // A lone low surrogate also encodes as U+FFFD, which is three bytes.
        private static int Utf8Length(char c) => c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
    }
}
