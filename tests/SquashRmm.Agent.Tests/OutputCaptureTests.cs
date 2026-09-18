using System.Text;
using SquashRmm.Agent;

namespace SquashRmm.Agent.Tests;

/// <summary>
/// Callers decide from the truncation flag whether output is safe to parse,
/// so the flag has to be exactly right, and the limit has to be in bytes.
/// </summary>
public class OutputCaptureTests
{
    /// <summary>
    /// Returns each chunk from its own read, as a pipe would, and never more
    /// than the caller's buffer holds; a longer chunk spans several reads.
    /// </summary>
    private sealed class ChunkedReader(params string[] chunks) : TextReader
    {
        private int next;
        private int offset;
        public int ChunksRead => next;

        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken ct = default)
        {
            if (next == chunks.Length) return ValueTask.FromResult(0);
            var remaining = chunks[next].AsSpan(offset);
            var count = Math.Min(remaining.Length, buffer.Length);
            remaining[..count].CopyTo(buffer.Span);
            offset += count;
            if (offset == chunks[next].Length) { next++; offset = 0; }
            return ValueTask.FromResult(count);
        }
    }

    private static Task<(string Text, bool Truncated)> Capture(int maxBytes, params string[] chunks) =>
        OutputCapture.ReadAsync(new ChunkedReader(chunks), maxBytes, CancellationToken.None);

    [Fact]
    public async Task One_byte_over_in_a_single_read_is_flagged()
    {
        // Previously: 1,024 bytes kept, the last one dropped, flag false.
        var (text, truncated) = await Capture(1024, new string('x', 1025));
        Assert.Equal(1024, text.Length);
        Assert.True(truncated);
    }

    [Fact]
    public async Task Output_that_exactly_fits_is_not_flagged()
    {
        var (text, truncated) = await Capture(1024, new string('x', 1024));
        Assert.Equal(1024, text.Length);
        Assert.False(truncated);
    }

    [Fact]
    public async Task Output_well_over_is_flagged()
    {
        var (text, truncated) = await Capture(1024, new string('x', 4097));
        Assert.Equal(1024, text.Length);
        Assert.True(truncated);
    }

    [Fact]
    public async Task The_limit_is_in_utf8_bytes_not_characters()
    {
        // Previously: 1,024 characters of é -- 2,048 bytes -- and flag false.
        var (text, truncated) = await Capture(1024, new string('é', 1024));
        Assert.Equal(1024, Encoding.UTF8.GetByteCount(text));
        Assert.Equal(512, text.Length);
        Assert.True(truncated);
    }

    [Fact]
    public async Task A_surrogate_pair_split_across_reads_is_kept_whole()
    {
        var (text, truncated) = await Capture(16, "a\uD83D", "\uDE00b");
        Assert.Equal("a😀b", text);
        Assert.False(truncated);
    }

    [Fact]
    public async Task A_surrogate_pair_that_does_not_fit_is_dropped_whole()
    {
        var (text, truncated) = await Capture(5, "abc😀");
        Assert.Equal("abc", text);
        Assert.True(truncated);
    }

    [Fact]
    public async Task An_unpaired_surrogate_is_counted_as_the_replacement_it_becomes()
    {
        // U+FFFD is three bytes; 1 + 3 = 4 fits, one more byte does not.
        var (fits, notFlagged) = await Capture(4, "a\uD800");
        Assert.Equal("a\uD800", fits);
        Assert.False(notFlagged);

        var (_, flagged) = await Capture(3, "a\uD800");
        Assert.True(flagged);
    }

    [Fact]
    public async Task The_stream_is_drained_after_the_limit()
    {
        // A child writing into a full pipe blocks, so reading must continue.
        var reader = new ChunkedReader("x".PadRight(2000, 'x'), "more", "and more", "and the end");
        var (_, truncated) = await OutputCapture.ReadAsync(reader, 1024, CancellationToken.None);
        Assert.True(truncated);
        Assert.Equal(4, reader.ChunksRead);
    }

    [Fact]
    public async Task Kept_output_is_always_a_prefix_within_the_limit()
    {
        var alphabet = new[] { "a", "é", "中", "😀", "\n", "\uD800" };
        var random = new Random(20260918);
        for (var trial = 0; trial < 500; trial++)
        {
            var original = new StringBuilder();
            for (var i = random.Next(0, 300); i > 0; i--)
                original.Append(alphabet[random.Next(alphabet.Length)]);
            var source = original.ToString();

            // Split at arbitrary points, including inside surrogate pairs.
            var chunks = new List<string>();
            for (var at = 0; at < source.Length;)
            {
                var size = Math.Min(random.Next(1, 40), source.Length - at);
                chunks.Add(source.Substring(at, size));
                at += size;
            }

            var max = random.Next(1, 400);
            var (text, truncated) = await Capture(max, chunks.ToArray());

            Assert.StartsWith(text, source, StringComparison.Ordinal);
            Assert.True(Encoding.UTF8.GetByteCount(text) <= max, $"trial {trial}");
            Assert.Equal(text.Length < source.Length, truncated);
        }
    }
}
