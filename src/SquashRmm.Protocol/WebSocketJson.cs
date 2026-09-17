using System.Buffers;
using System.Net.WebSockets;
using System.Text.Json;

namespace SquashRmm.Protocol;

public static class WebSocketJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    private const int MaxMessageBytes = 8 * 1024 * 1024;

    public static async Task SendAsync<T>(WebSocket socket, T message, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message, Options);
        await socket.SendAsync(bytes, WebSocketMessageType.Text, endOfMessage: true, ct);
    }

    public static async Task<T?> ReceiveAsync<T>(WebSocket socket, CancellationToken ct)
    {
        var buffer = new ArrayBufferWriter<byte>(4096);
        while (true)
        {
            var segment = buffer.GetMemory(4096);
            var result = await socket.ReceiveAsync(segment, ct);

            if (result.MessageType == WebSocketMessageType.Close) return default;

            buffer.Advance(result.Count);
            if (buffer.WrittenCount > MaxMessageBytes)
                throw new InvalidOperationException("Message exceeded maximum size.");

            if (result.EndOfMessage) break;
        }

        return buffer.WrittenCount == 0
            ? default
            : JsonSerializer.Deserialize<T>(buffer.WrittenSpan, Options);
    }
}
