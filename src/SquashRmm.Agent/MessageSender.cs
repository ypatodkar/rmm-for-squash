using System.Net.WebSockets;
using SquashRmm.Protocol;

namespace SquashRmm.Agent;

/// <summary>
/// The only way anything in a session writes to the socket.
/// </summary>
/// <remarks>
/// A WebSocket supports one send at a time, and a session has several
/// independent writers: the heartbeat timer, and every job, each of which runs
/// on its own and reports whenever it finishes. Two of them finishing together
/// is ordinary, and without this they would interleave on the socket.
/// </remarks>
public sealed class MessageSender(WebSocket socket)
{
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task SendAsync<T>(T message, CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            await WebSocketJson.SendAsync(socket, message, ct);
        }
        finally
        {
            gate.Release();
        }
    }
}
