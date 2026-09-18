using System.Net.WebSockets;
using SquashRmm.Agent;
using SquashRmm.Protocol;

namespace SquashRmm.Agent.Tests;

/// <summary>
/// A WebSocket supports one send at a time. A session has independent writers
/// -- the heartbeat and every job -- so the sender has to serialise them.
/// </summary>
public class MessageSenderTests
{
    /// <summary>Records how many sends were ever in progress at once.</summary>
    private sealed class OverlapDetectingSocket : WebSocket
    {
        private int active;
        public int MostAtOnce;
        public int Sent;

        public override async Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType messageType,
            bool endOfMessage, CancellationToken cancellationToken)
        {
            var now = Interlocked.Increment(ref active);
            InterlockedMax(ref MostAtOnce, now);
            await Task.Delay(5, cancellationToken);   // a send takes time on a real network
            Interlocked.Decrement(ref active);
            Interlocked.Increment(ref Sent);
        }

        private static void InterlockedMax(ref int target, int value)
        {
            int seen;
            while ((seen = Volatile.Read(ref target)) < value &&
                   Interlocked.CompareExchange(ref target, value, seen) != seen) { }
        }

        public override WebSocketCloseStatus? CloseStatus => null;
        public override string? CloseStatusDescription => null;
        public override WebSocketState State => WebSocketState.Open;
        public override string? SubProtocol => null;
        public override void Abort() { }
        public override Task CloseAsync(WebSocketCloseStatus s, string? d, CancellationToken ct) => Task.CompletedTask;
        public override Task CloseOutputAsync(WebSocketCloseStatus s, string? d, CancellationToken ct) => Task.CompletedTask;
        public override void Dispose() { }
        public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> b, CancellationToken ct) =>
            throw new NotSupportedException();
    }

    private static AgentMessage Heartbeat() => new AgentHeartbeat { SentAtUnixMs = 0 };

    [Fact]
    public async Task Concurrent_writers_never_overlap_on_the_socket()
    {
        var socket = new OverlapDetectingSocket();
        var sender = new MessageSender(socket);

        await Task.WhenAll(Enumerable.Range(0, 20)
            .Select(_ => Task.Run(() => sender.SendAsync(Heartbeat(), CancellationToken.None))));

        Assert.Equal(20, socket.Sent);
        Assert.Equal(1, socket.MostAtOnce);
    }

    [Fact]
    public async Task Without_the_sender_the_same_writers_do_overlap()
    {
        // Proves the socket above can see an overlap, so the test above means
        // something. This is what the agent did before.
        var socket = new OverlapDetectingSocket();

        await Task.WhenAll(Enumerable.Range(0, 20)
            .Select(_ => Task.Run(() => WebSocketJson.SendAsync(socket, Heartbeat(), CancellationToken.None))));

        Assert.True(socket.MostAtOnce > 1);
    }
}
