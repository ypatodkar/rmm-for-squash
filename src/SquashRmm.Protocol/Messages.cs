using System.Text.Json.Serialization;

namespace SquashRmm.Protocol;

[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(AgentHello), "hello")]
[JsonDerivedType(typeof(AgentHeartbeat), "heartbeat")]
[JsonDerivedType(typeof(AgentJobAccepted), "job_accepted")]
[JsonDerivedType(typeof(AgentJobResult), "job_result")]
public abstract record AgentMessage;

public sealed record AgentHello : AgentMessage
{
    public required string DeviceId { get; init; }
    public required string Hostname { get; init; }
    public required string OsVersion { get; init; }
    public required string AgentVersion { get; init; }
    public required string Signature { get; init; }
}

public sealed record AgentHeartbeat : AgentMessage
{
    public required long SentAtUnixMs { get; init; }
}

public sealed record AgentJobAccepted : AgentMessage
{
    public required string JobId { get; init; }
}

public sealed record AgentJobResult : AgentMessage
{
    public required JobResult Result { get; init; }
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(ServerJobDispatch), "job_dispatch")]
[JsonDerivedType(typeof(ServerHelloAck), "hello_ack")]
[JsonDerivedType(typeof(ServerChallenge), "challenge")]
public abstract record ServerMessage;

public sealed record ServerChallenge : ServerMessage
{
    public required string Nonce { get; init; }
}

public sealed record ServerHelloAck : ServerMessage
{
    public required string DeviceId { get; init; }
    public required int HeartbeatIntervalSeconds { get; init; }
}

public sealed record ServerJobDispatch : ServerMessage
{
    public required JobSpec Job { get; init; }
}

