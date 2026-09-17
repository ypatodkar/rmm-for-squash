namespace SquashRmm.Protocol;

public enum JobState
{
    Queued,
    Dispatched,
    Running,
    Completed,
    TimedOut,
    Unreachable,
    Failed
}

public static class JobStateExtensions
{
    public static bool IsTerminal(this JobState state) => state switch
    {
        JobState.Completed or JobState.TimedOut or JobState.Unreachable or JobState.Failed => true,
        _ => false
    };
}
