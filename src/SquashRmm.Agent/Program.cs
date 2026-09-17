using SquashRmm.Agent;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddSingleton<ScriptExecutor>();
builder.Services.AddSingleton<Enrollment>();
builder.Services.AddHostedService<AgentWorker>();

if (OperatingSystem.IsWindows())
{
    builder.Services.AddWindowsService(options => options.ServiceName = "SquashEndpoint");
}

var host = builder.Build();
host.Run();
