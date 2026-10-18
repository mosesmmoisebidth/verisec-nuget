namespace VeriSec.Tests.Support;

/// <summary>Clients wired to a stub, with the waits between attempts recorded instead of slept.</summary>
public static class Clients
{
    public const string TestKey = "sk_test_core";

    public static VeriSecClient For(string baseUrl, VeriSecOptions? options = null, List<TimeSpan>? delays = null)
    {
        options ??= new VeriSecOptions();
        options.ApiKey ??= TestKey;
        options.BaseUrl ??= baseUrl;
        var client = new VeriSecClient(options);
        client.Transport.Delay = (delay, _) =>
        {
            if (delays is not null)
            {
                lock (delays) delays.Add(delay);
            }
            return Task.CompletedTask;
        };
        return client;
    }

    public static VeriSecClient For(StubServer stub, VeriSecOptions? options = null, List<TimeSpan>? delays = null) => For(stub.BaseUrl, options, delays);

    public static MrzParseParams Mrz(params string[] lines) => new() { Lines = lines.Length == 0 ? ["x"] : lines };
}
