using System.Diagnostics;
using VeriSec.Tests.Support;

namespace VeriSec.Tests.Integration;

/// <summary><c>examples/Quickstart</c> as a developer runs it, against the test server.</summary>
[Collection(ServerCollection.Name)]
public sealed class QuickstartTests(TestServer server) : IAsyncLifetime
{
    public Task InitializeAsync() => server.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task The_quickstart_parses_an_MRZ_looks_up_a_BIN_and_compares_two_photos()
    {
        // the tests run from bin/<Configuration>/net8.0; the example is built next to them, in the same configuration
        var configuration = Path.GetFileName(Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)))!;
        var program = Path.Combine(Assets.DotnetRoot, "examples", "Quickstart", "bin", configuration, "net8.0", "Quickstart.dll");
        Assert.True(File.Exists(program), $"{program} was not built");
        var second = Assets.Write("id-photo.png", Assets.Png);

        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            ArgumentList = { program, Assets.PngPath, second },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.Environment["VERISEC_API_KEY"] = "sk_test_dotnet_quickstart";
        start.Environment["VERISEC_BASE_URL"] = server.BaseUrl;
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(60));

        Assert.True(process.ExitCode == 0, $"exit {process.ExitCode}: {await output}{await errors}");
        var text = await output;
        Assert.Contains("MRZ: ", text);
        Assert.Contains("BIN: ", text);
        Assert.Contains("Same person: ", text);
        var paths = (await server.RequestsAsync()).Select(r => r.GetProperty("path").GetString());
        Assert.Equal(new[] { "/v1/mrz/parse", "/v2/bin/424242", "/v1/face/verify" }, paths);
    }
}
