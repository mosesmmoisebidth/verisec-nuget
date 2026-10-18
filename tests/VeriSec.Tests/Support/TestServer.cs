using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VeriSec.Tests.Support;

/// <summary>
/// The shared test server (<c>test-server/server.mjs</c>) on this SDK's port, 4024: started once for every test in
/// the <see cref="ServerCollection"/> (<c>node ../test-server/server.mjs --port 4024</c>) and stopped after them.
/// Its <c>/__test/*</c> endpoints reset state, inject failures, show the request log and sign webhooks.
/// </summary>
public sealed class TestServer : IAsyncLifetime
{
    public const int Port = 4024;
    public const string Key = "sk_test_dotnet_sdk";

    private readonly HttpClient _control = new() { Timeout = TimeSpan.FromSeconds(30) };
    private readonly StringBuilder _output = new();
    private Process? _process;

    public string BaseUrl { get; } = $"http://127.0.0.1:{Port}";

    public async Task InitializeAsync()
    {
        var script = Path.Combine(Assets.RepoRoot, "test-server", "server.mjs");
        var start = new ProcessStartInfo("node")
        {
            ArgumentList = { script, "--port", Port.ToString(CultureInfo.InvariantCulture) },
            WorkingDirectory = Assets.DotnetRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        var listening = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _process = new Process { StartInfo = start, EnableRaisingEvents = true };
        _process.OutputDataReceived += (_, e) => Collect(e.Data, listening);
        _process.ErrorDataReceived += (_, e) => Collect(e.Data, listening);
        _process.Exited += (_, _) => listening.TrySetResult();
        try
        {
            _process.Start();
        }
        catch (System.ComponentModel.Win32Exception e)
        {
            throw new InvalidOperationException("Node.js is needed to run the shared test server: `node` was not found on PATH.", e);
        }
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();
        await listening.Task.WaitAsync(TimeSpan.FromSeconds(30));
        if (_process.HasExited)
        {
            throw new InvalidOperationException($"The test server did not start on port {Port}:\n{_output}");
        }
        await ResetAsync();
    }

    private void Collect(string? line, TaskCompletionSource listening)
    {
        if (line is null) return;
        lock (_output) _output.AppendLine(line);
        if (line.Contains("VeriSec test server on", StringComparison.Ordinal)) listening.TrySetResult();
    }

    public async Task DisposeAsync()
    {
        if (_process is { HasExited: false })
        {
            _process.Kill(entireProcessTree: true);
            await _process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        }
        _process?.Dispose();
        _control.Dispose();
    }

    /// <summary>A client for this server: a test key unless the options say otherwise.</summary>
    public VeriSecClient Client(VeriSecOptions? options = null)
    {
        options ??= new VeriSecOptions();
        options.ApiKey ??= Key;
        options.BaseUrl ??= BaseUrl;
        return new VeriSecClient(options);
    }

    /// <summary>Forgets requests, failures and tokens; <paramref name="tokenTtl"/> sets the lifetime of new tokens in seconds.</summary>
    public Task ResetAsync(int? tokenTtl = null) =>
        PostAsync("/__test/reset", tokenTtl is null ? new JsonObject() : new JsonObject { ["token_ttl"] = tokenTtl });

    /// <summary>The next <paramref name="count"/> calls to <paramref name="path"/> fail: <c>status</c>, <c>reset</c> or <c>hang</c>.</summary>
    public Task FailAsync(string path, int count = 1, int status = 503, int? retryAfter = null, string mode = "status")
    {
        var rule = new JsonObject { ["path"] = path, ["count"] = count, ["status"] = status, ["mode"] = mode };
        if (retryAfter is not null) rule["retry_after"] = retryAfter;
        return PostAsync("/__test/fail", rule);
    }

    /// <summary>What the server received since the last reset, oldest first.</summary>
    public async Task<List<JsonElement>> RequestsAsync()
    {
        var json = await _control.GetStringAsync($"{BaseUrl}/__test/requests");
        using var document = JsonDocument.Parse(json);
        return [.. document.RootElement.GetProperty("requests").EnumerateArray().Select(e => e.Clone())];
    }

    /// <summary>A delivery signed by the server as Standard Webhooks: <c>{secret, body, headers}</c>.</summary>
    public async Task<JsonElement> WebhookAsync(JsonObject? request = null)
    {
        var json = await PostAsync("/__test/webhook", request ?? new JsonObject());
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    /// <summary>
    /// The call answered as the spec's example says (KYC: the example's <c>data</c>, with its <c>latency_ms</c> and
    /// <c>warnings</c> in the response info; Financial: the example), and went to <paramref name="path"/> (with
    /// <paramref name="query"/>) with the test key, the SDK's user agent and, for uploads, <c>X-VeriSec-Source: sdk</c>.
    /// </summary>
    public async Task AssertAnsweredAsync(string operationId, ApiResult result, string path, bool upload, IReadOnlyDictionary<string, string>? query = null)
    {
        var (_, _, operation) = Assets.Operation(operationId);
        JsonAssert.Equivalent(Assets.ExpectedResult(operation), JsonAssert.Of(result), operationId);
        Assert.Equal(200, result.LastResponse.Status);
        Assert.StartsWith("req_", result.LastResponse.RequestId);
        if (operation["x-verisec-envelope"]?.GetValue<string>() == "data")
        {
            var example = operation["responses"]!["200"]!["content"]!["application/json"]!["example"]!;
            Assert.Equal(example["latency_ms"]?.GetValue<double>(), result.LastResponse.LatencyMs);
            Assert.Equal(example["warnings"]!.AsArray().Select(w => w!.GetValue<string>()), result.LastResponse.Warnings);
            Assert.Equal(result.LastResponse.RequestId, result.LastResponse.Headers["x-request-id"]);
        }

        var sent = (await RequestsAsync())[^1];
        Assert.Equal(path, sent.GetProperty("path").GetString());
        var sentQuery = sent.GetProperty("query").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString());
        Assert.Equal(query?.Count ?? 0, sentQuery.Count);
        foreach (var (name, value) in query ?? new Dictionary<string, string>()) Assert.Equal(value, sentQuery[name]);
        var headers = sent.GetProperty("headers");
        Assert.Equal($"Bearer {Key}"[..20], headers.GetProperty("authorization").GetString());
        Assert.Equal("verisec-dotnet/1.0.0", headers.GetProperty("user-agent").GetString());
        if (upload) Assert.Equal("sdk", headers.GetProperty("x-verisec-source").GetString());
        else Assert.False(headers.TryGetProperty("x-verisec-source", out _));
    }

    private async Task<string> PostAsync(string path, JsonNode body)
    {
        using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        using var response = await _control.PostAsync($"{BaseUrl}{path}", content);
        var text = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"{path} answered {(int)response.StatusCode}: {text}");
        return text;
    }
}

/// <summary>The tests that share the test server run one at a time, in this collection.</summary>
[CollectionDefinition(Name)]
public sealed class ServerCollection : ICollectionFixture<TestServer>
{
    public const string Name = "test server";
}

/// <summary>Tests that change process-wide state (environment variables) run alone.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class EnvironmentCollection
{
    public const string Name = "environment";
}
