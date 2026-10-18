using System.Text.Json;
using System.Text.Json.Nodes;

namespace VeriSec.Tests.Support;

/// <summary>A real 1x1 PNG (the test server checks image signatures), on disk and in memory, and the spec.</summary>
public static class Assets
{
    public const string PngBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

    public static readonly byte[] Png = Convert.FromBase64String(PngBase64);

    /// <summary>The repository root (the folder holding spec/ and test-server/).</summary>
    public static string RepoRoot { get; } = FindRepoRoot();

    private static readonly Lazy<string> TempDir = new(() => Directory.CreateTempSubdirectory("verisec-dotnet-").FullName);
    private static readonly Lazy<string> Photo = new(() => Write("photo.png", Png));
    private static readonly Lazy<JsonNode> SpecDocument = new(() => JsonNode.Parse(File.ReadAllText(Path.Combine(RepoRoot, "spec", "openapi.json")))!);

    /// <summary>A PNG file on disk.</summary>
    public static string PngPath => Photo.Value;

    /// <summary>A file of these bytes in this run's temporary folder.</summary>
    public static string Write(string name, byte[] bytes)
    {
        var path = Path.Combine(TempDir.Value, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    /// <summary>A JSON value, for the fields that take any JSON.</summary>
    public static JsonElement Json(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    /// <summary>The <c>dotnet/</c> folder.</summary>
    public static string DotnetRoot => Path.Combine(RepoRoot, "dotnet");

    public static JsonNode Spec => SpecDocument.Value;

    /// <summary>An operation of the spec by its operationId: its path, method and definition.</summary>
    public static (string Path, string Method, JsonObject Operation) Operation(string operationId)
    {
        foreach (var (path, item) in Spec["paths"]!.AsObject())
        {
            foreach (var (method, op) in item!.AsObject())
            {
                if (op?["operationId"]?.GetValue<string>() == operationId) return (path, method, op.AsObject());
            }
        }
        throw new KeyNotFoundException($"No operation {operationId} in the spec.");
    }

    /// <summary>Every operation of the spec.</summary>
    public static IEnumerable<(string Path, string Method, JsonObject Operation)> Operations()
    {
        foreach (var (path, item) in Spec["paths"]!.AsObject())
        {
            foreach (var (method, op) in item!.AsObject()) yield return (path, method, op!.AsObject());
        }
    }

    /// <summary>What a successful call of the operation returns: the example's <c>data</c> (KYC) or the example itself (Financial).</summary>
    public static JsonNode? ExpectedResult(JsonObject operation)
    {
        var example = operation["responses"]!["200"]!["content"]!["application/json"]!["example"];
        return operation["x-verisec-envelope"]?.GetValue<string>() == "data" ? example!["data"] : example;
    }

    private static string FindRepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "spec", "openapi.json")) && File.Exists(Path.Combine(dir.FullName, "test-server", "server.mjs")))
            {
                return dir.FullName;
            }
        }
        throw new DirectoryNotFoundException("The repository root (spec/openapi.json, test-server/server.mjs) is not above the test assembly.");
    }
}

/// <summary>JSON comparison for typed results: a field set to null and a field left out are the same.</summary>
public static class JsonAssert
{
    public static void Equivalent(JsonNode? expected, JsonNode? actual, string label = "")
    {
        var difference = Difference(Normalize(expected), Normalize(actual), "$");
        if (difference is not null)
        {
            Assert.Fail($"{label} JSON differs at {difference}\nexpected: {Trim(expected?.ToJsonString())}\nactual:   {Trim(actual?.ToJsonString())}");
        }
    }

    public static JsonNode? Of(object? value) => value is null ? null : JsonSerializer.SerializeToNode(value, value.GetType(), VeriSec.Core.Json.Options);

    private static string? Trim(string? text) => text is null || text.Length < 1500 ? text : text[..1500] + "…";

    private static JsonNode? Normalize(JsonNode? node) => node switch
    {
        null => null,
        JsonObject obj => new JsonObject(obj.Where(p => p.Value is not null && p.Value.GetValueKind() != JsonValueKind.Null)
            .Select(p => KeyValuePair.Create(p.Key, Normalize(p.Value)))),
        JsonArray array => new JsonArray(array.Select(Normalize).ToArray()),
        _ => node.GetValueKind() == JsonValueKind.Null ? null : node.DeepClone(),
    };

    private static string? Difference(JsonNode? a, JsonNode? b, string at)
    {
        if (a is null || b is null) return a is null && b is null ? null : $"{at} ({(a is null ? "expected null" : "actual null")})";
        if (a.GetValueKind() != b.GetValueKind()) return $"{at} ({a.GetValueKind()} vs {b.GetValueKind()})";
        switch (a)
        {
            case JsonObject x:
            {
                var y = (JsonObject)b;
                foreach (var key in x.Select(p => p.Key).Union(y.Select(p => p.Key)))
                {
                    if (!x.ContainsKey(key) || !y.ContainsKey(key)) return $"{at}.{key} ({(x.ContainsKey(key) ? "missing" : "unexpected")})";
                    if (Difference(x[key], y[key], $"{at}.{key}") is { } inner) return inner;
                }
                return null;
            }
            case JsonArray x:
            {
                var y = (JsonArray)b;
                if (x.Count != y.Count) return $"{at} ({x.Count} vs {y.Count} items)";
                for (var i = 0; i < x.Count; i++)
                {
                    if (Difference(x[i], y[i], $"{at}[{i}]") is { } inner) return inner;
                }
                return null;
            }
            default:
                return a.GetValueKind() switch
                {
                    JsonValueKind.Number => a.GetValue<double>().Equals(b.GetValue<double>()) ? null : $"{at} ({a} vs {b})",
                    JsonValueKind.String => a.GetValue<string>() == b.GetValue<string>() ? null : $"{at} (\"{a}\" vs \"{b}\")",
                    _ => a.ToJsonString() == b.ToJsonString() ? null : $"{at} ({a} vs {b})",
                };
        }
    }
}
