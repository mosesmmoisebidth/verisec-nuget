using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using VeriSec.Core;
using VeriSec.Tests.Support;

namespace VeriSec.Tests.Unit;

/// <summary>The generated surface against the spec: every operation a method, every schema a type, every example readable.</summary>
public sealed class ModelTests
{
    private static readonly Assembly Library = typeof(VeriSecClient).Assembly;

    private static string Pascal(string text) => string.Concat(text.Split('.', '-', '_').Where(p => p.Length > 0).Select(p => char.ToUpperInvariant(p[0]) + p[1..]));

    public static TheoryData<string> OperationIds()
    {
        var data = new TheoryData<string>();
        foreach (var (_, _, op) in Assets.Operations()) data.Add(op["operationId"]!.GetValue<string>());
        return data;
    }

    [Theory]
    [MemberData(nameof(OperationIds))]
    public void Every_operation_is_an_async_method_named_after_its_operationId(string operationId)
    {
        var (path, method, op) = Assets.Operation(operationId);
        var segments = operationId.Split('.');
        object target = new VeriSecClient(new VeriSecOptions { ApiKey = "sk_test_x", BaseUrl = "http://127.0.0.1:1" });
        foreach (var segment in segments[..^1])
        {
            var property = target.GetType().GetProperty(Pascal(segment)) ?? throw new Xunit.Sdk.XunitException($"No resource {Pascal(segment)} on {target.GetType().Name}");
            target = property.GetValue(target)!;
        }
        var call = target.GetType().GetMethod($"{Pascal(segments[^1])}Async") ?? throw new Xunit.Sdk.XunitException($"No method {Pascal(segments[^1])}Async on {target.GetType().Name}");

        var envelope = op["x-verisec-envelope"]!.GetValue<string>();
        var ok = op["responses"]!["200"]!["content"]!["application/json"]!["schema"]!["$ref"]!.GetValue<string>().Split('/')[^1];
        var answer = envelope == "data" ? Assets.Spec["components"]!["schemas"]![ok]!["properties"]!["data"]!["$ref"]!.GetValue<string>().Split('/')[^1] : ok;
        Assert.Equal($"Task`1[{answer}]", $"{call.ReturnType.Name}[{call.ReturnType.GetGenericArguments()[0].Name}]");
        Assert.True(typeof(ApiResult).IsAssignableFrom(call.ReturnType.GetGenericArguments()[0]));

        var parameters = call.GetParameters();
        Assert.Equal("cancellationToken", parameters[^1].Name);
        Assert.Equal(typeof(RequestOptions), parameters[^2].ParameterType);
        var paramsType = op["x-params-type"]?.GetValue<string>();
        if (op["requestBody"] is not null || path == "/v2/banks") Assert.Equal(paramsType, parameters[0].ParameterType.Name);
        if (path.Contains('{')) Assert.Equal(typeof(string), parameters[0].ParameterType);
        Assert.NotNull(method);
    }

    [Fact]
    public void Every_component_schema_is_a_type_and_the_open_answers_are_open()
    {
        var schemas = Assets.Spec["components"]!["schemas"]!.AsObject();
        foreach (var (name, _) in schemas)
        {
            Assert.True(Library.GetType($"VeriSec.{name}") is not null, $"no type for the schema {name}");
        }
        var open = Assets.Operations().Where(o => o.Operation["x-verisec-tier"]?.GetValue<string>() == "major").ToList();
        Assert.Equal(11, open.Count);
        foreach (var (_, _, op) in open)
        {
            var ok = op["responses"]!["200"]!["content"]!["application/json"]!["schema"]!["$ref"]!.GetValue<string>().Split('/')[^1];
            var data = schemas[ok]!["properties"]!["data"]!["$ref"]!.GetValue<string>().Split('/')[^1];
            Assert.True(typeof(OpenResult).IsAssignableFrom(Library.GetType($"VeriSec.{data}")), $"{data} should be an open result");
        }
    }

    [Theory]
    [MemberData(nameof(OperationIds))]
    public void Every_answer_example_reads_into_its_type_and_back_unchanged(string operationId)
    {
        var (_, _, op) = Assets.Operation(operationId);
        var expected = Assets.ExpectedResult(op);
        var ok = op["responses"]!["200"]!["content"]!["application/json"]!["schema"]!["$ref"]!.GetValue<string>().Split('/')[^1];
        var answer = op["x-verisec-envelope"]!.GetValue<string>() == "data"
            ? Assets.Spec["components"]!["schemas"]![ok]!["properties"]!["data"]!["$ref"]!.GetValue<string>().Split('/')[^1]
            : ok;
        var type = Library.GetType($"VeriSec.{answer}")!;

        var result = JsonSerializer.Deserialize(expected!.ToJsonString(), type, Json.Options);

        JsonAssert.Equivalent(expected, JsonAssert.Of(result), operationId);
        // the envelope types read the whole answer too
        if (op["x-verisec-envelope"]!.GetValue<string>() == "data")
        {
            var whole = op["responses"]!["200"]!["content"]!["application/json"]!["example"]!;
            JsonAssert.Equivalent(whole, JsonAssert.Of(JsonSerializer.Deserialize(whole.ToJsonString(), Library.GetType($"VeriSec.{ok}")!, Json.Options)), ok);
        }
    }

    [Fact]
    public void An_open_result_is_a_dictionary_of_the_fields_with_the_raw_JSON()
    {
        var result = JsonSerializer.Deserialize<DocumentRead>("""{"status":"ok","fields":[{"name":"surname","value":"ERIKSSON"}],"score":0.97,"nothing":null}""", Json.Options)!;

        Assert.IsAssignableFrom<IReadOnlyDictionary<string, JsonElement>>(result);
        Assert.Equal(new[] { "status", "fields", "score", "nothing" }, result.Keys);
        Assert.Equal(4, result.Count);
        Assert.Equal("ok", result["status"].GetString());
        Assert.True(result.TryGetValue("score", out var score));
        Assert.Equal(0.97, score.GetDouble());
        Assert.Equal(0.97, result.Get<double>("score"));
        Assert.Null(result.Get<string>("nothing"));
        Assert.Null(result.Get<string>("missing"));
        Assert.Equal("ERIKSSON", result.Get<List<Field>>("fields")![0].Value);
        Assert.Equal("ok", result.Deserialize<Summary>()!.Status);
        Assert.False(result.ContainsKey("missing"));
        Assert.Throws<KeyNotFoundException>(() => result["missing"]);
        Assert.Equal(JsonValueKind.Object, result.Raw.ValueKind);
        Assert.Equal("""{"status":"ok","fields":[{"name":"surname","value":"ERIKSSON"}],"score":0.97,"nothing":null}""", result.ToString());
        Assert.Equal(result.ToString(), JsonSerializer.Serialize(result, Json.Options));
        Assert.Equal(0, result.LastResponse.Status);
        Assert.Same(ResponseInfo.None, new DocumentRead().LastResponse);
        Assert.Empty(new DocumentRead());
    }

    [Fact]
    public void Answers_keep_fields_this_version_does_not_know()
    {
        var verify = JsonSerializer.Deserialize<FaceVerify>("""{"match":true,"similarity":0.9,"new_field":{"a":1}}""", Json.Options)!;

        Assert.True(verify.Match);
        Assert.Equal(1, verify.AdditionalProperties!["new_field"].GetProperty("a").GetInt32());
        Assert.Equal("""{"similarity":0.9,"match":true,"new_field":{"a":1}}""", verify.ToString());
    }

    [Fact]
    public void Map_and_string_schemas_are_types_too()
    {
        var zone = JsonSerializer.Deserialize<MicrZone>("""{"fields":[{"Routing":"021000021"}],"font":"E-13B","template":"us_business"}""", Json.Options)!;

        Assert.Equal("021000021", zone.Fields![0]["Routing"]);
        Assert.IsAssignableFrom<IDictionary<string, string>>(zone.Fields[0]);
        Assert.Equal(MicrTemplate.UsBusiness, zone.Template);
        Assert.Equal("partial", ScanStatus.Partial);
    }

    [Fact]
    public void The_version_is_1_0_0_everywhere()
    {
        Assert.Equal("1.0.0", VeriSecClient.Version);
        Assert.Equal("verisec-dotnet/1.0.0", HttpTransport.UserAgent);
        Assert.StartsWith("1.0.0", Library.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion);
        Assert.Equal(new Version(1, 0, 0, 0), Library.GetName().Version);
    }

    [Fact]
    public void Request_types_keep_the_wire_names_of_the_spec()
    {
        var json = JsonSerializer.Serialize(new PhoneLookupParams { Phone = "+15550100", FirstName = "Ann", DateOfBirth = "1990-01-01" }, Json.Options);
        Assert.Equal("""{"phone":"+15550100","first_name":"Ann","date_of_birth":"1990-01-01"}""", json);

        var names = typeof(FaceMatchParamsImage).GetProperties()
            .Select(p => p.GetCustomAttribute<System.Text.Json.Serialization.JsonPropertyNameAttribute>()?.Name)
            .Where(n => n is not null);
        Assert.Equal(new[] { "data", "index", "type", "detectAll", "livenessTransactionId" }, names);
    }

    private sealed class Field
    {
        [System.Text.Json.Serialization.JsonPropertyName("name")]
        public string? Name { get; init; }

        [System.Text.Json.Serialization.JsonPropertyName("value")]
        public string? Value { get; init; }
    }

    private sealed class Summary
    {
        [System.Text.Json.Serialization.JsonPropertyName("status")]
        public string? Status { get; init; }
    }

    [Fact]
    public void The_JSON_options_make_no_case_conversion()
    {
        Assert.Null(Json.Options.PropertyNamingPolicy);
        Assert.Null(Json.Options.DictionaryKeyPolicy);
        Assert.Equal(System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull, Json.Options.DefaultIgnoreCondition);
        var node = JsonNode.Parse("""{"detectAll":true,"image_front":"x"}""");
        Assert.Equal("""{"detectAll":true,"image_front":"x"}""", JsonSerializer.Serialize(node, Json.Options));
    }
}
