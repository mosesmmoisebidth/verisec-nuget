using System.Text.Json;
using System.Text.Json.Nodes;
using VeriSec.Tests.Support;

namespace VeriSec.Tests.Integration;

/// <summary>Against the shared test server: injected failures, keys, live OAuth, what the server sees, a signed webhook.</summary>
[Collection(ServerCollection.Name)]
public sealed class ServerTests(TestServer server) : IAsyncLifetime
{
    private static readonly MrzParseParams Mrz = new() { Lines = ["P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"] };

    public Task InitializeAsync() => server.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Two_injected_503s_are_retried_then_the_answer_comes_back()
    {
        await server.FailAsync("/v1/mrz/parse", count: 2, status: 503);
        using var client = server.Client();

        var result = await client.Mrz.ParseAsync(Mrz);

        Assert.True(result.Valid);
        Assert.Equal(3, (await server.RequestsAsync()).Count);
    }

    [Fact]
    public async Task A_429_with_Retry_After_is_retried()
    {
        await server.FailAsync("/v2/cards/check", count: 1, status: 429, retryAfter: 0);
        using var client = server.Client();

        var result = await client.Cards.CheckAsync(new CardCheckParams { Number = "4242 4242 4242 4242" });

        Assert.Equal("card_check", result.Object);
        Assert.Equal(2, (await server.RequestsAsync()).Count);
    }

    [Fact]
    public async Task A_429_left_after_the_retries_is_a_rate_limit_error_with_Retry_After()
    {
        await server.FailAsync("/v2/cards/check", count: 5, status: 429, retryAfter: 0);
        using var client = server.Client(new VeriSecOptions { MaxRetries = 1 });

        var e = await Assert.ThrowsAsync<RateLimitException>(() => client.Cards.CheckAsync(new CardCheckParams { Number = "4242 4242 4242 4242" }));

        Assert.Equal("rate_limited", e.Code);
        Assert.Equal(TimeSpan.Zero, e.RetryAfter);
        Assert.Equal(2, (await server.RequestsAsync()).Count);
    }

    [Fact]
    public async Task A_connection_dropped_after_the_request_is_not_sent_again()
    {
        await server.FailAsync("/v1/face/detect", count: 1, mode: "reset");
        using var client = server.Client(new VeriSecOptions { MaxRetries = 3 });

        var e = await Assert.ThrowsAsync<ApiConnectionException>(() => client.Face.DetectAsync(new FaceDetectParams { Image = Image.FromPath(Assets.PngPath) }));

        Assert.IsNotType<ApiTimeoutException>(e);
        Assert.Single(await server.RequestsAsync());
    }

    [Fact]
    public async Task A_call_that_never_gets_an_answer_times_out_and_is_not_sent_again()
    {
        await server.FailAsync("/v2/cheques/read", count: 1, mode: "hang");
        using var client = server.Client(new VeriSecOptions { Timeout = TimeSpan.FromMilliseconds(500), MaxRetries = 3 });

        await Assert.ThrowsAsync<ApiTimeoutException>(() => client.Cheques.ReadAsync(new ChequeReadParams { Image = FileInput.FromPath(Assets.PngPath) }));

        Assert.Single(await server.RequestsAsync());
    }

    [Fact]
    public async Task No_credits_a_revoked_key_and_a_forbidden_key_come_back_as_their_errors()
    {
        using var poor = server.Client(new VeriSecOptions { ApiKey = "sk_test_nocredits" });
        using var revoked = server.Client(new VeriSecOptions { ApiKey = "sk_test_revoked" });
        using var forbidden = server.Client(new VeriSecOptions { ApiKey = "sk_test_forbidden" });

        var credits = await Assert.ThrowsAsync<InsufficientCreditsException>(() => poor.Bin.LookupAsync("424242"));
        var auth = await Assert.ThrowsAsync<AuthenticationException>(() => revoked.Bin.LookupAsync("424242"));
        var permission = await Assert.ThrowsAsync<PermissionException>(() => forbidden.Face.VerifyAsync(new FaceVerifyParams { Image1 = Image.FromBytes(Assets.Png), Image2 = Image.FromBytes(Assets.Png) }));

        Assert.Equal((402, "insufficient_credits"), (credits.Status, credits.Code));
        Assert.Equal((401, "key_revoked"), (auth.Status, auth.Code));
        Assert.Equal((403, "forbidden"), (permission.Status, permission.Code));
        Assert.All(new ApiException[] { credits, auth, permission }, e => Assert.StartsWith("req_", e.RequestId));
        Assert.Equal(3, (await server.RequestsAsync()).Count); // none of them retried
    }

    [Fact]
    public async Task A_field_the_API_does_not_have_is_refused_with_its_name()
    {
        using var client = server.Client();

        var e = await Assert.ThrowsAsync<InvalidRequestException>(() => client.Mrz.ParseAsync(new MrzParseParams
        {
            Lines = ["x"],
            AdditionalProperties = new Dictionary<string, object?> { ["extra"] = true },
        }));

        Assert.Equal(400, e.Status);
        Assert.Equal("parameter_unknown", e.Code);
        Assert.Equal("extra", e.Param);
    }

    [Fact]
    public async Task Base64_that_is_not_an_image_is_refused_by_the_server_with_the_field()
    {
        using var client = server.Client();

        var e = await Assert.ThrowsAsync<InvalidRequestException>(() => client.Face.VerifyAsync(new FaceVerifyParams
        {
            Image1 = Image.FromBase64("bm90IGFuIGltYWdlIGF0IGFsbA=="),
            Image2 = Image.FromBytes(Assets.Png),
        }));

        Assert.Equal("image_unreadable", e.Code);
        Assert.Equal("image1", e.Param);
    }

    [Fact]
    public async Task An_upload_that_is_not_an_image_is_refused_with_415()
    {
        using var client = server.Client();

        var e = await Assert.ThrowsAsync<InvalidRequestException>(() => client.Cards.ReadAsync(new CardReadParams { Image = FileInput.FromBytes("not an image"u8.ToArray(), "card.txt") }));

        Assert.Equal(415, e.Status);
        Assert.Equal("unsupported_image", e.Code);
    }

    [Fact]
    public async Task A_route_the_gateway_does_not_know_is_a_not_found_error_with_its_message()
    {
        using var client = server.Client(new VeriSecOptions { BaseUrl = $"{server.BaseUrl}/nowhere" });

        var e = await Assert.ThrowsAsync<NotFoundException>(() => client.Bin.LookupAsync("424242"));

        Assert.Equal("404 Route Not Found", e.Message);
        Assert.Null(e.Code);
    }

    [Fact]
    public async Task The_server_sees_image_lists_with_the_index_and_ids_filled_in()
    {
        using var client = server.Client();

        await client.Face.MatchAsync(new FaceMatchParams { Images = [Image.FromPath(Assets.PngPath), Image.FromBytes(Assets.Png)] });
        await client.Face.ClusterAsync(new FaceClusterParams { Faces = [Image.FromBytes(Assets.Png), Image.FromPath(Assets.PngPath)], Threshold = 0.75 });

        var sent = await server.RequestsAsync();
        var images = sent[0].GetProperty("body").GetProperty("images");
        Assert.Equal(new[] { 0, 1 }, images.EnumerateArray().Select(i => i.GetProperty("index").GetInt32()));
        Assert.All(images.EnumerateArray(), i => Assert.Equal(Assets.PngBase64, i.GetProperty("data").GetString()));
        var faces = sent[1].GetProperty("body").GetProperty("faces");
        Assert.Equal(new[] { "face-1", "face-2" }, faces.EnumerateArray().Select(f => f.GetProperty("id").GetString()));
    }

    [Fact]
    public async Task A_live_key_works_through_one_token_exchange()
    {
        await server.ResetAsync(tokenTtl: 61);
        using var client = server.Client(new VeriSecOptions { ApiKey = "ak_live_dotnet", ClientId = "cli_dotnet", ClientSecret = "cs_dotnet" });
        var expected = Assets.ExpectedResult(Assets.Operation("bin.lookup").Operation)!["network"]!.GetValue<string>();

        Assert.Equal(expected, (await client.Bin.LookupAsync("424242")).Network);
        Assert.Equal(expected, (await client.Bin.LookupAsync("424242")).Network);
        Assert.Equal("card_check", (await client.Cards.CheckAsync(new CardCheckParams { Number = "4242 4242 4242 4242" })).Object);

        var sent = await server.RequestsAsync();
        var exchange = Assert.Single(sent, r => r.GetProperty("path").GetString() == "/v2/oauth/token");
        Assert.False(exchange.GetProperty("headers").TryGetProperty("authorization", out _));
        Assert.Equal("client_credentials", exchange.GetProperty("body").GetProperty("grant_type").GetString());
        Assert.Equal("ak_live_dotnet", exchange.GetProperty("body").GetProperty("api_key").GetString());
        Assert.Equal("cli_dotnet", exchange.GetProperty("body").GetProperty("client_id").GetString());
        Assert.StartsWith("Bearer at_live_", sent[^1].GetProperty("headers").GetProperty("authorization").GetString());
    }

    [Fact]
    public async Task A_live_token_that_expires_is_exchanged_again()
    {
        await server.ResetAsync(tokenTtl: 61); // kept for 1 s (renewed 60 s before it expires)
        using var client = server.Client(new VeriSecOptions { ApiKey = "ak_live_dotnet", ClientId = "cli_dotnet", ClientSecret = "cs_dotnet" });

        await client.Bin.LookupAsync("424242");
        await Task.Delay(TimeSpan.FromSeconds(1.2));
        await client.Bin.LookupAsync("424242");

        Assert.Equal(2, (await server.RequestsAsync()).Count(r => r.GetProperty("path").GetString() == "/v2/oauth/token"));
    }

    [Fact]
    public async Task A_wrong_client_secret_is_an_authentication_error()
    {
        using var client = server.Client(new VeriSecOptions { ApiKey = "ak_live_dotnet", ClientId = "cli_dotnet", ClientSecret = "cs_wrong" });

        var e = await Assert.ThrowsAsync<AuthenticationException>(() => client.Bin.LookupAsync("424242"));

        Assert.Equal("invalid_client", e.Code);
        Assert.Single(await server.RequestsAsync());
    }

    [Fact]
    public async Task A_delivery_signed_by_the_server_verifies()
    {
        var delivery = await server.WebhookAsync();
        var headers = delivery.GetProperty("headers").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);

        var evt = Webhooks.ConstructEvent(delivery.GetProperty("body").GetString()!, headers, delivery.GetProperty("secret").GetString()!);

        Assert.Equal("verification.completed", evt.Type);
        Assert.Equal("test", evt.Environment);
        Assert.Equal("approved", evt.Data.GetProperty("decision").GetString());
    }

    [Fact]
    public async Task A_delivery_with_your_own_secret_and_event_verifies_and_a_tampered_one_does_not()
    {
        var secret = $"whsec_{Convert.ToBase64String("dotnet-sdk-webhook-secret"u8.ToArray())}";
        var delivery = await server.WebhookAsync(new JsonObject
        {
            ["secret"] = secret,
            ["event"] = new JsonObject { ["type"] = "credits.low", ["timestamp"] = "2026-10-17T10:00:00Z", ["environment"] = "live", ["data"] = new JsonObject { ["balance"] = 3.5 } },
        });
        var headers = delivery.GetProperty("headers").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);
        var body = delivery.GetProperty("body").GetString()!;

        var evt = Webhooks.ConstructEvent(body, headers, secret);

        Assert.Equal("credits.low", evt.Type);
        Assert.Equal(3.5, evt.Data.GetProperty("balance").GetDouble());
        Assert.False(Webhooks.VerifySignature(body.Replace("3.5", "350"), headers, secret));
        Assert.False(Webhooks.VerifySignature(body, headers, $"whsec_{Convert.ToBase64String("another-secret"u8.ToArray())}"));
    }
}
