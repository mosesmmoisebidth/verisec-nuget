using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using VeriSec.Core;
using VeriSec.Tests.Support;

namespace VeriSec.Tests.Unit;

/// <summary>
/// The core against a stub on a real socket: headers, answers, errors, and the retry rules that keep a charged call
/// from running twice.
/// </summary>
public sealed class TransportTests
{
    [Fact]
    public async Task Sends_the_key_as_a_bearer_token_a_user_agent_and_the_body_exactly_as_given()
    {
        await using var stub = StubServer.Start(StubReply.Kyc(new { x = 1 }));
        using var client = Clients.For(stub);

        await client.Mrz.ParseAsync(new MrzParseParams { Lines = ["P<UTO", "L898902C3"] });

        var request = Assert.Single(stub.Requests);
        Assert.Equal("POST", request.Method);
        Assert.Equal("/v1/mrz/parse", request.Target);
        Assert.Equal("Bearer sk_test_core", request.Header("Authorization"));
        Assert.Equal("verisec-dotnet/1.0.0", request.Header("User-Agent"));
        Assert.Equal("application/json", request.Header("Accept"));
        Assert.StartsWith("application/json", request.Header("Content-Type"));
        Assert.Null(request.Header("Idempotency-Key"));
        Assert.Null(request.Header("VeriSec-Version"));
        Assert.Equal("""{"lines":["P<UTO","L898902C3"]}""", request.Text);
    }

    [Fact]
    public async Task Field_names_go_on_the_wire_as_the_spec_spells_them_and_unset_fields_are_left_out()
    {
        await using var stub = StubServer.Start(StubReply.Kyc(new { }));
        using var client = Clients.For(stub);

        await client.Documents.ReadAsync(new DocumentReadParams
        {
            ImageFront = Image.FromBytes(Assets.Png),
            DocHint = new DocumentReadParamsDocHint { Country = "ZA" },
        });
        await client.Face.MatchAsync(new FaceMatchParams
        {
            Images = [new FaceMatchParamsImage { Data = Image.FromBytes(Assets.Png), DetectAll = false, LivenessTransactionId = "lt_1" }, Image.FromBytes(Assets.Png)],
        });

        Assert.Equal("""{"image_front":"__","doc_hint":{"country":"ZA"}}""".Replace("__", Assets.PngBase64), stub.Requests[0].Text);
        var images = stub.Requests[1].Json.GetProperty("images");
        Assert.False(images[0].GetProperty("detectAll").GetBoolean());
        Assert.Equal("lt_1", images[0].GetProperty("livenessTransactionId").GetString());
        Assert.Equal(new[] { "data", "detectAll", "livenessTransactionId", "index" }, images[0].EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public async Task A_KYC_answer_returns_the_envelope_data_with_the_request_id_warnings_and_latency()
    {
        await using var stub = StubServer.Start(StubReply.Kyc(new { match = true, similarity = 0.98 }, warnings: ["low light"]));
        using var client = Clients.For(stub);

        var result = await client.Face.VerifyAsync(new FaceVerifyParams { Image1 = Image.FromPath(Assets.PngPath), Image2 = Image.FromBytes(Assets.Png) });

        Assert.True(result.Match);
        Assert.Equal(0.98, result.Similarity);
        JsonAssert.Equivalent(JsonAssert.Of(new { match = true, similarity = 0.98 }), JsonAssert.Of(result));
        Assert.Equal(200, result.LastResponse.Status);
        Assert.Equal("req_abc", result.LastResponse.RequestId);
        Assert.Equal(new[] { "low light" }, result.LastResponse.Warnings);
        Assert.Equal(12, result.LastResponse.LatencyMs);
        Assert.Equal("application/json", result.LastResponse.Headers["content-type"]);
    }

    [Fact]
    public async Task A_Financial_answer_is_the_object_as_it_is_with_the_request_id_from_the_header()
    {
        await using var stub = StubServer.Start(StubReply.Json(
            new { @object = "card_check", luhn_valid = true, brand_new_field = "kept" },
            headers: new Dictionary<string, string> { ["X-Request-Id"] = "req_fin" }));
        using var client = Clients.For(stub);

        var result = await client.Cards.CheckAsync(new CardCheckParams { Number = "4242 4242 4242 4242" });

        Assert.Equal("card_check", result.Object);
        Assert.True(result.LuhnValid);
        Assert.Equal("kept", result.AdditionalProperties!["brand_new_field"].GetString());
        JsonAssert.Equivalent(JsonAssert.Of(new { @object = "card_check", luhn_valid = true, brand_new_field = "kept" }), JsonAssert.Of(result));
        Assert.Equal("req_fin", result.LastResponse.RequestId);
        Assert.Empty(result.LastResponse.Warnings);
        Assert.Null(result.LastResponse.LatencyMs);
        Assert.Equal("""{"number":"4242 4242 4242 4242"}""", Assert.Single(stub.Requests).Text);
    }

    public static TheoryData<int, Type, string, string?, string?, string?, string?> Errors => new()
    {
        // status, class, body, code, message, param, request id
        { 400, typeof(InvalidRequestException), """{"ok":false,"request_id":"req_err","error":{"code":"invalid_input","message":"image1 is required.","param":"image1"},"warnings":[],"data":null}""", "invalid_input", "image1 is required.", "image1", "req_err" },
        { 401, typeof(AuthenticationException), """{"ok":false,"request_id":"req_401","error":{"code":"missing_key","message":"Send your API key."}}""", "missing_key", "Send your API key.", null, "req_401" },
        { 402, typeof(InsufficientCreditsException), """{"ok":false,"request_id":"req_402","error":{"code":"insufficient_credits","message":"Not enough credits."}}""", "insufficient_credits", "Not enough credits.", null, "req_402" },
        { 403, typeof(PermissionException), """{"ok":false,"error":{"code":"forbidden","message":"Not allowed."}}""", "forbidden", "Not allowed.", null, "req_hdr" },
        { 404, typeof(NotFoundException), """{"error_msg":"404 Route Not Found"}""", null, "404 Route Not Found", null, "req_hdr" },
        { 409, typeof(InvalidRequestException), """{"error":{"code":"conflict","message":"Busy."}}""", "conflict", "Busy.", null, "req_hdr" },
        { 413, typeof(InvalidRequestException), """{"error":{"code":"image_too_large","message":"Too large.","param":"image"}}""", "image_too_large", "Too large.", "image", "req_hdr" },
        { 415, typeof(InvalidRequestException), """{"error":"Not an image.","code":"unsupported_image"}""", "unsupported_image", "Not an image.", null, "req_hdr" },
        { 422, typeof(InvalidRequestException), """{"detail":[{"loc":["body","images",0,"data"],"msg":"field required","type":"missing"}]}""", "invalid_input", "field required", "images.0.data", "req_hdr" },
        { 422, typeof(InvalidRequestException), """{"detail":"lines must be a list"}""", "invalid_input", "lines must be a list", null, "req_hdr" },
        { 500, typeof(ApiServerException), "upstream exploded", null, "upstream exploded", null, "req_hdr" },
        { 502, typeof(ApiServerException), """{"ok":false,"request_id":"req_502","error":{"code":"engine_error","message":"The check could not run."}}""", "engine_error", "The check could not run.", null, "req_502" },
        { 503, typeof(ApiServerException), "", null, "VeriSec API request failed with status 503.", null, "req_hdr" },
    };

    [Theory]
    [MemberData(nameof(Errors))]
    public async Task Every_error_status_maps_to_its_class_with_code_message_param_and_request_id(int status, Type type, string body, string? code, string? message, string? param, string? requestId)
    {
        var header = new Dictionary<string, string> { ["X-Request-Id"] = "req_hdr" };
        await using var stub = StubServer.Start(body.StartsWith('{') ? StubReply.Json(body, status, header) : StubReply.Text(body, status, headers: header));
        using var client = Clients.For(stub, new VeriSecOptions { MaxRetries = 0 });

        var e = await Assert.ThrowsAnyAsync<ApiException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        Assert.IsType(type, e);
        Assert.IsAssignableFrom<VeriSecException>(e);
        Assert.Equal(status, e.Status);
        Assert.Equal(code, e.Code);
        Assert.Equal(message, e.Message);
        Assert.Equal(param, e.Param);
        Assert.Equal(requestId, e.RequestId);
        Assert.Equal("req_hdr", e.Headers["x-request-id"]);
    }

    [Fact]
    public async Task A_2xx_KYC_answer_with_ok_false_is_raised_not_returned()
    {
        await using var stub = StubServer.Start(StubReply.Json(new { ok = false, request_id = "req_nf", error = new { code = "no_face", message = "No face found." }, data = (object?)null }));
        using var client = Clients.For(stub);

        var e = await Assert.ThrowsAsync<InvalidRequestException>(() => client.Face.DetectAsync(new FaceDetectParams { Image = Image.FromBytes(Assets.Png) }));

        Assert.Equal("no_face", e.Code);
        Assert.Equal("No face found.", e.Message);
        Assert.Equal("req_nf", e.RequestId);
        Assert.Equal(200, e.Status);
    }

    [Fact]
    public async Task A_429_is_retried_after_its_Retry_After_then_succeeds()
    {
        await using var stub = StubServer.Start((_, n) => n == 1
            ? StubReply.Error(429, "rate_limited", "Slow down.", headers: new Dictionary<string, string> { ["Retry-After"] = "0" })
            : StubReply.Kyc(new { valid = true }));
        var delays = new List<TimeSpan>();
        using var client = Clients.For(stub, delays: delays);

        var result = await client.Mrz.ParseAsync(Clients.Mrz());

        Assert.True(result.Valid);
        Assert.Equal(2, stub.Requests.Count);
        Assert.Equal(new[] { TimeSpan.Zero }, delays);
    }

    [Fact]
    public async Task A_5xx_is_retried_up_to_MaxRetries_with_backoff_then_thrown()
    {
        await using var stub = StubServer.Start(StubReply.Error(503, "unavailable", "Try later."));
        var delays = new List<TimeSpan>();
        using var client = Clients.For(stub, new VeriSecOptions { MaxRetries = 2 }, delays);

        var e = await Assert.ThrowsAsync<ApiServerException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        Assert.Equal(503, e.Status);
        Assert.Equal(3, stub.Requests.Count);
        Assert.Equal(2, delays.Count);
        Assert.InRange(delays[0].TotalSeconds, 0.375, 0.625); // 0.5 s ±25%
        Assert.InRange(delays[1].TotalSeconds, 0.75, 1.25); // 1 s ±25%
    }

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(402)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(422)]
    public async Task A_4xx_is_never_retried(int status)
    {
        await using var stub = StubServer.Start(StubReply.Error(status, "nope", "No."));
        using var client = Clients.For(stub, new VeriSecOptions { MaxRetries = 5 });

        await Assert.ThrowsAnyAsync<ApiException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        Assert.Single(stub.Requests);
    }

    [Fact]
    public async Task A_connection_that_never_opened_is_retried()
    {
        var delays = new List<TimeSpan>();
        // (on Windows a refused local connect takes about 2 s: the stack retries the SYN)
        using var client = Clients.For(StubServer.ClosedUrl(), new VeriSecOptions { MaxRetries = 1 }, delays);

        var e = await Assert.ThrowsAsync<ApiConnectionException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        Assert.IsNotType<ApiTimeoutException>(e);
        Assert.Single(delays); // 2 attempts
        Assert.Contains("Could not reach", e.Message);
        Assert.Contains("2 attempts", e.Message);
    }

    [Fact]
    public async Task A_name_that_does_not_resolve_is_retried()
    {
        var delays = new List<TimeSpan>();
        using var client = Clients.For("http://verisec-sdk-test.invalid", new VeriSecOptions { MaxRetries = 1 }, delays);

        var e = await Assert.ThrowsAsync<ApiConnectionException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        Assert.Single(delays);
        Assert.Contains("Could not reach", e.Message);
    }

    [Fact]
    public async Task A_connect_that_takes_too_long_counts_as_never_opened_and_is_retried()
    {
        var delays = new List<TimeSpan>();
        // 10.255.255.1 is not routed: the connect never completes (or fails at once on some networks)
        using var client = Clients.For("http://10.255.255.1:81", new VeriSecOptions { MaxRetries = 1, Timeout = TimeSpan.FromSeconds(30) }, delays);
        client.Transport.ConnectTimeout = TimeSpan.FromMilliseconds(300);
        var watch = Stopwatch.StartNew();

        var e = await Assert.ThrowsAsync<ApiConnectionException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        Assert.IsNotType<ApiTimeoutException>(e);
        Assert.Single(delays);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(20), $"took {watch.Elapsed}");
    }

    [Theory]
    [InlineData("drop")]
    [InlineData("reset")]
    public async Task A_connection_lost_after_the_request_was_sent_is_NOT_retried(string how)
    {
        await using var stub = StubServer.Start(how == "drop" ? StubReply.Drop : StubReply.Reset);
        var delays = new List<TimeSpan>();
        using var client = Clients.For(stub, new VeriSecOptions { MaxRetries = 3 }, delays);

        var e = await Assert.ThrowsAsync<ApiConnectionException>(() => client.Face.DetectAsync(new FaceDetectParams { Image = Image.FromBytes(Assets.Png) }));

        Assert.IsNotType<ApiTimeoutException>(e);
        Assert.Single(stub.Requests); // the call may have run and been charged: one request only
        Assert.Empty(delays);
        Assert.Contains("may have run", e.Message);
    }

    [Fact]
    public async Task A_connection_lost_on_a_reused_connection_is_NOT_retried_either()
    {
        await using var stub = StubServer.Start((_, n) => n == 1 ? StubReply.Kyc(new { }) : StubReply.Drop);
        using var client = Clients.For(stub, new VeriSecOptions { MaxRetries = 3 });

        await client.Mrz.ParseAsync(Clients.Mrz());
        await Task.Delay(100);
        await Assert.ThrowsAsync<ApiConnectionException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        Assert.Equal(2, stub.Requests.Count);
    }

    [Fact]
    public async Task A_timeout_is_NOT_retried_and_says_the_call_may_have_run()
    {
        await using var stub = StubServer.Start(StubReply.Hang);
        var delays = new List<TimeSpan>();
        using var client = Clients.For(stub, new VeriSecOptions { Timeout = TimeSpan.FromMilliseconds(300), MaxRetries = 3 }, delays);

        var e = await Assert.ThrowsAsync<ApiTimeoutException>(() => client.Face.DetectAsync(new FaceDetectParams { Image = Image.FromBytes(Assets.Png) }));

        Assert.Contains("may still have run", e.Message);
        Assert.Single(stub.Requests);
        Assert.Empty(delays);
        Assert.IsAssignableFrom<ApiConnectionException>(e);
    }

    [Fact]
    public async Task A_per_call_timeout_overrides_the_client_timeout()
    {
        await using var stub = StubServer.Start(StubReply.Hang);
        using var client = Clients.For(stub);
        var watch = Stopwatch.StartNew();

        await Assert.ThrowsAsync<ApiTimeoutException>(() => client.Mrz.ParseAsync(Clients.Mrz(), new RequestOptions { Timeout = TimeSpan.FromMilliseconds(200) }));

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task Cancelling_a_call_throws_OperationCanceledException_and_is_never_retried()
    {
        await using var stub = StubServer.Start(StubReply.Hang);
        using var client = Clients.For(stub, new VeriSecOptions { MaxRetries = 3 });
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        var e = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.Mrz.ParseAsync(Clients.Mrz(), cancellationToken: cancel.Token));

        Assert.IsNotType<ApiTimeoutException>(e);
        Assert.Single(stub.Requests);
    }

    [Fact]
    public async Task Per_call_options_set_headers_and_retries()
    {
        await using var stub = StubServer.Start(StubReply.Error(503, "unavailable", "Try later."));
        using var client = Clients.For(stub, new VeriSecOptions
        {
            DefaultHeaders = new Dictionary<string, string> { ["X-Team"] = "kyc", ["X-Trace"] = "client" },
        });

        await Assert.ThrowsAsync<ApiServerException>(() => client.Mrz.ParseAsync(Clients.Mrz(), new RequestOptions
        {
            MaxRetries = 0,
            Headers = new Dictionary<string, string> { ["X-Trace"] = "call-7" },
        }));

        var request = Assert.Single(stub.Requests);
        Assert.Equal("kyc", request.Header("X-Team"));
        Assert.Equal("call-7", request.Header("X-Trace"));
    }

    [Fact]
    public async Task RateLimitException_exposes_Retry_After()
    {
        await using var stub = StubServer.Start(StubReply.Error(429, "rate_limited", "Slow down.", headers: new Dictionary<string, string> { ["Retry-After"] = "7" }));
        using var client = Clients.For(stub, new VeriSecOptions { MaxRetries = 0 });

        var e = await Assert.ThrowsAsync<RateLimitException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        Assert.Equal(TimeSpan.FromSeconds(7), e.RetryAfter);
        Assert.Equal("rate_limited", e.Code);
        Assert.Equal(429, e.Status);
    }

    [Fact]
    public async Task Retry_After_is_obeyed_up_to_60_seconds()
    {
        await using var stub = StubServer.Start((_, n) => n == 1
            ? StubReply.Error(429, "rate_limited", "Slow down.", headers: new Dictionary<string, string> { ["Retry-After"] = "120" })
            : StubReply.Kyc(new { }));
        var delays = new List<TimeSpan>();
        using var client = Clients.For(stub, delays: delays);

        await client.Mrz.ParseAsync(Clients.Mrz());

        Assert.Equal(new[] { TimeSpan.FromSeconds(60) }, delays);
    }

    [Fact]
    public void The_backoff_is_half_a_second_doubling_to_8_seconds_with_25_percent_jitter()
    {
        var now = new DateTimeOffset(2026, 10, 17, 10, 0, 0, TimeSpan.Zero); // whole seconds: an HTTP date has no fractions
        Assert.Equal(TimeSpan.FromSeconds(0.375), RetryPolicy.Delay(0, null, 0, now));
        Assert.Equal(TimeSpan.FromSeconds(0.625), RetryPolicy.Delay(0, null, 1, now));
        Assert.Equal(TimeSpan.FromSeconds(1), RetryPolicy.Delay(1, null, 0.5, now));
        Assert.Equal(TimeSpan.FromSeconds(2), RetryPolicy.Delay(2, null, 0.5, now));
        Assert.Equal(TimeSpan.FromSeconds(8), RetryPolicy.Delay(5, null, 0.5, now));
        Assert.Equal(TimeSpan.FromSeconds(8), RetryPolicy.Delay(10, null, 0.5, now));
        Assert.Equal(TimeSpan.FromSeconds(3), RetryPolicy.Delay(0, "3", 0.9, now));
        Assert.Equal(TimeSpan.FromSeconds(30), RetryPolicy.Delay(0, now.AddSeconds(30).ToString("r"), 0.9, now));
        Assert.Equal(TimeSpan.Zero, RetryPolicy.Delay(0, now.AddSeconds(-30).ToString("r"), 0.9, now));
        Assert.Equal(TimeSpan.FromSeconds(0.5), RetryPolicy.Delay(0, "soon", 0.5, now));
    }

    [Fact]
    public void Only_failures_before_the_request_left_count_as_never_sent()
    {
        Assert.True(RetryPolicy.NeverSent(new HttpRequestException(HttpRequestError.ConnectionError, "refused")));
        Assert.True(RetryPolicy.NeverSent(new HttpRequestException(HttpRequestError.NameResolutionError, "no such host")));
        Assert.True(RetryPolicy.NeverSent(new HttpRequestException("x", new SocketException((int)SocketError.ConnectionRefused))));
        Assert.True(RetryPolicy.NeverSent(new HttpRequestException("x", new SocketException((int)SocketError.HostUnreachable))));
        Assert.True(RetryPolicy.NeverSent(new HttpRequestException("x", new SocketException((int)SocketError.NetworkUnreachable))));
        Assert.False(RetryPolicy.NeverSent(new HttpRequestException("x", new IOException("reset", new SocketException((int)SocketError.ConnectionReset)))));
        Assert.False(RetryPolicy.NeverSent(new HttpRequestException(HttpRequestError.ResponseEnded, "ended")));
        Assert.False(RetryPolicy.NeverSent(new HttpRequestException(HttpRequestError.SecureConnectionError, "tls")));
        Assert.False(RetryPolicy.NeverSent(new IOException("broken pipe")));
    }

    [Fact]
    public async Task An_answer_that_is_not_JSON_fails_with_the_status_and_request_id()
    {
        await using var stub = StubServer.Start(StubReply.Json("<html>oops</html>", 200, new Dictionary<string, string> { ["X-Request-Id"] = "req_html" }));
        using var client = Clients.For(stub);

        var e = await Assert.ThrowsAsync<VeriSecException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        Assert.Contains("req_html", e.Message);
        Assert.Contains("succeeded", e.Message);
    }

    [Fact]
    public async Task A_KYC_answer_without_data_is_an_empty_result_with_its_response_info()
    {
        await using var stub = StubServer.Start(StubReply.Json(new { ok = true, request_id = "req_empty", data = (object?)null }));
        using var client = Clients.For(stub);

        var result = await client.Phone.Otp.SendAsync(new PhoneOtpSendParams { Phone = "+15550100" });

        Assert.Null(result.Status);
        Assert.Equal("req_empty", result.LastResponse.RequestId);
    }

    [Fact]
    public void The_client_validates_its_settings()
    {
        Assert.Throws<VeriSecException>(() => new VeriSecClient(new VeriSecOptions { ApiKey = "sk_test_x", BaseUrl = "not a url" }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new VeriSecClient(new VeriSecOptions { ApiKey = "sk_test_x", Timeout = TimeSpan.Zero }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new VeriSecClient(new VeriSecOptions { ApiKey = "sk_test_x", MaxRetries = -1 }));
        using var client = new VeriSecClient(new VeriSecOptions { ApiKey = "sk_test_x", BaseUrl = "http://127.0.0.1:1/" });
        Assert.Equal("http://127.0.0.1:1", client.BaseUrl);
        Assert.Equal(TimeSpan.FromSeconds(300), client.Timeout);
        Assert.Equal(2, client.MaxRetries);
    }

    [Fact]
    public async Task A_client_can_send_with_your_own_HttpClient()
    {
        await using var stub = StubServer.Start(StubReply.Kyc(new { valid = true }));
        using var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var client = new VeriSecClient(new VeriSecOptions { ApiKey = "sk_test_own", BaseUrl = stub.BaseUrl }, http);

        var result = await client.Mrz.ParseAsync(Clients.Mrz());

        Assert.True(result.Valid);
        Assert.Equal("Bearer sk_test_own", Assert.Single(stub.Requests).Header("Authorization"));
    }
}
