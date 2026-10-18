using VeriSec.Core;
using VeriSec.Tests.Support;

namespace VeriSec.Tests.Unit;

/// <summary>Test keys as bearer tokens; live keys through the OAuth exchange.</summary>
public sealed class AuthTests
{
    [Fact]
    public void A_live_key_without_client_credentials_is_refused_at_construction()
    {
        var e = Assert.Throws<VeriSecException>(() => new VeriSecClient(new VeriSecOptions { ApiKey = "ak_live_x", ClientId = "cli_only", BaseUrl = "http://127.0.0.1:1" }));

        Assert.Contains("ClientId and ClientSecret", e.Message);
    }

    [Fact]
    public async Task A_live_key_is_exchanged_once_for_concurrent_calls_cached_and_refreshed_once_on_a_401()
    {
        var issued = 0;
        await using var stub = StubServer.Start((request, _) =>
        {
            if (request.Path == "/v2/oauth/token")
            {
                var n = Interlocked.Increment(ref issued);
                Thread.Sleep(150); // a slow exchange: concurrent callers must wait for this one, not start their own
                return StubReply.Json(new { access_token = $"at_live_{n}", token_type = "Bearer", expires_in = 3600, scope = "api" });
            }
            var expired = request.Header("Authorization") == "Bearer at_live_1" && request.Text.Contains("expire");
            return expired ? StubReply.Error(401, "token_expired", "Expired.") : StubReply.Kyc(new { format = request.Header("Authorization") });
        });
        using var client = Clients.For(stub, new VeriSecOptions { ApiKey = "ak_live_abc", ClientId = "cli_1", ClientSecret = "cs_1" });

        var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => client.Mrz.ParseAsync(Clients.Mrz("x"))));

        Assert.All(results, r => Assert.Equal("Bearer at_live_1", r.Format));
        Assert.Equal(1, issued);
        var exchange = Assert.Single(stub.Requests, r => r.Path == "/v2/oauth/token");
        Assert.Equal("""{"grant_type":"client_credentials","api_key":"ak_live_abc","client_id":"cli_1","client_secret":"cs_1"}""", exchange.Text);
        Assert.Null(exchange.Header("Authorization"));
        Assert.Equal("POST", exchange.Method);

        var refreshed = await client.Mrz.ParseAsync(Clients.Mrz("expire"));
        Assert.Equal("Bearer at_live_2", refreshed.Format);
        Assert.Equal(2, issued);
        Assert.Equal(1 + 5 + 1 + 1 + 1, stub.Requests.Count); // exchange, 5 calls, the 401, the new exchange, the retried call
    }

    [Fact]
    public async Task A_401_with_a_fresh_token_is_thrown_after_one_refresh_and_not_counted_as_a_retry()
    {
        var issued = 0;
        await using var stub = StubServer.Start((request, _) => request.Path == "/v2/oauth/token"
            ? StubReply.Json(new { access_token = $"at_live_{Interlocked.Increment(ref issued)}", token_type = "Bearer", expires_in = 3600 })
            : StubReply.Error(401, "invalid_token", "No."));
        var delays = new List<TimeSpan>();
        using var client = Clients.For(stub, new VeriSecOptions { ApiKey = "ak_live_abc", ClientId = "cli_1", ClientSecret = "cs_1", MaxRetries = 0 }, delays);

        var e = await Assert.ThrowsAsync<AuthenticationException>(() => client.Bin.LookupAsync("424242"));

        Assert.Equal("invalid_token", e.Code);
        Assert.Equal(2, issued);
        Assert.Equal(2, stub.Requests.Count(r => r.Path == "/v2/bin/424242")); // the call, then once more with the fresh token
        Assert.Empty(delays);
    }

    [Fact]
    public async Task A_rejected_client_secret_is_an_authentication_error_and_the_exchange_is_not_retried()
    {
        await using var stub = StubServer.Start((request, _) => request.Path == "/v2/oauth/token"
            ? StubReply.Error(401, "invalid_client", "The client id or secret is not valid for this key.")
            : StubReply.Kyc(new { }));
        using var client = Clients.For(stub, new VeriSecOptions { ApiKey = "ak_live_abc", ClientId = "cli_1", ClientSecret = "cs_wrong" });

        var e = await Assert.ThrowsAsync<AuthenticationException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        Assert.Equal("invalid_client", e.Code);
        Assert.Single(stub.Requests); // the exchange only: no call went out without a token
    }

    [Fact]
    public async Task A_test_key_is_sent_as_it_is_and_a_401_is_not_retried()
    {
        await using var stub = StubServer.Start(StubReply.Error(401, "key_revoked", "This key was revoked."));
        using var client = Clients.For(stub, new VeriSecOptions { ApiKey = "sk_test_revoked" });

        await Assert.ThrowsAsync<AuthenticationException>(() => client.Mrz.ParseAsync(Clients.Mrz()));

        var request = Assert.Single(stub.Requests);
        Assert.Equal("Bearer sk_test_revoked", request.Header("Authorization"));
    }

    [Fact]
    public async Task The_token_is_kept_until_60_seconds_before_it_expires()
    {
        var clock = new ManualClock(DateTimeOffset.Parse("2026-10-17T10:00:00Z"));
        var exchanges = 0;
        var source = new ClientCredentialsTokenSource(
            _ => Task.FromResult(new OAuthToken { AccessToken = $"at_{Interlocked.Increment(ref exchanges)}", ExpiresIn = 3600 }),
            clock);

        Assert.Equal("at_1", await source.GetTokenAsync(default));
        clock.Advance(TimeSpan.FromSeconds(3539));
        Assert.Equal("at_1", await source.GetTokenAsync(default));
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal("at_2", await source.GetTokenAsync(default));
        Assert.Equal(2, exchanges);

        Assert.True(source.Invalidate("at_1")); // an old token: the fresh one stays
        Assert.Equal("at_2", await source.GetTokenAsync(default));
        Assert.True(source.Invalidate("at_2"));
        Assert.Equal("at_3", await source.GetTokenAsync(default));
    }

    [Fact]
    public async Task Concurrent_callers_share_one_exchange_and_its_failure()
    {
        var exchanges = 0;
        var release = new TaskCompletionSource<OAuthToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new ClientCredentialsTokenSource(_ =>
        {
            Interlocked.Increment(ref exchanges);
            return release.Task;
        });

        var first = source.GetTokenAsync(default).AsTask();
        var second = source.GetTokenAsync(default).AsTask();
        release.SetException(new AuthenticationException(401, "invalid_client", "No."));

        await Assert.ThrowsAsync<AuthenticationException>(() => first);
        await Assert.ThrowsAsync<AuthenticationException>(() => second);
        Assert.Equal(1, exchanges);
    }

    [Fact]
    public async Task One_caller_giving_up_does_not_cancel_the_exchange_for_the_others()
    {
        var release = new TaskCompletionSource<OAuthToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new ClientCredentialsTokenSource(_ => release.Task);
        using var cancel = new CancellationTokenSource();

        var impatient = source.GetTokenAsync(cancel.Token).AsTask();
        var patient = source.GetTokenAsync(default).AsTask();
        await cancel.CancelAsync();
        release.SetResult(new OAuthToken { AccessToken = "at_ok", ExpiresIn = 3600 });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => impatient);
        Assert.Equal("at_ok", await patient);
    }

    private sealed class ManualClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public void Advance(TimeSpan by) => _now += by;

        public override DateTimeOffset GetUtcNow() => _now;
    }
}

/// <summary>The environment variables the client falls back to.</summary>
[Collection(EnvironmentCollection.Name)]
public sealed class EnvironmentTests
{
    [Fact]
    public async Task The_key_live_credentials_and_base_url_come_from_the_environment_when_left_out()
    {
        await using var stub = StubServer.Start((request, _) => request.Path == "/v2/oauth/token"
            ? StubReply.Json(new { access_token = "at_live_env", token_type = "Bearer", expires_in = 3600 })
            : StubReply.Kyc(new { format = request.Header("Authorization") }));
        var saved = new[] { "VERISEC_API_KEY", "VERISEC_CLIENT_ID", "VERISEC_CLIENT_SECRET", "VERISEC_BASE_URL" }.ToDictionary(n => n, Environment.GetEnvironmentVariable);
        try
        {
            Environment.SetEnvironmentVariable("VERISEC_API_KEY", null);
            Assert.Throws<VeriSecException>(() => new VeriSecClient());

            Environment.SetEnvironmentVariable("VERISEC_API_KEY", "sk_test_from_env");
            Environment.SetEnvironmentVariable("VERISEC_BASE_URL", stub.BaseUrl);
            using (var client = new VeriSecClient())
            {
                Assert.Equal(stub.BaseUrl, client.BaseUrl);
                Assert.Equal("Bearer sk_test_from_env", (await client.Mrz.ParseAsync(Clients.Mrz())).Format);
            }

            Environment.SetEnvironmentVariable("VERISEC_API_KEY", "ak_live_env");
            Environment.SetEnvironmentVariable("VERISEC_CLIENT_ID", null);
            Environment.SetEnvironmentVariable("VERISEC_CLIENT_SECRET", null);
            Assert.Throws<VeriSecException>(() => new VeriSecClient());
            Environment.SetEnvironmentVariable("VERISEC_CLIENT_ID", "cli_env");
            Environment.SetEnvironmentVariable("VERISEC_CLIENT_SECRET", "cs_env");
            using (var live = new VeriSecClient((string?)null))
            {
                Assert.Equal("Bearer at_live_env", (await live.Mrz.ParseAsync(Clients.Mrz())).Format);
            }
            Assert.Contains(stub.Requests, r => r.Path == "/v2/oauth/token" && r.Text.Contains("\"client_id\":\"cli_env\"", StringComparison.Ordinal));

            using var explicitKey = new VeriSecClient(new VeriSecOptions { ApiKey = "sk_test_explicit" });
            Assert.Equal("Bearer sk_test_explicit", (await explicitKey.Mrz.ParseAsync(Clients.Mrz())).Format);
        }
        finally
        {
            foreach (var (name, value) in saved) Environment.SetEnvironmentVariable(name, value);
        }
    }

    [Fact]
    public void The_default_base_url_is_the_live_gateway()
    {
        var saved = Environment.GetEnvironmentVariable("VERISEC_BASE_URL");
        try
        {
            Environment.SetEnvironmentVariable("VERISEC_BASE_URL", null);
            using var client = new VeriSecClient("sk_test_x");
            Assert.Equal("https://verisec.mmose.me", client.BaseUrl);
            Assert.Equal(VeriSecClient.DefaultBaseUrl, client.BaseUrl);
        }
        finally
        {
            Environment.SetEnvironmentVariable("VERISEC_BASE_URL", saved);
        }
    }
}
