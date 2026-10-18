using System.Text.Json.Serialization;

namespace VeriSec.Core;

/// <summary>What the request pipeline needs from authentication.</summary>
internal interface ITokenSource
{
    /// <summary>The bearer token for the next request.</summary>
    ValueTask<string> GetTokenAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Forget a token the API rejected with 401, so the next call gets a fresh one.
    /// Returns true when asking again can help.
    /// </summary>
    bool Invalidate(string rejectedToken);
}

/// <summary>Test keys: the key (<c>sk_test_…</c>) is the bearer token.</summary>
internal sealed class SecretKeyTokenSource(string key) : ITokenSource
{
    public ValueTask<string> GetTokenAsync(CancellationToken cancellationToken) => new(key);

    public bool Invalidate(string rejectedToken) => false;
}

/// <summary>
/// Live keys: an <c>ak_live_…</c> key plus the client id and secret issued with it, exchanged at
/// <c>POST /v2/oauth/token</c> for a short-lived bearer token. The token is kept until 60 seconds before it
/// expires. Concurrent callers share one exchange (and its failure); a token the API rejects is dropped, so the
/// next call exchanges again.
/// </summary>
internal sealed class ClientCredentialsTokenSource : ITokenSource
{
    /// <summary>Renew this long before the token's own expiry.</summary>
    internal static readonly TimeSpan RefreshMargin = TimeSpan.FromSeconds(60);

    private readonly Func<CancellationToken, Task<OAuthToken>> _exchange;
    private readonly TimeProvider _clock;
    private readonly object _gate = new();
    private CachedToken? _cached;
    private Task<string>? _pending;

    public ClientCredentialsTokenSource(Func<CancellationToken, Task<OAuthToken>> exchange, TimeProvider? clock = null)
    {
        _exchange = exchange;
        _clock = clock ?? TimeProvider.System;
    }

    public async ValueTask<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        Task<string> pending;
        lock (_gate)
        {
            if (_cached is { } cached && _clock.GetUtcNow() < cached.RenewAt) return cached.Token;
            if (_pending is null || _pending.IsCompleted) _pending = ExchangeAsync();
            pending = _pending;
        }
        // The exchange runs for everyone waiting on it; one caller giving up does not cancel it for the others.
        return await pending.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    public bool Invalidate(string rejectedToken)
    {
        lock (_gate)
        {
            // Only drop the token that failed: another caller may already hold a fresh one.
            if (_cached is { } cached && cached.Token == rejectedToken) _cached = null;
        }
        return true;
    }

    private async Task<string> ExchangeAsync()
    {
        var response = await _exchange(CancellationToken.None).ConfigureAwait(false);
        if (string.IsNullOrEmpty(response.AccessToken)) throw new VeriSecException("The token endpoint answered without an access_token.");
        var lifetime = TimeSpan.FromSeconds(Math.Max(0, response.ExpiresIn ?? 3600)) - RefreshMargin;
        lock (_gate) _cached = new CachedToken(response.AccessToken, _clock.GetUtcNow() + (lifetime > TimeSpan.Zero ? lifetime : TimeSpan.Zero));
        return response.AccessToken;
    }

    private sealed record CachedToken(string Token, DateTimeOffset RenewAt);
}

/// <summary>The body of <c>POST /v2/oauth/token</c>.</summary>
internal sealed class OAuthTokenRequest
{
    [JsonPropertyName("grant_type")]
    public string GrantType { get; init; } = "client_credentials";

    [JsonPropertyName("api_key")]
    public required string ApiKey { get; init; }

    [JsonPropertyName("client_id")]
    public required string ClientId { get; init; }

    [JsonPropertyName("client_secret")]
    public required string ClientSecret { get; init; }
}

/// <summary>The answer of <c>POST /v2/oauth/token</c>.</summary>
internal sealed class OAuthToken
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; init; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; init; }

    [JsonPropertyName("expires_in")]
    public double? ExpiresIn { get; init; }

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }
}
