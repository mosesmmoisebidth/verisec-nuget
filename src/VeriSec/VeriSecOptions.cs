namespace VeriSec;

/// <summary>
/// Settings for a <see cref="VeriSecClient"/>. Everything is optional: the key and live credentials fall back to the
/// <c>VERISEC_API_KEY</c>, <c>VERISEC_CLIENT_ID</c> and <c>VERISEC_CLIENT_SECRET</c> environment variables, the
/// base URL to <c>VERISEC_BASE_URL</c>, and the rest to the defaults.
/// </summary>
/// <example>
/// <code>
/// var client = new VeriSecClient(new VeriSecOptions
/// {
///     ApiKey = Environment.GetEnvironmentVariable("VERISEC_API_KEY"),            // ak_live_…
///     ClientId = Environment.GetEnvironmentVariable("VERISEC_CLIENT_ID"),
///     ClientSecret = Environment.GetEnvironmentVariable("VERISEC_CLIENT_SECRET"),
/// });
/// </code>
/// </example>
public sealed class VeriSecOptions
{
    /// <summary>
    /// A test key (<c>sk_test_…</c>), sent as the bearer token, or a live key (<c>ak_live_…</c>), exchanged with
    /// <see cref="ClientId"/> and <see cref="ClientSecret"/> for a short-lived token. Defaults to <c>VERISEC_API_KEY</c>.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>Live keys only: the client id issued with the key (<c>cli_…</c>). Defaults to <c>VERISEC_CLIENT_ID</c>.</summary>
    public string? ClientId { get; set; }

    /// <summary>Live keys only: the client secret issued with the key. Defaults to <c>VERISEC_CLIENT_SECRET</c>.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>The API host. Defaults to <c>VERISEC_BASE_URL</c>, then <see cref="VeriSecClient.DefaultBaseUrl"/>.</summary>
    public string? BaseUrl { get; set; }

    /// <summary>
    /// How long one attempt may take. Defaults to 300 seconds: a deep cheque read can take up to about 250 s, and a
    /// call cut off by the client may still finish (and be charged) on the server.
    /// </summary>
    public TimeSpan? Timeout { get; set; }

    /// <summary>
    /// Retries after the first attempt, only where nothing was charged: a 429, a 5xx, or a connection that never
    /// opened. Defaults to 2 (3 attempts); 0 turns retries off.
    /// </summary>
    public int? MaxRetries { get; set; }

    /// <summary>Extra headers sent with every request.</summary>
    public IDictionary<string, string> DefaultHeaders { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Overrides for a single call, passed as the <c>options</c> argument of any method.</summary>
/// <example>
/// <code>
/// var cheque = await client.Cheques.ReadAsync(parameters, new RequestOptions { Timeout = TimeSpan.FromMinutes(6), MaxRetries = 0 });
/// </code>
/// </example>
public sealed class RequestOptions
{
    /// <summary>How long one attempt of this call may take, instead of the client's <see cref="VeriSecOptions.Timeout"/>.</summary>
    public TimeSpan? Timeout { get; set; }

    /// <summary>Retries for this call, instead of the client's <see cref="VeriSecOptions.MaxRetries"/>. 0 turns them off.</summary>
    public int? MaxRetries { get; set; }

    /// <summary>Extra headers for this call. They override the client's default headers.</summary>
    public IDictionary<string, string> Headers { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
