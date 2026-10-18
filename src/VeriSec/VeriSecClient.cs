using VeriSec.Core;

namespace VeriSec;

/// <summary>
/// The VeriSec API client, for KYC (faces, documents, MRZ, contact and risk checks) and Financial (cheques, cards,
/// banks, BINs). Every API is a method, grouped the way the API groups them (<see cref="Face"/>,
/// <see cref="Documents"/>, <see cref="Cheques"/>, …). Create one and reuse it: it is thread-safe and keeps its
/// connections and its live token.
/// </summary>
/// <example>
/// <code>
/// using VeriSec;
///
/// using var client = new VeriSecClient(Environment.GetEnvironmentVariable("VERISEC_API_KEY")); // sk_test_…
///
/// var result = await client.Face.VerifyAsync(new FaceVerifyParams
/// {
///     Image1 = Image.FromPath("selfie.jpg"),
///     Image2 = Image.FromPath("id-photo.jpg"),
///     Threshold = 0.8,
/// });
/// Console.WriteLine($"{result.Match} {result.Similarity} {result.LastResponse.RequestId}");
/// </code>
/// </example>
public sealed partial class VeriSecClient : IDisposable
{
    /// <summary>This library's version, sent in the <c>User-Agent</c> header (<c>verisec-dotnet/1.0.0</c>).</summary>
    public const string Version = "1.0.0";

    /// <summary>The API host: <c>https://verisec.mmose.me</c>.</summary>
    public const string DefaultBaseUrl = "https://verisec.mmose.me";

    /// <summary>Retries after the first attempt, by default: 2.</summary>
    public const int DefaultMaxRetries = 2;

    /// <summary>How long one attempt may take, by default: 300 seconds.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(300);

    private readonly HttpTransport _transport;

    /// <summary>A client with the key in <c>VERISEC_API_KEY</c> (and, for a live key, <c>VERISEC_CLIENT_ID</c> and <c>VERISEC_CLIENT_SECRET</c>).</summary>
    /// <exception cref="VeriSecException">No key is set, or a live key comes without its client id and secret.</exception>
    public VeriSecClient()
        : this(new VeriSecOptions())
    {
    }

    /// <summary>A client with an API key: a test key (<c>sk_test_…</c>), or a live key with its client credentials in the environment.</summary>
    /// <param name="apiKey">The key. When null, <c>VERISEC_API_KEY</c> is used.</param>
    /// <exception cref="VeriSecException">No key is given or set, or a live key comes without its client id and secret.</exception>
    public VeriSecClient(string? apiKey)
        : this(new VeriSecOptions { ApiKey = apiKey })
    {
    }

    /// <summary>A client with explicit settings: live credentials, base URL, timeout, retries, headers.</summary>
    /// <param name="options">The settings; anything left out falls back to the environment and the defaults.</param>
    /// <param name="httpClient">
    /// An <see cref="HttpClient"/> to send requests with (for proxies, custom handlers or <c>IHttpClientFactory</c>).
    /// The client does not dispose it. Set its <see cref="HttpClient.Timeout"/> to <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>:
    /// this client enforces <see cref="VeriSecOptions.Timeout"/> per attempt itself. Leave it out and the client
    /// makes and owns its own.
    /// </param>
    /// <exception cref="VeriSecException">No key is given or set, or a live key comes without its client id and secret.</exception>
    public VeriSecClient(VeriSecOptions options, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var apiKey = FirstSet(options.ApiKey, Environment.GetEnvironmentVariable("VERISEC_API_KEY"))
            ?? throw new VeriSecException("No API key. Pass one (sk_test_… or ak_live_…) or set VERISEC_API_KEY.");
        var baseUrl = FirstSet(options.BaseUrl, Environment.GetEnvironmentVariable("VERISEC_BASE_URL")) ?? DefaultBaseUrl;
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var parsed) || (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp))
        {
            throw new VeriSecException($"BaseUrl must be an absolute http(s) URL, not '{baseUrl}'.");
        }
        var timeout = options.Timeout ?? DefaultTimeout;
        if (timeout <= TimeSpan.Zero && timeout != System.Threading.Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Timeout must be positive.");
        }
        var maxRetries = options.MaxRetries ?? DefaultMaxRetries;
        if (maxRetries < 0) throw new ArgumentOutOfRangeException(nameof(options), "MaxRetries can't be negative.");

        ITokenSource tokens;
        if (apiKey.StartsWith("ak_live_", StringComparison.Ordinal))
        {
            var clientId = FirstSet(options.ClientId, Environment.GetEnvironmentVariable("VERISEC_CLIENT_ID"));
            var clientSecret = FirstSet(options.ClientSecret, Environment.GetEnvironmentVariable("VERISEC_CLIENT_SECRET"));
            if (clientId is null || clientSecret is null)
            {
                throw new VeriSecException("Live keys (ak_live_…) also need ClientId and ClientSecret, or VERISEC_CLIENT_ID and VERISEC_CLIENT_SECRET.");
            }
            var request = new OAuthTokenRequest { ApiKey = apiKey, ClientId = clientId, ClientSecret = clientSecret };
            tokens = new ClientCredentialsTokenSource(cancellationToken => _transport!.ExchangeTokenAsync(request, cancellationToken));
        }
        else
        {
            tokens = new SecretKeyTokenSource(apiKey);
        }

        _transport = new HttpTransport(baseUrl, timeout, maxRetries, options.DefaultHeaders, httpClient) { Tokens = tokens };
        InitializeResources(_transport);
    }

    /// <summary>The API host requests go to.</summary>
    public string BaseUrl => _transport.BaseUrl;

    /// <summary>How long one attempt may take.</summary>
    public TimeSpan Timeout => _transport.Timeout;

    /// <summary>Retries after the first attempt.</summary>
    public int MaxRetries => _transport.MaxRetries;

    /// <summary>The transport (tests reach its retry clock through this).</summary>
    internal HttpTransport Transport => _transport;

    /// <summary>Releases the client's own <see cref="HttpClient"/>. One you passed in is left alone.</summary>
    public void Dispose() => _transport.Dispose();

    private static string? FirstSet(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value)) return value;
        }
        return null;
    }
}
