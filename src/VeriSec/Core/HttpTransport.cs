using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;

namespace VeriSec.Core;

/// <summary>How a successful answer is read (the operation's <c>x-verisec-envelope</c>).</summary>
internal enum Envelope
{
    /// <summary>KYC: <c>{ok, request_id, latency_ms, data, warnings, error}</c>; the result is <c>data</c>.</summary>
    Data,

    /// <summary>Financial: the answer is the result, as it is.</summary>
    Object,
}

/// <summary>
/// The transport every resource uses: builds each request, authenticates it, retries only what cannot have been
/// charged (CONVENTIONS.md) and turns the answer into a result or an exception.
/// </summary>
internal sealed class HttpTransport : IDisposable
{
    internal const string UserAgent = "verisec-dotnet/" + VeriSecClient.Version;

    /// <summary>How long opening a connection may take before it counts as never opened (and is retried).</summary>
    internal static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(10);

    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly KeyValuePair<string, string>[] _defaultHeaders;
    private ITokenSource? _tokens;

    public HttpTransport(string baseUrl, TimeSpan timeout, int maxRetries, IEnumerable<KeyValuePair<string, string>>? defaultHeaders, HttpClient? httpClient)
    {
        BaseUrl = baseUrl.TrimEnd('/');
        Timeout = timeout;
        MaxRetries = maxRetries;
        _defaultHeaders = defaultHeaders?.ToArray() ?? [];
        if (httpClient is null)
        {
            var handler = new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                AutomaticDecompression = DecompressionMethods.All,
                ConnectCallback = (context, cancellationToken) => ConnectAsync(context, ConnectTimeout, cancellationToken),
            };
            // Timeouts are per attempt and enforced here, so the HttpClient never times out on its own.
            _http = new HttpClient(handler) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
        }
    }

    public string BaseUrl { get; }

    public TimeSpan Timeout { get; }

    public int MaxRetries { get; }

    /// <summary>Set once by the client, right after construction (the live exchange calls back into this transport).</summary>
    public ITokenSource Tokens
    {
        get => _tokens ?? throw new InvalidOperationException("No credentials configured.");
        set => _tokens = value;
    }

    /// <summary>How long opening a connection may take (own HttpClient only). Tests shorten it.</summary>
    internal TimeSpan ConnectTimeout { get; set; } = DefaultConnectTimeout;

    /// <summary>How the transport waits between attempts. Tests replace it to record the delays instead.</summary>
    internal Func<TimeSpan, CancellationToken, Task> Delay { get; set; } = static (delay, token) => Task.Delay(delay, token);

    /// <summary>The jitter source, a number in [0, 1). Tests pin it.</summary>
    internal Func<double> Jitter { get; set; } = static () => Random.Shared.NextDouble();

    public void Dispose()
    {
        if (_ownsHttpClient) _http.Dispose();
    }

    /// <summary>A JSON call: the parameters as the API spells them, images as base64, image lists filled in.</summary>
    public async Task<T> JsonAsync<T>(HttpMethod method, string path, object parameters, ImagePlan images, Envelope envelope, bool sdkSource, RequestOptions? options, CancellationToken cancellationToken)
        where T : ApiResult, new()
    {
        ArgumentNullException.ThrowIfNull(parameters);
        var body = await RequestBody.SerializeAsync(parameters, images, cancellationToken).ConfigureAwait(false);
        var answer = await ExecuteAsync(new Call(method, path) { Json = body, SdkSource = sdkSource }, options, cancellationToken).ConfigureAwait(false);
        return Read<T>(answer, envelope);
    }

    /// <summary>A multipart call (the Financial reads): the file under its field (<c>image</c>), the other fields as text.</summary>
    public async Task<T> UploadAsync<T>(HttpMethod method, string path, object parameters, Envelope envelope, bool sdkSource, RequestOptions? options, CancellationToken cancellationToken)
        where T : ApiResult, new()
    {
        ArgumentNullException.ThrowIfNull(parameters);
        var form = await MultipartBody.PrepareAsync(parameters, cancellationToken).ConfigureAwait(false);
        var answer = await ExecuteAsync(new Call(method, path) { Form = form, SdkSource = sdkSource }, options, cancellationToken).ConfigureAwait(false);
        return Read<T>(answer, envelope);
    }

    /// <summary>A call without a body: path and query parameters only (<c>GET /v2/banks?name=…</c>).</summary>
    public async Task<T> QueryAsync<T>(HttpMethod method, string path, object? query, Envelope envelope, RequestOptions? options, CancellationToken cancellationToken)
        where T : ApiResult, new()
    {
        var answer = await ExecuteAsync(new Call(method, path) { Query = QueryString.Of(query) }, options, cancellationToken).ConfigureAwait(false);
        return Read<T>(answer, envelope);
    }

    /// <summary>The live token exchange: no bearer token, not retried, the answer read as it is.</summary>
    internal async Task<OAuthToken> ExchangeTokenAsync(OAuthTokenRequest request, CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(request, Json.Options);
        var answer = await ExecuteAsync(new Call(HttpMethod.Post, "/v2/oauth/token") { Json = body, Anonymous = true }, new RequestOptions { MaxRetries = 0 }, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return JsonSerializer.Deserialize<OAuthToken>(answer.Body, Json.Options) ?? new OAuthToken();
        }
        catch (JsonException e)
        {
            throw new VeriSecException($"The token endpoint's answer could not be read: {e.Message}", e);
        }
    }

    /// <summary>
    /// One call: the 2xx answer, or an exception. Retries (up to <c>MaxRetries</c>) only when nothing can have been
    /// charged: a connection that never opened, a 429 or a 5xx. A timeout, or a connection that failed after the
    /// request was sent, is thrown as <see cref="ApiTimeoutException"/> / <see cref="ApiConnectionException"/>
    /// because the call may have run. A 401 on a live token gets one fresh token, which is not counted as a retry.
    /// </summary>
    private async Task<Answer> ExecuteAsync(Call call, RequestOptions? options, CancellationToken cancellationToken)
    {
        var maxRetries = options?.MaxRetries ?? MaxRetries;
        if (maxRetries < 0) throw new ArgumentOutOfRangeException(nameof(options), "MaxRetries can't be negative.");
        var timeout = options?.Timeout ?? Timeout;
        if (timeout <= TimeSpan.Zero && timeout != System.Threading.Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Timeout must be positive.");
        }
        var url = $"{BaseUrl}{call.Path}{call.Query}";

        var refreshed = false;
        for (var attempt = 0; ; attempt++)
        {
            var token = call.Anonymous ? null : await Tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false);
            using var request = BuildRequest(call, url, token, options);
            using var attemptTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (timeout != System.Threading.Timeout.InfiniteTimeSpan) attemptTimeout.CancelAfter(timeout);

            var started = Stopwatch.GetTimestamp();
            HttpResponseMessage response;
            try
            {
                response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, attemptTimeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw; // the caller cancelled: never retried, never wrapped
            }
            catch (OperationCanceledException e)
            {
                throw TimedOut(call, Stopwatch.GetElapsedTime(started), e);
            }
            catch (Exception e) when (e is HttpRequestException or IOException)
            {
                if (RetryPolicy.NeverSent(e))
                {
                    if (attempt < maxRetries)
                    {
                        await Delay(RetryPolicy.Delay(attempt, null, Jitter(), DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);
                        continue;
                    }
                    throw new ApiConnectionException($"Could not reach {BaseUrl} ({Attempts(attempt)}): {e.Message}", e);
                }
                throw new ApiConnectionException(
                    $"The connection to {BaseUrl} failed after the request was sent: {e.Message} The call may have run (and been charged) on the server, so it was not sent again.",
                    e);
            }

            using (response)
            {
                byte[] body;
                try
                {
                    body = await response.Content.ReadAsByteArrayAsync(attemptTimeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (OperationCanceledException e)
                {
                    throw TimedOut(call, Stopwatch.GetElapsedTime(started), e);
                }
                catch (Exception e) when (e is HttpRequestException or IOException)
                {
                    throw new ApiConnectionException(
                        $"The connection to {BaseUrl} failed while the answer was being read: {e.Message} The call may have run (and been charged) on the server, so it was not sent again.",
                        e);
                }

                var status = (int)response.StatusCode;
                var headers = HeadersOf(response);
                if (status is >= 200 and < 300) return new Answer(status, headers, body);

                if (status == 401 && token is not null && !refreshed && Tokens.Invalidate(token))
                {
                    refreshed = true; // one fresh token: not counted as a retry
                    attempt--;
                    continue;
                }
                if (RetryPolicy.RetryableStatus(status) && attempt < maxRetries)
                {
                    headers.TryGetValue("Retry-After", out var retryAfter);
                    await Delay(RetryPolicy.Delay(attempt, retryAfter, Jitter(), DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);
                    continue;
                }
                var error = ErrorBody.Read(body);
                throw ApiException.Create(status, error.Code, error.Message, error.Param, error.RequestId ?? Header(headers, "X-Request-Id"), headers);
            }
        }
    }

    private static string Attempts(int attempt) => attempt == 0 ? "1 attempt" : $"{attempt + 1} attempts";

    private static ApiTimeoutException TimedOut(Call call, TimeSpan waited, Exception cause) => new(
        string.Create(CultureInfo.InvariantCulture, $"No answer to {call.Method} {call.Path} after {waited.TotalSeconds:0.#} s. The call may still have run (and been charged) on the server, so it was not sent again."),
        cause);

    /// <summary>The result of a 2xx answer, with its response info.</summary>
    private static T Read<T>(Answer answer, Envelope envelope)
        where T : ApiResult, new()
    {
        JsonElement root = default;
        if (answer.Body.Length > 0)
        {
            try
            {
                using var document = JsonDocument.Parse(answer.Body);
                root = document.RootElement.Clone();
            }
            catch (JsonException e)
            {
                throw Unreadable(answer, e);
            }
        }
        var isObject = root.ValueKind == JsonValueKind.Object;
        var requestId = (isObject && root.TryGetProperty("request_id", out var id) && id.ValueKind == JsonValueKind.String ? id.GetString() : null)
            ?? Header(answer.Headers, "X-Request-Id");
        var info = new ResponseInfo(answer.Status, answer.Headers, requestId, Warnings(root), isObject && root.TryGetProperty("latency_ms", out var latency) && latency.ValueKind == JsonValueKind.Number ? latency.GetDouble() : null);

        JsonElement value = root;
        if (envelope == Envelope.Data)
        {
            if (isObject && root.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.False)
            {
                // a 2xx always carries a result; ok: false is a handled problem
                var error = ErrorBody.Read(root);
                throw ApiException.Create(answer.Status, error.Code, error.Message, error.Param, requestId, answer.Headers);
            }
            value = isObject && root.TryGetProperty("data", out var data) ? data : default;
        }

        T? result;
        try
        {
            result = value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null ? null : value.Deserialize<T>(Json.Options);
        }
        catch (JsonException e)
        {
            throw Unreadable(answer, e);
        }
        result ??= new T();
        result.LastResponse = info;
        return result;
    }

    private static VeriSecException Unreadable(Answer answer, Exception cause) => new(
        $"The call succeeded (status {answer.Status}, request {Header(answer.Headers, "X-Request-Id") ?? "unknown"}) but its answer could not be read: {cause.Message}",
        cause);

    private static IReadOnlyList<string> Warnings(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("warnings", out var warnings) || warnings.ValueKind != JsonValueKind.Array) return [];
        return warnings.EnumerateArray().Select(w => w.ValueKind == JsonValueKind.String ? w.GetString()! : w.GetRawText()).ToArray();
    }

    private static string? Header(IReadOnlyDictionary<string, string> headers, string name) => headers.TryGetValue(name, out var value) ? value : null;

    private static Dictionary<string, string> HeadersOf(HttpResponseMessage response)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, values) in response.Headers) headers[name] = string.Join(", ", values);
        foreach (var (name, values) in response.Content.Headers) headers[name] = string.Join(", ", values);
        return headers;
    }

    private HttpRequestMessage BuildRequest(Call call, string url, string? token, RequestOptions? options)
    {
        var message = new HttpRequestMessage(call.Method, url);
        if (call.Json is not null)
        {
            message.Content = new ByteArrayContent(call.Json);
            message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        }
        else if (call.Form is not null)
        {
            message.Content = call.Form.CreateContent();
        }
        Set(message, "Accept", "application/json");
        Set(message, "User-Agent", UserAgent);
        if (call.SdkSource) Set(message, "X-VeriSec-Source", "sdk");
        foreach (var (name, value) in _defaultHeaders) Set(message, name, value);
        if (options?.Headers is { } extra)
        {
            foreach (var (name, value) in extra) Set(message, name, value);
        }
        if (token is not null) Set(message, "Authorization", $"Bearer {token}");
        return message;
    }

    /// <summary>Sets a header, replacing any earlier value; content headers go on the content.</summary>
    private static void Set(HttpRequestMessage message, string name, string value)
    {
        message.Headers.Remove(name);
        if (message.Headers.TryAddWithoutValidation(name, value)) return;
        if (message.Content is not null)
        {
            message.Content.Headers.Remove(name);
            message.Content.Headers.TryAddWithoutValidation(name, value);
        }
    }

    /// <summary>
    /// Opens the TCP connection, as <see cref="SocketsHttpHandler"/> would, but reports a connect that takes longer
    /// than <paramref name="timeout"/> as a connection error (the request was never sent, so it can be retried)
    /// rather than as a cancellation that looks like a timeout while waiting for the answer.
    /// </summary>
    private static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectTimeout.CancelAfter(timeout);
            try
            {
                await socket.ConnectAsync(context.DnsEndPoint, connectTimeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new SocketException((int)SocketError.TimedOut);
            }
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>One call as the resources describe it.</summary>
    private sealed class Call(HttpMethod method, string path)
    {
        public HttpMethod Method { get; } = method;

        public string Path { get; } = path;

        /// <summary><c>?a=1&amp;b=2</c>, or empty.</summary>
        public string Query { get; init; } = "";

        public byte[]? Json { get; init; }

        public MultipartBody? Form { get; init; }

        /// <summary>Send <c>X-VeriSec-Source: sdk</c>, so the console files the scan under "SDK".</summary>
        public bool SdkSource { get; init; }

        /// <summary>Send without a bearer token (the token exchange itself).</summary>
        public bool Anonymous { get; init; }
    }

    private sealed record Answer(int Status, IReadOnlyDictionary<string, string> Headers, byte[] Body);
}
