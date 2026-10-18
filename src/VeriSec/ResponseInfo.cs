namespace VeriSec;

/// <summary>
/// Where an answer came from: the HTTP status and headers, the request id, and the KYC envelope's warnings and
/// timing. Every result a method returns carries one as <see cref="ApiResult.LastResponse"/>.
/// </summary>
/// <example>
/// <code>
/// var result = await client.Face.VerifyAsync(parameters);
/// Console.WriteLine($"{result.LastResponse.RequestId} {result.LastResponse.LatencyMs} ms");
/// foreach (var warning in result.LastResponse.Warnings) Console.WriteLine(warning);
/// </code>
/// </example>
public sealed class ResponseInfo
{
    private static readonly IReadOnlyDictionary<string, string> NoHeaders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The response info of a result that did not come from a call (one you built, or a nested object).</summary>
    public static ResponseInfo None { get; } = new(0, NoHeaders, null, [], null);

    /// <summary>Response info, as the library builds it for each answer (public so you can build results in your own tests).</summary>
    /// <param name="status">The HTTP status code.</param>
    /// <param name="headers">The response headers (looked up case-insensitively).</param>
    /// <param name="requestId">The request id: the envelope's <c>request_id</c>, else the <c>X-Request-Id</c> header.</param>
    /// <param name="warnings">The envelope's <c>warnings</c>.</param>
    /// <param name="latencyMs">The envelope's <c>latency_ms</c>.</param>
    public ResponseInfo(int status, IReadOnlyDictionary<string, string> headers, string? requestId, IReadOnlyList<string> warnings, double? latencyMs)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(warnings);
        Status = status;
        Headers = headers;
        RequestId = requestId;
        Warnings = warnings;
        LatencyMs = latencyMs;
    }

    /// <summary>The HTTP status code, such as 200. 0 when the result did not come from a call.</summary>
    public int Status { get; }

    /// <summary>The response headers, looked up case-insensitively. Repeated headers are joined with <c>", "</c>.</summary>
    public IReadOnlyDictionary<string, string> Headers { get; }

    /// <summary>The request id (<c>req_…</c>). Quote it when you contact support.</summary>
    public string? RequestId { get; }

    /// <summary>Notes about the result that are not errors (KYC answers). Empty when there are none.</summary>
    public IReadOnlyList<string> Warnings { get; }

    /// <summary>How long the check took on the server, in milliseconds (KYC answers).</summary>
    public double? LatencyMs { get; }

    /// <inheritdoc/>
    public override string ToString() => $"{Status} {RequestId}";
}
