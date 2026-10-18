namespace VeriSec;

/// <summary>Base class of every exception this library throws.</summary>
public class VeriSecException : Exception
{
    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">What went wrong.</param>
    public VeriSecException(string message) : base(message) { }

    /// <summary>Creates an exception with a message and the exception that caused it.</summary>
    /// <param name="message">What went wrong.</param>
    /// <param name="innerException">The cause.</param>
    public VeriSecException(string message, Exception? innerException) : base(message, innerException) { }
}

/// <summary>
/// The API answered with an error. Catch a subclass to handle one kind: <see cref="InvalidRequestException"/>,
/// <see cref="AuthenticationException"/>, <see cref="InsufficientCreditsException"/>, <see cref="PermissionException"/>,
/// <see cref="NotFoundException"/>, <see cref="RateLimitException"/> or <see cref="ApiServerException"/>.
/// A call that fails is never charged.
/// </summary>
public class ApiException : VeriSecException
{
    private static readonly IReadOnlyDictionary<string, string> NoHeaders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Creates an API exception from the parts of an error answer.</summary>
    /// <param name="status">The HTTP status code.</param>
    /// <param name="code">The machine-readable reason, such as <c>invalid_input</c>.</param>
    /// <param name="message">What went wrong, written for a developer.</param>
    /// <param name="param">The request field the error is about, when there is one.</param>
    /// <param name="requestId">The request id to quote to support.</param>
    /// <param name="headers">The response headers.</param>
    public ApiException(int status, string? code, string message, string? param = null, string? requestId = null, IReadOnlyDictionary<string, string>? headers = null)
        : base(message)
    {
        Status = status;
        Code = code;
        Param = param;
        RequestId = requestId;
        Headers = headers ?? NoHeaders;
    }

    /// <summary>The HTTP status code, such as 400 or 402.</summary>
    public int Status { get; }

    /// <summary>The machine-readable reason, such as <c>invalid_input</c>, <c>missing_key</c> or <c>insufficient_credits</c>.</summary>
    public string? Code { get; }

    /// <summary>The request field the error is about (<c>image1</c>, <c>images[0].data</c>), when there is one.</summary>
    public string? Param { get; }

    /// <summary>The id of the failed request (<c>req_…</c>). Quote it when you contact support.</summary>
    public string? RequestId { get; }

    /// <summary>The response headers, looked up case-insensitively.</summary>
    public IReadOnlyDictionary<string, string> Headers { get; }

    /// <summary>The exception class for a status (CONVENTIONS.md, Errors).</summary>
    internal static ApiException Create(int status, string? code, string? message, string? param, string? requestId, IReadOnlyDictionary<string, string> headers)
    {
        var text = string.IsNullOrWhiteSpace(message) ? $"VeriSec API request failed with status {status}." : message!;
        return status switch
        {
            401 => new AuthenticationException(status, code, text, param, requestId, headers),
            402 => new InsufficientCreditsException(status, code, text, param, requestId, headers),
            403 => new PermissionException(status, code, text, param, requestId, headers),
            404 => new NotFoundException(status, code, text, param, requestId, headers),
            429 => new RateLimitException(status, code, text, param, requestId, headers),
            >= 500 => new ApiServerException(status, code, text, param, requestId, headers),
            _ => new InvalidRequestException(status, code, text, param, requestId, headers),
        };
    }
}

/// <summary>400, 413, 415, 422 (or another 4xx): a field is missing or not valid, the file is too large or not an image.</summary>
public class InvalidRequestException : ApiException
{
    /// <inheritdoc cref="ApiException(int, string?, string, string?, string?, IReadOnlyDictionary{string, string}?)"/>
    public InvalidRequestException(int status, string? code, string message, string? param = null, string? requestId = null, IReadOnlyDictionary<string, string>? headers = null)
        : base(status, code, message, param, requestId, headers) { }
}

/// <summary>401: no API key, or the key (or live client credentials) is not valid, expired or revoked.</summary>
public class AuthenticationException : ApiException
{
    /// <inheritdoc cref="ApiException(int, string?, string, string?, string?, IReadOnlyDictionary{string, string}?)"/>
    public AuthenticationException(int status, string? code, string message, string? param = null, string? requestId = null, IReadOnlyDictionary<string, string>? headers = null)
        : base(status, code, message, param, requestId, headers) { }
}

/// <summary>402: not enough credits for this call, or the key reached its spend cap. Nothing was charged: top up in the console.</summary>
public class InsufficientCreditsException : ApiException
{
    /// <inheritdoc cref="ApiException(int, string?, string, string?, string?, IReadOnlyDictionary{string, string}?)"/>
    public InsufficientCreditsException(int status, string? code, string message, string? param = null, string? requestId = null, IReadOnlyDictionary<string, string>? headers = null)
        : base(status, code, message, param, requestId, headers) { }
}

/// <summary>403: the key may not call this API (permission, environment or IP allow-list). Nothing was charged.</summary>
public class PermissionException : ApiException
{
    /// <inheritdoc cref="ApiException(int, string?, string, string?, string?, IReadOnlyDictionary{string, string}?)"/>
    public PermissionException(int status, string? code, string message, string? param = null, string? requestId = null, IReadOnlyDictionary<string, string>? headers = null)
        : base(status, code, message, param, requestId, headers) { }
}

/// <summary>404: nothing was found (an unknown BIN, a bank not in the directory, a route that does not exist).</summary>
public class NotFoundException : ApiException
{
    /// <inheritdoc cref="ApiException(int, string?, string, string?, string?, IReadOnlyDictionary{string, string}?)"/>
    public NotFoundException(int status, string? code, string message, string? param = null, string? requestId = null, IReadOnlyDictionary<string, string>? headers = null)
        : base(status, code, message, param, requestId, headers) { }
}

/// <summary>429: too many requests for this key. Nothing was charged. The library already waited and retried; this is what was left.</summary>
public class RateLimitException : ApiException
{
    /// <inheritdoc cref="ApiException(int, string?, string, string?, string?, IReadOnlyDictionary{string, string}?)"/>
    public RateLimitException(int status, string? code, string message, string? param = null, string? requestId = null, IReadOnlyDictionary<string, string>? headers = null)
        : base(status, code, message, param, requestId, headers)
    {
        RetryAfter = Core.RetryPolicy.ParseRetryAfter(Headers.TryGetValue("Retry-After", out var value) ? value : null, DateTimeOffset.UtcNow);
    }

    /// <summary>How long to wait before trying again, from the <c>Retry-After</c> header, when the API sent one.</summary>
    public TimeSpan? RetryAfter { get; }
}

/// <summary>5xx: the check could not run. Nothing was charged; it is safe to try again.</summary>
public class ApiServerException : ApiException
{
    /// <inheritdoc cref="ApiException(int, string?, string, string?, string?, IReadOnlyDictionary{string, string}?)"/>
    public ApiServerException(int status, string? code, string message, string? param = null, string? requestId = null, IReadOnlyDictionary<string, string>? headers = null)
        : base(status, code, message, param, requestId, headers) { }
}

/// <summary>
/// The call got no answer: the API could not be reached, or the connection failed. When the message says the
/// request was sent, the call may have run (and been charged) on the server, so the library did not send it again.
/// </summary>
public class ApiConnectionException : VeriSecException
{
    /// <inheritdoc cref="VeriSecException(string, Exception?)"/>
    public ApiConnectionException(string message, Exception? innerException = null) : base(message, innerException) { }
}

/// <summary>
/// No answer within the timeout. The call may still have run (and been charged) on the server, so it was not sent
/// again. A deep cheque read can take up to about 250 s: the default timeout is 300 s per attempt.
/// </summary>
public class ApiTimeoutException : ApiConnectionException
{
    /// <inheritdoc cref="VeriSecException(string, Exception?)"/>
    public ApiTimeoutException(string message, Exception? innerException = null) : base(message, innerException) { }
}

/// <summary>A webhook signature did not verify, a header is missing, or the timestamp is outside the tolerance.</summary>
public class SignatureVerificationException : VeriSecException
{
    /// <inheritdoc cref="VeriSecException(string)"/>
    public SignatureVerificationException(string message) : base(message) { }
}
