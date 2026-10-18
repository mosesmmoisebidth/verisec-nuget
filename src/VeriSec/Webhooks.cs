using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using VeriSec.Core;

namespace VeriSec;

/// <summary>
/// Verifies webhook deliveries. They are signed as Standard Webhooks: the headers <c>webhook-id</c>,
/// <c>webhook-timestamp</c> (unix seconds) and <c>webhook-signature</c>, a space-separated list of
/// <c>v1,&lt;base64 HMAC-SHA256 of "id.timestamp.body"&gt;</c> keyed with your endpoint's signing secret
/// (<c>whsec_…</c>). Any listed signature may match (secrets rotate), and the <c>svix-*</c> header names work too.
/// </summary>
/// <example>
/// An ASP.NET Core endpoint (read the raw body: the signature covers it byte for byte):
/// <code>
/// app.MapPost("/webhooks/verisec", async (HttpRequest request) =>
/// {
///     using var reader = new StreamReader(request.Body);
///     var body = await reader.ReadToEndAsync();
///     try
///     {
///         var evt = Webhooks.ConstructEvent(body, name => request.Headers[name], secret);
///         if (evt.Type == "verification.completed") { /* evt.Data */ }
///         return Results.Ok();
///     }
///     catch (SignatureVerificationException)
///     {
///         return Results.BadRequest();
///     }
/// });
/// </code>
/// </example>
public static class Webhooks
{
    /// <summary>How far a delivery's timestamp may be from now, to stop replays: 300 seconds.</summary>
    public static readonly TimeSpan DefaultTolerance = TimeSpan.FromSeconds(300);

    /// <summary>Verifies the signature, then parses the event.</summary>
    /// <param name="payload">The request body exactly as received, before any JSON parsing.</param>
    /// <param name="headers">The delivery's headers (looked up case-insensitively).</param>
    /// <param name="secret">The endpoint's signing secret (<c>whsec_…</c>).</param>
    /// <param name="tolerance">How far the timestamp may be from now; 300 s when left out, zero turns the check off.</param>
    /// <exception cref="SignatureVerificationException">A header is missing, no signature matches, or the timestamp is outside the tolerance.</exception>
    /// <exception cref="ArgumentException">The secret is empty or not <c>whsec_</c> followed by base64.</exception>
    public static WebhookEvent ConstructEvent(string payload, IDictionary<string, string> headers, string secret, TimeSpan? tolerance = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return ConstructEvent(Encoding.UTF8.GetBytes(payload), Lookup(headers), secret, tolerance);
    }

    /// <inheritdoc cref="ConstructEvent(string, IDictionary{string, string}, string, TimeSpan?)"/>
    public static WebhookEvent ConstructEvent(byte[] payload, IDictionary<string, string> headers, string secret, TimeSpan? tolerance = null) =>
        ConstructEvent(payload, Lookup(headers), secret, tolerance);

    /// <inheritdoc cref="ConstructEvent(string, IDictionary{string, string}, string, TimeSpan?)"/>
    public static WebhookEvent ConstructEvent(string payload, HttpHeaders headers, string secret, TimeSpan? tolerance = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return ConstructEvent(Encoding.UTF8.GetBytes(payload), Lookup(headers), secret, tolerance);
    }

    /// <inheritdoc cref="ConstructEvent(string, IDictionary{string, string}, string, TimeSpan?)"/>
    public static WebhookEvent ConstructEvent(byte[] payload, HttpHeaders headers, string secret, TimeSpan? tolerance = null) =>
        ConstructEvent(payload, Lookup(headers), secret, tolerance);

    /// <summary>Verifies the signature, then parses the event; headers come from a lookup such as ASP.NET Core's <c>name => request.Headers[name]</c>.</summary>
    /// <param name="payload">The request body exactly as received, before any JSON parsing.</param>
    /// <param name="header">Returns a header's value by name, or null when it is missing.</param>
    /// <param name="secret">The endpoint's signing secret (<c>whsec_…</c>).</param>
    /// <param name="tolerance">How far the timestamp may be from now; 300 s when left out, zero turns the check off.</param>
    /// <exception cref="SignatureVerificationException">A header is missing, no signature matches, or the timestamp is outside the tolerance.</exception>
    /// <exception cref="ArgumentException">The secret is empty or not <c>whsec_</c> followed by base64.</exception>
    public static WebhookEvent ConstructEvent(string payload, Func<string, string?> header, string secret, TimeSpan? tolerance = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return ConstructEvent(Encoding.UTF8.GetBytes(payload), header, secret, tolerance);
    }

    /// <inheritdoc cref="ConstructEvent(string, Func{string, string?}, string, TimeSpan?)"/>
    public static WebhookEvent ConstructEvent(byte[] payload, Func<string, string?> header, string secret, TimeSpan? tolerance = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(header);
        Verify(payload, header, secret, tolerance ?? DefaultTolerance, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        try
        {
            return JsonSerializer.Deserialize<WebhookEvent>(payload, Json.Options) ?? throw new VeriSecException("The webhook body is not an event.");
        }
        catch (JsonException e)
        {
            throw new VeriSecException($"The webhook body is not valid JSON: {e.Message}", e);
        }
    }

    /// <summary>True when a signature matches the payload and the timestamp is within the tolerance.</summary>
    /// <param name="payload">The request body exactly as received.</param>
    /// <param name="headers">The delivery's headers (looked up case-insensitively).</param>
    /// <param name="secret">The endpoint's signing secret (<c>whsec_…</c>).</param>
    /// <param name="tolerance">How far the timestamp may be from now; 300 s when left out, zero turns the check off.</param>
    /// <exception cref="ArgumentException">The secret is empty or not <c>whsec_</c> followed by base64.</exception>
    public static bool VerifySignature(string payload, IDictionary<string, string> headers, string secret, TimeSpan? tolerance = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return VerifySignature(Encoding.UTF8.GetBytes(payload), Lookup(headers), secret, tolerance);
    }

    /// <inheritdoc cref="VerifySignature(string, IDictionary{string, string}, string, TimeSpan?)"/>
    public static bool VerifySignature(byte[] payload, IDictionary<string, string> headers, string secret, TimeSpan? tolerance = null) =>
        VerifySignature(payload, Lookup(headers), secret, tolerance);

    /// <inheritdoc cref="VerifySignature(string, IDictionary{string, string}, string, TimeSpan?)"/>
    public static bool VerifySignature(string payload, HttpHeaders headers, string secret, TimeSpan? tolerance = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return VerifySignature(Encoding.UTF8.GetBytes(payload), Lookup(headers), secret, tolerance);
    }

    /// <inheritdoc cref="VerifySignature(string, IDictionary{string, string}, string, TimeSpan?)"/>
    public static bool VerifySignature(byte[] payload, HttpHeaders headers, string secret, TimeSpan? tolerance = null) =>
        VerifySignature(payload, Lookup(headers), secret, tolerance);

    /// <summary>True when a signature matches the payload and the timestamp is within the tolerance; headers come from a lookup.</summary>
    /// <param name="payload">The request body exactly as received.</param>
    /// <param name="header">Returns a header's value by name, or null when it is missing.</param>
    /// <param name="secret">The endpoint's signing secret (<c>whsec_…</c>).</param>
    /// <param name="tolerance">How far the timestamp may be from now; 300 s when left out, zero turns the check off.</param>
    /// <exception cref="ArgumentException">The secret is empty or not <c>whsec_</c> followed by base64.</exception>
    public static bool VerifySignature(string payload, Func<string, string?> header, string secret, TimeSpan? tolerance = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return VerifySignature(Encoding.UTF8.GetBytes(payload), header, secret, tolerance);
    }

    /// <inheritdoc cref="VerifySignature(string, Func{string, string?}, string, TimeSpan?)"/>
    public static bool VerifySignature(byte[] payload, Func<string, string?> header, string secret, TimeSpan? tolerance = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(header);
        try
        {
            Verify(payload, header, secret, tolerance ?? DefaultTolerance, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            return true;
        }
        catch (SignatureVerificationException)
        {
            return false;
        }
    }

    /// <summary>Valid delivery headers for a payload (<c>webhook-id</c>, <c>webhook-timestamp</c>, <c>webhook-signature</c>), to test your own handler.</summary>
    /// <param name="payload">The body you will send.</param>
    /// <param name="secret">The endpoint's signing secret (<c>whsec_…</c>).</param>
    /// <param name="id">The message id; a new <c>msg_…</c> when left out.</param>
    /// <param name="timestamp">The time to sign with; now when left out.</param>
    public static IDictionary<string, string> GenerateTestHeaders(string payload, string secret, string? id = null, DateTimeOffset? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return GenerateTestHeaders(Encoding.UTF8.GetBytes(payload), secret, id, timestamp);
    }

    /// <inheritdoc cref="GenerateTestHeaders(string, string, string?, DateTimeOffset?)"/>
    public static IDictionary<string, string> GenerateTestHeaders(byte[] payload, string secret, string? id = null, DateTimeOffset? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var messageId = id ?? $"msg_{Guid.NewGuid():N}";
        var seconds = (timestamp ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["webhook-id"] = messageId,
            ["webhook-timestamp"] = seconds,
            ["webhook-signature"] = $"v1,{Convert.ToBase64String(Sign(Key(secret), messageId, seconds, payload))}",
        };
    }

    /// <summary>Throws <see cref="SignatureVerificationException"/> unless a signature matches the payload and the timestamp is fresh.</summary>
    internal static void Verify(ReadOnlySpan<byte> payload, Func<string, string?> header, string secret, TimeSpan tolerance, long now)
    {
        var key = Key(secret);
        var id = header("webhook-id") ?? header("svix-id");
        var timestamp = header("webhook-timestamp") ?? header("svix-timestamp");
        var signatures = header("webhook-signature") ?? header("svix-signature");
        if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(timestamp) || string.IsNullOrEmpty(signatures))
        {
            throw new SignatureVerificationException("Missing webhook-id, webhook-timestamp or webhook-signature header.");
        }
        if (!long.TryParse(timestamp.Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var seconds))
        {
            throw new SignatureVerificationException("Malformed webhook-timestamp header: expected unix seconds.");
        }
        if (tolerance > TimeSpan.Zero && Math.Abs(now - seconds) > tolerance.TotalSeconds)
        {
            throw new SignatureVerificationException($"The webhook timestamp is outside the {tolerance.TotalSeconds:0.###} s tolerance.");
        }

        var expected = Sign(key, id, timestamp, payload);
        var matched = false;
        foreach (var part in signatures.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var comma = part.IndexOf(',');
            if (comma <= 0 || part[..comma] != "v1") continue;
            var given = new byte[expected.Length + 3];
            if (!Convert.TryFromBase64String(part[(comma + 1)..], given, out var length)) continue;
            matched |= CryptographicOperations.FixedTimeEquals(given.AsSpan(0, length), expected);
        }
        if (!matched)
        {
            throw new SignatureVerificationException("No signature matches the payload. Check the signing secret and that the body is unmodified.");
        }
    }

    private static byte[] Key(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        var encoded = secret.StartsWith("whsec_", StringComparison.Ordinal) ? secret["whsec_".Length..] : secret;
        try
        {
            return Convert.FromBase64String(encoded);
        }
        catch (FormatException e)
        {
            throw new ArgumentException("The webhook secret is not valid: expected whsec_ followed by base64.", nameof(secret), e);
        }
    }

    private static byte[] Sign(byte[] key, string id, string timestamp, ReadOnlySpan<byte> payload)
    {
        var prefix = Encoding.UTF8.GetBytes($"{id}.{timestamp}.");
        var message = new byte[prefix.Length + payload.Length];
        prefix.CopyTo(message, 0);
        payload.CopyTo(message.AsSpan(prefix.Length));
        return HMACSHA256.HashData(key, message);
    }

    private static Func<string, string?> Lookup(IDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        return name =>
        {
            if (headers.TryGetValue(name, out var exact)) return exact;
            foreach (var (key, value) in headers)
            {
                if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase)) return value;
            }
            return null;
        };
    }

    private static Func<string, string?> Lookup(HttpHeaders headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        return name => headers.TryGetValues(name, out var values) ? string.Join(" ", values) : null;
    }
}

/// <summary>A webhook delivery's body: what happened (<see cref="Type"/>), when, in which environment, and its data.</summary>
public sealed class WebhookEvent
{
    /// <summary>The event type, such as <c>verification.completed</c>, <c>verification.declined</c>, <c>aml.hit</c> or <c>credits.low</c>.</summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = "";

    /// <summary>When the event happened (ISO 8601).</summary>
    [JsonPropertyName("timestamp")]
    public string? Timestamp { get; init; }

    /// <summary><c>test</c> or <c>live</c>.</summary>
    [JsonPropertyName("environment")]
    public string? Environment { get; init; }

    /// <summary>The event's data, as JSON. Read it with <see cref="GetData{T}"/> or as a <see cref="JsonElement"/>.</summary>
    [JsonPropertyName("data")]
    public JsonElement Data { get; init; }

    /// <summary>Fields of the body this class does not declare, as raw JSON.</summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; init; }

    /// <summary>The event's data as <typeparamref name="T"/> (a class of yours, or <c>Dictionary&lt;string, JsonElement&gt;</c>).</summary>
    /// <typeparam name="T">The type to read the data as.</typeparam>
    public T? GetData<T>() =>
        Data.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null ? default : Data.Deserialize<T>(Json.Options);
}
