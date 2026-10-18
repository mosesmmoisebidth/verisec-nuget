using System.Globalization;
using System.Net.Sockets;

namespace VeriSec.Core;

/// <summary>
/// When a failed call is sent again (CONVENTIONS.md, "Retries: never run a charged call twice"). Calls are charged
/// only when they succeed, so a 429 or a 5xx, and a connection that never opened, cost nothing and are retried.
/// A timeout while waiting for the answer, or a connection that failed after the request was sent, may come after
/// the server ran (and charged) the check: those are never retried.
/// </summary>
internal static class RetryPolicy
{
    /// <summary>The longest a <c>Retry-After</c> header can make the library wait.</summary>
    public static readonly TimeSpan MaxRetryAfter = TimeSpan.FromSeconds(60);

    /// <summary>Statuses worth another try: refused before running (429) or the check did not complete (5xx).</summary>
    public static bool RetryableStatus(int status) => status == 429 || status >= 500;

    /// <summary>
    /// True when the request cannot have reached the server: DNS failed, the connection was refused, the host or
    /// network was unreachable, or connecting timed out. Anything else (a reset, an early end of the answer) may have
    /// happened after the server did the work.
    /// </summary>
    public static bool NeverSent(Exception error)
    {
        for (Exception? e = error; e is not null; e = e.InnerException)
        {
            switch (e)
            {
                case HttpRequestException { HttpRequestError: HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError }:
                    return true;
                case SocketException { SocketErrorCode: SocketError.ConnectionRefused or SocketError.HostNotFound or SocketError.TryAgain or SocketError.NoData or SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.HostDown or SocketError.NetworkDown }:
                    return true;
                case HttpRequestException { HttpRequestError: not HttpRequestError.Unknown }:
                    return false; // a later phase: TLS, protocol, the answer ended early
            }
        }
        return false;
    }

    /// <summary>
    /// How long to wait before attempt <paramref name="attempt"/> + 1: the <c>Retry-After</c> header when the server
    /// sent one (at most 60 s), else <c>min(0.5 · 2^attempt, 8)</c> seconds ±25%.
    /// </summary>
    public static TimeSpan Delay(int attempt, string? retryAfter, double jitter, DateTimeOffset now)
    {
        if (ParseRetryAfter(retryAfter, now) is { } told) return told < MaxRetryAfter ? told : MaxRetryAfter;
        var seconds = Math.Min(0.5 * Math.Pow(2, attempt), 8);
        return TimeSpan.FromSeconds(seconds * (0.75 + jitter * 0.5));
    }

    /// <summary>A <c>Retry-After</c> header: delay-seconds, or an HTTP date. Null when absent or not understood.</summary>
    public static TimeSpan? ParseRetryAfter(string? value, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var text = value.Trim();
        if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds))
        {
            return seconds >= 0 && !double.IsInfinity(seconds) && !double.IsNaN(seconds) ? TimeSpan.FromSeconds(Math.Min(seconds, TimeSpan.MaxValue.TotalSeconds / 2)) : null;
        }
        if (DateTimeOffset.TryParseExact(text, "r", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var date))
        {
            var wait = date - now;
            return wait > TimeSpan.Zero ? wait : TimeSpan.Zero;
        }
        return null;
    }
}
