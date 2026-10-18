using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace VeriSec.Tests.Support;

/// <summary>A request as the stub saw it on the wire.</summary>
public sealed record StubRequest(string Method, string Target, IReadOnlyDictionary<string, string> Headers, byte[] Body)
{
    public string Path => Target.Split('?')[0];

    public string Text => Encoding.UTF8.GetString(Body);

    /// <summary>The body as Latin-1, to look into multipart bodies byte for byte.</summary>
    public string Raw => Encoding.Latin1.GetString(Body);

    public JsonElement Json
    {
        get
        {
            using var document = JsonDocument.Parse(Body);
            return document.RootElement.Clone();
        }
    }

    public string? Header(string name) => Headers.TryGetValue(name, out var value) ? value : null;
}

/// <summary>What the stub does with a request: answer it, drop the connection, reset it, or never answer.</summary>
public sealed class StubReply
{
    private StubReply(string kind, int status = 200, string body = "", string contentType = "application/json", IReadOnlyDictionary<string, string>? headers = null)
    {
        Kind = kind;
        Status = status;
        Body = body;
        ContentType = contentType;
        Headers = headers ?? new Dictionary<string, string>();
    }

    public string Kind { get; }

    public int Status { get; }

    public string Body { get; }

    public string ContentType { get; }

    public IReadOnlyDictionary<string, string> Headers { get; }

    /// <summary>Close the connection (FIN) after reading the request, without answering.</summary>
    public static StubReply Drop { get; } = new("drop");

    /// <summary>Reset the connection (RST) after reading the request, without answering.</summary>
    public static StubReply Reset { get; } = new("reset");

    /// <summary>Read the request and never answer.</summary>
    public static StubReply Hang { get; } = new("hang");

    public static StubReply Json(object body, int status = 200, IReadOnlyDictionary<string, string>? headers = null) =>
        new("answer", status, body as string ?? JsonSerializer.Serialize(body), "application/json", headers);

    public static StubReply Text(string body, int status, string contentType = "text/plain", IReadOnlyDictionary<string, string>? headers = null) =>
        new("answer", status, body, contentType, headers);

    /// <summary>A KYC envelope around <paramref name="data"/>.</summary>
    public static StubReply Kyc(object data, IReadOnlyList<string>? warnings = null) =>
        Json(new { ok = true, request_id = "req_abc", latency_ms = 12, data, warnings = warnings ?? [], error = (object?)null });

    /// <summary>The API's error body.</summary>
    public static StubReply Error(int status, string code, string message, string? param = null, IReadOnlyDictionary<string, string>? headers = null) =>
        Json(new { ok = false, request_id = "req_err", error = param is null ? (object)new { code, message } : new { code, message, param }, warnings = Array.Empty<string>(), data = (object?)null }, status, headers);
}

/// <summary>
/// A minimal HTTP/1.1 server on a real socket, so the tests see what a client sees on the network: answers,
/// connections dropped or reset after the request arrived, and requests that never get an answer.
/// </summary>
public sealed class StubServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly Func<StubRequest, int, StubReply> _handler;
    private readonly CancellationTokenSource _stop = new();
    private readonly List<StubRequest> _requests = [];
    private readonly List<Socket> _sockets = [];
    private readonly Task _accepting;

    private StubServer(Func<StubRequest, int, StubReply> handler)
    {
        _handler = handler;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        BaseUrl = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";
        _accepting = AcceptAsync();
    }

    public string BaseUrl { get; }

    public IReadOnlyList<StubRequest> Requests
    {
        get
        {
            lock (_requests) return [.. _requests];
        }
    }

    /// <summary>Starts a stub; <paramref name="handler"/> gets each request and its number (1, 2, …).</summary>
    public static StubServer Start(Func<StubRequest, int, StubReply> handler) => new(handler);

    /// <summary>Starts a stub that answers every request the same way.</summary>
    public static StubServer Start(StubReply reply) => new((_, _) => reply);

    /// <summary>A base URL where nothing listens: connections are refused.</summary>
    public static string ClosedUrl()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return $"http://127.0.0.1:{port}";
    }

    private async Task AcceptAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await _listener.AcceptSocketAsync(_stop.Token);
            }
            catch (Exception) when (_stop.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException)
            {
                return;
            }
            lock (_sockets) _sockets.Add(socket);
            _ = Task.Run(() => ServeAsync(socket));
        }
    }

    private async Task ServeAsync(Socket socket)
    {
        var buffer = new List<byte>();
        var chunk = new byte[64 * 1024];
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var request = await ReadRequestAsync(socket, buffer, chunk);
                if (request is null) return;
                int number;
                lock (_requests)
                {
                    _requests.Add(request);
                    number = _requests.Count;
                }
                var reply = _handler(request, number);
                switch (reply.Kind)
                {
                    case "drop":
                        socket.Shutdown(SocketShutdown.Both);
                        socket.Close();
                        return;
                    case "reset":
                        socket.LingerState = new LingerOption(true, 0);
                        socket.Close();
                        return;
                    case "hang":
                        // never answer: wait until the client gives up (closes) or the stub stops
                        while (await socket.ReceiveAsync(chunk, SocketFlags.None, _stop.Token) > 0)
                        {
                        }
                        socket.Close();
                        return;
                }
                var body = Encoding.UTF8.GetBytes(reply.Body);
                var head = new StringBuilder()
                    .Append($"HTTP/1.1 {reply.Status} {Reason(reply.Status)}\r\n")
                    .Append($"Content-Type: {reply.ContentType}\r\n")
                    .Append($"Content-Length: {body.Length}\r\n")
                    .Append("Connection: keep-alive\r\n");
                foreach (var (name, value) in reply.Headers) head.Append($"{name}: {value}\r\n");
                head.Append("\r\n");
                await socket.SendAsync(Encoding.ASCII.GetBytes(head.ToString()), SocketFlags.None, _stop.Token);
                await socket.SendAsync(body, SocketFlags.None, _stop.Token);
            }
        }
        catch (Exception) when (_stop.IsCancellationRequested)
        {
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        finally
        {
            socket.Dispose();
        }
    }

    private async Task<StubRequest?> ReadRequestAsync(Socket socket, List<byte> buffer, byte[] chunk)
    {
        int headerEnd;
        while ((headerEnd = IndexOf(buffer, "\r\n\r\n"u8)) < 0)
        {
            var n = await socket.ReceiveAsync(chunk, SocketFlags.None, _stop.Token);
            if (n == 0) return null;
            buffer.AddRange(chunk.AsSpan(0, n).ToArray());
        }
        var head = Encoding.ASCII.GetString(buffer.GetRange(0, headerEnd).ToArray()).Split("\r\n");
        buffer.RemoveRange(0, headerEnd + 4);
        var line = head[0].Split(' ');
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in head.Skip(1))
        {
            var colon = header.IndexOf(':');
            if (colon <= 0) continue;
            var name = header[..colon].Trim();
            var value = header[(colon + 1)..].Trim();
            headers[name] = headers.TryGetValue(name, out var earlier) ? $"{earlier}, {value}" : value;
        }

        byte[] body;
        if (headers.TryGetValue("Transfer-Encoding", out var encoding) && encoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            var decoded = new List<byte>();
            while (true)
            {
                int lineEnd;
                while ((lineEnd = IndexOf(buffer, "\r\n"u8)) < 0) await FillAsync(socket, buffer, chunk);
                var size = Convert.ToInt32(Encoding.ASCII.GetString(buffer.GetRange(0, lineEnd).ToArray()).Split(';')[0].Trim(), 16);
                buffer.RemoveRange(0, lineEnd + 2);
                while (buffer.Count < size + 2) await FillAsync(socket, buffer, chunk);
                decoded.AddRange(buffer.GetRange(0, size));
                buffer.RemoveRange(0, size + 2);
                if (size == 0) break;
            }
            body = [.. decoded];
        }
        else
        {
            var length = headers.TryGetValue("Content-Length", out var text) ? int.Parse(text, System.Globalization.CultureInfo.InvariantCulture) : 0;
            while (buffer.Count < length) await FillAsync(socket, buffer, chunk);
            body = buffer.GetRange(0, length).ToArray();
            buffer.RemoveRange(0, length);
        }
        return new StubRequest(line[0], line.Length > 1 ? line[1] : "/", headers, body);
    }

    private async Task FillAsync(Socket socket, List<byte> buffer, byte[] chunk)
    {
        var n = await socket.ReceiveAsync(chunk, SocketFlags.None, _stop.Token);
        if (n == 0) throw new SocketException((int)SocketError.ConnectionReset);
        buffer.AddRange(chunk.AsSpan(0, n).ToArray());
    }

    private static int IndexOf(List<byte> buffer, ReadOnlySpan<byte> needle)
    {
        for (var i = 0; i + needle.Length <= buffer.Count; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length && match; j++) match = buffer[i + j] == needle[j];
            if (match) return i;
        }
        return -1;
    }

    private static string Reason(int status) => status switch
    {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    };

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        _listener.Stop();
        lock (_sockets)
        {
            foreach (var socket in _sockets)
            {
                try
                {
                    socket.Close();
                }
                catch (ObjectDisposedException)
                {
                }
            }
        }
        try
        {
            await _accepting;
        }
        catch (Exception) when (_stop.IsCancellationRequested)
        {
        }
        _stop.Dispose();
    }
}
