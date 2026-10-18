using System.Text.Json;
using System.Text.Json.Serialization;
using VeriSec.Core;

namespace VeriSec;

/// <summary>
/// An image for a KYC API. The KYC APIs take images as base64 inside the JSON body; build one from a file, bytes,
/// a stream or base64 you already have, and the library sends it the way each API expects (plain base64, no
/// <c>data:</c> prefix). JPEG or PNG.
/// </summary>
/// <remarks>
/// Nothing is read or checked until the call is made. A file that does not exist, or text that is not base64 or a
/// <c>data:</c> URI, fails the call before anything is sent, with a <see cref="VeriSecException"/> naming the field
/// (<c>image1: there is no file at selfie.jpg.</c>).
/// <para>
/// The client reads and encodes images itself. Serializing a request with <see cref="JsonSerializer"/> directly (to
/// log it, say) writes each image as its description (<c>Image.FromPath(selfie.jpg)</c>); reading a request from JSON
/// takes each image as base64 or a <c>data:</c> URI.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// var result = await client.Face.VerifyAsync(new FaceVerifyParams
/// {
///     Image1 = Image.FromPath("selfie.jpg"),
///     Image2 = Image.FromBytes(idPhotoBytes),
/// });
/// </code>
/// </example>
[JsonConverter(typeof(ImageJsonConverter))]
public sealed class Image
{
    private enum Source
    {
        Path,
        Bytes,
        Stream,
        Base64,
    }

    private readonly Source _source;
    private readonly string? _text;
    private readonly byte[]? _bytes;
    private readonly Stream? _stream;
    private readonly SemaphoreSlim? _streamGate;
    private string? _streamBase64;

    private Image(Source source, string? text = null, byte[]? bytes = null, Stream? stream = null)
    {
        _source = source;
        _text = text;
        _bytes = bytes;
        _stream = stream;
        if (stream is not null) _streamGate = new SemaphoreSlim(1, 1);
    }

    /// <summary>An image file on disk, read when the call is made.</summary>
    /// <param name="path">The file's path, such as <c>selfie.jpg</c>.</param>
    public static Image FromPath(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return new Image(Source.Path, text: path);
    }

    /// <summary>The bytes of an image file already in memory (not a copy: they are read when the call is made).</summary>
    /// <param name="bytes">The image file's bytes, JPEG or PNG.</param>
    public static Image FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return new Image(Source.Bytes, bytes: bytes);
    }

    /// <summary>
    /// A stream, read from its current position to its end the first time the image is sent. The bytes are kept,
    /// so the same <see cref="Image"/> can be sent again. The stream is not closed: it stays yours to dispose.
    /// </summary>
    /// <param name="stream">A readable stream of the image file.</param>
    public static Image FromStream(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead) throw new ArgumentException("The stream can't be read.", nameof(stream));
        return new Image(Source.Stream, stream: stream);
    }

    /// <summary>Base64 you already have, or a <c>data:image/…;base64,…</c> URI (the prefix is removed).</summary>
    /// <param name="base64">The base64 text or the <c>data:</c> URI.</param>
    public static Image FromBase64(string base64)
    {
        ArgumentNullException.ThrowIfNull(base64);
        return new Image(Source.Base64, text: base64);
    }

    /// <inheritdoc/>
    public override string ToString() => _source switch
    {
        Source.Path => $"Image.FromPath({_text})",
        Source.Bytes => $"Image.FromBytes({_bytes!.Length} bytes)",
        Source.Stream => "Image.FromStream(…)",
        _ => $"Image.FromBase64({_text!.Length} characters)",
    };

    /// <summary>The image as plain base64, the way the KYC APIs take it.</summary>
    /// <param name="field">Where the image sits in the request, for the error message (<c>images[0].data</c>).</param>
    /// <param name="cancellationToken">Cancels reading a file or stream.</param>
    /// <exception cref="VeriSecException">The file does not exist or can't be read, or the text is not base64.</exception>
    internal async ValueTask<string> ToBase64Async(string field, CancellationToken cancellationToken)
    {
        switch (_source)
        {
            case Source.Path:
                if (!File.Exists(_text)) throw new VeriSecException($"{field}: there is no file at {_text}.");
                try
                {
                    return Convert.ToBase64String(await File.ReadAllBytesAsync(_text!, cancellationToken).ConfigureAwait(false));
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    throw new VeriSecException($"{field}: could not read {_text}: {e.Message}", e);
                }
            case Source.Bytes:
                return Convert.ToBase64String(_bytes!);
            case Source.Stream:
                if (_streamBase64 is not null) return _streamBase64;
                await _streamGate!.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    if (_streamBase64 is null)
                    {
                        using var buffer = new MemoryStream();
                        await _stream!.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
                        _streamBase64 = Convert.ToBase64String(buffer.GetBuffer(), 0, (int)buffer.Length);
                    }
                    return _streamBase64;
                }
                finally
                {
                    _streamGate.Release();
                }
            default:
                return PlainBase64(_text!, field);
        }
    }

    /// <summary>Base64 or a <c>data:</c> URI as plain base64, with whitespace removed.</summary>
    internal static string PlainBase64(string text, string field)
    {
        var value = text.Trim();
        if (value.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            var comma = value.IndexOf(',');
            if (comma < 0 || !value.AsSpan(0, comma).EndsWith(";base64", StringComparison.OrdinalIgnoreCase))
            {
                throw new VeriSecException($"{field}: a data: URI must carry base64 (data:image/jpeg;base64,…).");
            }
            value = value[(comma + 1)..];
        }
        var compact = string.Concat(value.Where(c => !char.IsWhiteSpace(c)));
        if (!IsBase64(compact)) throw new VeriSecException($"{field}: not base64 or a data: URI.");
        return compact;
    }

    private static bool IsBase64(string value)
    {
        if (value.Length == 0 || value.Length % 4 != 0) return false;
        var padding = value.EndsWith("==", StringComparison.Ordinal) ? 2 : value.EndsWith('=') ? 1 : 0;
        for (var i = 0; i < value.Length - padding; i++)
        {
            var c = value[i];
            if (!(char.IsAsciiLetterOrDigit(c) || c == '+' || c == '/')) return false;
        }
        return true;
    }
}

/// <summary>An <see cref="Image"/> in JSON outside the client: written as its description, read as base64.</summary>
internal sealed class ImageJsonConverter : JsonConverter<Image>
{
    public override Image? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.String ? Image.FromBase64(reader.GetString()!) : throw new JsonException("An image is base64 text or a data: URI.");

    public override void Write(Utf8JsonWriter writer, Image value, JsonSerializerOptions options) => writer.WriteStringValue(value.ToString());
}
