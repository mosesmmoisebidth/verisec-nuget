using System.Text.Json;
using System.Text.Json.Serialization;
using VeriSec.Core;

namespace VeriSec;

/// <summary>
/// A file to upload: the <c>image</c> of the Financial reads (cheques and cards), sent as
/// <c>multipart/form-data</c>. Build one from a path, bytes or a stream. JPG, PNG or BMP, up to 10 MB.
/// </summary>
/// <remarks>Nothing is read until the call is made; a path with no file fails the call before anything is sent.</remarks>
/// <example>
/// <code>
/// var cheque = await client.Cheques.ReadAsync(new ChequeReadParams { Image = FileInput.FromPath("cheque.jpg") });
/// var card = await client.Cards.ReadAsync(new CardReadParams { Image = FileInput.FromBytes(bytes, "card.jpg") });
/// </code>
/// </example>
[JsonConverter(typeof(FileInputJsonConverter))]
public sealed class FileInput
{
    private readonly string? _path;
    private readonly Stream? _stream;
    private readonly SemaphoreSlim? _streamGate;
    private byte[]? _bytes;

    private FileInput(string fileName, string? contentType, string? path, Stream? stream, byte[]? bytes)
    {
        FileName = fileName;
        ContentType = contentType;
        _path = path;
        _stream = stream;
        _bytes = bytes;
        if (stream is not null) _streamGate = new SemaphoreSlim(1, 1);
    }

    /// <summary>The file name sent with the upload.</summary>
    public string FileName { get; }

    /// <summary>The media type you set. When null, it is detected from the file's first bytes.</summary>
    public string? ContentType { get; }

    /// <summary>A file on disk, read when the call is made. Its name is sent as the file name.</summary>
    /// <param name="path">The file's path, such as <c>cheque.jpg</c>.</param>
    /// <param name="contentType">The media type. Detected from the bytes when left out.</param>
    public static FileInput FromPath(string path, string? contentType = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return new FileInput(Path.GetFileName(path), contentType, path, null, null);
    }

    /// <summary>Bytes already in memory.</summary>
    /// <param name="bytes">The file's bytes.</param>
    /// <param name="fileName">The file name to send, such as <c>cheque.jpg</c>.</param>
    /// <param name="contentType">The media type. Detected from the bytes when left out.</param>
    public static FileInput FromBytes(byte[] bytes, string fileName = "image", string? contentType = null)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        return new FileInput(fileName, contentType, null, null, bytes);
    }

    /// <summary>
    /// A stream, read from its current position to its end the first time the file is sent (the bytes are kept, so
    /// the same <see cref="FileInput"/> can be sent again). The stream is not closed: it stays yours to dispose.
    /// </summary>
    /// <param name="stream">A readable stream of the file.</param>
    /// <param name="fileName">The file name to send, such as <c>card.jpg</c>.</param>
    /// <param name="contentType">The media type. Detected from the bytes when left out.</param>
    public static FileInput FromStream(Stream stream, string fileName = "image", string? contentType = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        if (!stream.CanRead) throw new ArgumentException("The stream can't be read.", nameof(stream));
        return new FileInput(fileName, contentType, null, stream, null);
    }

    /// <inheritdoc/>
    public override string ToString() => _path is not null ? $"FileInput.FromPath({_path})" : $"FileInput({FileName})";

    /// <summary>The bytes, file name and media type to send.</summary>
    /// <param name="field">The form field, for the error message.</param>
    /// <param name="cancellationToken">Cancels reading the file or stream.</param>
    internal async Task<FilePart> ReadAsync(string field, CancellationToken cancellationToken)
    {
        var bytes = _bytes;
        if (bytes is null && _path is not null)
        {
            if (!File.Exists(_path)) throw new VeriSecException($"{field}: there is no file at {_path}.");
            try
            {
                bytes = await File.ReadAllBytesAsync(_path, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new VeriSecException($"{field}: could not read {_path}: {e.Message}", e);
            }
        }
        else if (bytes is null)
        {
            await _streamGate!.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_bytes is null)
                {
                    using var buffer = new MemoryStream();
                    await _stream!.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
                    _bytes = buffer.ToArray();
                }
                bytes = _bytes;
            }
            finally
            {
                _streamGate.Release();
            }
        }
        return new FilePart(bytes, FileName, string.IsNullOrEmpty(ContentType) ? MediaTypes.Sniff(bytes) : ContentType!);
    }
}

/// <summary>A file read into memory, ready for a multipart body.</summary>
internal sealed record FilePart(byte[] Bytes, string FileName, string ContentType);

/// <summary>A <see cref="FileInput"/> in JSON (a logged request): written as its description; files are not read from JSON.</summary>
internal sealed class FileInputJsonConverter : JsonConverter<FileInput>
{
    public override FileInput Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new JsonException("A file to upload can't be read from JSON: use FileInput.FromPath, FromBytes or FromStream.");

    public override void Write(Utf8JsonWriter writer, FileInput value, JsonSerializerOptions options) => writer.WriteStringValue(value.ToString());
}
