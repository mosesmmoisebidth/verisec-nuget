using System.Collections;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace VeriSec.Core;

/// <summary>
/// A <c>multipart/form-data</c> body, read once before the first attempt and rebuilt, unchanged, for each retry:
/// every <see cref="FileInput"/> of the parameters as a file part under its field name (<c>image</c>), every other
/// set field as a text part (<c>format=e13b</c>).
/// </summary>
internal sealed class MultipartBody
{
    private readonly List<(string Name, FilePart File)> _files = [];
    private readonly List<(string Name, string Value)> _fields = [];

    public IReadOnlyList<(string Name, FilePart File)> Files => _files;

    public IReadOnlyList<(string Name, string Value)> Fields => _fields;

    public static async Task<MultipartBody> PrepareAsync(object parameters, CancellationToken cancellationToken)
    {
        var body = new MultipartBody();
        var info = Json.Options.GetTypeInfo(parameters.GetType());
        foreach (var property in info.Properties)
        {
            if (property.Get is null) continue;
            var value = property.Get(parameters);
            if (value is null) continue;
            if (property.IsExtensionData)
            {
                foreach (var (key, extra) in Entries(value)) body.Add(key, extra);
                continue;
            }
            if (value is FileInput file)
            {
                body._files.Add((property.Name, await file.ReadAsync(property.Name, cancellationToken).ConfigureAwait(false)));
                continue;
            }
            body.Add(property.Name, value);
        }
        return body;
    }

    private void Add(string name, object? value)
    {
        if (value is null) return;
        if (value is not string && value is IEnumerable list)
        {
            foreach (var item in list) Add(name, item);
            return;
        }
        if (Json.Text(value) is { } text) _fields.Add((name, text));
    }

    public HttpContent CreateContent()
    {
        var form = new MultipartFormDataContent();
        foreach (var (name, file) in _files)
        {
            var part = new ByteArrayContent(file.Bytes);
            part.Headers.ContentType = MediaTypeHeaderValue.Parse(file.ContentType);
            var disposition = new ContentDispositionHeaderValue("form-data") { Name = Quote(name), FileName = Quote(Ascii(file.FileName)) };
            if (!IsAscii(file.FileName)) disposition.FileNameStar = file.FileName;
            part.Headers.ContentDisposition = disposition;
            form.Add(part);
        }
        foreach (var (name, value) in _fields)
        {
            var part = new ByteArrayContent(Encoding.UTF8.GetBytes(value));
            part.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data") { Name = Quote(name) };
            form.Add(part);
        }
        return form;
    }

    private static IEnumerable<KeyValuePair<string, object?>> Entries(object dictionary) => dictionary switch
    {
        IEnumerable<KeyValuePair<string, object?>> objects => objects,
        IEnumerable<KeyValuePair<string, JsonElement>> elements => elements.Select(e => new KeyValuePair<string, object?>(e.Key, e.Value)),
        _ => [],
    };

    private static string Quote(string value) => $"\"{value.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"";

    private static bool IsAscii(string value) => value.All(c => c >= 0x20 && c < 0x7F);

    private static string Ascii(string value) => IsAscii(value) ? value : new string(value.Select(c => c >= 0x20 && c < 0x7F ? c : '_').ToArray());
}

/// <summary>A query string from a parameters object: set fields only, lists repeated, values as invariant text.</summary>
internal static class QueryString
{
    public static string Of(object? parameters)
    {
        if (parameters is null) return "";
        var pairs = new List<string>();
        var info = Json.Options.GetTypeInfo(parameters.GetType());
        foreach (var property in info.Properties)
        {
            if (property.Get is null) continue;
            var value = property.Get(parameters);
            if (value is null) continue;
            if (property.IsExtensionData && value is IEnumerable<KeyValuePair<string, object?>> extra)
            {
                foreach (var (key, item) in extra) Add(pairs, key, item);
                continue;
            }
            Add(pairs, property.Name, value);
        }
        return pairs.Count == 0 ? "" : "?" + string.Join("&", pairs);
    }

    private static void Add(List<string> pairs, string name, object? value)
    {
        if (value is null) return;
        if (value is not string && value is IEnumerable list)
        {
            foreach (var item in list) Add(pairs, name, item);
            return;
        }
        if (Json.Text(value) is { } text) pairs.Add($"{Uri.EscapeDataString(name)}={Uri.EscapeDataString(text)}");
    }
}
