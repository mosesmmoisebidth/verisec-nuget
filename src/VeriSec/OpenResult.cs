using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using VeriSec.Core;

namespace VeriSec;

/// <summary>
/// The engine's full result, for the APIs that return everything they found (Face Analyze, Face Match, Document
/// Read, Sanctions Screening, …): an open set of fields rather than a fixed class, so nothing the engine sends is
/// lost and a new field never breaks your code. Read it as a dictionary of <see cref="JsonElement"/>, one field
/// as your own type with <see cref="Get{T}(string)"/>, the whole of it with <see cref="Deserialize{T}"/>, or the
/// JSON as it came with <see cref="Raw"/>.
/// </summary>
/// <example>
/// <code>
/// var doc = await client.Documents.ReadAsync(new DocumentReadParams { ImageFront = Image.FromPath("id-front.jpg") });
/// if (doc.TryGetValue("status", out var status)) Console.WriteLine(status);
/// var fields = doc.Get&lt;List&lt;MyField&gt;&gt;("fields");
/// Console.WriteLine(doc.LastResponse.RequestId);
/// </code>
/// </example>
public abstract class OpenResult : ApiResult, IReadOnlyDictionary<string, JsonElement>
{
    private static readonly JsonElement EmptyObject = JsonDocument.Parse("{}").RootElement.Clone();

    private JsonElement _raw = EmptyObject;
    private Dictionary<string, JsonElement>? _fields;

    /// <summary>Only the library's generated results derive from this type.</summary>
    private protected OpenResult()
    {
    }

    /// <summary>The result exactly as the API sent it (a JSON object; empty when the answer had no data).</summary>
    public JsonElement Raw => _raw;

    /// <summary>One top-level field of the result.</summary>
    /// <param name="key">The field name, as the API spells it.</param>
    /// <exception cref="KeyNotFoundException">The result has no such field.</exception>
    public JsonElement this[string key] =>
        Fields.TryGetValue(key, out var value) ? value : throw new KeyNotFoundException($"The result has no field '{key}'.");

    /// <summary>The names of the top-level fields, in the order the API sent them.</summary>
    public IEnumerable<string> Keys => Fields.Keys;

    /// <summary>The values of the top-level fields.</summary>
    public IEnumerable<JsonElement> Values => Fields.Values;

    /// <summary>How many top-level fields the result has.</summary>
    public int Count => Fields.Count;

    private Dictionary<string, JsonElement> Fields
    {
        get
        {
            if (_fields is not null) return _fields;
            var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            if (_raw.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in _raw.EnumerateObject()) fields[property.Name] = property.Value;
            }
            return _fields = fields;
        }
    }

    /// <summary>True when the result has the field.</summary>
    /// <param name="key">The field name, as the API spells it.</param>
    public bool ContainsKey(string key) => Fields.ContainsKey(key);

    /// <summary>One top-level field, when the result has it.</summary>
    /// <param name="key">The field name, as the API spells it.</param>
    /// <param name="value">The field's value.</param>
    public bool TryGetValue(string key, [MaybeNullWhen(false)] out JsonElement value) => Fields.TryGetValue(key, out value);

    /// <summary>One top-level field as <typeparamref name="T"/>, or <c>default</c> when it is missing or null.</summary>
    /// <typeparam name="T">The type to read the field as, such as <see cref="string"/>, <see cref="double"/> or a class of yours.</typeparam>
    /// <param name="key">The field name, as the API spells it.</param>
    /// <exception cref="JsonException">The field's JSON does not fit <typeparamref name="T"/>.</exception>
    public T? Get<T>(string key) =>
        Fields.TryGetValue(key, out var value) && value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined)
            ? value.Deserialize<T>(Json.Options)
            : default;

    /// <summary>The whole result as <typeparamref name="T"/>, a class of yours with the fields you need.</summary>
    /// <typeparam name="T">The type to read the result as.</typeparam>
    /// <exception cref="JsonException">The result's JSON does not fit <typeparamref name="T"/>.</exception>
    public T? Deserialize<T>() => _raw.Deserialize<T>(Json.Options);

    /// <inheritdoc/>
    public IEnumerator<KeyValuePair<string, JsonElement>> GetEnumerator() => Fields.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>The result as JSON, exactly as the API sent it.</summary>
    public override string ToString() => _raw.GetRawText();

    internal void SetRaw(JsonElement raw)
    {
        _raw = raw;
        _fields = null;
    }
}

/// <summary>Reads an <see cref="OpenResult"/> as the JSON it is, and writes it back unchanged.</summary>
/// <typeparam name="T">The generated result type.</typeparam>
internal sealed class OpenResultConverter<T> : JsonConverter<T>
    where T : OpenResult, new()
{
    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        var result = new T();
        result.SetRaw(document.RootElement.Clone());
        return result;
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options) => value.Raw.WriteTo(writer);
}
