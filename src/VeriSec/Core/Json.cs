using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace VeriSec.Core;

/// <summary>The one JSON configuration the library reads and writes with.</summary>
internal static class Json
{
    /// <summary>
    /// No naming policy: every generated property carries its exact API name (the API mixes <c>detectAll</c> and
    /// <c>image_front</c>, and both go on the wire unchanged). Unset (null) properties are left out, so an optional
    /// field is only sent when you set it. Numbers sent as strings are still read. <c>&lt;</c> and non-ASCII text
    /// (MRZ lines, names) are written as they are rather than as <c>\u</c> escapes.
    /// </summary>
    public static readonly JsonSerializerOptions Options = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
            PropertyNameCaseInsensitive = false,
            TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
        };
        options.MakeReadOnly();
        return options;
    }

    /// <summary>A scalar as the text of a query parameter or a form field: invariant numbers, <c>true</c>/<c>false</c>, raw JSON otherwise.</summary>
    public static string? Text(object? value) => value switch
    {
        null => null,
        string s => s,
        bool b => b ? "true" : "false",
        IFormattable f when value is not Enum => f.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
        JsonElement { ValueKind: JsonValueKind.String } e => e.GetString(),
        JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,
        JsonElement e => e.GetRawText(),
        _ => JsonSerializer.Serialize(value, value.GetType(), Options),
    };
}
