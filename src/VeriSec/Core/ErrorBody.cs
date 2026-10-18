using System.Text;
using System.Text.Json;

namespace VeriSec.Core;

/// <summary>
/// What a failed answer says, from any of the shapes the API and the gateway use: the API's
/// <c>{ok: false, request_id, error: {code, message, param}}</c>, a bare <c>{error: {code, message}}</c>,
/// <c>{error: "…", code}</c>, a validation <c>{detail: "…" | [{loc, msg}]}</c>, the gateway's <c>{error_msg}</c>,
/// or plain text.
/// </summary>
internal readonly record struct ErrorBody(string? Code, string? Message, string? Param, string? RequestId)
{
    public static ErrorBody Read(byte[] body)
    {
        if (body.Length == 0) return default;
        JsonElement root;
        try
        {
            using var document = JsonDocument.Parse(body);
            root = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            var text = Encoding.UTF8.GetString(body).Trim();
            return new ErrorBody(null, text.Length > 500 ? text[..500] : text.Length == 0 ? null : text, null, null);
        }
        return Read(root);
    }

    public static ErrorBody Read(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.String) return new ErrorBody(null, root.GetString(), null, null);
        if (root.ValueKind != JsonValueKind.Object) return default;
        var requestId = Field(root, "request_id");

        if (root.TryGetProperty("error", out var error))
        {
            if (error.ValueKind == JsonValueKind.Object) return new ErrorBody(Field(error, "code"), Field(error, "message"), Field(error, "param"), requestId);
            if (error.ValueKind == JsonValueKind.String) return new ErrorBody(Field(root, "code"), error.GetString(), null, requestId);
        }
        if (root.TryGetProperty("detail", out var detail))
        {
            if (detail.ValueKind == JsonValueKind.String) return new ErrorBody("invalid_input", detail.GetString(), null, requestId);
            if (detail.ValueKind == JsonValueKind.Array && detail.GetArrayLength() > 0)
            {
                var first = detail[0];
                string? param = null;
                if (first.ValueKind == JsonValueKind.Object && first.TryGetProperty("loc", out var loc) && loc.ValueKind == JsonValueKind.Array)
                {
                    var parts = loc.EnumerateArray()
                        .Select(part => part.ValueKind == JsonValueKind.String ? part.GetString() : part.GetRawText())
                        .Where(part => part != "body");
                    param = string.Join(".", parts);
                    if (param.Length == 0) param = null;
                }
                var message = first.ValueKind == JsonValueKind.Object ? Field(first, "msg") : null;
                return new ErrorBody("invalid_input", message ?? "The request is not valid.", param, requestId);
            }
        }
        if (Field(root, "error_msg") is { } gateway) return new ErrorBody(null, gateway, null, requestId);
        return new ErrorBody(null, null, null, requestId);
    }

    private static string? Field(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
