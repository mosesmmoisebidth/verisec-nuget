using System.Collections;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;

namespace VeriSec.Core;

/// <summary>
/// Builds a request's JSON from the caller's parameters: a new tree with the API's field names, unset fields left
/// out, every <see cref="Image"/> read and written as plain base64, and image lists filled in (index and ids). The
/// caller's objects are never changed.
/// </summary>
internal static class RequestBody
{
    public static async Task<byte[]> SerializeAsync(object parameters, ImagePlan images, CancellationToken cancellationToken)
    {
        var node = await ToNodeAsync(parameters, "", cancellationToken).ConfigureAwait(false);
        images.Apply(node);
        return JsonSerializer.SerializeToUtf8Bytes(node, Json.Options);
    }

    /// <summary>One value as JSON. <paramref name="path"/> is where it sits (<c>images[0].data</c>), for error messages.</summary>
    internal static async ValueTask<JsonNode?> ToNodeAsync(object? value, string path, CancellationToken cancellationToken)
    {
        switch (value)
        {
            case null:
                return null;
            case Image image:
                return JsonValue.Create(await image.ToBase64Async(path.Length == 0 ? "image" : path, cancellationToken).ConfigureAwait(false));
            case FileInput:
                throw new VeriSecException($"{path}: a FileInput is only for the Financial uploads; KYC images are an Image.");
            case string text:
                return JsonValue.Create(text);
            case JsonNode node:
                return node.DeepClone();
            case JsonElement element:
                return element.ValueKind is JsonValueKind.Undefined ? null : JsonNode.Parse(element.GetRawText());
        }

        // objects, lists and dictionaries are walked (so an image anywhere in them is read and encoded), with the
        // names and rules System.Text.Json would use; anything else (numbers, booleans, types with their own
        // converter) is written by System.Text.Json itself
        var type = value.GetType();
        var info = Json.Options.GetTypeInfo(type);
        switch (info.Kind)
        {
            case JsonTypeInfoKind.Object:
            {
                var result = new JsonObject();
                foreach (var property in info.Properties)
                {
                    if (property.Get is null) continue;
                    var member = property.Get(value);
                    if (member is null || (property.ShouldSerialize is { } include && !include(value, member))) continue;
                    if (property.IsExtensionData)
                    {
                        foreach (var (key, extra) in Entries(member))
                        {
                            if (extra is not null) result[key] = await ToNodeAsync(extra, Join(path, key), cancellationToken).ConfigureAwait(false);
                        }
                        continue;
                    }
                    result[property.Name] = await ToNodeAsync(member, Join(path, property.Name), cancellationToken).ConfigureAwait(false);
                }
                return result;
            }
            case JsonTypeInfoKind.Dictionary when value is IDictionary dictionary:
            {
                var result = new JsonObject();
                foreach (DictionaryEntry entry in dictionary)
                {
                    var key = Convert.ToString(entry.Key, System.Globalization.CultureInfo.InvariantCulture) ?? "";
                    result[key] = await ToNodeAsync(entry.Value, Join(path, key), cancellationToken).ConfigureAwait(false);
                }
                return result;
            }
            case JsonTypeInfoKind.Enumerable when value is IEnumerable items:
            {
                var array = new JsonArray();
                var i = 0;
                foreach (var item in items) array.Add(await ToNodeAsync(item, $"{path}[{i++}]", cancellationToken).ConfigureAwait(false));
                return array;
            }
            default:
                return JsonSerializer.SerializeToNode(value, type, Json.Options);
        }
    }

    private static string Join(string path, string name) => path.Length == 0 ? name : $"{path}.{name}";

    private static IEnumerable<KeyValuePair<string, object?>> Entries(object dictionary) => dictionary switch
    {
        IEnumerable<KeyValuePair<string, object?>> objects => objects,
        IEnumerable<KeyValuePair<string, JsonElement>> elements => elements.Select(e => new KeyValuePair<string, object?>(e.Key, e.Value)),
        IDictionary legacy => legacy.Keys.Cast<object>().Select(k => new KeyValuePair<string, object?>(k.ToString()!, legacy[k])),
        _ => [],
    };
}

/// <summary>An image list of a request (<c>x-verisec-image-list</c> in the spec) whose entries are objects.</summary>
/// <param name="Path">Where the list sits, dotted when nested (<c>images</c>, <c>gallery</c>).</param>
/// <param name="ImageKey">The entry field that holds the image (<c>data</c>, <c>image</c>).</param>
/// <param name="IndexKey">The entry field set to the entry's position when left out (<c>index</c>).</param>
/// <param name="IdKey">The entry field set to <c>&lt;ItemLabel&gt;-1</c>, <c>-2</c>, … when left out or empty (<c>id</c>).</param>
/// <param name="ItemLabel">The id prefix (<c>face</c>, <c>image</c>).</param>
internal sealed record ImageList(string Path, string ImageKey, string? IndexKey = null, string? IdKey = null, string? ItemLabel = null);

/// <summary>Where an operation's image lists are, generated from the spec; applied to the JSON before it is sent.</summary>
internal sealed class ImagePlan
{
    public static readonly ImagePlan None = new();

    private readonly ImageList[] _lists;

    public ImagePlan(params ImageList[] lists) => _lists = lists;

    public IReadOnlyList<ImageList> Lists => _lists;

    /// <summary>Fills each list entry's index and id when the caller left them out, as the Playground does.</summary>
    public void Apply(JsonNode? root)
    {
        foreach (var list in _lists)
        {
            JsonNode? node = root;
            foreach (var key in list.Path.Split('.')) node = node is JsonObject obj && obj.TryGetPropertyValue(key, out var next) ? next : null;
            if (node is not JsonArray entries) continue;
            for (var i = 0; i < entries.Count; i++)
            {
                if (entries[i] is not JsonObject entry) continue;
                if (list.IndexKey is { } indexKey && !entry.ContainsKey(indexKey)) entry[indexKey] = i;
                if (list.IdKey is { } idKey && (!entry.TryGetPropertyValue(idKey, out var id) || id is null || (id is JsonValue v && v.TryGetValue<string>(out var s) && s.Length == 0)))
                {
                    entry[idKey] = $"{list.ItemLabel ?? "item"}-{i + 1}";
                }
            }
        }
    }
}
