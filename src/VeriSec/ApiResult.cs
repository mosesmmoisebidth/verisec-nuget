using System.Text.Json;
using System.Text.Json.Serialization;
using VeriSec.Core;

namespace VeriSec;

/// <summary>
/// The base of every answer a method returns: the KYC envelope's <c>data</c> (such as <see cref="FaceVerify"/>), or
/// a Financial object (such as <see cref="CardCheck"/>). <see cref="LastResponse"/> says where it came from.
/// </summary>
public abstract class ApiResult
{
    /// <summary>The status, headers, request id, warnings and latency of the answer this result came from.</summary>
    [JsonIgnore]
    public ResponseInfo LastResponse { get; internal set; } = ResponseInfo.None;

    /// <summary>The result as JSON, with the API's field names.</summary>
    public override string ToString() => JsonSerializer.Serialize(this, GetType(), Json.Options);
}
