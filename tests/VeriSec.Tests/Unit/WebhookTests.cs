using System.Net.Http.Headers;
using System.Text;
using VeriSec.Tests.Support;

namespace VeriSec.Tests.Unit;

/// <summary>Standard Webhooks verification.</summary>
public sealed class WebhookTests
{
    private static readonly string Secret = $"whsec_{Convert.ToBase64String(Encoding.UTF8.GetBytes(new string('a', 24)))}";
    private static readonly string OtherSecret = $"whsec_{Convert.ToBase64String(Encoding.UTF8.GetBytes(new string('b', 24)))}";
    private const string Body = """{"type":"verification.completed","timestamp":"2026-10-17T10:00:00Z","environment":"test","data":{"verification_id":"ver_1","decision":"approved"}}""";

    [Fact]
    public void A_signed_delivery_verifies_and_parses()
    {
        var headers = Webhooks.GenerateTestHeaders(Body, Secret);

        var evt = Webhooks.ConstructEvent(Body, headers, Secret);

        Assert.Equal("verification.completed", evt.Type);
        Assert.Equal("2026-10-17T10:00:00Z", evt.Timestamp);
        Assert.Equal("test", evt.Environment);
        Assert.Equal("approved", evt.Data.GetProperty("decision").GetString());
        Assert.Equal("ver_1", evt.GetData<Dictionary<string, string>>()!["verification_id"]);
        Assert.True(Webhooks.VerifySignature(Encoding.UTF8.GetBytes(Body), headers, Secret));
        Assert.StartsWith("msg_", headers["webhook-id"]);
        Assert.StartsWith("v1,", headers["webhook-signature"]);
    }

    [Fact]
    public void The_Standard_Webhooks_test_vector_verifies()
    {
        // from the Standard Webhooks specification
        const string secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        const string payload = """{"test": 2432232314}""";
        var at = DateTimeOffset.FromUnixTimeSeconds(1614265330);

        var headers = Webhooks.GenerateTestHeaders(payload, secret, "msg_p5jXN8AQM9LWM0D4loKWxJek", at);

        Assert.Equal("v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=", headers["webhook-signature"]);
        Assert.True(Webhooks.VerifySignature(payload, headers, secret, TimeSpan.Zero));
    }

    [Fact]
    public void A_wrong_secret_a_tampered_body_and_a_bad_signature_do_not_verify()
    {
        var headers = Webhooks.GenerateTestHeaders(Body, Secret);

        Assert.False(Webhooks.VerifySignature(Body, headers, OtherSecret));
        Assert.False(Webhooks.VerifySignature(Body.Replace("approved", "declined"), headers, Secret));
        Assert.False(Webhooks.VerifySignature(Body, new Dictionary<string, string>(headers) { ["webhook-signature"] = "v1,not-base64!" }, Secret));
        Assert.False(Webhooks.VerifySignature(Body, new Dictionary<string, string>(headers) { ["webhook-signature"] = headers["webhook-signature"].Replace("v1,", "v2,") }, Secret));
        var e = Assert.Throws<SignatureVerificationException>(() => Webhooks.ConstructEvent(Body, headers, OtherSecret));
        Assert.Contains("No signature matches", e.Message);
    }

    [Fact]
    public void A_stale_timestamp_is_refused_unless_the_tolerance_allows_it()
    {
        var old = Webhooks.GenerateTestHeaders(Body, Secret, timestamp: DateTimeOffset.UtcNow.AddHours(-1));

        var e = Assert.Throws<SignatureVerificationException>(() => Webhooks.ConstructEvent(Body, old, Secret));
        Assert.Contains("tolerance", e.Message);
        Assert.False(Webhooks.VerifySignature(Body, old, Secret));
        Assert.True(Webhooks.VerifySignature(Body, old, Secret, TimeSpan.FromHours(2)));
        Assert.True(Webhooks.VerifySignature(Body, old, Secret, TimeSpan.Zero));
        var future = Webhooks.GenerateTestHeaders(Body, Secret, timestamp: DateTimeOffset.UtcNow.AddMinutes(10));
        Assert.False(Webhooks.VerifySignature(Body, future, Secret));
    }

    [Fact]
    public void Missing_or_malformed_headers_are_refused()
    {
        var headers = Webhooks.GenerateTestHeaders(Body, Secret);

        var e = Assert.Throws<SignatureVerificationException>(() => Webhooks.ConstructEvent(Body, new Dictionary<string, string>(), Secret));
        Assert.Contains("Missing webhook-id", e.Message);
        foreach (var name in new[] { "webhook-id", "webhook-timestamp", "webhook-signature" })
        {
            var partial = new Dictionary<string, string>(headers);
            partial.Remove(name);
            Assert.False(Webhooks.VerifySignature(Body, partial, Secret));
        }
        Assert.Throws<SignatureVerificationException>(() =>
            Webhooks.ConstructEvent(Body, new Dictionary<string, string>(headers) { ["webhook-timestamp"] = "yesterday" }, Secret));
    }

    [Fact]
    public void Several_signatures_any_match_passes_and_svix_names_and_any_casing_work()
    {
        var headers = Webhooks.GenerateTestHeaders(Body, Secret);

        var rotated = new Dictionary<string, string>(headers) { ["webhook-signature"] = $"v1,{new string('A', 43)}= {headers["webhook-signature"]}" };
        Assert.True(Webhooks.VerifySignature(Body, rotated, Secret));

        var svix = new Dictionary<string, string>
        {
            ["svix-id"] = headers["webhook-id"],
            ["svix-timestamp"] = headers["webhook-timestamp"],
            ["svix-signature"] = headers["webhook-signature"],
        };
        Assert.True(Webhooks.VerifySignature(Body, svix, Secret));

        var cased = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Webhook-Id"] = headers["webhook-id"],
            ["WEBHOOK-TIMESTAMP"] = headers["webhook-timestamp"],
            ["Webhook-Signature"] = headers["webhook-signature"],
        };
        Assert.True(Webhooks.VerifySignature(Body, cased, Secret));
    }

    [Fact]
    public void HttpHeaders_and_a_header_lookup_work_like_a_dictionary()
    {
        var headers = Webhooks.GenerateTestHeaders(Body, Secret);
        using var request = new HttpRequestMessage();
        foreach (var (name, value) in headers) request.Headers.TryAddWithoutValidation(name, value);
        HttpHeaders http = request.Headers;

        Assert.Equal("verification.completed", Webhooks.ConstructEvent(Body, http, Secret).Type);
        Assert.True(Webhooks.VerifySignature(Encoding.UTF8.GetBytes(Body), http, Secret));
        Assert.Equal("verification.completed", Webhooks.ConstructEvent(Body, name => headers.TryGetValue(name, out var v) ? v : null, Secret).Type);
        Assert.False(Webhooks.VerifySignature(Body, _ => null, Secret));
    }

    [Fact]
    public void A_secret_that_is_not_whsec_base64_is_an_argument_error()
    {
        var headers = Webhooks.GenerateTestHeaders(Body, Secret);

        Assert.Throws<ArgumentException>(() => Webhooks.VerifySignature(Body, headers, "whsec_not base64!"));
        Assert.Throws<ArgumentException>(() => Webhooks.VerifySignature(Body, headers, ""));
    }
}
