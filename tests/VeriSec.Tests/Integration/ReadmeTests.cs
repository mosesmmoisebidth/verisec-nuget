using System.Text.Json.Serialization;
using VeriSec.Tests.Support;

namespace VeriSec.Tests.Integration;

/// <summary>The README's samples, as written there (file names swapped for the test image), against the test server.</summary>
[Collection(ServerCollection.Name)]
public sealed class ReadmeTests(TestServer server) : IAsyncLifetime
{
    public Task InitializeAsync() => server.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task KYC_response_info_and_full_results()
    {
        using var client = server.Client();
        var idPhotoBytes = Assets.Png;
        var selfie = Assets.PngPath;

        var result = await client.Face.VerifyAsync(new FaceVerifyParams
        {
            Image1 = Image.FromPath(selfie),
            Image2 = Image.FromBytes(idPhotoBytes),
            Threshold = 0.8,
        });
        Assert.NotNull(result.Match);
        Assert.NotNull(result.Similarity);

        var match = await client.Face.MatchAsync(new FaceMatchParams { Images = [Image.FromPath(selfie), Image.FromPath(selfie)] });
        Assert.True(match.ContainsKey("results"));

        var doc = await client.Documents.ReadAsync(new DocumentReadParams { ImageFront = Image.FromPath(selfie), ImageBack = Image.FromPath(selfie) });
        Assert.True(doc.Count > 0);

        var mrz = await client.Mrz.ParseAsync(new MrzParseParams
        {
            Lines = ["P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"],
        });
        Assert.NotNull(mrz.Parsed);

        Assert.StartsWith("req_", result.LastResponse.RequestId);
        Assert.NotNull(result.LastResponse.LatencyMs);
        Assert.NotNull(result.LastResponse.Warnings);
        Assert.Equal(200, result.LastResponse.Status);

        var screening = await client.Screening.SanctionsAsync(new ScreeningSanctionsParams { Name = "Jane Example" });
        Assert.Equal(1, screening["summary"].GetProperty("matches").GetInt32());
        Assert.Contains(screening["results"].EnumerateArray(), hit => hit.GetProperty("name").GetString() == "Jane EXAMPLE");
        Assert.Equal(1, screening.Get<MySummary>("summary")!.Matches);
        Assert.Equal("Jane Example", screening.Deserialize<MyScreening>()!.Query!.Name);
        Assert.Contains("\"summary\"", screening.Raw.GetRawText());
    }

    [Fact]
    public async Task Financial_errors_retries_and_webhooks()
    {
        using var client = server.Client();
        var bytes = Assets.Png;

        var cheque = await client.Cheques.ReadAsync(new ChequeReadParams { Image = FileInput.FromPath(Assets.PngPath) });
        Assert.Equal("2450 to Keza Amani, MICR A123456780A4821093755C1042", $"{cheque.Vision?.Amount?.Numeric} to {cheque.Vision?.Payee}, MICR {cheque.Micr?.Micr?.Text}");

        var line = await client.Cheques.MicrLineAsync(new ChequeMicrLineParams { Image = FileInput.FromBytes(bytes, "cheque.jpg"), Format = "e13b" });
        var card = await client.Cards.CheckAsync(new CardCheckParams { Number = "4242 4242 4242 4242", Expiry = "09/29" });
        var bin = await client.Bin.LookupAsync("424242");
        var bank = await client.Banks.LookupAsync(new BankLookupParams { Name = "Harbor Point Bank", Country = "US" });
        Assert.Equal(("micr_line", "card_check", "Visa", "bank_lookup"), (line.Object, card.Object, bin.Network, bank.Object));

        using var poor = server.Client(new VeriSecOptions { ApiKey = "sk_test_nocredits" });
        var caught = "";
        try
        {
            await poor.Face.VerifyAsync(new FaceVerifyParams { Image1 = Image.FromBytes(bytes), Image2 = Image.FromBytes(bytes) });
        }
        catch (InsufficientCreditsException)
        {
            caught = "Top up credits in the console.";
        }
        catch (ApiException e)
        {
            caught = $"{e.Status} {e.Code} {e.RequestId}";
        }
        Assert.Equal("Top up credits in the console.", caught);

        using var cancel = new CancellationTokenSource();
        var again = await client.Cheques.ReadAsync(new ChequeReadParams { Image = FileInput.FromPath(Assets.PngPath) },
            new RequestOptions { Timeout = TimeSpan.FromMinutes(6), MaxRetries = 0, Headers = { ["X-Trace"] = "abc" } },
            cancel.Token);
        Assert.Equal("cheque_read", again.Object);
        Assert.Equal("abc", (await server.RequestsAsync())[^1].GetProperty("headers").GetProperty("x-trace").GetString());

        var delivery = await server.WebhookAsync();
        var headers = delivery.GetProperty("headers");
        var body = delivery.GetProperty("body").GetString()!;
        var secret = delivery.GetProperty("secret").GetString()!;
        var evt = Webhooks.ConstructEvent(body, name => headers.TryGetProperty(name, out var value) ? value.GetString() : null, secret);
        Assert.Equal("verification.completed", evt.Type);
        Assert.Equal("approved", evt.Data.GetProperty("decision").GetString());
    }

    private sealed class MySummary
    {
        [JsonPropertyName("matches")]
        public int Matches { get; init; }
    }

    private sealed class MyScreening
    {
        [JsonPropertyName("query")]
        public MyQuery? Query { get; init; }
    }

    private sealed class MyQuery
    {
        [JsonPropertyName("name")]
        public string? Name { get; init; }
    }
}
