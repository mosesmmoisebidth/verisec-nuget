using VeriSec.Tests.Support;

namespace VeriSec.Tests.Unit;

/// <summary>Financial uploads (multipart with <c>X-VeriSec-Source: sdk</c>) and the calls without a body.</summary>
public sealed class UploadTests
{
    public static TheoryData<string, string> Inputs => new()
    {
        { "path", "photo.png" },
        { "bytes", "cheque.png" },
        { "bytes-unnamed", "image" },
        { "stream", "card.png" },
    };

    [Theory]
    [MemberData(nameof(Inputs))]
    public async Task Each_input_goes_as_multipart_with_its_file_name_and_the_source_header(string kind, string fileName)
    {
        await using var stub = StubServer.Start(StubReply.Json(new { @object = "micr_line", status = "read" }));
        using var client = Clients.For(stub);
        var image = kind switch
        {
            "path" => FileInput.FromPath(Assets.PngPath),
            "bytes" => FileInput.FromBytes(Assets.Png, "cheque.png"),
            "bytes-unnamed" => FileInput.FromBytes(Assets.Png),
            _ => FileInput.FromStream(new MemoryStream(Assets.Png), "card.png"),
        };

        var result = await client.Cheques.MicrLineAsync(new ChequeMicrLineParams { Image = image, Format = "e13b" });

        Assert.Equal("micr_line", result.Object);
        var request = Assert.Single(stub.Requests);
        Assert.Equal("/v2/cheques/micr-line", request.Path);
        Assert.Matches("^multipart/form-data; boundary=", request.Header("Content-Type"));
        Assert.Equal("sdk", request.Header("X-VeriSec-Source"));
        Assert.Equal("Bearer sk_test_core", request.Header("Authorization"));
        var raw = request.Raw;
        Assert.Contains($"Content-Disposition: form-data; name=\"image\"; filename=\"{fileName}\"", raw);
        Assert.Contains("Content-Type: image/png", raw);
        Assert.Contains("Content-Disposition: form-data; name=\"format\"\r\n\r\ne13b\r\n", raw);
        Assert.Contains(System.Text.Encoding.Latin1.GetString(Assets.Png), raw);
    }

    [Fact]
    public async Task Optional_fields_left_out_are_not_sent_and_a_set_media_type_wins()
    {
        await using var stub = StubServer.Start(StubReply.Json(new { @object = "card" }));
        using var client = Clients.For(stub);

        await client.Cards.ReadAsync(new CardReadParams { Image = FileInput.FromBytes(Assets.Png, "card.bin", "image/jpeg") });
        await client.Cheques.ReadAsync(new ChequeReadParams { Image = FileInput.FromBytes(Assets.Png) });

        Assert.Contains("Content-Type: image/jpeg", stub.Requests[0].Raw);
        Assert.DoesNotContain("name=\"format\"", stub.Requests[1].Raw);
        Assert.All(stub.Requests, r => Assert.Equal("sdk", r.Header("X-VeriSec-Source")));
    }

    [Fact]
    public async Task A_file_that_does_not_exist_fails_naming_the_field_before_anything_is_sent()
    {
        await using var stub = StubServer.Start(StubReply.Json(new { }));
        using var client = Clients.For(stub);

        var e = await Assert.ThrowsAsync<VeriSecException>(() => client.Cards.NumberAsync(new CardNumberParams { Image = FileInput.FromPath("no-such-card.jpg") }));

        Assert.StartsWith("image: there is no file at no-such-card.jpg", e.Message);
        Assert.Empty(stub.Requests);
    }

    [Fact]
    public async Task A_retried_upload_sends_the_same_file_again()
    {
        await using var stub = StubServer.Start((_, n) => n == 1 ? StubReply.Error(503, "unavailable", "Try later.") : StubReply.Json(new { @object = "cheque_amount" }));
        using var client = Clients.For(stub);

        await client.Cheques.AmountAsync(new ChequeAmountParams { Image = FileInput.FromStream(new MemoryStream(Assets.Png), "c.png") });

        Assert.Equal(2, stub.Requests.Count);
        Assert.All(stub.Requests, r => Assert.Contains(System.Text.Encoding.Latin1.GetString(Assets.Png), r.Raw));
    }

    [Fact]
    public async Task GET_calls_put_path_and_query_parameters_in_the_URL()
    {
        await using var stub = StubServer.Start(StubReply.Json(new { @object = "bin" }));
        using var client = Clients.For(stub);

        await client.Bin.LookupAsync("424242");
        await client.Banks.LookupAsync(new BankLookupParams { Name = "Harbor Point", Country = "US" });
        await client.Banks.LookupAsync();
        await client.Bin.LookupAsync("42 42/");

        Assert.Equal("GET", stub.Requests[0].Method);
        Assert.Equal("/v2/bin/424242", stub.Requests[0].Target);
        Assert.Equal("/v2/banks?name=Harbor%20Point&country=US", stub.Requests[1].Target);
        Assert.Equal("/v2/banks", stub.Requests[2].Target);
        Assert.Equal("/v2/bin/42%2042%2F", stub.Requests[3].Target);
        Assert.All(stub.Requests, r => Assert.Empty(r.Body));
        Assert.All(stub.Requests, r => Assert.Null(r.Header("Content-Type")));
        Assert.Throws<ArgumentException>(() => { _ = client.Bin.LookupAsync(""); });
    }
}
