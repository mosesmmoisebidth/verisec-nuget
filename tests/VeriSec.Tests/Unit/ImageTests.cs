using System.Text;
using System.Text.Json;
using VeriSec.Core;
using VeriSec.Tests.Support;

namespace VeriSec.Tests.Unit;

/// <summary>KYC images: every accepted form becomes plain base64; image lists are filled in; the caller's input is untouched.</summary>
public sealed class ImageTests
{
    private static async Task<JsonElement> BodyOf(Func<VeriSecClient, Task> call)
    {
        await using var stub = StubServer.Start(StubReply.Kyc(new { }));
        using var client = Clients.For(stub);
        await call(client);
        return Assert.Single(stub.Requests).Json;
    }

    [Fact]
    public async Task A_path_bytes_a_stream_base64_and_a_data_URI_all_become_plain_base64()
    {
        Assert.Equal(Assets.PngBase64, await Image.FromPath(Assets.PngPath).ToBase64Async("image", default));
        Assert.Equal(Assets.PngBase64, await Image.FromBytes(Assets.Png).ToBase64Async("image", default));
        Assert.Equal(Assets.PngBase64, await Image.FromStream(new MemoryStream(Assets.Png)).ToBase64Async("image", default));
        Assert.Equal(Assets.PngBase64, await Image.FromBase64(Assets.PngBase64).ToBase64Async("image", default));
        Assert.Equal(Assets.PngBase64, await Image.FromBase64($"data:image/png;base64,{Assets.PngBase64}").ToBase64Async("image", default));
        Assert.Equal(Assets.PngBase64, await Image.FromBase64($"  {Assets.PngBase64[..40]}\n{Assets.PngBase64[40..]}  ").ToBase64Async("image", default));
    }

    [Fact]
    public async Task Each_form_reaches_the_wire_as_base64()
    {
        var body = await BodyOf(c => c.Face.VerifyAsync(new FaceVerifyParams { Image1 = Image.FromPath(Assets.PngPath), Image2 = Image.FromStream(new MemoryStream(Assets.Png)) }));

        Assert.Equal(Assets.PngBase64, body.GetProperty("image1").GetString());
        Assert.Equal(Assets.PngBase64, body.GetProperty("image2").GetString());
    }

    [Theory]
    [InlineData("path", "image1: there is no file at")]
    [InlineData("base64", "image2: not base64 or a data: URI.")]
    [InlineData("data", "image2: a data: URI must carry base64")]
    public async Task An_image_that_is_not_one_fails_naming_the_field_before_anything_is_sent(string kind, string message)
    {
        await using var stub = StubServer.Start(StubReply.Kyc(new { }));
        using var client = Clients.For(stub);
        var parameters = kind switch
        {
            "path" => new FaceVerifyParams { Image1 = Image.FromPath(Path.Combine(Path.GetTempPath(), "no-such-selfie.jpg")), Image2 = Image.FromBytes(Assets.Png) },
            "base64" => new FaceVerifyParams { Image1 = Image.FromBytes(Assets.Png), Image2 = Image.FromBase64("not an image!") },
            _ => new FaceVerifyParams { Image1 = Image.FromBytes(Assets.Png), Image2 = Image.FromBase64("data:image/png,rawtext") },
        };

        var e = await Assert.ThrowsAsync<VeriSecException>(() => client.Face.VerifyAsync(parameters));

        Assert.StartsWith(message, e.Message);
        Assert.Empty(stub.Requests);
    }

    [Fact]
    public void The_factories_refuse_nothing_to_read()
    {
        Assert.Throws<ArgumentNullException>(() => Image.FromBytes(null!));
        Assert.Throws<ArgumentException>(() => Image.FromPath(""));
        Assert.Throws<ArgumentNullException>(() => Image.FromBase64(null!));
        Assert.Throws<ArgumentNullException>(() => Image.FromStream(null!));
        Assert.Equal("Image.FromPath(selfie.jpg)", Image.FromPath("selfie.jpg").ToString());
    }

    [Fact]
    public async Task Image_lists_take_bare_images_and_get_the_index_and_ids_the_API_expects()
    {
        var match = await BodyOf(c => c.Face.MatchAsync(new FaceMatchParams
        {
            Images = [Image.FromPath(Assets.PngPath), new FaceMatchParamsImage { Data = Image.FromBytes(Assets.Png), Type = 1 }],
        }));
        Assert.Equal(
            $$"""{"images":[{"data":"{{Assets.PngBase64}}","index":0},{"data":"{{Assets.PngBase64}}","type":1,"index":1}]}""",
            match.GetRawText());

        var search = await BodyOf(c => c.Face.SearchAsync(new FaceSearchParams
        {
            Probe = Image.FromBytes(Assets.Png),
            Gallery = [Image.FromBytes(Assets.Png), new FaceSearchParamsGallery { Image = Image.FromBytes(Assets.Png), Id = "alice" }, new FaceSearchParamsGallery { Image = Image.FromBytes(Assets.Png), Id = "" }],
            TopK = 2,
        }));
        var gallery = search.GetProperty("gallery");
        Assert.Equal(new[] { "face-1", "alice", "face-3" }, gallery.EnumerateArray().Select(e => e.GetProperty("id").GetString()));
        Assert.All(gallery.EnumerateArray(), e => Assert.Equal(Assets.PngBase64, e.GetProperty("image").GetString()));
        Assert.False(gallery[0].TryGetProperty("index", out _));

        var watchlist = await BodyOf(c => c.Face.WatchlistAsync(new FaceWatchlistParams
        {
            Probe = Image.FromBytes(Assets.Png),
            List = [new FaceWatchlistParamsList { Image = Image.FromBytes(Assets.Png), Label = "wanted" }],
        }));
        Assert.Equal("""{"image":"__","label":"wanted","id":"face-1"}""".Replace("__", Assets.PngBase64), watchlist.GetProperty("list")[0].GetRawText());
    }

    [Fact]
    public async Task An_explicit_index_is_kept()
    {
        var body = await BodyOf(c => c.Face.MatchAsync(new FaceMatchParams
        {
            Images = [new FaceMatchParamsImage { Data = Image.FromBytes(Assets.Png), Index = 1 }, new FaceMatchParamsImage { Data = Image.FromBytes(Assets.Png), Index = 0 }],
        }));

        Assert.Equal(new[] { 1, 0 }, body.GetProperty("images").EnumerateArray().Select(e => e.GetProperty("index").GetInt32()));
    }

    [Fact]
    public async Task A_list_of_images_is_a_list_of_base64()
    {
        var body = await BodyOf(c => c.Photo.BestFrameAsync(new PhotoBestFrameParams { Frames = [Image.FromBytes(Assets.Png), Image.FromPath(Assets.PngPath)] }));

        Assert.Equal($$"""{"frames":["{{Assets.PngBase64}}","{{Assets.PngBase64}}"]}""", body.GetRawText());
    }

    [Fact]
    public async Task The_callers_parameters_are_never_changed()
    {
        var entry = new FaceMatchParamsImage { Data = Image.FromPath(Assets.PngPath) };
        var parameters = new FaceMatchParams { Images = [entry, Image.FromBytes(Assets.Png)] };
        var images = parameters.Images;

        await BodyOf(c => c.Face.MatchAsync(parameters));

        Assert.Same(images, parameters.Images);
        Assert.Same(entry, parameters.Images[0]);
        Assert.Null(entry.Index);
        Assert.Null(parameters.Images[1].Index);
        Assert.Null(entry.AdditionalProperties);
        Assert.Equal($"Image.FromPath({Assets.PngPath})", entry.Data.ToString());
    }

    [Fact]
    public async Task A_stream_image_is_read_once_and_can_be_sent_again()
    {
        var image = Image.FromStream(new MemoryStream(Assets.Png));
        await using var stub = StubServer.Start(StubReply.Kyc(new { }));
        using var client = Clients.For(stub);

        await client.Face.DetectAsync(new FaceDetectParams { Image = image });
        await client.Face.DetectAsync(new FaceDetectParams { Image = image });

        Assert.All(stub.Requests, r => Assert.Equal(Assets.PngBase64, r.Json.GetProperty("image").GetString()));
    }

    [Fact]
    public async Task Fields_that_take_any_JSON_send_what_you_give_them()
    {
        var body = await BodyOf(c => c.Face.AnalyzeAsync(new FaceAnalyzeParams
        {
            Image = Image.FromBytes(Assets.Png),
            Crop = new FaceAnalyzeParamsCrop { Type = 1 },
            QualityChecks = [new { name = "Yaw", range = new[] { -5, 5 } }, Assets.Json("""{"name":"BlurLevel","range":[0,0.15]}""")],
        }));
        Assert.Equal(1, body.GetProperty("crop").GetProperty("type").GetInt32());
        Assert.Equal("""[{"name":"Yaw","range":[-5,5]},{"name":"BlurLevel","range":[0,0.15]}]""", body.GetProperty("qualityChecks").GetRawText());

        var empty = await BodyOf(c => c.Face.MatchAsync(new FaceMatchParams { Images = [Image.FromBytes(Assets.Png), Image.FromBytes(Assets.Png)], Crop = new FaceMatchParamsCrop { Type = "" } }));
        Assert.Equal("", empty.GetProperty("crop").GetProperty("type").GetString());
    }

    [Fact]
    public async Task Fields_this_version_does_not_know_go_out_through_AdditionalProperties()
    {
        var body = await BodyOf(c => c.Mrz.ParseAsync(new MrzParseParams
        {
            Lines = ["P<UTO"],
            AdditionalProperties = new Dictionary<string, object?> { ["strict"] = true, ["hint"] = new { country = "UTO" }, ["dropped"] = null },
        }));

        Assert.Equal("""{"lines":["P<UTO"],"strict":true,"hint":{"country":"UTO"}}""", body.GetRawText());
    }

    [Fact]
    public async Task Text_goes_out_as_it_is_not_as_escapes()
    {
        await using var stub = StubServer.Start(StubReply.Kyc(new { }));
        using var client = Clients.For(stub);

        await client.Screening.SanctionsAsync(new ScreeningSanctionsParams { Name = "Zoë O'Brien <&>", Countries = ["ZA"] });

        var text = Encoding.UTF8.GetString(Assert.Single(stub.Requests).Body);
        Assert.Equal("""{"name":"Zoë O'Brien <&>","countries":["ZA"]}""", text);
    }

    [Fact]
    public async Task An_image_inside_your_own_objects_and_dictionaries_is_encoded_too()
    {
        var body = await BodyOf(c => c.Face.QualityAsync(new FaceQualityParams
        {
            Image = Image.FromBytes(Assets.Png),
            CustomChecks = new { reference = Image.FromPath(Assets.PngPath), keep = new[] { 1, 2 }, skip = (string?)null },
            AdditionalProperties = new Dictionary<string, object?> { ["extra"] = new Dictionary<string, object?> { ["photo"] = Image.FromBytes(Assets.Png), ["none"] = null } },
        }));

        Assert.Equal($$"""{"reference":"{{Assets.PngBase64}}","keep":[1,2]}""", body.GetProperty("customChecks").GetRawText());
        Assert.Equal($$"""{"photo":"{{Assets.PngBase64}}","none":null}""", body.GetProperty("extra").GetRawText());
    }

    [Fact]
    public void Serializing_a_request_yourself_describes_its_images_and_reading_one_takes_base64()
    {
        var parameters = new FaceVerifyParams { Image1 = Image.FromPath("selfie.jpg"), Image2 = Image.FromBytes(Assets.Png), Threshold = 0.8 };
        Assert.Equal($$"""{"image1":"Image.FromPath(selfie.jpg)","image2":"Image.FromBytes({{Assets.Png.Length}} bytes)","threshold":0.8}""", JsonSerializer.Serialize(parameters, Json.Options));
        Assert.Equal("""{"image":"FileInput.FromPath(cheque.jpg)","format":"e13b"}""", JsonSerializer.Serialize(new ChequeMicrParams { Image = FileInput.FromPath("cheque.jpg"), Format = "e13b" }, Json.Options));

        var read = JsonSerializer.Deserialize<FaceVerifyParams>($$"""{"image1":"{{Assets.PngBase64}}","image2":"data:image/png;base64,{{Assets.PngBase64}}"}""", Json.Options)!;
        Assert.Equal($"Image.FromBase64({Assets.PngBase64.Length} characters)", read.Image1.ToString());
    }

    [Fact]
    public void The_image_plan_fills_nested_lists_and_leaves_other_entries_alone()
    {
        var root = System.Text.Json.Nodes.JsonNode.Parse("""{"outer":{"faces":[{"image":"a"},"bare",{"image":"b","id":"keep"}]}}""");
        new ImagePlan(new ImageList("outer.faces", "image", "index", "id", "face")).Apply(root);

        Assert.Equal("""{"outer":{"faces":[{"image":"a","index":0,"id":"face-1"},"bare",{"image":"b","id":"keep","index":2}]}}""", root!.ToJsonString());
    }
}
