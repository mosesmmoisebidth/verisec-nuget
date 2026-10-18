# VeriSec .NET SDK

The official .NET library for the VeriSec API: identity (KYC) and Financial checks, with typed requests and
answers, images from files, safe retries and webhook verification.

```sh
dotnet add package VeriSec
```

.NET 8 or later. No dependencies beyond the .NET runtime (`HttpClient`, `System.Text.Json`).

## Configure

```csharp
using VeriSec;

using var client = new VeriSecClient(Environment.GetEnvironmentVariable("VERISEC_API_KEY")); // sk_test_…
```

Create keys in the console under **API Keys**. A test key (`sk_test_…`) is used as is. A live key (`ak_live_…`)
also needs the client id and secret issued with it; the library exchanges them for a short-lived token and renews
it for you:

```csharp
using var client = new VeriSecClient(new VeriSecOptions
{
    ApiKey = Environment.GetEnvironmentVariable("VERISEC_API_KEY"),            // ak_live_…
    ClientId = Environment.GetEnvironmentVariable("VERISEC_CLIENT_ID"),
    ClientSecret = Environment.GetEnvironmentVariable("VERISEC_CLIENT_SECRET"),
});
```

`new VeriSecClient()` reads all three from `VERISEC_API_KEY`, `VERISEC_CLIENT_ID` and `VERISEC_CLIENT_SECRET`.
Other options: `BaseUrl` (default `https://verisec.mmose.me`, or `VERISEC_BASE_URL`), `Timeout` (default 300 s per
attempt), `MaxRetries` (default 2) and `DefaultHeaders`. To send through your own `HttpClient` (a proxy,
`IHttpClientFactory`), pass it as the second argument: `new VeriSecClient(options, httpClient)`; give it
`Timeout = Timeout.InfiniteTimeSpan`, since the client times each attempt itself. Create one client and reuse it:
it is thread-safe.

## KYC: pass images as files

Every API is an async method, grouped the way the API groups them (`client.Face`, `client.Documents`,
`client.Mrz`, `client.Screening`, `client.Phone.Otp`, …; the full list with prices is in `../spec/README.md`).
Images are `Image.FromPath`, `Image.FromBytes`, `Image.FromStream` or `Image.FromBase64` (base64 or a `data:` URI);
the library sends each one the way the API expects.

```csharp
var result = await client.Face.VerifyAsync(new FaceVerifyParams
{
    Image1 = Image.FromPath("selfie.jpg"),
    Image2 = Image.FromBytes(idPhotoBytes),
    Threshold = 0.8,
});
Console.WriteLine($"{result.Match} {result.Similarity}");

// image lists take the images themselves; the index and ids are filled in for you
var match = await client.Face.MatchAsync(new FaceMatchParams
{
    Images = [Image.FromPath("selfie.jpg"), Image.FromPath("passport.jpg")],
});

var doc = await client.Documents.ReadAsync(new DocumentReadParams
{
    ImageFront = Image.FromPath("id-front.jpg"),
    ImageBack = Image.FromPath("id-back.jpg"),
});

var mrz = await client.Mrz.ParseAsync(new MrzParseParams
{
    Lines = ["P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"],
});
```

Properties are PascalCase in C# and go on the wire exactly as the API spells them (it uses both `detectAll` and
`image_front`). Required fields are `required` members; leave an optional one unset and it is not sent. Each method
and type carries the API's own documentation and the price of the call. A field this version does not know yet can
be sent through `AdditionalProperties`, and an answer keeps the fields it does not declare in its own
`AdditionalProperties`.

### Response info

A KYC call returns the answer's `data`; a Financial call returns the answer object. Where it came from is on
`LastResponse`:

```csharp
Console.WriteLine(result.LastResponse.RequestId);   // req_…, quote it to support
Console.WriteLine(result.LastResponse.LatencyMs);   // how long the check took on the server
foreach (var warning in result.LastResponse.Warnings) Console.WriteLine(warning);
Console.WriteLine(result.LastResponse.Status);      // and .Headers
```

### Full results

Face Analyze, Face Match, Age Estimation, Photo Quality, Liveness, Document Read, Proof of Address, MRZ Read, IP Risk,
Sanctions Screening and Contact Dossier return the engine's full result. Their types (`DocumentRead`,
`ScreeningSanctions`, …) are an `OpenResult`: a read-only dictionary of `JsonElement`, with the JSON as it came on
`Raw`, so nothing the engine sends is lost:

```csharp
var screening = await client.Screening.SanctionsAsync(new ScreeningSanctionsParams { Name = "Jane Example" });
Console.WriteLine(screening["summary"].GetProperty("matches").GetInt32());
foreach (var hit in screening["results"].EnumerateArray()) Console.WriteLine(hit.GetProperty("name").GetString());

var summary = screening.Get<MySummary>("summary");      // one field as your own type
var everything = screening.Deserialize<MyScreening>();  // or all of it
Console.WriteLine(screening.Raw);                       // the JSON as sent
```

## Financial: cheques, cards, banks, BINs

Reads take the file with `FileInput.FromPath`, `FileInput.FromBytes(bytes, "cheque.jpg")` or
`FileInput.FromStream(stream, "cheque.jpg")` and upload it as `multipart/form-data` (filed under "SDK" in the
console's scan history).

```csharp
var cheque = await client.Cheques.ReadAsync(new ChequeReadParams { Image = FileInput.FromPath("cheque.jpg") });
Console.WriteLine($"{cheque.Vision?.Amount?.Numeric} to {cheque.Vision?.Payee}, MICR {cheque.Micr?.Micr?.Text}");

var line = await client.Cheques.MicrLineAsync(new ChequeMicrLineParams { Image = FileInput.FromBytes(bytes, "cheque.jpg"), Format = "e13b" });
var card = await client.Cards.CheckAsync(new CardCheckParams { Number = "4242 4242 4242 4242", Expiry = "09/29" });
var bin = await client.Bin.LookupAsync("424242");
var bank = await client.Banks.LookupAsync(new BankLookupParams { Name = "Harbor Point Bank", Country = "US" });
```

## Credits

Each call costs its API's price in credits, charged only when it succeeds. Refused calls (no credits, no permission,
rate limited, a field not valid) and calls that could not run are free.

## Errors

```csharp
try
{
    await client.Face.VerifyAsync(parameters);
}
catch (InsufficientCreditsException)
{
    Console.WriteLine("Top up credits in the console."); // 402: nothing was charged
}
catch (InvalidRequestException e)
{
    Console.WriteLine($"{e.Code} {e.Param}: {e.Message}"); // invalid_input image1: …
}
catch (RateLimitException e)
{
    Console.WriteLine($"Wait {e.RetryAfter?.TotalSeconds} s.");
}
catch (ApiException e)
{
    Console.WriteLine($"{e.Status} {e.Code} {e.RequestId}");
}
catch (ApiConnectionException e) // ApiTimeoutException too
{
    Console.WriteLine(e.Message); // says whether the call may have run
}
```

Classes: `InvalidRequestException` (400, 413, 415, 422), `AuthenticationException` (401),
`InsufficientCreditsException` (402), `PermissionException` (403), `NotFoundException` (404), `RateLimitException`
(429), `ApiServerException` (5xx), all `ApiException` with `Status`, `Code`, `Message`, `Param`, `RequestId` and
`Headers`; `ApiConnectionException` and `ApiTimeoutException`; `SignatureVerificationException` for webhooks. They
all derive from `VeriSecException`, which is also thrown for a client-side problem such as an image file that does
not exist (the message names the field: `image1: there is no file at selfie.jpg.`).

## Retries

The library retries rate limits (429), server errors (5xx) and connections that never opened (refused, DNS, a
connect over 10 s), up to `MaxRetries` times with backoff (0.5 s doubling to 8 s, ±25%, or the `Retry-After` the API
sent, at most 60 s): none of those were charged. It never sends a call again after a timeout or a connection that
failed once the request was sent, because the check may already have run and been charged; you get an
`ApiTimeoutException` / `ApiConnectionException` saying so. A 401 on a live token gets one fresh token.

Per call, pass `RequestOptions` and a `CancellationToken`:

```csharp
var cheque = await client.Cheques.ReadAsync(parameters,
    new RequestOptions { Timeout = TimeSpan.FromMinutes(6), MaxRetries = 0, Headers = { ["X-Trace"] = "abc" } },
    cancellationToken);
```

## Webhooks

Deliveries are signed as Standard Webhooks (`webhook-id`, `webhook-timestamp`, `webhook-signature`; the `svix-*`
names work too). Pass the raw body, the headers and your endpoint's signing secret (`whsec_…`); deliveries older
than 5 minutes are refused (`tolerance` changes that).

```csharp
app.MapPost("/webhooks/verisec", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var body = await reader.ReadToEndAsync();
    try
    {
        var evt = Webhooks.ConstructEvent(body, name => request.Headers[name], secret);
        if (evt.Type == "verification.completed") Console.WriteLine(evt.Data.GetProperty("decision"));
        return Results.Ok();
    }
    catch (SignatureVerificationException)
    {
        return Results.BadRequest();
    }
});
```

Headers can also be an `IDictionary<string, string>` or `HttpHeaders`. `Webhooks.VerifySignature` returns a bool,
and `Webhooks.GenerateTestHeaders(body, secret)` signs a body for your own tests.

## Example

`examples/Quickstart` parses an MRZ, looks up a BIN and compares the faces in two photos:

```sh
VERISEC_API_KEY=sk_test_… dotnet run --project examples/Quickstart -- selfie.jpg id-photo.jpg
```

## Development

```sh
node scripts/generate.mjs   # after the spec changes: models, resources and the per-operation tests
dotnet test                 # builds, then runs the unit and integration tests
```

`scripts/generate.mjs` reads `../spec/openapi.json` and writes `src/VeriSec/Generated/Models.g.cs` (a type per
schema), `src/VeriSec/Generated/Resources.g.cs` (a method per operation) and
`tests/VeriSec.Tests/Integration/EveryOperationTests.g.cs`; everything else in `src/VeriSec` is written by hand. The
integration tests start the shared test server (`node ../test-server/server.mjs --port 4024`, Node 18 or later
on `PATH`), call every operation through the SDK and stop the server when they finish.
