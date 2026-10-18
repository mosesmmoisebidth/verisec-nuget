// Quickstart: three real calls.
//   VERISEC_API_KEY=sk_test_… dotnet run --project examples/Quickstart -- selfie.jpg id-photo.jpg
// Against the local test server:
//   VERISEC_BASE_URL=http://127.0.0.1:4010 VERISEC_API_KEY=sk_test_demo dotnet run --project examples/Quickstart -- a.png b.png
using VeriSec;

using var client = new VeriSecClient(); // VERISEC_API_KEY, and VERISEC_BASE_URL when set

try
{
    // MRZ parse: the machine-readable lines of a passport, checked digit by digit
    var mrz = await client.Mrz.ParseAsync(new MrzParseParams
    {
        Lines = ["P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"],
    });
    Console.WriteLine($"MRZ: {mrz.Format}, valid {mrz.Valid}, {mrz.Parsed?.Surname} {mrz.Parsed?.GivenName}, expires {mrz.Parsed?.Expiry}");

    // BIN lookup: a card's network and issuer from its first digits
    var bin = await client.Bin.LookupAsync("424242");
    Console.WriteLine($"BIN: {bin.Network} {bin.Type} from {bin.Issuer} ({bin.CountryName})");

    // Face verify: are two photos the same person?
    if (args.Length >= 2)
    {
        var result = await client.Face.VerifyAsync(new FaceVerifyParams
        {
            Image1 = Image.FromPath(args[0]),
            Image2 = Image.FromPath(args[1]),
        });
        Console.WriteLine($"Same person: {result.Match}, similarity {result.Similarity}, request {result.LastResponse.RequestId}");
    }
    else
    {
        Console.WriteLine("Pass two image files to compare the faces in them.");
    }
}
catch (InsufficientCreditsException)
{
    Console.Error.WriteLine("Not enough credits: top up in the console.");
    return 1;
}
catch (ApiException e)
{
    Console.Error.WriteLine($"{e.Status} {e.Code}: {e.Message} (request {e.RequestId})");
    return 1;
}
return 0;
