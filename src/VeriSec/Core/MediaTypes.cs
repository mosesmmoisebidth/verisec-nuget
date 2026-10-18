namespace VeriSec.Core;

/// <summary>Media types from file signatures.</summary>
internal static class MediaTypes
{
    /// <summary>An image type from the first bytes, or <c>application/octet-stream</c>.</summary>
    public static string Sniff(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8) return "image/jpeg";
        if (bytes.Length >= 4 && bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47) return "image/png";
        if (bytes.Length >= 2 && bytes[0] == 0x42 && bytes[1] == 0x4D) return "image/bmp";
        if (bytes.Length >= 12 && bytes[0] == 0x52 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x46
            && bytes[8] == 0x57 && bytes[9] == 0x45 && bytes[10] == 0x42 && bytes[11] == 0x50) return "image/webp";
        return "application/octet-stream";
    }
}
