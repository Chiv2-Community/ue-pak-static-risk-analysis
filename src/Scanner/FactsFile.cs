using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PakRisk.Scanner;

internal static class FactsFile
{
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(28)] public ushort Mode;
    }
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int GetStatx(SafeFileHandle fd, string path, int flags, uint mask, out Statx stat);

    internal static byte[] Read(string path)
    {
        if (!OperatingSystem.IsLinux() || path.Length is 0 or > 4096 || path.Contains('\0')) throw new FactsException();
        var fd = Open(path, 0x800 | 0x20000 | 0x80000);
        if (fd < 0) throw new FactsException();
        using var handle = new SafeFileHandle(fd, true);
        if (GetStatx(handle, "", 0x1000, 1, out var stat) != 0 || (stat.Mask & 1) == 0 || (stat.Mode & 0xf000) != 0x8000)
            throw new FactsException();
        using var stream = new FileStream(handle, FileAccess.Read);
        var bytes = new byte[FactsCodec.MaxBytes + 1];
        var count = 0;
        while (count < bytes.Length)
        {
            var read = stream.Read(bytes, count, bytes.Length - count);
            if (read == 0) break;
            count += read;
        }
        if (count > FactsCodec.MaxBytes) throw new FactsException();
        return bytes.AsSpan(0, count).ToArray();
    }
}
