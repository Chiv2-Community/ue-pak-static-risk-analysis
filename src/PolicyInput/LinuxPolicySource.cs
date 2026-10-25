using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PakRisk.PolicyInput;

internal static class LinuxPolicySource
{
    // Linux UAPI statx has fixed layout, unlike architecture-dependent struct stat.
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(28)] public ushort Mode;
    }

    [DllImport("libc", EntryPoint = "getenv")]
    private static extern nint GetEnv([MarshalAs(UnmanagedType.LPUTF8Str)] string name);
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int GetStatx(SafeFileHandle fd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        int flags, uint mask, out Statx stat);

    private static void RequireLinux()
    {
        if (!OperatingSystem.IsLinux()) throw new PolicyInputException("unsupported-platform");
    }

    internal static byte[]? ReadEnvironment(int maxBytes)
    {
        RequireLinux();
        var pointer = GetEnv(PolicyLoader.EnvironmentName);
        if (pointer == 0) return null;
        // Do not use Environment.GetEnvironmentVariable: invalid UTF-8 is replaced there.
        // Host must not concurrently mutate the process environment during loading.
        var length = 0;
        while (length <= maxBytes && Marshal.ReadByte(pointer, length) != 0) length++;
        if (length > maxBytes) throw new PolicyInputException("size-limit");
        var bytes = new byte[length];
        Marshal.Copy(pointer, bytes, 0, length);
        return bytes;
    }

    internal static byte[] ReadFile(string path, int maxBytes, CancellationToken cancellationToken)
    {
        RequireLinux();
        if (path.Length is 0 or > 4096 || path.Contains('\0'))
            throw new PolicyInputException("invalid-file-source");
        // O_NONBLOCK avoids hanging on FIFOs; O_NOFOLLOW rejects final symlinks.
        // Inspect the opened handle, not a racy path check. Fail closed without statx.
        var fd = Open(path, 0x800 | 0x20000 | 0x80000);
        if (fd < 0) throw new PolicyInputException("file-open-failed");
        using var handle = new SafeFileHandle(fd, ownsHandle: true);
        if (GetStatx(handle, "", 0x1000, 1, out var stat) != 0 || (stat.Mask & 1) == 0
            || (stat.Mode & 0xf000) != 0x8000)
            throw new PolicyInputException("not-regular-file");
        using var stream = new FileStream(handle, FileAccess.Read);
        var buffer = new byte[maxBytes + 1];
        try
        {
            var count = 0;
            while (count < buffer.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var read = stream.Read(buffer, count, buffer.Length - count);
                if (read == 0) break;
                count += read;
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (count > maxBytes) throw new PolicyInputException("size-limit");
            return buffer.AsSpan(0, count).ToArray();
        }
        finally { Array.Clear(buffer); }
    }
}
