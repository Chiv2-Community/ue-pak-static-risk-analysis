using System.Runtime.InteropServices;
using System.Text;
using PakRisk.Policy;
using PakRisk.PolicyInput;
using Xunit;

namespace PolicyInput.Tests;

[CollectionDefinition("Native environment", DisableParallelization = true)]
public sealed class NativeEnvironmentCollection;

[Collection("Native environment")]
public sealed class NativeEnvironmentTests
{
    [DllImport("libc", EntryPoint = "getenv")]
    private static extern nint GetEnv(string name);
    [DllImport("libc", EntryPoint = "setenv")]
    private static extern int SetEnv(string name, nint value, int overwrite);
    [DllImport("libc", EntryPoint = "unsetenv")]
    private static extern int UnsetEnv(string name);
    [DllImport("libc", EntryPoint = "strdup")]
    private static extern nint Duplicate(nint value);
    [DllImport("libc", EntryPoint = "free")]
    private static extern void Free(nint value);

    [Fact]
    public void RawLibcBoundaryDistinguishesAbsentEmptyAndInvalidUtf8()
    {
        var original = GetEnv(PolicyLoader.EnvironmentName);
        var saved = original == 0 ? 0 : Duplicate(original);
        Assert.True(original == 0 || saved != 0);
        try
        {
            Assert.Equal(0, UnsetEnv(PolicyLoader.EnvironmentName));
            Assert.Equal("missing-source", Assert.Throws<PolicyInputException>(() => PolicyLoader.Load()).Code);
            Set([]);
            Assert.Equal("empty-source", Assert.Throws<PolicyInputException>(() => PolicyLoader.Load()).Code);
            Set([0xff]);
            Assert.Equal("invalid-utf8", Assert.Throws<PolicyInputException>(() => PolicyLoader.Load()).Code);
            Set(Encoding.UTF8.GetBytes("""
                schema-version: 1
                rules:
                  - id: native
                    description: Native boundary
                    effect: forbid
                    match:
                      kind: invocation
                      target:
                        kind: exact
                        owner: /Script/Engine.KismetSystemLibrary
                        function: LaunchURL
                """));
            Assert.NotNull(PolicyLoader.Load());
            Set(Encoding.UTF8.GetBytes("schema-version: 1\nrules: []"));
            Assert.Throws<PolicyException>(() => PolicyLoader.Load());
            Set(Encoding.UTF8.GetBytes(new string('a', 32)));
            Assert.Equal("size-limit", Assert.Throws<PolicyInputException>(() => PolicyLoader.Load(maxBytes: 31)).Code);
        }
        finally
        {
            if (saved == 0) Assert.Equal(0, UnsetEnv(PolicyLoader.EnvironmentName));
            else
            {
                try { Assert.Equal(0, SetEnv(PolicyLoader.EnvironmentName, saved, 1)); }
                finally { Free(saved); }
            }
        }
    }

    private static void Set(byte[] bytes)
    {
        var pointer = Marshal.AllocHGlobal(bytes.Length + 1);
        try
        {
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            Marshal.WriteByte(pointer, bytes.Length, 0);
            Assert.Equal(0, SetEnv(PolicyLoader.EnvironmentName, pointer, 1));
        }
        finally { Marshal.FreeHGlobal(pointer); }
    }
}
