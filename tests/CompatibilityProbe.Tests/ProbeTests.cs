using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;
using Xunit;

namespace CompatibilityProbe.Tests;

public sealed class ProbeTests
{
    private static UAsset Asset()
    {
        var asset = new UAsset(EngineVersion.VER_UE4_25)
        {
            PackageFlags = EPackageFlags.PKG_Cooked,
            Imports = [],
            Exports = []
        };
        asset.ClearNameIndexList();
        asset.Imports.Add(new Import("/Script/CoreUObject", "Package", new FPackageIndex(), "/Script/Engine", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new FPackageIndex(-1), "KismetSystemLibrary", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new FPackageIndex(-2), "ExecuteConsoleCommand", false, asset));
        return asset;
    }

    private static void AddFunction(UAsset asset, KismetExpression[]? code)
    {
        asset.Exports.Add(new FunctionExport
        {
            ObjectName = new FName(asset, "ExecuteUbergraph_Test"),
            OuterIndex = new FPackageIndex(),
            ScriptBytecode = code,
            ScriptBytecodeSize = code?.Sum(expression => (int)expression.GetSize(asset)) ?? 10
        });
    }

    [Fact]
    public void ResolvesOwnerAndFunctionRatherThanJustName()
    {
        var asset = Asset();
        Assert.Equal("/Script/Engine.KismetSystemLibrary:ExecuteConsoleCommand",
            TargetResolver.Resolve(asset, new FPackageIndex(-3), "Test.uasset"));
    }

    [Fact]
    public void SameFunctionNameOnDifferentOwnerHasDifferentIdentity()
    {
        var asset = Asset();
        asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new FPackageIndex(-1), "OtherLibrary", false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Function", new FPackageIndex(-4), "ExecuteConsoleCommand", false, asset));
        Assert.Equal("/Script/Engine.OtherLibrary:ExecuteConsoleCommand",
            TargetResolver.Resolve(asset, new FPackageIndex(-5), "Test.uasset"));
        Assert.NotEqual(TargetResolver.Resolve(asset, new FPackageIndex(-3), "Test.uasset"),
            TargetResolver.Resolve(asset, new FPackageIndex(-5), "Test.uasset"));
    }

    [Fact]
    public void LocalExportTargetKeepsItsPackageAndClass()
    {
        var asset = Asset();
        asset.Exports.Add(new NormalExport { ObjectName = new FName(asset, "BP_Test_C"), OuterIndex = new FPackageIndex() });
        asset.Exports.Add(new FunctionExport { ObjectName = new FName(asset, "Run"), OuterIndex = new FPackageIndex(1) });
        Assert.Equal("Test.uasset.BP_Test_C:Run", TargetResolver.Resolve(asset, new FPackageIndex(2), "Test.uasset"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-99)]
    [InlineData(99)]
    [InlineData(int.MinValue)]
    public void InvalidTargetsRemainUnresolved(int index)
    {
        Assert.Null(TargetResolver.Resolve(Asset(), new FPackageIndex(index), "Test.uasset"));
    }

    [Fact]
    public void CyclicOuterChainsTerminate()
    {
        var asset = Asset();
        asset.Imports[1].OuterIndex = new FPackageIndex(-3);
        Assert.Null(TargetResolver.Resolve(asset, new FPackageIndex(-3), "Test.uasset"));
    }

    [Fact]
    public void NestedCallIsVisitedWithVmOffset()
    {
        var asset = Asset();
        var nested = new EX_CallMath { StackNode = new FPackageIndex(-3), Parameters = [] };
        AddFunction(asset, [new EX_FinalFunction { StackNode = new FPackageIndex(-3), Parameters = [nested] }]);
        var result = Probe.Inspect(asset, "Test.uasset", []);
        Assert.True(result.ParseComplete);
        Assert.Equal([0u, 9u], result.Invocations.Select(call => call.BytecodeOffset));
        Assert.All(result.Invocations, call => Assert.Equal("package-index", call.Resolution));
    }

    [Fact]
    public void RawFunctionBytecodeIsNotClean()
    {
        var asset = Asset();
        AddFunction(asset, null);
        var result = Probe.Inspect(asset, "Test.uasset", []);
        Assert.False(result.ParseComplete);
        Assert.Equal(0, result.ParsedFunctions);
        Assert.Contains(result.Diagnostics, d => d.Code == "unparsed-bytecode");
    }

    [Fact]
    public void VirtualCallIsNotReportedAsResolved()
    {
        var asset = Asset();
        AddFunction(asset, [new EX_VirtualFunction { VirtualFunctionName = new FName(asset, "Run"), Parameters = [] }]);
        var result = Probe.Inspect(asset, "Test.uasset", []);
        Assert.False(result.ParseComplete);
        Assert.Equal("name-only", Assert.Single(result.Invocations).Resolution);
        Assert.Contains(result.Diagnostics, d => d.Code == "unresolved-virtual-target");
    }

    [Fact]
    public void VisitorSizeMismatchIsVisible()
    {
        var asset = Asset();
        AddFunction(asset, [new EX_EndOfScript()]);
        ((FunctionExport)asset.Exports[0]).ScriptBytecodeSize++;
        Assert.Contains(Probe.Inspect(asset, "Test.uasset", []).Diagnostics, d => d.Code == "bytecode-size-mismatch");
    }

    [Fact]
    public void RawExportIsVisible()
    {
        var asset = Asset();
        asset.Exports.Add(new RawExport { ObjectName = new FName(asset, "Unknown") });
        Assert.Contains(Probe.Inspect(asset, "Test.uasset", []).Diagnostics, d => d.Code == "raw-export");
    }

    [Fact]
    public void ParserSuccessNeverMeansSecurityAnalysisComplete()
    {
        var asset = Asset();
        var result = new ProbeReport([Probe.Inspect(asset, "Test.uasset", [])]);
        Assert.True(result.ParseComplete);
        Assert.False(result.AnalysisComplete);
        Assert.False(new ProbeReport([]).ParseComplete);
    }

    [Fact]
    public void EditorOnlyFilteringDoesNotRequireTheCookedFlag()
    {
        var asset = Asset();
        asset.PackageFlags = EPackageFlags.PKG_FilterEditorOnly;
        var result = Probe.Inspect(asset, "Test.uasset", []);
        Assert.True(result.ParseComplete);
        Assert.False(result.CookedFlag);
        Assert.True(result.EditorOnlyFiltered);
    }

    [Fact]
    public void NoCookedMarkersAreReported()
    {
        var asset = Asset();
        asset.PackageFlags = 0;
        Assert.Contains(Probe.Inspect(asset, "Test.uasset", []).Diagnostics,
            d => d.Code == "no-cooked-or-filtered-marker");
    }

    [Fact]
    public void MissingMappingsAreReported()
    {
        var asset = Asset();
        asset.PackageFlags |= EPackageFlags.PKG_UnversionedProperties;
        Assert.Contains(Probe.Inspect(asset, "Test.uasset", []).Diagnostics,
            d => d.Code == "missing-property-mappings");
    }

    [Fact]
    public void CorruptPackageProducesAnExplicitFailureWithoutExceptionContents()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "Corrupt.uasset");
        try
        {
            File.WriteAllText(path, "not an unreal package");
            var result = Probe.Read(path, "Corrupt.uasset");
            Assert.False(result.ParseComplete);
            Assert.Equal("asset-read-failed", Assert.Single(result.Diagnostics).Code);
            Assert.Single(result.Inputs);
        }
        finally
        {
            File.Delete(path);
            Directory.Delete(directory);
        }
    }

    [Fact]
    public void ProbeNeverOverwritesAnExistingReport()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(directory);
        var input = Path.Combine(directory, "Corrupt.uasset");
        var output = Path.Combine(directory, "report.json");
        try
        {
            File.WriteAllText(input, "not an unreal package");
            File.WriteAllText(output, "preserve me");
            Assert.Equal(1, Program.Main([input, output]));
            Assert.Equal("preserve me", File.ReadAllText(output));
            Assert.Equal("not an unreal package", File.ReadAllText(input));
        }
        finally
        {
            File.Delete(input);
            File.Delete(output);
            Directory.Delete(directory);
        }
    }
}
