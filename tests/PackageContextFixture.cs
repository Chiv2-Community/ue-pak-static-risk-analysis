using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;

// Original serialization model. No engine/game binary or native behavior assertion.
internal static class PackageContextFixture
{
    internal static UAsset Asset(string name, bool face = false)
    {
        var asset = new UAsset(EngineVersion.VER_UE4_25) { PackageFlags = EPackageFlags.PKG_Cooked | EPackageFlags.PKG_FilterEditorOnly,
            Imports = [], Exports = [], LegacyFileVersion = -7, FolderName = new("None"), Generations = [], ChunkIDs = [],
            AssetRegistryRecords = [], AdditionalFiles = [], RecordedEngineVersion = new(), RecordedCompatibleWithEngineVersion = new(),
            UseSeparateBulkDataFiles = true };
        asset.ClearNameIndexList(); asset.AddNameReference(new("None"));
        typeof(UAsset).GetField("AdditionalPackagesToCook", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .SetValue(asset, new List<FString>());
        typeof(UAsset).GetField("doWeHaveWorldTileInfo", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .SetValue(asset, false);
        asset.Imports.Add(new Import("/Script/CoreUObject", "Package", new(0), "/Script/CoreUObject", false, asset));
        foreach (var type in new[] { "BlueprintGeneratedClass", "Function", "Object" })
            asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-1), type, false, asset));
        asset.Exports.Add(new ClassExport { Asset = asset, ObjectName = new(asset, name), OuterIndex = new(0), ClassIndex = new(-2),
            SuperIndex = new(0), SuperStruct = new(0), Data = [], Extras = [], Field = new(), Children = [], LoadedProperties = [],
            ScriptBytecode = [], FuncMap = new(), ClassWithin = new(-4), ClassConfigName = new(asset, "None"), ClassGeneratedBy = new(0),
            Interfaces = [], ClassDefaultObject = new(2), bCooked = true, ClassFlags = face ? EClassFlags.CLASS_Interface : 0 });
        asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, "Default__" + name), OuterIndex = new(0),
            ClassIndex = new(1), ObjectFlags = EObjectFlags.RF_ClassDefaultObject, Data = [], Extras = [] });
        return asset;
    }

    internal static int ImportClass(UAsset asset, string package, string name = "Type")
    {
        asset.Imports.Add(new Import("/Script/CoreUObject", "Package", new(0), package, false, asset));
        asset.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-asset.Imports.Count), name, false, asset));
        return -asset.Imports.Count;
    }

    internal static void Parent(UAsset asset, int index)
    {
        var type = (ClassExport)asset.Exports[0];
        type.SuperStruct = new(index); type.SuperIndex = new(index);
    }

    internal static int Function(UAsset asset, string name, params KismetExpression[] code)
    {
        var index = asset.Exports.Count + 1;
        asset.Exports.Add(new FunctionExport { Asset = asset, ObjectName = new(asset, name), OuterIndex = new(1), ClassIndex = new(-3),
            SuperIndex = new(0), SuperStruct = new(0), ScriptBytecode = code, ScriptBytecodeSize = code.Sum(e => (int)e.GetSize(asset)),
            Data = [], Extras = [], LoadedProperties = [], Children = [], Field = new() });
        ((ClassExport)asset.Exports[0]).FuncMap.Add(new(asset, name), new(index));
        return index;
    }

    internal static EX_VirtualFunction Virtual(UAsset asset) => new() { VirtualFunctionName = new(asset, "sEnSiTiVe"), Parameters = [] };

    internal static Dictionary<string, UAsset> Create()
    {
        var parent = Asset("Type");
        Function(parent, "Sensitive");
        Function(parent, "Run", Virtual(parent));
        var face = Asset("Type", face: true);
        var child = Asset("Type");
        Parent(child, ImportClass(child, "/Game/Base"));
        ((ClassExport)child.Exports[0]).Interfaces = [new(ImportClass(child, "/Game/Interface"), 0, true)];
        child.Imports.Add(new Import("/Script/CoreUObject", "Package", new(0), "/Script/Corpus", false, child));
        child.Imports.Add(new Import("/Script/CoreUObject", "Class", new(-child.Imports.Count), "Sensitive", false, child));
        child.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-child.Imports.Count), "Record", false, child));
        Function(child, "Sensitive", new EX_FinalFunction { StackNode = new(-child.Imports.Count), Parameters = [] });
        var caller = Asset("Caller");
        var baseImport = ImportClass(caller, "/game/base", "tYpE");
        var faceImport = ImportClass(caller, "/Game/Interface");
        foreach (var (name, type) in new[] { ("BaseReceiver", baseImport), ("InterfaceReceiver", faceImport) })
            caller.Exports.Add(new NormalExport { Asset = caller, ObjectName = new(caller, name), OuterIndex = new(0),
                ClassIndex = new(type), Data = [], Extras = [] });
        KismetExpression Context(KismetExpression receiver) => new EX_Context { ObjectExpression = receiver,
            RValuePointer = new KismetPropertyPointer(new FFieldPath { Path = [], ResolvedOwner = new(0) }), ContextExpression = Virtual(caller) };
        Function(caller, "Run", Context(new EX_ObjectConst { Value = new(3) }), Context(new EX_ObjectConst { Value = new(4) }),
            Context(new EX_NoObject()));
        var unrelated = Asset("Type"); // Same class/function names, different package: not an override.
        Function(unrelated, "Sensitive");
        return new() { ["Base"] = parent, ["ChildOverride"] = child, ["Interface"] = face, ["Caller"] = caller, ["Collision"] = unrelated };
    }

    internal static void Boundary(Dictionary<string, UAsset> assets, int calls = 5001, bool local = true)
    {
        var asset = assets["Base"];
        if (!local) asset.Exports[2].ObjectName = new(asset, "Other");
        var run = (FunctionExport)asset.Exports[3];
        run.ScriptBytecode = new KismetExpression[] { new EX_FinalFunction { StackNode = new(3), Parameters = [] } }
            .Concat(Enumerable.Range(0, calls).Select(_ => Virtual(asset))).ToArray();
        run.ScriptBytecodeSize = run.ScriptBytecode.Sum(e => (int)e.GetSize(asset));
    }

    internal static void CaseImport(Dictionary<string, UAsset> assets)
    {
        var caller = assets["Caller"];
        caller.Imports.Add(new Import("/Script/CoreUObject", "Function", new(-6), "SENSITIVE", false, caller));
    }

    internal static void Write(string root, string mode = "package-context")
    {
        Directory.CreateDirectory(root);
        var assets = Create();
        if (mode == "package-context-budget") Boundary(assets);
        if (mode == "package-context-case") CaseImport(assets);
        foreach (var (name, asset) in assets) asset.Write(Path.Combine(root, name + ".uasset"));
    }
}
