using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.FieldTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;

// Original UE4.25 serialization model; no engine binary or native behavior.
internal static class DelegateFlowFixture
{
    internal static FDelegateProperty Property(UAsset asset, string name, bool multicast = false)
    {
        FDelegateProperty property = multicast ? new FMulticastInlineDelegateProperty() : new FDelegateProperty();
        property.Name = new(asset, name);
        property.SerializedType = new(asset, multicast ? "MulticastInlineDelegateProperty" : "DelegateProperty");
        property.RepNotifyFunc = new(asset, "None");
        property.ArrayDim = (EArrayDim)1;
        property.ElementSize = 16;
        property.SignatureFunction = new(5);
        return property;
    }

    internal static EX_LocalVariable Local(UAsset asset, string name = "Callback", int owner = 6) => new()
    { Variable = new(new FFieldPath { Path = [new(asset, name)], ResolvedOwner = new(owner) }) };
    internal static EX_InstanceVariable Events(UAsset asset, int owner = 1) => new()
    { Variable = new(new FFieldPath { Path = [new(asset, "Events")], ResolvedOwner = new(owner) }) };
    internal static EX_BindDelegate Bind(UAsset asset, string name = "Sensitive") => new()
    { FunctionName = new(asset, name), Delegate = Local(asset), ObjectTerm = new EX_Self() };
    internal static EX_CallMulticastDelegate Call(UAsset asset, KismetExpression? receiver = null) => new()
    { StackNode = new(5), Delegate = receiver ?? Events(asset), Parameters = [] };
    internal static EX_Context Context(UAsset asset, int receiver, KismetExpression expression) => new()
    { ObjectExpression = new EX_ObjectConst { Value = new(receiver) }, ContextExpression = expression,
        RValuePointer = new(new FFieldPath { Path = [], ResolvedOwner = new(0) }) };

    internal static UAsset Create(string mode = "history")
    {
        var asset = PackageContextFixture.Asset("Type");
        PackageContextFixture.Function(asset, "Sensitive");
        PackageContextFixture.Function(asset, "Safe");
        PackageContextFixture.Function(asset, "Signature");
        PackageContextFixture.Function(asset, "Run");
        ((ClassExport)asset.Exports[0]).LoadedProperties = [Property(asset, "Events", true), Property(asset, "Callback")];
        var run = (FunctionExport)asset.Exports[5];
        run.LoadedProperties = [Property(asset, "Callback"), Property(asset, "Copy"), Property(asset, "LocalEvents", true)];
        KismetExpression Add() => new EX_AddMulticastDelegate { Delegate = Events(asset), DelegateToAdd = Local(asset) };
        KismetExpression Assign(string name) => new EX_LetDelegate { VariableExpression = Local(asset),
            AssignmentExpression = new EX_InstanceDelegate { FunctionName = new(asset, name) } };
        KismetExpression[] code = mode switch
        {
            "history" => [new EX_FinalFunction { StackNode = new(3), Parameters = [] }, Bind(asset), Add(), Call(asset),
                new EX_ClearMulticastDelegate { DelegateToClear = Events(asset) }, Call(asset),
                new EX_RemoveMulticastDelegate { Delegate = Events(asset), DelegateToAdd = Local(asset) }, Call(asset),
                Bind(asset, "Safe"), Add(), Call(asset), Assign("None"), Add(), Call(asset)],
            "instance" => [Assign("Sensitive"), Add(), Call(asset)],
            "none" => [Assign("nOnE"), Add(), Call(asset)],
            "numbered-none" => [Assign("None_0"), Add(), Call(asset)],
            "literal-null" => [Assign("null"), Add(), Call(asset)],
            "copy" => [Bind(asset), new EX_LetDelegate { VariableExpression = Local(asset, "Copy"), AssignmentExpression = Local(asset) },
                new EX_AddMulticastDelegate { Delegate = Local(asset, "LocalEvents"), DelegateToAdd = Local(asset, "Copy") },
                new EX_LetMulticastDelegate { VariableExpression = Events(asset), AssignmentExpression = Local(asset, "LocalEvents") }, Call(asset)],
            "before" => [Call(asset), Bind(asset), Add()],
            "branch" => [new EX_JumpIfNot { CodeOffset = 0, BooleanExpression = new EX_True() }, Bind(asset), Add(), Call(asset)],
            "loop" => [Call(asset), Bind(asset), Add(), new EX_Jump { CodeOffset = 0 }],
            "alias" => [Bind(asset), new EX_AddMulticastDelegate { Delegate = Events(asset),
                DelegateToAdd = new EX_LocalOutVariable { Variable = Local(asset).Variable } }, Call(asset)],
            "unknown-assignment" => [Bind(asset), new EX_LetDelegate { VariableExpression = Local(asset), AssignmentExpression = new EX_Nothing() }, Add(), Call(asset)],
            "remove-only" => [Bind(asset), new EX_RemoveMulticastDelegate { Delegate = Events(asset), DelegateToAdd = Local(asset) }, Call(asset)],
            "objects" => [new EX_BindDelegate { FunctionName = new(asset, "Sensitive"), ObjectTerm = new EX_Self(),
                Delegate = Context(asset, 7, new EX_InstanceVariable { Variable = new(new FFieldPath { Path = [new(asset, "Callback")], ResolvedOwner = new(1) }) }) },
                new EX_AddMulticastDelegate { Delegate = Context(asset, 7, Events(asset)),
                    DelegateToAdd = Context(asset, 7, new EX_InstanceVariable { Variable = new(new FFieldPath { Path = [new(asset, "Callback")], ResolvedOwner = new(1) }) }) },
                Context(asset, 8, Call(asset)), Context(asset, 7, Call(asset))],
            _ => throw new ArgumentException(nameof(mode))
        };
        if (mode == "objects")
            foreach (var name in new[] { "First", "Second" })
                asset.Exports.Add(new NormalExport { Asset = asset, ObjectName = new(asset, name), OuterIndex = new(0),
                    ClassIndex = new(1), Data = [], Extras = [] });
        run.ScriptBytecode = code;
        run.ScriptBytecodeSize = code.Sum(e => (int)e.GetSize(asset));
        if (mode == "numbered-none") PackageContextFixture.Function(asset, "None_0");
        if (mode == "literal-null") PackageContextFixture.Function(asset, "null");
        return asset;
    }

    internal static void Budget(UAsset asset, int calls = 200)
    {
        var run = (FunctionExport)asset.Exports[5];
        run.ScriptBytecode = new KismetExpression[] { new EX_FinalFunction { StackNode = new(3), Parameters = [] } }
            .Concat(Enumerable.Range(0, 40).Select(_ => Bind(asset)))
            .Append(new EX_AddMulticastDelegate { Delegate = Events(asset), DelegateToAdd = Local(asset) })
            .Concat(Enumerable.Range(0, calls).Select(_ => Call(asset))).ToArray();
        run.ScriptBytecodeSize = run.ScriptBytecode.Sum(e => (int)e.GetSize(asset));
    }

    internal static void Write(string root, bool budget = false)
    {
        Directory.CreateDirectory(root);
        if (!budget) Create().Write(Path.Combine(root, "DelegateFlow.uasset"));
        else
        {
            foreach (var name in new[] { "A", "B", "Z" })
            {
                var asset = Create();
                if (name != "Z") Budget(asset);
                asset.Write(Path.Combine(root, name + ".uasset"));
            }
        }
    }
}
