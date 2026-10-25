using System.Security.Cryptography;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.UnrealTypes;
using UAssetAPI.Unversioned;

namespace CompatibilityProbe;

public static class Probe
{
    public static AssetReport Read(string path, string identity, Usmap? mappings = null)
    {
        var inputs = new List<InputFile>();
        try
        {
            foreach (var input in new[] { path, Path.ChangeExtension(path, ".uexp"), Path.ChangeExtension(path, ".ubulk") })
            {
                if (input != path && !File.Exists(input))
                    continue;
                using var stream = File.OpenRead(input);
                inputs.Add(new InputFile(Path.GetFileName(input), Convert.ToHexStringLower(SHA256.HashData(stream)), stream.Length));
            }
            var asset = PackageReader.Read(path, mappings);
            return Inspect(asset, identity, inputs.ToArray());
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // Dependency exception messages can include arbitrary asset contents.
            return new AssetReport(identity, inputs.ToArray(), null, null, null, 0, 0, 0, [],
                [new Diagnostic("asset-read-failed", null, error.GetType().Name)]);
        }
    }

    public static AssetReport Inspect(UAsset asset, string identity, InputFile[] inputs)
    {
        var diagnostics = new List<Diagnostic>();
        var invocations = new List<Invocation>();
        var functions = 0;
        var parsedFunctions = 0;
        var cooked = asset.PackageFlags.HasFlag(EPackageFlags.PKG_Cooked);
        // Real cooked UE 4.25 packages may omit PKG_Cooked but set PKG_FilterEditorOnly.
        if (!cooked && !asset.IsFilterEditorOnly)
            diagnostics.Add(new Diagnostic("no-cooked-or-filtered-marker", null));
        if (asset.HasUnversionedProperties && asset.Mappings is null)
            diagnostics.Add(new Diagnostic("missing-property-mappings", null));

        foreach (var export in asset.Exports)
        {
            var name = export.ObjectName?.ToString() ?? "<unnamed>";
            if (export is RawExport)
                diagnostics.Add(new Diagnostic("raw-export", name));
            if (export is not FunctionExport function)
                continue;
            functions++;
            if (function.ScriptBytecode is null)
            {
                diagnostics.Add(new Diagnostic("unparsed-bytecode", name));
                continue;
            }
            try
            {
                uint offset = 0;
                foreach (var expression in function.ScriptBytecode)
                {
                    expression.Visit(asset, ref offset, (instruction, position) =>
                    {
                        if (instruction is EX_CallMulticastDelegate)
                        {
                            diagnostics.Add(new Diagnostic("unresolved-delegate-behavior", name, position.ToString()));
                        }
                        else if (instruction is EX_FinalFunction direct)
                        {
                            var target = TargetResolver.Resolve(asset, direct.StackNode, identity);
                            invocations.Add(new Invocation(name, position, instruction.Token.ToString(), target,
                                target is null ? "unresolved" : "package-index"));
                            if (target is null)
                                diagnostics.Add(new Diagnostic("unresolved-direct-target", name, position.ToString()));
                        }
                        else if (instruction is EX_VirtualFunction virtualCall)
                        {
                            invocations.Add(new Invocation(name, position, instruction.Token.ToString(),
                                virtualCall.VirtualFunctionName?.ToString(), "name-only"));
                            diagnostics.Add(new Diagnostic("unresolved-virtual-target", name, position.ToString()));
                        }
                        else if (instruction.Token is EExprToken.EX_CallMulticastDelegate or EExprToken.EX_BindDelegate
                                 or EExprToken.EX_InstanceDelegate or EExprToken.EX_AddMulticastDelegate
                                 or EExprToken.EX_RemoveMulticastDelegate or EExprToken.EX_ClearMulticastDelegate)
                        {
                            diagnostics.Add(new Diagnostic("unresolved-delegate-behavior", name, position.ToString()));
                        }
                    });
                }
                // Visit offsets are VM offsets, not serialized file offsets.
                if (offset != function.ScriptBytecodeSize)
                    diagnostics.Add(new Diagnostic("bytecode-size-mismatch", name,
                        $"declared={function.ScriptBytecodeSize};visited={offset}"));
                parsedFunctions++;
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                diagnostics.Add(new Diagnostic("bytecode-visit-failed", name, error.GetType().Name));
            }
        }
        return new AssetReport(identity, inputs, cooked, asset.IsFilterEditorOnly, asset.HasUnversionedProperties,
            asset.Exports.Count, functions, parsedFunctions, invocations.ToArray(), diagnostics.ToArray());
    }
}
