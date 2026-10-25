using CompatibilityProbe;
using PakRisk.Extraction;
using PakRisk.Policy;
using UAssetAPI;
using UAssetAPI.ExportTypes;
using UAssetAPI.Kismet.Bytecode.Expressions;
using UAssetAPI.PropertyTypes.Objects;
using UAssetAPI.Unversioned;

if (args.Length == 3 && args[1] == "--class-fixtures")
    return ClassOwnership.WriteFixtures(args[0], args[2]);
if (args.Length != 1)
{
    Console.Error.WriteLine("Usage: OwnedFixtures.Verify <external-evidence-directory>");
    return 1;
}

var root = Path.GetFullPath(args[0]);
try
{
    foreach (var (name, number, text) in new[] {
        ("BP_OwnedParent", 10101, "owned-parent-default"),
        ("BP_OwnedChild", 20202, "owned-child-default") })
    {
        var path = Path.Combine(root, "tagged/OwnedFixtures/Content", name + ".uasset");
        var asset = PackageReader.Read(path, null);
        Check(!asset.HasUnversionedProperties, name + " must use tagged properties");
        CheckCooked(asset, name);
        CheckGraph(asset, path, name, "ExecuteUbergraph_" + name, "/Script/OwnedFixtures.FixtureActor:RecordFixture",
            name == "BP_OwnedParent" ? 101 : 202);
        var defaults = asset.Exports.OfType<NormalExport>().Single(e => e.ObjectName.ToString() == "Default__" + name + "_C");
        CheckValues(defaults, number, text);
        var generated = asset.Exports.Single(e => e.ObjectName.ToString() == name + "_C");
        Check(generated.SuperIndex.IsImport(), name + " superclass import");
        var superclass = asset.Imports[-generated.SuperIndex.Index - 1].ObjectName.ToString();
        Check(superclass == (name == "BP_OwnedParent" ? "FixtureActor" : "BP_OwnedParent_C"), name + " superclass identity");
    }

    var mapPath = Path.Combine(root, "tagged/OwnedFixtures/Content/OwnedMap.umap");
    var map = PackageReader.Read(mapPath, null);
    CheckCooked(map, "OwnedMap");
    CheckGraph(map, mapPath, "OwnedMap", "ExecuteUbergraph_OwnedMap", "/Script/OwnedFixtures.FixtureLibrary:ObserveFixture", 303);
    var taggedData = PackageReader.Read(Path.Combine(root, "tagged/OwnedFixtures/Content/Data/OwnedData.uasset"), null);
    Check(!taggedData.HasUnversionedProperties, "tagged native data control");
    CheckCooked(taggedData, "tagged OwnedData");
    CheckValues(taggedData.Exports.OfType<NormalExport>().Single(e => e.ObjectName.ToString() == "OwnedData"),
        424242, "owned-unversioned-value");
    var mappedPath = Path.Combine(root, "unversioned/OwnedFixtures/Content/Data/OwnedData.uasset");
    var mappings = new Usmap(Path.Combine(root, "owned.usmap"));
    var data = PackageReader.Read(mappedPath, mappings);
    Check(data.HasUnversionedProperties, "real unversioned property package flag");
    CheckCooked(data, "OwnedData");
    CheckValues(data.Exports.OfType<NormalExport>().Single(e => e.ObjectName.ToString() == "OwnedData"),
        424242, "owned-unversioned-value");
    var missing = Probe.Read(mappedPath, "OwnedData-without-mappings");
    Check(!missing.ParseComplete, "missing mappings must fail closed");
    Check(missing.Diagnostics.Any(d => d.Code is "missing-property-mappings" or "asset-read-failed"),
        "missing mappings must have explicit diagnostic");
    Console.WriteLine("OwnedData: unversioned=true; FixtureNumber=424242; FixtureText=owned-unversioned-value; RawExport=0; missing-mappings=incomplete.");
    Console.WriteLine("PASS: cooked parent/child inheritance, executable Blueprint and Level graphs, tagged custom defaults, real unversioned values, no RawExport, and missing-mappings negative.");
    Console.WriteLine("LinuxNoEditor compatibility only; no game execution or safety verdict.");
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine("FAIL: " + error.Message);
    return 1;
}

static void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static void CheckCooked(UAsset asset, string name)
{
    Check(asset.IsFilterEditorOnly, name + " editor-only filtered marker");
    Check(!asset.Exports.Any(e => e is RawExport), name + " must not contain RawExport");
}

static void CheckGraph(UAsset asset, string path, string name, string ubergraph, string target, int argument)
{
    var functions = asset.Exports.OfType<FunctionExport>().ToArray();
    Check(functions.Any(f => f.ObjectName.ToString() == ubergraph && f.ScriptBytecode is { Length: > 0 }), name + " executable ubergraph");
    Check(functions.Any(f => f.ObjectName.ToString() == "ReceiveBeginPlay" && f.ScriptBytecode is { Length: > 0 }), name + " BeginPlay function");
    var report = Probe.Inspect(asset, name, []);
    Check(report.ParseComplete, name + " probe diagnostics: " + string.Join(",", report.Diagnostics.Select(d => d.Code)));
    Check(report.ParsedFunctions == report.Functions && report.Functions >= 2, name + " parsed real functions");
    Check(report.Invocations.Any(call => call.Function == ubergraph && call.Target == target
        && call.Resolution == "package-index"), name + " expected executable native call");
    var matchedArgument = false;
    uint offset = 0;
    foreach (var expression in functions.Single(f => f.ObjectName.ToString() == ubergraph).ScriptBytecode)
        expression.Visit(asset, ref offset, (instruction, _) =>
        {
            if (instruction is not EX_FinalFunction call || TargetResolver.Resolve(asset, call.StackNode, name) != target)
                return;
            Check(call.Parameters.Length == 1, name + " native argument count");
            var value = call.Parameters[0] switch
            {
                EX_IntConst integer => integer.Value,
                EX_IntConstByte integer => integer.Value,
                _ => throw new InvalidOperationException(name + " native argument encoding")
            };
            Check(value == argument, name + " native argument value");
            matchedArgument = true;
        });
    Check(matchedArgument, name + " executable native argument");
    CheckNormalized(asset, path, name, ubergraph, target, argument);
    Console.WriteLine($"{name}: functions={report.ParsedFunctions}/{report.Functions}; native-target={target}; argument={argument}; RawExport=0.");
}

static void CheckNormalized(UAsset asset, string path, string name, string ubergraph, string target, int argument)
{
    // These are loose cooked fixtures, not an archived submission identity.
    var input = new PackageInput("owned-loose-cook", name, "/Game/" + name, path);
    var extracted = InvocationExtractor.Inspect(asset, input);
    Check(extracted.Functions.Length == 2, name + " normalized function coverage");
    Check(extracted.Analysis.CoverageGaps.IsEmpty, name + " no global policy gaps");
    var call = extracted.Invocations.Single(c => c.ContainingFunction.Name == ubergraph
        && c.ResolvedIdentity is { } identity && identity.Owner + ":" + identity.Function == target);
    Check(call.Arguments.Single().Value is ArgumentValue.Constant { Value: PolicyLiteral.Integer value }
        && value.Value == argument, name + " normalized native constant");
    Check(call.Fact.Arguments is ArgumentMetadata.Unavailable, name + " imported metadata remains unavailable");
    var resolved = (InvocationTarget.Resolved)call.Target;
    var match = new MatchExpression.Invocation(new TargetMatcher.Exact(resolved.Owner, resolved.Function));
    PolicyEvaluation Evaluate(MatchExpression expression) => new PolicyEvaluator(new PolicyDocument(1,
        [new PolicyRule("owned-call", "Owned fixture call", RuleEffect.Forbid, expression)])).Evaluate(extracted.Analysis);
    var exact = Evaluate(match);
    Check(exact.Findings.Length == 1 && !exact.IsIncomplete, name + " invocation-only policy completeness");
    var valueMatch = new MatchExpression.Argument("Value", new ValuePredicate.EqualTo(new PolicyLiteral.Integer(argument)));
    var unknown = Evaluate(new MatchExpression.All([match, new MatchExpression.Not(valueMatch)]));
    Check(unknown.Findings.IsEmpty && unknown.Uncertainties.Length == 1 && unknown.IsIncomplete,
        name + " unknown imported arguments survive negation");
    var irrelevant = Evaluate(new MatchExpression.All([
        new MatchExpression.Invocation(new TargetMatcher.Exact("/Script/Other.Owner", "Unrelated")), valueMatch]));
    Check(irrelevant.Findings.IsEmpty && irrelevant.Uncertainties.IsEmpty && !irrelevant.IsIncomplete,
        name + " unrelated target suppresses argument uncertainty");
    Console.WriteLine($"{name}: normalized-calls={extracted.Invocations.Length}; invocation-policy=complete; required-imported-arguments=unknown; unrelated-policy=complete.");
}

static void CheckValues(NormalExport export, int number, string text)
{
    Check(export.Data.OfType<IntPropertyData>().Single(p => p.Name.ToString() == "FixtureNumber").Value == number, "known int32 value");
    Check(export.Data.OfType<StrPropertyData>().Single(p => p.Name.ToString() == "FixtureText").Value.ToString() == text, "known FString value");
}
