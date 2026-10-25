using PakRisk.Scanner;
using Xunit;

namespace Scanner.Tests;

public sealed class ContentPolicyTests
{
    private static ContentPolicy Config(params string[] args) => ContentPolicy.Parse(args).Policy!;
    public static MemberEvidence Member(string path = "Owned/Content/A.uasset", string identity = "/Script/Engine.Actor") =>
        new("r00000000", path, 10, new string('a', 64), "payload_verified", ["unreal_package_tag"],
            ["Actor"], "parsed", "not_applicable", [new(identity, "export-class-index-import")], true, true);
    private static InspectionEvidence Inventory(params MemberEvidence[] members) => new("validated", "completed", [.. members]);

    [Theory]
    [InlineData("Owned/Content", "Owned/Content/A.uasset", "allow")]
    [InlineData("owned/content", "Owned/Content/A.uasset", "allow")]
    [InlineData("Owned/Cont", "Owned/Content/A.uasset", "reject")]
    [InlineData("Owned/Content", "Owned/ContentElse/A.uasset", "reject")]
    [InlineData("Owned/Content/A.uasset", "Owned/Content/A.uasset", "allow")]
    public void PathsUseAsciiCaseInsensitiveComponentBoundaries(string prefix, string path, string expected) =>
        Assert.Equal(expected, Config("--allowed-path", prefix).Evaluate(Inventory(Member(path))).Decision);

    [Theory]
    [InlineData("/Script/Engine.Actor", "allow")]
    [InlineData("/Script/Engine.Pawn", "reject")]
    [InlineData("/Script/engine.Actor", "reject")]
    public void SameFilenameRequiresActualCaseSensitiveParsedClass(string identity, string expected) =>
        Assert.Equal(expected, Config("--allowed-class", "/Script/Engine.Actor").Evaluate(Inventory(Member(identity: identity))).Decision);

    [Theory]
    [InlineData("")]
    [InlineData("/Owned")]
    [InlineData("Owned/")]
    [InlineData("Owned//Content")]
    [InlineData("Owned/../Content")]
    [InlineData("Owned/./Content")]
    [InlineData("Owned\\Content")]
    [InlineData("Owned/Content\n")]
    [InlineData("Owned/Contént")]
    [InlineData("Owned/CON.ini")]
    [InlineData("Owned/com9")]
    [InlineData("Owned/a.")]
    [InlineData("Owned/a ")]
    [InlineData("Owned/C:")]
    public void InvalidPrefixesFailWithoutDetails(string value)
    {
        var error = Assert.Throws<ContentConfigurationException>(() => Config("--allowed-path", value));
        Assert.Equal("Invalid configuration.", error.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Actor")]
    [InlineData("/Script/Engine.Actor\n")]
    [InlineData("/Script/Engine.Actör")]
    public void InvalidClassesFail(string value) => Assert.Throws<ContentConfigurationException>(() => Config("--allowed-class", value));

    [Fact]
    public void DuplicateAndBoundedSettingsFail()
    {
        foreach (var args in new[] {
            new[] { "--allowed-path", "Owned", "--allowed-path", "owned" },
            ["--allowed-class", "/Script/Engine.Actor", "--allowed-class", "/Script/Engine.Actor"],
            ["--replacement-policy", "reject"],
            ["--protected-path", "Owned", "--replacement-policy", "unknown"],
            ["--protected-path", "Owned", "--replacement-policy", "allow", "--replacement-policy", "allow"],
            ["--protected-path"],
            Enumerable.Range(0, 257).SelectMany(i => new[] { "--allowed-path", "Owned/" + i }).ToArray() })
            Assert.Throws<ContentConfigurationException>(() => Config(args));
        Assert.Null(ContentPolicy.Parse(["evaluate"]).Policy);
    }

    [Theory]
    [InlineData("allow", "allow", false)]
    [InlineData("review", "needs-review", true)]
    [InlineData("reject", "reject", true)]
    public void ProtectedCandidatesHaveSeparateMandatoryGate(string replacement, string expected, bool fails)
    {
        var result = Config("--protected-path", "owned", "--replacement-policy", replacement).Evaluate(Inventory(Member()));
        Assert.Equal(expected, result.Decision);
        Assert.False(result.Incomplete);
        Assert.Equal("protected-path-candidate", Assert.Single(result.Findings).Diagnostic);
        var report = RiskReport.Failed("analysis-failed") with { Status = "successful", AnalysisComplete = true };
        report = report.WithContent(result);
        for (var bits = 0; bits < 8; bits++)
            Assert.Equal(fails, new GateOptions((bits & 1) != 0, (bits & 2) != 0, (bits & 4) != 0).Fails(report));
        Assert.Equal("needs-review", Config("--protected-path", "Owned").Evaluate(Inventory(Member())).Decision);
        Assert.Equal("allow", Config("--protected-path", "Other").Evaluate(Inventory(Member())).Decision);
    }

    [Theory]
    [InlineData("elf")]
    [InlineData("shebang_script")]
    [InlineData("unknown_content")]
    [InlineData("pe")]
    public void AllowlistsCannotApproveNonPackageSignatures(string signature)
    {
        var member = Member() with { Signatures = [signature] };
        var result = Config("--allowed-path", "Owned", "--allowed-class", "/Script/Engine.Actor").Evaluate(Inventory(member));
        Assert.True(result.Incomplete);
        Assert.Contains(result.Findings, f => f.Diagnostic == "content-inspection-unavailable");
    }

    [Theory]
    [InlineData("parse_failed")]
    [InlineData("uninspected")]
    [InlineData("unknown_content_root")]
    public void MissingClassesOrParsingCannotBecomeComplete(string status)
    {
        var policy = Config("--allowed-class", "/Script/Engine.Actor");
        Assert.True(policy.Evaluate(Inventory(Member() with { InspectionStatus = status })).Incomplete);
        Assert.True(policy.Evaluate(Inventory(Member() with { ParsedClasses = null })).Incomplete);
        Assert.True(policy.Evaluate(Inventory(Member() with { ParsedClasses = [] })).Incomplete);
        Assert.True(policy.Evaluate(null).Incomplete);
        Assert.True(policy.Evaluate(Inventory()).Incomplete);
    }

    [Fact]
    public void OnlyUnknownPairedExportsAreExemptFromOwnClassEvidence()
    {
        var policy = Config("--allowed-class", "/Script/Engine.Actor");
        var member = Member("Owned/Content/A.uexp") with { ParsedClasses = null, InspectionStatus = "paired_export_data", Signatures = ["unknown_content"] };
        Assert.False(policy.Evaluate(Inventory(member)).Incomplete);
        Assert.True(policy.Evaluate(Inventory(member with { Signatures = ["elf"] })).Incomplete);
    }

    [Theory]
    [InlineData("--allowed-path", "Owned")]
    [InlineData("--allowed-class", "/Script/Engine.Actor")]
    [InlineData("--protected-path", "Other")]
    public void ClassInventoryCoverageDoesNotDependOnAClassRestriction(string flag, string value)
    {
        var policy = Config(flag, value);
        Assert.False(policy.Evaluate(Inventory(Member())).Incomplete);
        foreach (var member in new[] { Member() with { ParsedClasses = null },
            Member() with { ParsedClasses = [] }, Member() with { ParsedClassesComplete = false },
            Member() with { ParsedClassesComplete = null } })
        {
            var result = policy.Evaluate(Inventory(member));
            Assert.Equal("allow", result.Decision);
            Assert.True(result.Incomplete);
            Assert.Equal("class-inspection-unavailable", Assert.Single(result.Findings).Diagnostic);
        }
        var paired = Member() with { InspectionStatus = "paired_export_data", Signatures = ["unknown_content"],
            ParsedClasses = null, ParsedClassesComplete = null };
        Assert.False(policy.Evaluate(Inventory(paired)).Incomplete);
    }

    [Fact]
    public void PathOnlyNonPackageHasContentGapNotAClassRequirement()
    {
        var result = Config("--allowed-path", "Owned").Evaluate(Inventory(Member() with {
            Signatures = ["config_candidate"], InspectionStatus = "uninspected", ParsedClasses = null,
            ParsedClassesComplete = null }));
        Assert.True(result.Incomplete);
        Assert.Equal("content-inspection-unavailable", Assert.Single(result.Findings).Diagnostic);
    }

    [Fact]
    public void IncompleteOrAdditionalSignaturesCannotHideKnownClassRejection()
    {
        var policy = Config("--allowed-class", "/Script/Engine.Other");
        foreach (var member in new[] { Member() with { ParsedClassesComplete = false },
            Member() with { Signatures = ["unreal_package_tag", "config_candidate"] } })
        {
            var result = policy.Evaluate(Inventory(member));
            Assert.Equal("reject", result.Decision);
            Assert.True(result.Incomplete);
            Assert.Contains(result.Findings, f => f.Diagnostic == "class-not-allowed");
        }
    }

    [Fact]
    public void RawFallbackNamesAreNotNormalizedProtectionCandidates()
    {
        var policy = Config("--allowed-path", "Different", "--protected-path", "Owned", "--replacement-policy", "reject");
        var result = policy.Evaluate(Inventory(Member() with { PathNormalized = false }));
        Assert.Equal("allow", result.Decision);
        Assert.True(result.Incomplete);
        Assert.Equal("path-identity-unavailable", Assert.Single(result.Findings).Diagnostic);
        Assert.True(policy.Evaluate(Inventory(Member() with { PathNormalized = null })).Incomplete);
    }
}
