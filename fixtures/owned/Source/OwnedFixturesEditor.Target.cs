using UnrealBuildTool;

public class OwnedFixturesEditorTarget : TargetRules
{
    public OwnedFixturesEditorTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Editor;
        DefaultBuildSettings = BuildSettingsVersion.V2;
        ExtraModuleNames.AddRange(new[] { "OwnedFixtures", "OwnedFixturesEditor" });
    }
}
