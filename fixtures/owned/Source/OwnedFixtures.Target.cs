using UnrealBuildTool;

public class OwnedFixturesTarget : TargetRules
{
    public OwnedFixturesTarget(TargetInfo Target) : base(Target)
    {
        Type = TargetType.Game;
        DefaultBuildSettings = BuildSettingsVersion.V2;
        ExtraModuleNames.Add("OwnedFixtures");
    }
}
