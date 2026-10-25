using UnrealBuildTool;

public class OwnedFixturesEditor : ModuleRules
{
    public OwnedFixturesEditor(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PrivateDependencyModuleNames.AddRange(new[] {
            "Core", "CoreUObject", "Engine", "OwnedFixtures", "UnrealEd",
            "Kismet", "KismetCompiler", "BlueprintGraph", "Json"
        });
    }
}
