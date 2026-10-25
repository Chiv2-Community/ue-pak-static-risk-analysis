#include "GenerateOwnedFixturesCommandlet.h"
#include "FixtureTypes.h"
#include "EdGraph/EdGraph.h"
#include "EdGraphSchema_K2.h"
#include "Engine/Blueprint.h"
#include "Engine/BlueprintGeneratedClass.h"
#include "Engine/Level.h"
#include "Engine/LevelScriptActor.h"
#include "Engine/LevelScriptBlueprint.h"
#include "Engine/World.h"
#include "FileHelpers.h"
#include "K2Node_CallFunction.h"
#include "K2Node_Event.h"
#include "Kismet2/BlueprintEditorUtils.h"
#include "Kismet2/KismetEditorUtilities.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
#include "Modules/ModuleManager.h"
#include "Serialization/JsonSerializer.h"
#include "UObject/Package.h"
#include "UObject/UnrealType.h"

IMPLEMENT_MODULE(FDefaultModuleImpl, OwnedFixturesEditor);

UGenerateOwnedFixturesCommandlet::UGenerateOwnedFixturesCommandlet()
{
    IsClient = false;
    IsServer = false;
    IsEditor = true;
    LogToConsole = true;
}

static void AddExecutableGraph(UBlueprint* Blueprint, UClass* EventClass, UFunction* Function, int32 Value)
{
    check(Blueprint->UbergraphPages.Num() > 0);
    UEdGraph* Graph = Blueprint->UbergraphPages[0];
    // CreateBlueprint can supply an unconnected default event; reuse it.
    UK2Node_Event* Event = nullptr;
    for (UEdGraphNode* Node : Graph->Nodes)
    {
        UK2Node_Event* Candidate = Cast<UK2Node_Event>(Node);
        if (Candidate && Candidate->EventReference.GetMemberName() == TEXT("ReceiveBeginPlay"))
            Event = Candidate;
    }
    int32 EventPositionY = 0;
    if (!Event)
        Event = FKismetEditorUtilities::AddDefaultEventNode(Blueprint, Graph, TEXT("ReceiveBeginPlay"), EventClass, EventPositionY);
    check(Event);
    UK2Node_CallFunction* Call = NewObject<UK2Node_CallFunction>(Graph);
    Call->SetFromFunction(Function);
    Graph->AddNode(Call, false, false);
    Call->CreateNewGuid();
    Call->PostPlacedNewNode();
    Call->AllocateDefaultPins();
    Call->NodePosX = 400;
    Call->FindPinChecked(TEXT("Value"))->DefaultValue = FString::FromInt(Value);
    const UEdGraphSchema_K2* Schema = GetDefault<UEdGraphSchema_K2>();
    check(Schema->TryCreateConnection(Event->FindPinChecked(UEdGraphSchema_K2::PN_Then),
        Call->FindPinChecked(UEdGraphSchema_K2::PN_Execute)));
    FBlueprintEditorUtils::MarkBlueprintAsStructurallyModified(Blueprint);
    FKismetEditorUtilities::CompileBlueprint(Blueprint);
    check(Blueprint->Status != BS_Error);
}

static bool SaveAsset(UObject* Asset, const FString& Filename)
{
    return UPackage::SavePackage(Asset->GetOutermost(), Asset, RF_Public | RF_Standalone,
        *Filename, GError, nullptr, false, true, SAVE_NoError);
}

int32 UGenerateOwnedFixturesCommandlet::Main(const FString& Params)
{
    const FString Content = FPaths::ProjectContentDir();
    IFileManager::Get().MakeDirectory(*Content, true);
    UPackage* ParentPackage = CreatePackage(nullptr, TEXT("/Game/BP_OwnedParent"));
    UBlueprint* Parent = FKismetEditorUtilities::CreateBlueprint(AFixtureActor::StaticClass(), ParentPackage,
        TEXT("BP_OwnedParent"), BPTYPE_Normal, UBlueprint::StaticClass(), UBlueprintGeneratedClass::StaticClass());
    AddExecutableGraph(Parent, AActor::StaticClass(), AFixtureActor::StaticClass()->FindFunctionByName(TEXT("RecordFixture")), 101);
    AFixtureActor* ParentDefault = CastChecked<AFixtureActor>(Parent->GeneratedClass->GetDefaultObject());
    ParentDefault->FixtureNumber = 10101;
    ParentDefault->FixtureText = TEXT("owned-parent-default");
    if (!SaveAsset(Parent, Content / TEXT("BP_OwnedParent.uasset"))) return 1;

    UPackage* ChildPackage = CreatePackage(nullptr, TEXT("/Game/BP_OwnedChild"));
    UBlueprint* Child = FKismetEditorUtilities::CreateBlueprint(Parent->GeneratedClass, ChildPackage,
        TEXT("BP_OwnedChild"), BPTYPE_Normal, UBlueprint::StaticClass(), UBlueprintGeneratedClass::StaticClass());
    AddExecutableGraph(Child, AActor::StaticClass(), AFixtureActor::StaticClass()->FindFunctionByName(TEXT("RecordFixture")), 202);
    AFixtureActor* ChildDefault = CastChecked<AFixtureActor>(Child->GeneratedClass->GetDefaultObject());
    ChildDefault->FixtureNumber = 20202;
    ChildDefault->FixtureText = TEXT("owned-child-default");
    if (!SaveAsset(Child, Content / TEXT("BP_OwnedChild.uasset"))) return 1;

    UWorld* World = UWorld::CreateWorld(EWorldType::Editor, false, TEXT("OwnedMap"), CreatePackage(nullptr, TEXT("/Game/OwnedMap")));
    ULevelScriptBlueprint* LevelBlueprint = World->PersistentLevel->GetLevelScriptBlueprint();
    AddExecutableGraph(LevelBlueprint, AActor::StaticClass(), UFixtureLibrary::StaticClass()->FindFunctionByName(TEXT("ObserveFixture")), 303);
    World->SpawnActor<AFixtureActor>(Child->GeneratedClass);
    if (!FEditorFileUtils::SaveMap(World, Content / TEXT("OwnedMap.umap"))) return 1;

    IFileManager::Get().MakeDirectory(*(Content / TEXT("Data")), true);
    UPackage* DataPackage = CreatePackage(nullptr, TEXT("/Game/Data/OwnedData"));
    UFixtureData* Data = NewObject<UFixtureData>(DataPackage, TEXT("OwnedData"), RF_Public | RF_Standalone);
    Data->FixtureNumber = 424242;
    Data->FixtureText = TEXT("owned-unversioned-value");
    if (!SaveAsset(Data, Content / TEXT("Data/OwnedData.uasset"))) return 1;

    // Emit actual producer serialization order, including zero-property superclasses.
    TArray<TSharedPtr<FJsonValue>> Schemas;
    for (UClass* Class = UFixtureData::StaticClass(); Class; Class = Class->GetSuperClass())
    {
        TSharedPtr<FJsonObject> Schema = MakeShared<FJsonObject>();
        Schema->SetStringField(TEXT("name"), Class->GetName());
        if (Class->GetSuperClass()) Schema->SetStringField(TEXT("super"), Class->GetSuperClass()->GetName());
        TArray<TSharedPtr<FJsonValue>> Properties;
        for (FProperty* Property = Class->PropertyLink; Property; Property = Property->PropertyLinkNext)
        {
            if (Property->GetOwnerClass() != Class || Property->HasAnyPropertyFlags(CPF_EditorOnly)) continue;
            TSharedPtr<FJsonObject> Record = MakeShared<FJsonObject>();
            Record->SetStringField(TEXT("name"), Property->GetName());
            Record->SetStringField(TEXT("type"), Property->GetClass()->GetName());
            Record->SetNumberField(TEXT("array_dim"), Property->ArrayDim);
            Properties.Add(MakeShared<FJsonValueObject>(Record));
        }
        Schema->SetArrayField(TEXT("properties"), Properties);
        Schemas.Add(MakeShared<FJsonValueObject>(Schema));
    }
    TSharedRef<FJsonObject> Receipt = MakeShared<FJsonObject>();
    Receipt->SetStringField(TEXT("order"), TEXT("PropertyLink; local slots before superclass; editor-only excluded"));
    Receipt->SetArrayField(TEXT("schemas"), Schemas);
    FString Json;
    FJsonSerializer::Serialize(Receipt, TJsonWriterFactory<>::Create(&Json));
    return FFileHelper::SaveStringToFile(Json, *(FPaths::ProjectSavedDir() / TEXT("producer-reflection.json"))) ? 0 : 1;
}
