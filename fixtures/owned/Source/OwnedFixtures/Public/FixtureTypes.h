#pragma once

#include "CoreMinimal.h"
#include "GameFramework/Actor.h"
#include "Kismet/BlueprintFunctionLibrary.h"
#include "FixtureTypes.generated.h"

UCLASS(Blueprintable)
class OWNEDFIXTURES_API AFixtureActor : public AActor
{
    GENERATED_BODY()
public:
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category="Fixture")
    int32 FixtureNumber = 31415;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category="Fixture")
    FString FixtureText = TEXT("owned-native-default");

    UFUNCTION(BlueprintCallable, Category="Fixture")
    void RecordFixture(int32 Value) { FixtureNumber = Value; }
};

UCLASS()
class OWNEDFIXTURES_API UFixtureData : public UObject
{
    GENERATED_BODY()
public:
    UPROPERTY()
    int32 FixtureNumber = 0;

    UPROPERTY()
    FString FixtureText;
};

UCLASS()
class OWNEDFIXTURES_API UFixtureLibrary : public UBlueprintFunctionLibrary
{
    GENERATED_BODY()
public:
    UFUNCTION(BlueprintCallable, Category="Fixture")
    static void ObserveFixture(int32 Value) { (void)Value; }
};
