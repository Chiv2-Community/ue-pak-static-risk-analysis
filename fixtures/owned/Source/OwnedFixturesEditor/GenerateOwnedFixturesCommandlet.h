#pragma once

#include "Commandlets/Commandlet.h"
#include "GenerateOwnedFixturesCommandlet.generated.h"

UCLASS()
class UGenerateOwnedFixturesCommandlet : public UCommandlet
{
    GENERATED_BODY()
public:
    UGenerateOwnedFixturesCommandlet();
    virtual int32 Main(const FString& Params) override;
};
