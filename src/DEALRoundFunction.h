#pragma once
#include "KeyExpansion.h"
#include "DES.h"


class DEALRoundFunction : public IRoundFunction
{
    void roundFun(uint8_t* text, uint8_t* result, uint8_t* roundKey) override
    {
        auto alg = DES();

        alg.encrypt(text, result, roundKey);
    }
};
