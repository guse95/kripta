#pragma once
#include "ISymmetricCypher.h"

class DES : ISymmetricCypher
{


public:
    DES() {}

    uint8_t* encrypt(uint8_t* text, uint8_t* key) override
    {

    }

    uint8_t* decrypt(uint8_t* text, uint8_t* key) override
    {

    }
};
