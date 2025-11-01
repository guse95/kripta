#pragma once
#include <cstdint>

class ISymmetricCypher
{
public:
    virtual ~ISymmetricCypher() = default;

    virtual uint8_t* encrypt(uint8_t* text, uint8_t* key) = 0;
    virtual uint8_t* decrypt(uint8_t* text, uint8_t* key) = 0;
};