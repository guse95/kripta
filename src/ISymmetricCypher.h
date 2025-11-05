#pragma once
#include <cstdint>

class ISymmetricCypher
{
public:
    virtual ~ISymmetricCypher() = default;

    virtual void encrypt(uint8_t* text, uint8_t* encrText, uint8_t* key) = 0;
    virtual void decrypt(uint8_t* text, uint8_t* decrText, uint8_t* key) = 0;
};