#pragma once
#include <cstdint>

class IKeyExpansion
{
public:
    virtual ~IKeyExpansion() = default;

    virtual void expandKey(const uint8_t* key, uint8_t* new_keys) = 0;
};

class IRoundFunction
{
public:
    virtual ~IRoundFunction() = default;

    virtual void roundFun(uint8_t* text, uint8_t* result, uint8_t* roundKey) = 0;
};

