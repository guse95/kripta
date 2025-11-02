#pragma once
#include <cstdint>

class IKeyExpansion
{
public:
    virtual ~IKeyExpansion() = default;

    virtual uint8_t** expandKey(const uint8_t* key) = 0;
};

class IRoundFunction
{
public:
    virtual ~IRoundFunction() = default;

    virtual uint8_t* roundFun(uint8_t* text, const uint8_t* roundKey) = 0;
};

