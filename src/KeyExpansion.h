#pragma once
#include <cstdint>

class IKeyExpansion
{
public:
    virtual ~IKeyExpansion() = default;

    virtual uint8_t** expandKey(uint8_t* key) = 0;
};

class IRoundFunction
{
public:
    virtual ~IRoundFunction() = default;

    virtual uint8_t* roundKey(uint8_t* text, uint8_t* roundKey) = 0;
};

