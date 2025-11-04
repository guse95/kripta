#pragma once
#include "KeyExpansion.h"
#include "P_Block.h"

const int PC_1[][] = {
    {
        57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36
    },
    {
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    }
};

const int PC_2[] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

class DESKeyExpansion final : IKeyExpansion
{
    void expandKey(const uint8_t* key, uint8_t** new_keys) override
    {
        uint8_t tmp_c[4];
        uint8_t tmp_d[4];

        permutations(key, 64, PC_1[0], 28, tmp_c, true);
        const auto c = reinterpret_cast<uint32_t*>(tmp_c);
        permutations(key, 64, PC_1[1], 28, tmp_c, true);
        const auto d = reinterpret_cast<uint32_t*>(tmp_d);

        constexpr uint32_t mask = (1 << 28) - 1;
        uint32_t shift;

        for (int i = 1; i <= 16; i++)
        {
            if (i == 1 || i == 16 || i == 2 || i == 9)
                shift = 1;
            else
                shift = 2;
            *c = (*c << shift) | (*c >> (28 - shift)) & mask;
            *d = (*d << shift) | (*d >> (28 - shift)) & mask;

            uint64_t tmp_key_i = *c;
            tmp_key_i <<= 28;
            tmp_key_i |= *d;
            tmp_key_i <<= 8;
            permutations(reinterpret_cast<uint8_t*>(&tmp_key_i), 56,
                PC_2, 48, new_keys[i], true);
        }
    }
};
