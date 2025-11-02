#include "P_Block.h"

uint8_t get_bit(const uint8_t* text, const size_t ind, const size_t size_text, bool is_indexing_strait)
{
    uint8_t bit;
    if (is_indexing_strait)
        bit = text[(size_text - 1 - ind) / 8] & (1 << (ind % 8));
    else
        bit = text[ind / 8] & (1 << ((size_text - 1 - ind) % 8));
    return bit > 0;
}

void set_bit(uint8_t* text, const size_t new_ind, uint8_t bit, const size_t size_text, bool is_indexing_strait)
{
    if (is_indexing_strait)
        text[(size_text - 1 - new_ind) / 8] |= bit << (new_ind % 8);
    else
        text[new_ind / 8] |= bit << ((size_text - 1 - new_ind) % 8);
}

void permutations(const uint8_t* block, const size_t size_block,
    const int* p_block, const size_t size_p, uint8_t* new_block,
    bool is_indexing_strait) // strait == 63 -> 0
{
    for (size_t i = 0; i < size_p; i++)
    {
        const uint8_t bit = get_bit(block, p_block[i], size_block, is_indexing_strait);
        set_bit(new_block, i, bit, size_p, is_indexing_strait);
    }
}