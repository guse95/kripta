#include <iostream>
#include <cstdint>

void get_bit(uint8_t* text, size_t ind, bool is_indexing_strait)
{
    size_t bit;
    if (is_indexing_strait)
        bit = text[ind / 8] & (1 << (ind % 8));
    else
        bit = text[(size - ind) / 8] & (1 << ((size - ind) % 8));
}

void set_bit(uint8_t* text, size_t ind)
{
    //TODO: переделать перестановки чтобы учитывался порядок индексации битов
}

void permutations(const unsigned char* value, const int* p_block, bool is_indexing_strait, size_t size)
{
    unsigned char tmp[size / sizeof(char)];

    for (size_t i = 0; i < size; i++)
    {
        const uint8_t c = (value[p_block[i] / 8] & (1 << (p_block[i] % 8))) >> (p_block[i] % 8) << (i % 8);
        tmp[i / 8] |= c;
    }
    value = tmp;
}