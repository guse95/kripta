#ifndef P_BLOCK_H
#define P_BLOCK_H

#include <iostream>
#include <cstdint>

enum class ByteOrder{BigEndian, LittleEndian};

uint8_t get_bit(const uint8_t* text, size_t ind, size_t size_text, const ByteOrder order);

void set_bit(uint8_t* text, size_t new_ind, uint8_t bit, size_t size_text, const ByteOrder order);

void permutations(const uint8_t* block, const size_t size_block,
    const int* p_block, const size_t size_p, uint8_t* new_block,
    const ByteOrder order = ByteOrder::BigEndian, bool is_indexing_from_zero = false); // strait == 63 -> 0

#endif
