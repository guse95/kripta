#ifndef AESKEYEXPANTION_H
#define AESKEYEXPANTION_H

#include "../KeyExpansion.h"

class AESKeyExpantion : IKeyExpansion {
    uint32_t block_size = 0;
    uint8_t *S_box;

public:
    AESKeyExpantion(uint32_t block_size_, uint8_t *S_box_ptr) : block_size(block_size_), S_box(S_box_ptr) {}

    void expandKey(const uint8_t* key, uint8_t* new_keys, uint32_t key_len) override;
};



#endif
