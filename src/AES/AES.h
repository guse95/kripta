#ifndef AES_H
#define AES_H
#include <cstdint>
#include "../ISymmetricCypher.h"


constexpr int perm16[16] = {
    0, 4, 8, 12,
    1, 5, 9, 13,
    2, 6, 10, 14,
    3, 7, 11, 15,
};

constexpr int perm24[24] = {
    0, 4, 8, 12, 16, 20,
    1, 5, 9, 13, 17, 21,
    2, 6, 10, 14, 18, 22,
    3, 7, 11, 15, 19, 23,
};

constexpr int perm32[32] = {
    0, 4, 8, 12, 16, 20, 24, 28,
    1, 5, 9, 13, 17, 21, 25, 29,
    2, 6, 10, 14, 18, 22, 26, 30,
    3, 7, 11, 15, 19, 23, 27, 31,
};

class AES : public ISymmetricCypher {
    uint8_t* init_key;

public:
    uint8_t* exp_key;
    uint32_t key_len;
    uint32_t block_len;
    uint8_t S_box[256] = {0};
    uint8_t S_box_inv[256] = {0};

    AES(uint32_t block_len, uint32_t key_len, uint8_t* init_key);

    ~AES() override;

    static void sub_bytes(uint8_t *state, uint32_t byte_len, const uint8_t* S_box);

    static void shift_rows(uint8_t *state, uint32_t byte_len, bool inverted);

    static void mix_columns(uint8_t *state, uint32_t byte_len, bool inverted);

    static void add_round_key(uint8_t *state, uint32_t byte_len, const uint8_t* r_key);

    void encrypt(uint8_t* text, uint8_t* encrText, uint8_t* key) override;

    void decrypt(uint8_t* text, uint8_t* encrText, uint8_t* key) override;
};



#endif
