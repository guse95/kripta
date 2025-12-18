#include "AES.h"

#include <cstring>
#include "AESKeyExpantion.h"
#include "AES.h"

#include "GaloisField.h"



AES::AES(uint32_t block_len, uint32_t key_len, uint8_t* init_key_ptr) : key_len(key_len), block_len(block_len) {
    init_key = new uint8_t[key_len]();
    memcpy(init_key, init_key_ptr, key_len);

    uint16_t mod = 0x11B;
    static const unsigned char BitsSetTable256[256] = {
        #   define B2(n) n,     n+1,     n+1,     n+2
        #   define B4(n) B2(n), B2(n+1), B2(n+1), B2(n+2)
        #   define B6(n) B4(n), B4(n+1), B4(n+1), B4(n+2)
        B6(0), B6(1), B6(1), B6(2)
    };

    for (int iter = 0; iter < 256; ++iter) {
        auto i = static_cast<uint8_t>(iter);
        uint8_t y = GaloisField::inverse_mod(i, mod);

        // uint8_t A[] = {
        //     0b10001111,
        //     0b11000111,
        //     0b11100011,
        //     0b11110001,
        //     0b11111000,
        //     0b01111100,
        //     0b00111110,
        //     0b00011111
        // };
        //
        // for (int j = 0; j < 8; ++j)
        // {
        //     this->S_box[i] |= BitsSetTable256[A[i] * y] << i;
        // }

        uint8_t y0 = (y >> 0) & 1;
        uint8_t y1 = (y >> 1) & 1;
        uint8_t y2 = (y >> 2) & 1;
        uint8_t y3 = (y >> 3) & 1;
        uint8_t y4 = (y >> 4) & 1;
        uint8_t y5 = (y >> 5) & 1;
        uint8_t y6 = (y >> 6) & 1;
        uint8_t y7 = (y >> 7) & 1;

        uint8_t z0 = y0 ^ y4 ^ y5 ^ y6 ^ y7 ^ 1;
        uint8_t z1 = y0 ^ y1 ^ y5 ^ y6 ^ y7 ^ 1;
        uint8_t z2 = y0 ^ y1 ^ y2 ^ y6 ^ y7 ^ 0;
        uint8_t z3 = y0 ^ y1 ^ y2 ^ y3 ^ y7 ^ 0;
        uint8_t z4 = y0 ^ y1 ^ y2 ^ y3 ^ y4 ^ 0;
        uint8_t z5 = y1 ^ y2 ^ y3 ^ y4 ^ y5 ^ 1;
        uint8_t z6 = y2 ^ y3 ^ y4 ^ y5 ^ y6 ^ 1;
        uint8_t z7 = y3 ^ y4 ^ y5 ^ y6 ^ y7 ^ 0;

        this->S_box[i] = z0 | (z1 << 1) | (z2 << 2) | (z3 << 3) | (z4 << 4) | (z5 << 5) | (z6 << 6) | (z7 << 7);
    }

    for (int i = 0; i < 256; ++i) {
        S_box_inv[S_box[i]] = i;
    }

    int rounds_cnt = key_len == 16 ? 10 : (key_len == 24 ? 12 : 14);
    size_t exp_key_size = (rounds_cnt + 1) * block_len;
    exp_key = new uint8_t[exp_key_size]();

    AESKeyExpantion key_extenser(block_len, reinterpret_cast<uint8_t*>(&S_box));
    key_extenser.expandKey(init_key, exp_key, key_len);
}

AES::~AES() {
    delete[] exp_key;
    delete[] init_key;
}

void AES::sub_bytes(uint8_t *state, uint32_t byte_len, const uint8_t* S_box) {
    for (int i = 0; i < static_cast<int>(byte_len); ++i) {
        state[i] = S_box[state[i]];
    }
}

void AES::shift_rows(uint8_t* state, uint32_t byte_len, bool inverted) {
    const int Nb = static_cast<int>(byte_len / 4);
    uint8_t tmp[32] = {0};

    for (int i = 0; i < static_cast<int>(byte_len); ++i) tmp[i] = state[i];

    for (int r = 1; r < 4; ++r) {
        const int shift = r % Nb;
        for (int c = 0; c < Nb; ++c) {
            int src_c;
            if (!inverted) {
                src_c = (c + shift) % Nb;
            } else {
                src_c = (c - shift + Nb) % Nb;
            }
            state[r * Nb + c] = tmp[r * Nb + src_c];
        }
    }
    for (int c = 0; c < Nb; ++c) state[c] = tmp[c];
}

void matr_mult_col(const uint8_t* matr, const uint8_t* col, uint8_t* res_col) {
    for (int i = 0; i < 4; ++i) {
        uint8_t cell = 0;
        for (int j = 0; j < 4; ++j) {
            uint8_t mult_res = GaloisField::mult_mod(matr[i * 4 + j], col[j], 0x11B);
            cell = GaloisField::add(cell, mult_res);
        }
        res_col[i] = cell;
    }
}

void AES::mix_columns(uint8_t *state, uint32_t byte_len, bool inverted) {
    uint8_t mix_col_matr[16] = {
        2, 3, 1, 1,
        1, 2, 3, 1,
        1, 1, 2, 3,
        3, 1, 1, 2,
    };

    uint8_t inv_mix_col_matr[16] = {
        0x0e, 0x0b, 0x0d, 0x09,
        0x09, 0x0e, 0x0b, 0x0d,
        0x0d, 0x09, 0x0e, 0x0b,
        0x0b, 0x0d, 0x09, 0x0e,
    };

    for (int i = 0; i < static_cast<int>(byte_len) / 4; ++i) {
        uint8_t col[4] = {*(state + i), *(state + i + (byte_len / 4)), *(state + i + byte_len / 4 * 2), *(state + i + byte_len / 4 * 3)};
        uint8_t new_col[4] = { 0 };
        if (inverted) {
            matr_mult_col(reinterpret_cast<uint8_t*>(&inv_mix_col_matr), reinterpret_cast<const uint8_t *>(&col), reinterpret_cast<uint8_t *>(&new_col));
        }
        else {
            matr_mult_col(reinterpret_cast<uint8_t*>(&mix_col_matr), reinterpret_cast<const uint8_t *>(&col), reinterpret_cast<uint8_t *>(&new_col));
        }
        for (int j = 0; j < 4; ++j) {
            state[i + j * byte_len / 4] = new_col[j];
        }
    }
}

void AES::add_round_key(uint8_t *state, uint32_t byte_len, const uint8_t *r_key) {
    for (int i = 0; i < static_cast<int>(byte_len); ++i) {
        state[i] ^= r_key[i];
    }
}


void AES::encrypt(uint8_t *block, uint8_t *res, uint8_t *key) {
    uint8_t state[32] = { 0 };
    memcpy(state, block, block_len);

    add_round_key(state, block_len, exp_key);

    int rounds_cnt = key_len == 16 ? 10 : (key_len == 24 ? 12 : 14);
    for (int i = 0; i < rounds_cnt; ++i) {
        sub_bytes(state, block_len, reinterpret_cast<uint8_t*>(&S_box));
        shift_rows(state, block_len, false);
        if (i != rounds_cnt - 1) {
            mix_columns(state, block_len, false);
        }
        add_round_key(state, block_len, exp_key + block_len * (i + 1));
    }

    memcpy(res, state, block_len);
}

void AES::decrypt(uint8_t *block, uint8_t *res, uint8_t *key) {
    uint8_t state[32] = { 0 };
    memcpy(state, block, block_len);

    int rounds_cnt = key_len == 16 ? 10 : (key_len == 24 ? 12 : 14);

    add_round_key(state, block_len, exp_key + rounds_cnt * block_len);

    for (int i = 0; i < rounds_cnt; ++i) {
        shift_rows(state, block_len, true);
        sub_bytes(state, block_len, reinterpret_cast<uint8_t*>(&S_box_inv));
        add_round_key(state, block_len, exp_key + (rounds_cnt - i - 1) * block_len);
        if (i != rounds_cnt - 1) {
            mix_columns(state, block_len, true);
        }
    }
    memcpy(res, state, block_len);
}

