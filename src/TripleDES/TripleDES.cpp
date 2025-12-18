#include "TripleDES.h"


void TripleDES::encrypt(uint8_t* text, uint8_t* encrText, uint8_t* key)
{
    uint8_t tmp[8] = {0};
    alg.encrypt(text, tmp, key);
    uint8_t tmp1[8] = {0};
    alg.decrypt(tmp, tmp1, key + 8);
    alg.encrypt(tmp1, encrText, key + 16);
}

void TripleDES::decrypt(uint8_t* text, uint8_t* decrText, uint8_t* key)
{
    uint8_t tmp[8] = {0};
    alg.decrypt(text, tmp, key + 16);
    uint8_t tmp1[8] = {0};
    alg.encrypt(tmp, tmp1, key + 8);
    alg.decrypt(tmp1, decrText, key);
}