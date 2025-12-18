#ifndef TRIPLEDES_H
#define TRIPLEDES_H

#include "DES.h"
#include "ISymmetricCypher.h"


class TripleDES final : public ISymmetricCypher {
    DES alg;
public:
    TripleDES() : alg() {}
    ~TripleDES() override = default;

    void encrypt(uint8_t* text, uint8_t* encrText, uint8_t* key) override;

    void decrypt(uint8_t* text, uint8_t* decrText, uint8_t* key) override;
};



#endif
