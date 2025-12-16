#ifndef RSA_H
#define RSA_H
#include <cstdint>
#include <gmpxx.h>

#include "PrimeTestBase.h"


class RSA {
public:
    enum PrimaryTest
    {
        FERMAT,
        SOLOVAY_STRASSEN,
        MILLER_RABIN
    };
private:

    std::pair<mpz_class, mpz_class> key_pub;
    std::pair<mpz_class, mpz_class> key_priv;

    class KeyGenerator
    {
        std::unique_ptr<PrimeTestBase> test_type;
        double min_probability;
        uint64_t bit_len;
        public:
        KeyGenerator(PrimaryTest _test_type, double _min_probability, uint64_t _bit_len);
        ~KeyGenerator() = default;

        void generateKeys(RSA& papa) const;
    };

    KeyGenerator keygen;
public:
    RSA(PrimaryTest _test_type, double _min_probability, uint64_t _bit_len);

    void generateKeys();

    mpz_class encrypt(const mpz_class& mess) const;

    mpz_class decrypt(const mpz_class& mess) const;
};



#endif