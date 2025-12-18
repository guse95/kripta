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

    std::pair<mpz_class, mpz_class> key_pub;

private:
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

        void generateWeakKeys(RSA& papa) const;
    };

    mutable size_t key_bytes;
    mutable size_t plain_block;
    mutable size_t cipher_block;

    void init_sizes() const {
        if (key_bytes == 0) {
            key_bytes = bit_len / 4;
            plain_block = key_bytes - 11;
            cipher_block = key_bytes;
        }
    }

    uint64_t bit_len;
    KeyGenerator keygen;
public:
    RSA(PrimaryTest _test_type, double _min_probability, uint64_t _bit_len);

    void generateKeys();

    void generateWeakKeys();

    mpz_class encrypt(const mpz_class& mess) const;

    mpz_class decrypt(const mpz_class& mess) const;

    void encrypt(const std::string& input, const std::string& output) const;

    void decrypt(const std::string& input, const std::string& output) const;

    void add_pkcs1_padding(uint8_t* output, const uint8_t* input,
                           size_t input_len) const;

    size_t remove_pkcs1_padding(uint8_t* output, const uint8_t* input) const;
};



#endif