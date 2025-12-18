#include "RSA.h"

#include <fstream>
#include <random>

#include "Ferma.h"
#include "MillerRabin.h"
#include "SoloveiStrassen.h"
#include "ServiceGCD.h"

#define DEBUG


long long fast_pow(const long long& a, const long long& pow) {
    if (pow < 2) {
        if (pow == 1) {
            return a;
        }
        return 1;
    }
    long long res = fast_pow(a, pow / 2);
    res = res * res;
    if (pow % 2 == 1) {
        res = (res * a);
    }
    return res;
}

RSA::KeyGenerator::KeyGenerator(PrimaryTest _test_type, double _min_probability, uint64_t _bit_len) :
        min_probability(_min_probability), bit_len(_bit_len)
{
    switch (_test_type)
    {
        case FERMAT:
        {
            test_type = std::make_unique<Ferma>();
            break;
        }
        case SOLOVAY_STRASSEN:
        {
            test_type = std::make_unique<SoloveiStrassen>();
            break;
        }
        case MILLER_RABIN:
        {
            test_type = std::make_unique<MillerRabin>();
            break;
        }
        default:
            std::cout << "Test type not recognized" << std::endl;
    }
}

void RSA::KeyGenerator::generateKeys(RSA& papa) const
{
    // p и q
    std::random_device rd;
    thread_local gmp_randclass rng(gmp_randinit_default);
    rng.seed(rd());

    mpz_class phi_n;

    while (true) {
        mpz_class p = rng.get_z_bits(bit_len) | 1;
        p |= (mpz_class(1) << (bit_len - 1));
        while (!test_type->isPrime(p, min_probability))
        {
            p = rng.get_z_bits(bit_len) | 1;
            p |= (mpz_class(1) << (bit_len - 1));
#ifdef DEBUG_HARD
            std::cout << p << '\n';
#endif
        }
#ifdef DEBUG
        std::cout << p << '\n';
#endif

        mpz_class diff(1);
        diff <<= bit_len / 2 - 1;

#if defined(DEBUG) || defined(DEBUG_HARD)
        std::cout << "STARTED Q:\n";
#endif
        mpz_class q = rng.get_z_bits(bit_len) | 1;
        q |= (mpz_class(1) << (bit_len - 1));

        while (abs(p - q) <= diff || !test_type->isPrime(q, min_probability))
        {
            q = rng.get_z_bits(bit_len) | 1;
            q |= (mpz_class(1) << (bit_len - 1));
#ifdef DEBUG_HARD
            std::cout << q << '\n';
#endif
        }
#ifdef DEBUG
        std::cout << q << '\n';
#endif
        // p и q

        papa.key_pub.first = 65537;

        mpz_class n = p * q;
        papa.key_pub.second = n;
        papa.key_priv.second = n;

        phi_n = (p - 1) * (q - 1);

        mpz_class pohyi;
        mpz_class g = ServiceGCD::exp_gcd(papa.key_pub.first, phi_n, papa.key_priv.first, pohyi);

        if (g != 1)
        {
            std::cout << "gcd: " << g << '\n';
            throw std::runtime_error("Inverse doesn't exist");
        }

        papa.key_priv.first %= phi_n;
        if (papa.key_priv.first < 0) {
            papa.key_priv.first += phi_n;
        }
        if (papa.key_priv.first > sqrt(sqrt(n)) / 3)
        {
            break;
        }
    }

    mpz_class tmp = (papa.key_pub.first * papa.key_priv.first) % phi_n;

    if (tmp != 1)
    {
        std::cout << "NE OBRATNIY" << '\n';
        std::cout << papa.key_pub.first << '\n';
        std::cout << papa.key_priv.first << '\n';
        std::cout << tmp << '\n';
        std::cout << phi_n << '\n';
    }
}

void RSA::KeyGenerator::generateWeakKeys(RSA& papa) const
{
    // p и q
    std::random_device rd;
    thread_local gmp_randclass rng(gmp_randinit_default);
    rng.seed(rd());

    mpz_class p = rng.get_z_bits(bit_len) | 1;
    p |= (mpz_class(1) << (bit_len - 1));
    while (!test_type->isPrime(p, min_probability))
    {
        p = rng.get_z_bits(bit_len) | 1;
        p |= (mpz_class(1) << (bit_len - 1));
#ifdef DEBUG_HARD
        std::cout << p << '\n';
#endif
    }
#ifdef DEBUG
    std::cout << p << '\n';
#endif


#if defined(DEBUG) || defined(DEBUG_HARD)
    std::cout << "STARTED Q:\n";
#endif
    mpz_class q = rng.get_z_bits(bit_len) | 1;
    q |= (mpz_class(1) << (bit_len - 1));

    while (!test_type->isPrime(q, min_probability))
    {
        q = rng.get_z_bits(bit_len) | 1;
        q |= (mpz_class(1) << (bit_len - 1));
#ifdef DEBUG_HARD
        std::cout << q << '\n';
#endif
    }
#ifdef DEBUG
    std::cout << q << '\n';
#endif
    // p и q

    mpz_class n = p * q;
    mpz_class phi_n = (p - 1) * (q - 1);

    do {
        papa.key_priv.first = 2 + (rng.get_z_range(sqrt(sqrt(n)) / 3) | 1);
    } while (ServiceGCD::gcd(papa.key_priv.first, phi_n) != 1);
#ifdef DEBUG
    std::cout << "WEAK d: " << papa.key_priv.first << '\n';
#endif
    papa.key_pub.second = n;
    papa.key_priv.second = n;

    mpz_class pohyi;
    mpz_class g = ServiceGCD::exp_gcd(papa.key_priv.first, phi_n, papa.key_pub.first, pohyi);


    if (g != 1)
    {
        std::cout << "gcd: " << g << '\n';
        throw std::runtime_error("Inverse doesn't exist");
    }

    papa.key_pub.first %= phi_n;
    if (papa.key_pub.first < 0) {
        papa.key_pub.first += phi_n;
    }
#ifdef DEBUG
    std::cout << "WEAK e: " << papa.key_pub.first << '\n';
#endif

    mpz_class tmp = (papa.key_pub.first * papa.key_priv.first) % phi_n;

    if (tmp != 1)
    {
        std::cout << "NE OBRATNIY" << '\n';
        std::cout << papa.key_pub.first << '\n';
        std::cout << papa.key_priv.first << '\n';
        std::cout << tmp << '\n';
        std::cout << phi_n << '\n';
    }
}

RSA::RSA(PrimaryTest _test_type, double _min_probability, uint64_t _bit_len) :
    keygen(_test_type, _min_probability, _bit_len), bit_len(_bit_len) {}

void RSA::generateKeys()
{
    keygen.generateKeys(*this);
}

void RSA::generateWeakKeys()
{
    keygen.generateWeakKeys(*this);
}

mpz_class RSA::encrypt(const mpz_class& mess) const
{
    return ServiceGCD::mod_pow(mess, key_pub.first, key_pub.second);
}

mpz_class RSA::decrypt(const mpz_class& mess) const
{
    return ServiceGCD::mod_pow(mess, key_priv.first, key_priv.second);
}

void RSA::encrypt(const std::string& inputPath, const std::string& outputPath) const
{
    if (inputPath == outputPath) {
        std::cout << "Input and output files must differ." << std::endl;
        return;
    }

    std::ifstream in(inputPath, std::ios::binary);
    if (!in) {
        std::cout << "Cannot open input file: " << inputPath << std::endl;
        return;
    }

    std::ofstream out(outputPath, std::ios::binary);
    if (!out) {
        std::cout << "Cannot open output file: " << outputPath << std::endl;
        return;
    }

    init_sizes();

    uint8_t buffer[cipher_block];

    const size_t PB = plain_block;
    const size_t CB = cipher_block;
    const size_t KB = key_bytes;

    while (true) {
        in.read(reinterpret_cast<char*>(buffer), PB);
        const size_t bytes_read = in.gcount();

        if (bytes_read == 0) break;

        if (bytes_read < PB) {
            memset(buffer + bytes_read, 0, PB - bytes_read);
        }

        memmove(buffer + KB - bytes_read, buffer, bytes_read);

        buffer[0] = 0x00;
        buffer[1] = 0x02;

        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<uint16_t> dis(1, 255);

        const size_t padding_len = KB - 3 - bytes_read;
        for (size_t i = 0; i < padding_len; ++i) {
            uint8_t r;
            do { r = static_cast<uint8_t>(dis(gen)); } while (r == 0);
            buffer[2 + i] = r;
        }

        buffer[2 + padding_len] = 0x00;

        mpz_class plaintext;
        mpz_import(plaintext.get_mpz_t(), KB, 1, 1, 0, 0, buffer);

        mpz_class ciphertext = encrypt(plaintext);

        size_t export_size;
        mpz_export(buffer, &export_size, 1, 1, 0, 0, ciphertext.get_mpz_t());

        if (export_size < CB) {
            const size_t offset = CB - export_size;
            memmove(buffer + offset, buffer, export_size);
            memset(buffer, 0, offset);
        }

        out.write(reinterpret_cast<const char*>(buffer), CB);
    }
}

void RSA::decrypt(const std::string& inputPath, const std::string& outputPath) const
{
    if (inputPath == outputPath) {
        std::cout << "Input and output files must differ." << std::endl;
        return;
    }

    std::ifstream in(inputPath, std::ios::binary);
    if (!in) {
        std::cout << "Cannot open input file: " << inputPath << std::endl;
        return;
    }

    std::ofstream out(outputPath, std::ios::binary);
    if (!out) {
        std::cout << "Cannot open output file: " << outputPath << std::endl;
        return;
    }

    init_sizes();

    uint8_t cipher_buffer[cipher_block];
    uint8_t result_buffer[plain_block];

    const size_t CB = cipher_block;
    const size_t KB = key_bytes;

    while (true) {
        in.read(reinterpret_cast<char*>(cipher_buffer), CB);
        const size_t bytes_read = in.gcount();

        if (bytes_read == 0) break;

        if (bytes_read != CB) continue;

        mpz_class ciphertext;
        mpz_import(ciphertext.get_mpz_t(), CB, 1, 1, 0, 0, cipher_buffer);

        mpz_class padded_plaintext = decrypt(ciphertext);

        size_t export_size;
        uint8_t* export_ptr = cipher_buffer;
        mpz_export(export_ptr, &export_size, 1, 1, 0, 0, padded_plaintext.get_mpz_t());

        if (export_size < KB) {
            const size_t offset = KB - export_size;
            memmove(export_ptr + offset, export_ptr, export_size);
            memset(export_ptr, 0, offset);
        }

        if (export_ptr[0] != 0x00 || export_ptr[1] != 0x02) {
            std::cout << "Padding error - skipping block" << std::endl;
            continue;
        }

        size_t i = 2;
        while (i < KB && export_ptr[i] != 0x00) {
            ++i;
        }

        if (i >= KB - 1) {
            std::cout << "No data separator - skipping block" << std::endl;
            continue;
        }

        const size_t data_start = i + 1;
        const size_t data_len = KB - data_start;

        memcpy(result_buffer, export_ptr + data_start, data_len);

        out.write(reinterpret_cast<const char*>(result_buffer), data_len);
    }
}

void RSA::add_pkcs1_padding(uint8_t* output, const uint8_t* input,
                           size_t input_len) const
{
    init_sizes();
    const size_t KB = key_bytes;
    const size_t padding_len = KB - 3 - input_len;

    output[0] = 0x00;
    output[1] = 0x02;

    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint16_t> dis(1, 255);

    for (size_t i = 0; i < padding_len; ++i) {
        uint8_t r;
        do { r = static_cast<uint8_t>(dis(gen)); } while (r == 0);
        output[2 + i] = r;
    }

    output[2 + padding_len] = 0x00;
    memcpy(output + 2 + padding_len + 1, input, input_len);
}

size_t RSA::remove_pkcs1_padding(uint8_t* output, const uint8_t* input) const
{
    init_sizes();
    const size_t KB = key_bytes;

    if (input[0] != 0x00 || input[1] != 0x02) {
        return 0;
    }

    size_t i = 2;
    while (i < KB && input[i] != 0x00) {
        ++i;
    }

    if (i >= KB - 1) {
        return 0;
    }

    const size_t data_len = KB - i - 1;
    memcpy(output, input + i + 1, data_len);

    return data_len;
}