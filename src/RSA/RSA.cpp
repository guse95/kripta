#include "RSA.h"

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

bool is_candidate(const mpz_class& n) {
    static const std::vector<int> small_primes = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97, 101, 103, 107};
    for (int prime : small_primes) {
        if (n % prime == 0) return false;
    }
    return true;
}

void RSA::KeyGenerator::generateKeys(RSA& papa) const
{
    // p и q
    std::random_device rd;
    thread_local gmp_randclass rng(gmp_randinit_default);
    rng.seed(rd());

    mpz_class p = rng.get_z_bits(bit_len) | 1;
    p |= (mpz_class(1) << (bit_len - 1));
    while (!is_candidate(p) || !test_type->isPrime(p, min_probability))
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

    while (!is_candidate(p) || abs(p - q) <= diff || !test_type->isPrime(q, min_probability))
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

    mpz_class phi_n = (p - 1) * (q - 1);

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
    keygen(_test_type, _min_probability, _bit_len) {}

void RSA::generateKeys()
{
    keygen.generateKeys(*this);
}

mpz_class RSA::encrypt(const mpz_class& mess) const
{
    return ServiceGCD::mod_pow(mess, key_pub.first, key_pub.second);
}

mpz_class RSA::decrypt(const mpz_class& mess) const
{
    return ServiceGCD::mod_pow(mess, key_priv.first, key_priv.second);
}
