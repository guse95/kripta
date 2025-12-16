#include "RSA.h"

#include "Ferma.h"
#include "MillerRabin.h"
#include "SoloveiStrassen.h"
#include "ServiceGCD.h"


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
    thread_local gmp_randclass rng(gmp_randinit_default);
    rng.seed(std::chrono::system_clock::now().time_since_epoch().count());

    mpz_class p = rng.get_z_bits(bit_len) | 1;
    while (!test_type->isPrime(p, min_probability))
    {
        p = rng.get_z_bits(bit_len) | 1;
        std::cout << p << '\n';
    }

    mpz_class diff(1);

    diff <<= bit_len / 2;

    std::cout << "STARTED Q:\n";
    mpz_class q = rng.get_z_bits(bit_len) | 1;
    while (!test_type->isPrime(q, min_probability) && (p - q) <= diff)
    {
        q = rng.get_z_bits(bit_len) | 1;
        std::cout << q << '\n';
    }
    // p и q

    papa.key_pub.first = 65537;

    mpz_class n = p * q;
    papa.key_pub.second = n;
    papa.key_priv.second = n;

    mpz_class phi_n = (p - 1) * (q - 1);

    mpz_class pohyi;
    ServiceGCD::exp_gcd(papa.key_pub.first, phi_n, papa.key_priv.first, pohyi);

    mpz_class tmp = papa.key_pub.first * papa.key_priv.first % phi_n;
    if (tmp != mpz_class(1))
    {
        std::cout << "PIZDETS" << '\n';
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
