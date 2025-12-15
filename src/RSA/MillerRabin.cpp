#include "MillerRabin.h"

#include "ServiceGCD.h"

[[nodiscard]] double MillerRabin::getProbForOneIter() const
{
    return 0.25;
}

[[nodiscard]] bool MillerRabin::testIteration(const mpz_class& a, const mpz_class& n) const
{
    mpz_class pow = n - 1;
    mpz_class s = 0;
    const mpz_class n_uno = n - 1;
    while (pow % 2 == 0)
    {
        pow /= mpz_class(2);
        ++s;
    }
    mpz_class x = ServiceGCD::mod_pow(a, pow, n);

    if (x == mpz_class(1) || x == n_uno)
    {
        return true;
    }
    for (mpz_class i = 0; i < s; ++i)
    {
        x = x * x % n;
        if (x == n_uno)
        {
            return true;
        }
    }
    return false;
}