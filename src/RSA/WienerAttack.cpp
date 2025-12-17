#include "WienerAttack.h"

#include "ServiceGCD.h"


std::vector<mpz_class> WienerAttack::chainFraction(const mpz_class& e, const mpz_class& N)
{
    std::vector<mpz_class> res;
    mpz_class g = ServiceGCD::gcd(e, N);
    mpz_class k = e / g;
    mpz_class d = N / g;
    while (k != 1)
    {
        res.push_back(k / d);
        k = k % d;
        swap(k, d);
    }
    return res;
}

std::pair<mpz_class, mpz_class> WienerAttack::fromChainFraction(const std::vector<mpz_class>& chain, int precision)
{
    mpz_class k = 1;
    mpz_class d = chain[precision];
    for (int i = precision - 1; i > 0; i--)
    {
        k += chain[i] * d;
        swap(k, d);
    }
    return std::make_pair(k, d);
}

mpz_class WienerAttack::predictKeyPriv(const mpz_class& e, const mpz_class& N)
{
    auto chain = chainFraction(e, N);

    mpz_class p, q;

    for (int i = 1; i < chain.size(); i++)
    {
        auto suitableFraction = fromChainFraction(chain, i);

        mpz_class b = N - (e * suitableFraction.second - 1) / suitableFraction.first + 1;
        mpz_class discriminant = b * b - 4 * N;
        if (discriminant <= 0)
        {
            continue;
        }
        p = (-b - sqrt(discriminant)) / 2;
        q = (-b + sqrt(discriminant)) / 2;
        if (q * p == N) return suitableFraction.second;
    }
    return -1;
}