#ifndef PRIMETESTBASE_H
#define PRIMETESTBASE_H
#include <chrono>

#include "IPrimeTest.h"
#include "ServiceGCD.h"


class PrimeTestBase : public IPrimeTest {
    public:
    ~PrimeTestBase() override = default;

    [[nodiscard]] virtual bool testIteration(const mpz_class& a, const mpz_class& n) const = 0;

    [[nodiscard]] virtual double getProbForOneIter() const = 0;

    [[nodiscard]] bool isPrime(const mpz_class& num, const double min_probability) const override
    {
        if (min_probability < 0.5 || min_probability >= 1.0) {
            throw std::invalid_argument("min_probability must be in [0.5, 1)");
        }
        const double prob_for_one_iter = getProbForOneIter();
        double tmp_prob = 1.0;

        gmp_randclass rng(gmp_randinit_default);
        rng.seed(std::chrono::system_clock::now().time_since_epoch().count());

        while ( (1 - tmp_prob) < min_probability)
        {
            tmp_prob *= prob_for_one_iter;
            mpz_class a = rng.get_z_range(num - 1);
            // if (ServiceGCD::gcd(a, num) != mpz_class(1))
            // {
            //     return false;
            // }
            if (!testIteration(a, num))
            {
                return false;
            }
        }

        return true;
    }
};

#endif
