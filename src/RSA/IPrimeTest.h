#ifndef IPRIMETEST_H
#define IPRIMETEST_H
#include <gmpxx.h>


class IPrimeTest {
    public:
    virtual ~IPrimeTest() = default;

    [[nodiscard]] virtual double getProbForOneIter() const = 0;

    [[nodiscard]] virtual bool isPrime(const mpz_class& num, double min_probability) const = 0;
};
#endif
