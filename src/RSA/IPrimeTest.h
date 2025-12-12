#ifndef IPRIMETEST_H
#define IPRIMETEST_H
#include "my_BigInt.h"


class IPrimeTest {
    public:
    virtual ~IPrimeTest() = default;

    [[nodiscard]] virtual bool isPrime(const BigInt& num, double min_probability) const = 0;
};
#endif
