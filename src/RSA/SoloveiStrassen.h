#ifndef SOLOVEISTRASSEN_H
#define SOLOVEISTRASSEN_H
#include "PrimeTestBase.h"
#include "my_BigInt.h"


class SoloveiStrassen : public PrimeTestBase {
public:
    ~SoloveiStrassen() final = default;

    [[nodiscard]] double getProbForOneIter() const final;

    [[nodiscard]] bool testIteration(const BigInt& a, const BigInt& n) const final;
};

#endif
