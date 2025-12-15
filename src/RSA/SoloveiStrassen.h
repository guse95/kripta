#ifndef SOLOVEISTRASSEN_H
#define SOLOVEISTRASSEN_H
#include "PrimeTestBase.h"



class SoloveiStrassen : public PrimeTestBase {
public:
    ~SoloveiStrassen() final = default;

    [[nodiscard]] double getProbForOneIter() const final;

    [[nodiscard]] bool testIteration(const mpz_class& a, const mpz_class& n) const final;
};

#endif
