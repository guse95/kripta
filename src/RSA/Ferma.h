#ifndef FERMA_H
#define FERMA_H
#include "PrimeTestBase.h"
#include <gmpxx.h>

class Ferma : public PrimeTestBase {
    public:
    ~Ferma() final = default;

    [[nodiscard]] double getProbForOneIter() const final;

    [[nodiscard]] bool testIteration(const mpz_class& a, const mpz_class& n) const final;
};



#endif
