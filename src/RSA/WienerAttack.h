#ifndef WIENERATTACK_H
#define WIENERATTACK_H

#include <gmpxx.h>
#include <vector>


class WienerAttack {
public:
    static std::vector<mpz_class> chainFraction(const mpz_class& e, const mpz_class& N);

    static std::pair<mpz_class, mpz_class> fromChainFraction(const std::vector<mpz_class>& e, int precision);

    static mpz_class predictKeyPriv(const mpz_class& e, const mpz_class& N);
};



#endif
