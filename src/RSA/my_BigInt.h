#pragma once

#include <bits/stdc++.h>

inline long long takeFromStr(const int ind, const int cnt, const std::string &str) {
    long long val = 0;
    for (int i = 0; i < cnt; i++) {
        if (!isdigit(str[ind + i])) {
            throw std::invalid_argument("Invalid input in BigInt");
        }
        val = val * 10 + (str[ind + i] - '0');
    }
    return val;
}

class BigInt {
protected:
    using ll = long long;
    ll base = 100000000;

    std::vector<ll> dig;
    bool isNeg;

public:
    BigInt() : BigInt(0) {};

    explicit BigInt(const ll val) : isNeg(val < 0) {
        ll tmp = val < 0 ? -val : val;
        if (tmp < base) {
            dig = {tmp};
        }
        else {
            if (tmp / base < base) {
                dig = {tmp / base, tmp % base};
            } else {
                dig = {tmp / base / base, tmp / base % base, tmp % base};
            }
        }
    }

    explicit BigInt(const std::string& str) : isNeg(str[0] == '-') {
        int ind = (str[0] == '-') ? 1 : 0;
        const int sz = static_cast<int>(str.length()) - ind;
        if (sz <= 0) {
            throw std::invalid_argument("Invalid input in BigInt");
        }
        const int first_len = sz % 8;

        if (first_len) {
            dig.push_back(takeFromStr(ind, first_len, str));
            ind += first_len;
        }

        for (ll i = sz / 8; i > 0; i--) {
            dig.push_back(takeFromStr(ind, 8, str));
            ind += 8;
        }
    }

    BigInt(const BigInt& other) : dig(other.dig), isNeg(other.isNeg) {}

    BigInt(BigInt&& other) noexcept : dig(std::move(other.dig)), isNeg(other.isNeg) {
        other.isNeg = false;
        other.dig.clear();
    }

    ~BigInt() = default;

    BigInt& operator=(const BigInt& other) {
        dig = other.dig;
        isNeg = other.isNeg;
        return *this;
    }
    BigInt& operator=(BigInt&& other) noexcept {
        dig = std::move(other.dig);
        isNeg = other.isNeg;
        return *this;
    }

    BigInt operator+(const BigInt& other) const {
        BigInt res = *this;
        if (other.isNeg == isNeg) {
            ll mind = 0;
            int ind = static_cast<int>(dig.size()) - 1;
            int ind_other = static_cast<int>(other.dig.size()) - 1;
            while (ind >= 0 && ind_other >= 0) {
                const ll sum = dig[ind] + other.dig[ind_other] + mind;
                res.dig[ind] = sum % base;
                mind = sum / base;
                --ind;
                --ind_other;
            }
            while (ind_other >= 0 && mind) {
                const ll sum = other.dig[ind_other] + mind;
                res.dig.insert(res.dig.begin(), sum % base);
                mind = sum / base;
                --ind_other;
            }
            while (ind >= 0 && mind) {
                const ll sum = dig[ind] + mind;
                res.dig[ind] = sum % base;
                mind = sum / base;
                --ind_other;
            }
            if (mind > 0) {
                res.dig.insert(res.dig.begin(), mind);
            }
            if (ind_other >= 0) {
                res.dig.insert(res.dig.begin(), other.dig.begin(), other.dig.begin() + ind_other + 1);
            }
            if (res.dig.size() == 1 && res.dig[0] == 0 && res.isNeg) {
                res.isNeg = false;
            }
            return res;
        }

        BigInt tmp = other;
        tmp.isNeg = !tmp.isNeg;
        return res - tmp;
    }
    BigInt operator-() const {
        BigInt res = *this;
        res.isNeg = !res.isNeg;
        return res;
    }
    BigInt operator-(const BigInt& other) const {
        if (other.isNeg == isNeg) {
            if ((*this >= other && !isNeg) || (*this <= other && isNeg)) {
                BigInt res = *this;
                ll mind = 0;
                int ind = static_cast<int>(dig.size()) - 1;
                int ind_other = static_cast<int>(other.dig.size()) - 1;
                while (ind_other >= 0) {
                    const ll dif = dig[ind] - other.dig[ind_other] - mind;
                    mind = dif < 0 ? 1 : 0;
                    res.dig[ind] = dif + mind * base;
                    --ind;
                    --ind_other;
                }
                while (mind != 0) {
                    const ll dif = dig[ind] - mind;
                    mind = dif < 0 ? 1 : 0;
                    res.dig[ind] = dif + mind * base;
                    --ind;
                }
                while (res.dig.front() == 0 && res.dig.size() != 1) {
                    res.dig.erase(res.dig.begin());
                }
                if (res.dig.size() == 1 && res.dig[0] == 0 && res.isNeg) {
                    res.isNeg = false;
                }
                return res;
            }

            BigInt tmp = other - *this;
            tmp.isNeg = !tmp.isNeg;
            return tmp;
        }
        BigInt tmp = other;
        tmp.isNeg = !tmp.isNeg;
        return *this + tmp;
    }
    BigInt operator*(const BigInt& other) const {
        const int ind = static_cast<int>(dig.size()) - 1;
        int ind_other = 0;

        BigInt res;
        if (*this == res || other == res) {
            return res;
        }
        res.dig = std::vector<ll>(ind, 0);
        res.isNeg = (isNeg != other.isNeg);

        while (ind_other != static_cast<int>(other.dig.size())) {
            res.dig.push_back(0);
            ll mind = 0;
            int ind_res = static_cast<int>(res.dig.size()) - 1;
            for (int i = ind; i >= 0; --i) {
                const ll sum = dig[i] * other.dig[ind_other] + mind + res.dig[ind_res];
                res.dig[ind_res] = sum % base;
                mind = sum / base;
                --ind_res;
            }

            while (ind_res >= 0 && mind) {
                const ll sum = mind + res.dig[ind_res];
                res.dig[ind_res] = sum % base;
                mind = sum / base;
                --ind_res;
            }
            if (mind) {
                res.dig.insert(res.dig.begin(), mind);
            }
            ++ind_other;
        }
        return res;
    }
    BigInt operator/(const BigInt& other) const {
        if (other == BigInt(0)) {
            throw std::invalid_argument("Divide by 0");
        }
        int ind = 0;

        BigInt res;
        if (*this == res) {
            return res;
        }
        res.dig.pop_back();
        BigInt tmp;
        tmp.dig.pop_back();
        res.isNeg = (isNeg != other.isNeg);
        BigInt other_abs = abs(other);
        while (ind != static_cast<int>(dig.size())) {
            tmp.dig.push_back(dig[ind]);
            if (tmp >= other_abs) {
                ll l = 0;
                ll r = base;
                while (l + 1 < r) {
                    const ll m = (l + r) / 2;
                    BigInt mult = (other_abs * BigInt(m));
                    if (tmp >= mult) {
                        l = m;
                    } else {
                        r = m;
                    }
                }
                res.dig.push_back(l);
                tmp -= other_abs * BigInt(l);
                if (tmp == BigInt(0)) {
                    tmp.dig.pop_back();
                }
            } else {
                if (!res.dig.empty()) {
                    res.dig.push_back(0);
                }
            }
            ++ind;
        }
        if (res.dig.empty()) {
            res.dig.push_back(0);
        }
        return res;
    }

    BigInt& operator+=(const BigInt& other) {
        *this = *this + other;
        return *this;
    }

    BigInt& operator-=(const BigInt& other) {
        *this = *this - other;
        return *this;
    }

    BigInt& operator*=(const BigInt& other) {
        *this = *this * other;
        return *this;
    }
    BigInt& operator/=(const BigInt& other) {
        *this = *this / other;
        return *this;
    }
    BigInt operator++() {
        *this += BigInt(1);
        return *this;
    }
    BigInt operator--() {
        *this -= BigInt(1);
        return *this;
    }

    BigInt operator%(const BigInt& other) const {
        if (*this >= other) {
            if (other == BigInt(2))
            {
                return BigInt(other.dig.back() & 1);
            }
            BigInt res = *this - (*this / other) * other;
            return res;
        }
        return *this;
    }

    BigInt& operator%=(const BigInt& other)
    {
        if (*this >= other) {
            *this = *this - (*this / other) * other;
            return *this;
        }
        return *this;
    }

    static BigInt abs(const BigInt& other) {
        BigInt res = other;
        if (other.isNeg) {
            res.isNeg = false;
        }
        return res;
    }

    static BigInt rnd(const BigInt& other)
    {
        if (other <= BigInt(1)) {
            throw std::invalid_argument("Parameter must be greater than 1");
        }

        static std::random_device rd;
        static std::mt19937 gen(rd());

        BigInt max_val = other - BigInt(1);

        std::uniform_int_distribution<size_t> len_dist(1, max_val.dig.size());
        size_t len = len_dist(gen);


        BigInt result;
        result.isNeg = false;
        result.dig.resize(len);

        if (len < max_val.dig.size()) {
            std::uniform_int_distribution<ll> first_dist(1, other.base - 1);
            result.dig[0] = first_dist(gen);
        } else
        {
            std::uniform_int_distribution<ll> first_dist(1, other.dig[0] - 1);
            result.dig[0] = first_dist(gen);
        }
        for (size_t i = 1; i < len; i++) {
            std::uniform_int_distribution<ll> digit_dist(0, other.base - 1);
            result.dig[i] = digit_dist(gen);
        }
        return result;
    }

    bool operator==(const BigInt& other) const {
        return (dig == other.dig) && (isNeg == other.isNeg);
    }
    bool operator!=(const BigInt& other) const {
        return !(*this == other);
    }
    bool operator<(const BigInt& other) const {
        if (isNeg == other.isNeg) {
            if (isNeg) {
                if (dig.size() != other.dig.size()) {
                    return dig.size() > other.dig.size();
                }
                return dig > other.dig;
            }
            if (dig.size() != other.dig.size()) {
                return dig.size() < other.dig.size();
            }
            return dig < other.dig;
        }
        if (isNeg) {
            return true;
        }
        return false;
    }
    bool operator>(const BigInt& other) const {
        return !(*this < other || *this == other);
    }
    bool operator<=(const BigInt& other) const {
        return !(*this > other);
    }
    bool operator>=(const BigInt& other) const {
        return !(*this < other);
    }

    [[nodiscard]] BigInt mod_exp(const BigInt& exp, const BigInt& mod) const {
        if (exp < BigInt(2)) {
            if (exp == BigInt(1)) {
                return *this % mod;
            }
            return BigInt(1);
        }
        BigInt res = mod_exp(exp/BigInt(2), mod);
        res = (res * res) % mod;
        if (exp.dig[exp.dig.size() - 1] % 2 == 1) {
            res = (res * *this) % mod;
        }
        return res;
    }

    static void fft(std::vector<std::complex<long double>> &a, const std::complex<long double> w) {
        const int n = static_cast<int>(a.size());
        if (n == 1)
        {
            return;
        }
        std::complex<long double> wn(1, 0);

        std::vector<std::complex<long double>> r0(n / 2), r1(n / 2);
        for (int i = n / 2 - 1; i >= 0; --i) {
            r0[i] = a[i + n / 2] + a[i];
            r1[i] = (a[i + n / 2] - a[i]) * wn;
            wn *= w;
        }

        fft(r0, w * w);
        fft(r1, w * w);


        for (int i = n / 2 - 1; i >= 0; --i) {
            a[2 * i] = r1[i];
            a[2 * i + 1] = r0[i];
        }
    }

    BigInt fft_multiply(const BigInt &a) const
    {
        std::vector<std::complex<long double>> fa(dig.begin(), dig.end()), fb(a.dig.begin(), a.dig.end());
        size_t n = 1;

        while (n < std::max(dig.size(), a.dig.size()))
        {
            n <<= 1;
        }
        n <<= 1;

        fa.insert(fa.begin(), static_cast<int>(n - fa.size()), std::complex<long double>(0, 0));
        fb.insert(fb.begin(), static_cast<int>(n - fb.size()), std::complex<long double>(0, 0));

        const long double ang = 2 * (acos(-1)) / static_cast<long double>(n);
        const std::complex w(std::cos(ang), std::sin(ang));

        fft(fa, w);
        fft(fb, w);

        for (size_t i = 0; i < n; ++i)
        {
            fa[i] *= fb[i];
        }

        fft(fa, std::complex<long double>(1, 0) / w);

        BigInt res;
        res.dig = std::vector<long long>(n, 0);

        for (size_t i = 0; i < n; ++i)
        {
            res.dig[i] = static_cast<long long>(std::round(fa[i].real() / n));
        }

        std::vector<long long> res_digits;

        while (res.dig.size() > 1 && res.dig.front() == 0)
        {
            res.dig.erase(res.dig.begin());
        }
        module_digits(res.dig, res_digits);
        res.dig = res_digits;

        res.isNeg = this->isNeg != a.isNeg;
        return res;
    }

    static void module_digits(const std::vector<long long> &_digits, std::vector<long long> &_res_digits)
    {
        long long div = 0, mod = 0;
        constexpr long long base = 100000000;
        for (int i = static_cast<int>(_digits.size()) - 1; i >= 0; --i)
        {
            mod = _digits[i] + div;
            if (div < 0) {
                _res_digits.push_back((base - (std::abs(mod) % base)));
                div = -(std::abs(mod) / base) - 1;
            } else {
                _res_digits.push_back(mod % base);
                div = mod / base;
            }
        }
        if (div != 0)
        {
            _res_digits.push_back(div);
        }
        std::reverse(_res_digits.begin(), _res_digits.end());
    }

    [[nodiscard]] BigInt karatsuba_multiply(const BigInt& a) const {
        if (dig.size() < 2 || a.dig.size() < 2) {
            return *this * a;
        }
        const size_t m = (a.dig.size() < dig.size() ? dig.size() : a.dig.size()) / 2;
        BigInt res;
        BigInt g2, g1;
        if (m < dig.size()) {
            g1.dig = {a.dig.end() - m, a.dig.end()};
            g2.dig = {a.dig.begin(), a.dig.end() - m};

        } else {
            g1.dig = a.dig;
        }
        BigInt f2, f1;
        if (m < dig.size()) {
            f1.dig = {dig.end() - m, dig.end()};
            f2.dig = {dig.begin(), dig.end() - m};
        } else {
            f1.dig = a.dig;
        }

        BigInt sum_of_f_parts = f2 + f1;
        BigInt sum_of_g_parts = g2 + g1;
        BigInt mult_of_first_parts = g1.karatsuba_multiply(f1);
        BigInt mult_of_second_parts = g2.karatsuba_multiply(f2);
        BigInt mult_of_sum = sum_of_f_parts.karatsuba_multiply(sum_of_g_parts);
        BigInt sum_of_mid_part = mult_of_sum - mult_of_first_parts - mult_of_second_parts;

        res = mult_of_second_parts;

        for (size_t i = 0; i < (mult_of_first_parts.dig.size() - m); ++i) {
            res.dig.push_back(mult_of_first_parts.dig[i]);
        }
        res += sum_of_mid_part;
        for (size_t i = m; i < mult_of_first_parts.dig.size(); ++i) {
            res.dig.push_back(mult_of_first_parts.dig[i]);
        }
        res.isNeg = (isNeg != a.isNeg);
        return res;
    }

    static long long ex_gcd(long long a, long long b, long long& x, long long& y) {
        if (a == 0) {
            x = 0;
            y = 1;
            return b;
        }
        long long x1, y1;
        long long g = ex_gcd(b % a, a, x1, y1);
        x = y1 -(b / a) * x1;
        y = x1;

        if (x < 0) {
            long long k = (-x + (b / g) - 1) / (b / g);
            x += k * (b / g);
            y -= k * (a / g);
        }
        return g;
    }

    [[nodiscard]] static BigInt newton_opposite(const BigInt& f, const int& l) {
        const int k = static_cast<int>(std::log2(l * 2 - 1));
        long long f0, y;

        ex_gcd(f.dig.back(), f.base, f0, y);

        auto g = BigInt(f0); // как-то посчетать f0^-1

        for (int i = 1; i <= k; ++i) {
            g = (BigInt(2) - f * g) * g;

            g.dig.erase(g.dig.begin(), g.dig.begin() + g.dig.size() - (1 << i));
            if (g.isNeg) {
                BigInt tmp = BigInt(1);
                tmp.dig.insert(tmp.dig.end(), 1 << i, 0);
                g = tmp - g;
            }
        }

        return g;
    }

    BigInt newton_divide(const BigInt& g) const {
        if (dig.size() < g.dig.size()) {
            return BigInt();
        }
        const int m = static_cast<int>(dig.size() - g.dig.size());
        BigInt h = g;
        std::reverse(h.dig.begin(), h.dig.end());
        h = newton_opposite(h, m + 1);

        BigInt q = *this;
        std::reverse(q.dig.begin(), q.dig.end());
        q = q * h;

        q.dig.erase(q.dig.begin(), q.dig.begin() + q.dig.size() - (m + 1));

        std::reverse(q.dig.begin() + m, q.dig.end());
        return q;
    }


    friend std::istream& operator>>(std::istream& is, BigInt& num) {
        std::string input;
        is >> input;
        if (input.empty()) {
            throw std::invalid_argument("Invalid input");
        }
        size_t start = 0;
        if (input[0] == '-') {
            ++start;
        }
        for (size_t i = start; i < input.size(); ++i) {
            if (!isdigit(input[i])) {
                throw std::invalid_argument("Invalid input");
            }
        }
        num = BigInt(input);
        return is;
    }

    static size_t numb_len(ll numb) {
        size_t len = 0;
        while (numb > 0) {
            ++len;
            numb /= 10;
        }
        return len;
    }

    friend std::ostream& operator<<(std::ostream& os, const BigInt& num) {
        if (num.isNeg) {
            os << '-';
        }
        for (size_t i = 0; i < num.dig.size(); ++i) {

            if (i != 0) {
                size_t len = numb_len(num.dig[i]);
                while (8 - len > 0) {
                    os << '0';
                    ++len;
                }
            }
            os << num.dig[i];
        }
        return os;
    }
};
