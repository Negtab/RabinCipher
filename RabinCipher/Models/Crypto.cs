using System;
using System.Collections.Generic;
using System.Numerics;

namespace RabinCipher.Models;

public class Crypto
{
    private BigInteger _p;
    private BigInteger _q;
    private BigInteger _n;
    private BigInteger _b;

    public BigInteger P
    {
        get => _p;
        set
        {
            if (value % 4 == 3 && IsPrime(value))
                _p = value;
            else
                throw new ArgumentException($"p должно быть простым и p ≡ 3 (mod 4). Получено: {value}");
            if (_q != 0) _n = _p * _q;
        }
    }

    public BigInteger Q
    {
        get => _q;
        set
        {
            if (value % 4 == 3 && IsPrime(value))
                _q = value;
            else
                throw new ArgumentException($"q должно быть простым и q ≡ 3 (mod 4). Получено: {value}");
            if (_p != 0) _n = _p * _q;
        }
    }

    public BigInteger N => _n;

    public BigInteger B
    {
        get => _b;
        set
        {
            if (_n == 0) throw new InvalidOperationException("Сначала задайте p и q.");
            if (value < 0 || value >= _n)
                throw new ArgumentException($"b должно быть в диапазоне [0, n-1]. n = {_n}");
            _b = value;
        }
    }

    // ── Шифрование: c = m*(m+b) mod n ────────────────────────────────────────
    public BigInteger Cipher(BigInteger m)
    {
        if (_n == 0) throw new InvalidOperationException("Ключи не заданы.");
        return m * (m + _b) % _n;
    }

    // ── Дешифрование — возвращает до 4 кандидатов ────────────────────────
    public List<BigInteger> Decipher(BigInteger c)
    {
        if (_n == 0) throw new InvalidOperationException("Ключи не заданы.");

        BigInteger d = _b * _b + 4 * c;                     // дискриминант

        List<BigInteger> rootsP = SqrtMod(d, _p);
        if (rootsP.Count == 0) return new List<BigInteger>();

        List<BigInteger> rootsQ = SqrtMod(d, _q);
        if (rootsQ.Count == 0) return new List<BigInteger>();

        BigInteger inv2 = ModInverse(2, _n);

        var solutions = new HashSet<BigInteger>();

        foreach (var rp in rootsP)
        {
            foreach (var rq in rootsQ)
            {
                BigInteger sqrtD = ChineseRemainder(rp, _p, rq, _q);
                BigInteger m1 = ((-_b + sqrtD) % _n + _n) % _n * inv2 % _n;
                BigInteger m2 = ((-_b - sqrtD) % _n + _n) % _n * inv2 % _n;

                // Убрана проверка на m <= 256 – теперь добавляются все кандидаты
                solutions.Add(m1);
                solutions.Add(m2);
            }
        }

        return new List<BigInteger>(solutions);
    }

    // ── sqrt(a) mod p ─────────────────────────────────────────────────────────
    private static List<BigInteger> SqrtMod(BigInteger a, BigInteger p)
    {
        a = ((a % p) + p) % p;
        if (a == 0) return new List<BigInteger> { 0 };
        if (!IsQuadraticResidue(a, p)) return new List<BigInteger>();
        BigInteger r = TonelliShanks(a, p);
        var res = new List<BigInteger> { r };
        BigInteger r2 = p - r;
        if (r2 != r) res.Add(r2);
        return res;
    }

    // ── Проверка простоты (пробное деление) ───────────────────────────────────
    public static bool IsPrime(BigInteger n)
    {
        if (n < 2) return false;
        if (n == 2) return true;
        if (n % 2 == 0) return false;
        for (BigInteger i = 3; i * i <= n; i += 2)
            if (n % i == 0) return false;
        return true;
    }

    // ── Критерий Эйлера: a — квадратичный вычет mod p ────────────────────────
    private static bool IsQuadraticResidue(BigInteger a, BigInteger p)
    {
        a = ((a % p) + p) % p;
        if (a == 0) return true;
        // Используем СВОЁ быстрое возведение в степень
        return ModPow(a, (p - 1) / 2, p) == 1;
    }

    // ── Быстрое возведение в степень (метод двоичного возведения) ────────────
    // a^exp mod m за O(log exp) умножений
    public static BigInteger ModPow(BigInteger a, BigInteger exp, BigInteger m)
    {
        if (m == 1) return 0;
        BigInteger result = 1;
        a %= m;
        if (a < 0) a += m;

        while (exp > 0)
        {
            // Если текущий бит exp равен 1 — умножаем результат на a
            if ((exp & 1) == 1)
                result = result * a % m;
            // Сдвигаем exp вправо на 1 бит (делим на 2)
            exp >>= 1;
            // Возводим основание в квадрат
            a = a * a % m;
        }
        return result;
    }

    // ── Тонелли-Шенкс: sqrt(a) mod p ─────────────────────────────────────────
    private static BigInteger TonelliShanks(BigInteger a, BigInteger p)
    {
        a = ((a % p) + p) % p;
        if (a == 0) return 0;
        if (p == 2) return a & 1;

        // Условие задачи: p ≡ 3 (mod 4) — корень вычисляется за одно возведение в степень
        if (p % 4 == 3)
            return ModPow(a, (p + 1) / 4, p); // используем СВОЁ ModPow

        // Общий случай Тонелли-Шенкса (на случай других p)
        BigInteger q = p - 1, s = 0;
        while (q % 2 == 0) { q /= 2; s++; }

        BigInteger z = 2;
        while (IsQuadraticResidue(z, p)) z++;

        BigInteger M = s;
        BigInteger cc = ModPow(z, q, p);   // своё ModPow
        BigInteger t  = ModPow(a, q, p);   // своё ModPow
        BigInteger r  = ModPow(a, (q + 1) / 2, p); // своё ModPow

        while (true)
        {
            if (t == 1) return r;
            BigInteger t2i = t, i = 1;
            for (; i < M; i++) { t2i = t2i * t2i % p; if (t2i == 1) break; }
            BigInteger b = cc;
            for (BigInteger j = 0; j < M - i - 1; j++) b = b * b % p;
            M = i; cc = b * b % p; t = t * cc % p; r = r * b % p;
        }
    }

    // ── Расширенный алгоритм Евклида ─────────────────────────────────────────
    // Находит x, y такие что: a*x + m*y = gcd(a, m)
    // Возвращает x — обратный элемент a по модулю m (если gcd == 1)
    public static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger old_r = a, r = m;
        BigInteger old_s = 1, s = 0; // коэффициент при a (x Безу)

        while (r != 0)
        {
            BigInteger q = old_r / r;

            (old_r, r) = (r, old_r - q * r);
            (old_s, s) = (s, old_s - q * s);
        }

        // old_r == gcd(a, m), old_s == x такой что a*x ≡ gcd (mod m)
        if (old_r != 1)
            throw new ArgumentException($"Обратного элемента не существует: gcd({a}, {m}) = {old_r}");

        return ((old_s % m) + m) % m;
    }

    // ── КТО: x ≡ rp (mod p), x ≡ rq (mod q) ─────────────────────────────────
    private static BigInteger ChineseRemainder(BigInteger rp, BigInteger p, BigInteger rq, BigInteger q)
    {
        BigInteger diff = ((rq - rp) % q + q) % q;
        BigInteger k    = diff * ModInverse(p % q, q) % q; // расш. Евклид для inv(p mod q, q)
        BigInteger x    = rp + p * k;
        BigInteger n    = p * q;
        return ((x % n) + n) % n;
    }
}