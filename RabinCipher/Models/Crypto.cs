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

    // Шифрование одного числа: c = m*(m+b) mod n
    public BigInteger Cipher(BigInteger m)
    {
        if (_n == 0) throw new InvalidOperationException("Ключи не заданы.");
        return m * (m + _b) % _n;
    }

    // Дешифрование: возвращает список возможных открытых текстов
    public List<BigInteger> Decipher(BigInteger c)
    {
        if (_n == 0) throw new InvalidOperationException("Ключи не заданы.");

        // d = b^2 + 4c  (дискриминант)
        BigInteger d = (_b * _b + 4 * c) % _n;

        // Корни mod p
        List<BigInteger> rootsP = SqrtMod(d % _p, _p);
        if (rootsP.Count == 0) return new List<BigInteger>();

        // Корни mod q
        List<BigInteger> rootsQ = SqrtMod(d % _q, _q);
        if (rootsQ.Count == 0) return new List<BigInteger>();

        // inv(2) mod n для формулы m = (-b ± sqrt(d)) * inv(2) mod n
        BigInteger inv2 = ModInverse(2, _n);

        HashSet<BigInteger> solutions = new HashSet<BigInteger>();
        foreach (var rp in rootsP)
        {
            foreach (var rq in rootsQ)
            {
                BigInteger sqrtD = ChineseRemainder(rp, _p, rq, _q);
                BigInteger m1 = ((-_b + sqrtD) % _n + _n) % _n * inv2 % _n;
                BigInteger m2 = ((-_b - sqrtD) % _n + _n) % _n * inv2 % _n;
                solutions.Add(m1);
                solutions.Add(m2);
            }
        }

        return new List<BigInteger>(solutions);
    }

    // Квадратный корень по модулю простого p (алгоритм Тонелли-Шенкса)
    private List<BigInteger> SqrtMod(BigInteger a, BigInteger p)
    {
        a = ((a % p) + p) % p;
        if (a == 0) return new List<BigInteger> { 0 };
        if (!IsQuadraticResidue(a, p)) return new List<BigInteger>();
        BigInteger r = TonelliShanks(a, p);
        var res = new List<BigInteger> { r };
        if (r != 0) res.Add(p - r);
        return res;
    }

    // Проверка простоты (пробное деление — подходит для небольших чисел лабораторной работы)
    public static bool IsPrime(BigInteger n)
    {
        if (n < 2) return false;
        if (n == 2) return true;
        if (n % 2 == 0) return false;
        for (BigInteger i = 3; i * i <= n; i += 2)
            if (n % i == 0) return false;
        return true;
    }

    // Критерий Эйлера: a — квадратичный вычет mod p ⟺ a^((p-1)/2) ≡ 1 (mod p)
    private static bool IsQuadraticResidue(BigInteger a, BigInteger p)
    {
        if (a % p == 0) return true;
        return BigInteger.ModPow(a, (p - 1) / 2, p) == 1;
    }

    // Алгоритм Тонелли-Шенкса
    private static BigInteger TonelliShanks(BigInteger a, BigInteger p)
    {
        a = ((a % p) + p) % p;
        if (a == 0) return 0;
        if (p == 2) return a % 2;

        // Частный случай p ≡ 3 (mod 4)
        if (p % 4 == 3)
            return BigInteger.ModPow(a, (p + 1) / 4, p);

        // p-1 = Q * 2^S
        BigInteger q = p - 1, s = 0;
        while (q % 2 == 0) { q /= 2; s++; }

        // Ищем квадратичный невычет z
        BigInteger z = 2;
        while (IsQuadraticResidue(z, p)) z++;

        BigInteger M = s;
        BigInteger c = BigInteger.ModPow(z, q, p);
        BigInteger t = BigInteger.ModPow(a, q, p);
        BigInteger r = BigInteger.ModPow(a, (q + 1) / 2, p);

        while (true)
        {
            if (t == 1) return r;
            BigInteger t2i = t; BigInteger i = 0;
            do { t2i = t2i * t2i % p; i++; } while (t2i != 1);

            BigInteger b = c;
            for (BigInteger j = 0; j < M - i - 1; j++) b = b * b % p;
            M = i; c = b * b % p; t = t * c % p; r = r * b % p;
        }
    }

    // Расширенный алгоритм Евклида: обратный элемент a^(-1) mod m
    public static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger m0 = m, x = 1, y = 0;
        if (m == 1) return 0;
        while (a > 1)
        {
            BigInteger q = a / m;
            (a, m) = (m, a % m);
            (x, y) = (y, x - q * y);
        }
        return x < 0 ? x + m0 : x;
    }

    // Китайская теорема об остатках: x ≡ rp (mod p), x ≡ rq (mod q)
    private static BigInteger ChineseRemainder(BigInteger rp, BigInteger p, BigInteger rq, BigInteger q)
    {
        BigInteger diff = ((rq - rp) % q + q) % q;
        BigInteger k = diff * ModInverse(p % q, q) % q;
        BigInteger x = rp + p * k;
        BigInteger n = p * q;
        return ((x % n) + n) % n;
    }
}