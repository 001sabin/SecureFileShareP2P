using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Numerics;
using System.Security.Cryptography;

namespace SecureFileShareP2P.Cryptography
{
    public static class RSAKeyGenerator
    {
        // Generate RSA key pair (public + private)
        //public static (BigInteger n, BigInteger e, BigInteger d) GenerateKeys(int bitLength = 512)
        //{
        //    // Step 1: Choose two large primes p and q
        //    BigInteger p = GenerateLargePrime(bitLength / 2);
        //    BigInteger q = GenerateLargePrime(bitLength / 2);

        //    // Step 2: Compute n = p * q
        //    BigInteger n = p * q;

        //    // Step 3: Compute φ(n) = (p-1)*(q-1)
        //    BigInteger phi = (p - 1) * (q - 1);

        //    // Step 4: Choose e (public exponent)
        //    BigInteger e = 65537; // Common choice for e

        //    // Step 5: Compute d (private exponent) ≡ e⁻¹ mod φ(n)
        //    BigInteger d = ModInverse(e, phi);

        //    return (n, e, d); // Public: (n,e), Private: (n,d)
        //}

        public static (BigInteger n, BigInteger e, BigInteger d) GenerateKeys(int bitLength = 512)
        {
            BigInteger p, q, n, phi, e = 65537, d;
            do
            {
                p = GenerateLargePrime(bitLength / 2);
                q = GenerateLargePrime(bitLength / 2);
                n = p * q;
                phi = (p - 1) * (q - 1);

                // Ensure phi is at least 2 (since e = 65537 is fixed)
                if (phi <= 1)
                    continue; // Regenerate p and q if phi is invalid
            }
            while (BigInteger.GreatestCommonDivisor(e, phi) != 1);

            d = ModInverse(e, phi);
            return (n, e, d);
        }



        // Miller-Rabin primality test
        private static bool IsProbablePrime(BigInteger n, int k = 40)
        {
            if (n <= 1) return false;
            if (n == 2 || n == 3) return true;
            if (n % 2 == 0) return false;

            // Write n-1 as d*2^s
            BigInteger d = n - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            // Test k times
            byte[] bytes = new byte[n.ToByteArray().Length];
            using (var rng = RandomNumberGenerator.Create())
            {
                for (int i = 0; i < k; i++)
                {
                    BigInteger a;
                    do
                    {
                        rng.GetBytes(bytes);
                        a = new BigInteger(bytes);
                    } while (a < 2 || a >= n - 2);

                    BigInteger x = BigInteger.ModPow(a, d, n);
                    if (x == 1 || x == n - 1)
                        continue;

                    for (int j = 0; j < s - 1; j++)
                    {
                        x = BigInteger.ModPow(x, 2, n);
                        if (x == n - 1)
                            break;
                    }

                    if (x != n - 1)
                        return false;
                }
            }
            return true;
        }

        // Generate a large prime number
        private static BigInteger GenerateLargePrime(int bitLength)
        {
            BigInteger prime;
            byte[] bytes = new byte[bitLength / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                do
                {
                    rng.GetBytes(bytes);
                    prime = new BigInteger(bytes);
                    prime = BigInteger.Abs(prime);
                } while (!IsProbablePrime(prime));
            }
            return prime;
        }

        //private static BigInteger GenerateLargePrime(int bitLength)
        //{
        //    if (bitLength < 2)
        //        throw new ArgumentException("Bit length must be at least 2.");

        //    BigInteger prime;
        //    byte[] bytes = new byte[bitLength / 8 + 1]; // +1 to avoid small numbers

        //    using (var rng = RandomNumberGenerator.Create())
        //    {
        //        do
        //        {
        //            rng.GetBytes(bytes);
        //            prime = new BigInteger(bytes);
        //            prime = BigInteger.Abs(prime);

        //            // Ensure prime is at least 2 (avoid 0, 1, or negative)
        //            if (prime < 2)
        //                prime = 2;
        //        }
        //        while (!IsProbablePrime(prime));
        //    }
        //    return prime;
        //}
        // Modular inverse using Extended Euclidean Algorithm

        //private static BigInteger ModInverse(BigInteger a, BigInteger m)
        //{
        //    //if (m == 0)
        //    //    throw new ArgumentException("Modulus must not be zero (a and m must be coprime).");
        //    //if (a == 0)
        //    //    throw new ArgumentException("Value (a) cannot be zero.");
        //    BigInteger m0 = m;
        //    BigInteger y = 0, x = 1;

        //    if (m == 1)
        //        return 0;

        //    while (a > 1)
        //    {
        //        if (m == 0) // Extra safety check
        //            throw new InvalidOperationException("Modulus became zero during computation.");

        //        BigInteger q = a / m;
        //        BigInteger t = m;

        //        m = a % m;
        //        a = t;
        //        t = y;

        //        y = x - q * y;
        //        x = t;
        //    }

        //    if (x < 0)
        //        x += m0;

        //    return x;
        //}
        private static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            if (m == 1)
                return 0; // Edge case

            // Extended Euclidean Algorithm (with zero checks)
            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            while (a > 1)
            {
                // Ensure m is never zero (should not happen if gcd(a,m)=1)
                if (m == 0)
                    throw new InvalidOperationException("Modulus became zero during inversion.");

                BigInteger q = a / m;  // Division happens here
                BigInteger t = m;

                m = a % m;  // Modulo happens here
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            // Ensure x is positive
            if (x < 0)
                x += m0;

            return x;
        }
    }
}