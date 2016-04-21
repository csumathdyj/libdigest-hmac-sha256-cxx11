#include <string>
#include <cstdint>
#include "digest.hpp"

// SHA-512, SHA-384, SHA-512/224, SHA-512/256 implementation

namespace digest {

static inline void
unpack_big_endian (std::string& t, std::size_t const i, std::uint64_t const x)
{
    t[i + 0] = (x >> 56) & 0xff;    
    t[i + 1] = (x >> 48) & 0xff;
    t[i + 2] = (x >> 40) & 0xff;
    t[i + 3] = (x >> 32) & 0xff;
    t[i + 4] = (x >> 24) & 0xff;    
    t[i + 5] = (x >> 16) & 0xff;
    t[i + 6] = (x >>  8) & 0xff;
    t[i + 7] = x & 0xff;
}

static inline std::uint64_t
rotate_right (std::uint64_t const x, std::size_t const n)
{
    return (x >> n) | (x << (64 - n));
}

static inline std::uint64_t
ch (std::uint64_t const x, std::uint64_t const y, std::uint64_t const z)
{
    return (x & y) ^ ((~x) & z);
}

static inline std::uint64_t
ma (std::uint64_t const x, std::uint64_t const y, std::uint64_t const z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline std::uint64_t
gamma0 (std::uint64_t const x)
{
    return rotate_right (x, 1) ^ rotate_right (x, 8) ^ (x >> 7);
}

static inline std::uint64_t
gamma1 (std::uint64_t const x)
{
    return rotate_right (x, 19) ^ rotate_right (x, 61) ^ (x >> 6);
}

static inline std::uint64_t
sigma0 (std::uint64_t const x)
{
    return rotate_right (x, 28) ^ rotate_right (x, 34) ^ rotate_right (x, 39);
}

static inline std::uint64_t
sigma1 (std::uint64_t const x)
{
    return rotate_right (x, 14) ^ rotate_right (x, 18) ^ rotate_right (x, 41);
}

void
SHA512::init_sum ()
{
    sum[0] = 0x6a09e667f3bcc908ULL; sum[1] = 0xbb67ae8584caa73bULL;
    sum[2] = 0x3c6ef372fe94f82bULL; sum[3] = 0xa54ff53a5f1d36f1ULL;
    sum[4] = 0x510e527fade682d1ULL; sum[5] = 0x9b05688c2b3e6c1fULL;
    sum[6] = 0x1f83d9abfb41bd6bULL; sum[7] = 0x5be0cd19137e2179ULL;
}

void
SHA384::init_sum ()
{
    sum[0] = 0xcbbb9d5dc1059ed8ULL; sum[1] = 0x629a292a367cd507ULL;
    sum[2] = 0x9159015a3070dd17ULL; sum[3] = 0x152fecd8f70e5939ULL;
    sum[4] = 0x67332667ffc00b31ULL; sum[5] = 0x8eb44a8768581511ULL;
    sum[6] = 0xdb0c2e0d64f98fa7ULL; sum[7] = 0x47b5481dbefa4fa4ULL;
}

static inline void
round (
    std::uint64_t const a, std::uint64_t const b, std::uint64_t const c,
    std::uint64_t& d,
    std::uint64_t const e, std::uint64_t const f, std::uint64_t const g,
    std::uint64_t& h,
    std::uint64_t const k, std::uint64_t const w)
{
    std::uint64_t const t0 = h + sigma1 (e) + ch (e, f, g) + k + w;
    std::uint64_t const t1 = sigma0 (a) + ma (a, b, c);
    d += t0;
    h = t0 + t1;
}

void
SHA2_64BIT::update_sum (std::string::const_iterator s)
{
    static const std::uint64_t K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
        0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
        0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
        0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
        0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
        0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
        0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
        0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
        0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
        0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
        0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
        0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
        0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
        0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
        0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
        0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
        0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
        0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
        0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
        0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
        0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };
    std::uint64_t w[80];
    std::uint64_t a = sum[0], b = sum[1], c = sum[2], d = sum[3];
    std::uint64_t e = sum[4], f = sum[5], g = sum[6], h = sum[7];
    for (std::size_t i = 0; i < 16U; i++)
        w[i] = (static_cast<std::uint64_t> (static_cast<std::uint8_t>(*s++)) << 56)
             | (static_cast<std::uint64_t> (static_cast<std::uint8_t>(*s++)) << 48)
             | (static_cast<std::uint64_t> (static_cast<std::uint8_t>(*s++)) << 40)
             | (static_cast<std::uint64_t> (static_cast<std::uint8_t>(*s++)) << 32)
             | (static_cast<std::uint64_t> (static_cast<std::uint8_t>(*s++)) << 24)
             | (static_cast<std::uint64_t> (static_cast<std::uint8_t>(*s++)) << 16)
             | (static_cast<std::uint64_t> (static_cast<std::uint8_t>(*s++)) <<  8)
             |  static_cast<std::uint64_t> (static_cast<std::uint8_t>(*s++));
    for (std::size_t i = 16U; i < 80U; i++)
        w[i] = gamma1 (w[i - 2]) + w[i - 7] + gamma0 (w[i - 15]) + w[i - 16];
    for (std::size_t i = 0; i < 80U; i += 8U) {
        round (a, b, c, d, e, f, g, h, K[i + 0], w[i + 0]);
        round (h, a, b, c, d, e, f, g, K[i + 1], w[i + 1]);
        round (g, h, a, b, c, d, e, f, K[i + 2], w[i + 2]);
        round (f, g, h, a, b, c, d, e, K[i + 3], w[i + 3]);
        round (e, f, g, h, a, b, c, d, K[i + 4], w[i + 4]);
        round (d, e, f, g, h, a, b, c, K[i + 5], w[i + 5]);
        round (c, d, e, f, g, h, a, b, K[i + 6], w[i + 6]);
        round (b, c, d, e, f, g, h, a, K[i + 7], w[i + 7]);
    }
    sum[0] += a; sum[1] += b; sum[2] += c; sum[3] += d;
    sum[4] += e; sum[5] += f; sum[6] += g; sum[7] += h;
}

void
SHA2_64BIT::last_sum ()
{
    mbuf.push_back (0x80);
    std::size_t n = (mbuf.size () + 8U + 128U - 1U) / 128U * 128U;
    mbuf.resize (n, 0);
    std::uint64_t bitlen = static_cast<std::uint64_t> (mlen) << 3;
    unpack_big_endian (mbuf, n - 8, bitlen);
    std::string::const_iterator p = mbuf.cbegin ();
    for (std::size_t i = 0; i < n; i += 128U)
        update_sum (p);
}

std::string
SHA512::digest ()
{
    std::string octets (64, 0);
    finish ();
    std::uint64_t *p = sum;
    for (std::size_t i = 0; i < octets.size (); i += 8)
        unpack_big_endian (octets, i, *p++);
    return octets;
}

std::string
SHA384::digest ()
{
    std::string octets (48, 0);
    finish ();
    std::uint64_t *p = sum;
    for (std::size_t i = 0; i < octets.size (); i += 8)
        unpack_big_endian (octets, i, *p++);
    return octets;
}

std::string
SHA512_224::digest ()
{
    std::string octets (32, 0);
    finish ();
    std::uint64_t *p = sum;
    for (std::size_t i = 0; i < octets.size (); i += 8)
        unpack_big_endian (octets, i, *p++);
    return octets.substr (0, 28);
}

std::string
SHA512_256::digest ()
{
    std::string octets (32, 0);
    finish ();
    std::uint64_t *p = sum;
    for (std::size_t i = 0; i < octets.size (); i += 8)
        unpack_big_endian (octets, i, *p++);
    return octets;
}

}//namespace digest

/* Copyright (c) 2016, MIZUTANI Tociyuki  
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
