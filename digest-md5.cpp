#include <string>
#include <cstdint>
#include "digest.hpp"

namespace digest {

static inline void
unpack_little_endian (std::string& t, std::size_t const i, std::uint32_t const x)
{
    t[i + 0] = x & 0xff;
    t[i + 1] = (x >>  8) & 0xff;
    t[i + 2] = (x >> 16) & 0xff;
    t[i + 3] = (x >> 24) & 0xff;    
}

static inline std::uint32_t
rotate_left (std::uint32_t const x, std::size_t const n)
{
    return (x << n) | (x >> (32 - n));
}

void
MD5::init_sum ()
{
    sum[0] = 0x67452301L;
    sum[1] = 0xefcdab89L;
    sum[2] = 0x98badcfeL;
    sum[3] = 0x10325476L;
}

static inline void
round (
    std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d,
    std::uint32_t const f, std::uint32_t const x, int const s, std::uint32_t const k)
{
    std::uint32_t const e = rotate_left (a + f + x + k, s);
    a = d;
    d = c;
    c = b;
    b += e;
}

void
MD5::update_sum (std::string::const_iterator& s)
{
    static const int SH[64] = {
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
    };
    static const std::uint32_t K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    };
    std::uint32_t w[16];
    for (std::size_t i = 0; i < 16; ++i)
        w[i] =  static_cast<std::uint8_t> (*s++)
             | (static_cast<std::uint8_t> (*s++) <<  8)
             | (static_cast<std::uint8_t> (*s++) << 16)
             | (static_cast<std::uint8_t> (*s++) << 24);
    std::uint32_t a = sum[0], b = sum[1], c = sum[2], d = sum[3];
    std::size_t i = 0;
    for (; i < 16U; ++i)
        round (a, b, c, d, (b & c) | (~b & d), w[i],       SH[i], K[i]);
    std::size_t g = i * 5 + 1U;
    for (; i < 32U; ++i, g += 5U)
        round (a, b, c, d, (d & b) | (~d & c), w[g & 15U], SH[i], K[i]);
    g = i * 3 + 5U;
    for (; i < 48U; ++i, g += 3U)
        round (a, b, c, d, b ^ c ^ d,          w[g & 15U], SH[i], K[i]);
    g = i * 7;
    for (; i < 64U; ++i, g += 7U)
        round (a, b, c, d, c ^ (b | ~d),       w[g & 15U], SH[i], K[i]);
    sum[0] += a, sum[1] += b, sum[2] += c, sum[3] += d;
}

void
MD5::last_sum ()
{
    mbuf.push_back (0x80);
    std::size_t n = (mbuf.size () + 8U + 64U - 1U) / 64U * 64U;
    mbuf.resize (n, 0);
    unpack_little_endian (mbuf, n - 8U, mlen <<  3);
    unpack_little_endian (mbuf, n - 4U, mlen >> 29);
    std::string::const_iterator p = mbuf.cbegin ();
    for (std::size_t i = 0; i < n; i += 64U)
        update_sum (p);
}

std::string
MD5::digest ()
{
    std::string octets (16, 0);
    finish ();
    std::uint32_t *p = sum;
    for (std::size_t i = 0; i < octets.size (); i += 4)
        unpack_little_endian (octets, i, *p++);
    return octets;
}

}//namespace digest

/* Copyright (c) 2015, MIZUTANI Tociyuki  
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
