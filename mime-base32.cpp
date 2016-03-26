#include <cstdint>
#include <string>
#include <algorithm>
#include "mime-base32.hpp"

namespace mime {
// RFC 4648 <http://tools.ietf.org/html/rfc4648>

// 6. Base 32 Encoding
std::string
encode_base32 (std::string const& in, std::string const& endline, int const width)
{
    static const std::string B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    return encode_base32basic (in, B32, '=', endline, width);
}

// 7. Base 32 Encoding with Extended Hex Alphabet
std::string
encode_base32hex (std::string const& in, std::string const& endline, int const width)
{
    static const std::string B32 = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    return encode_base32basic (in, B32, '=', endline, width);
}

// 6. Base 32 Encoding
bool
decode_base32 (std::string const& str32, std::string& octets)
{
    static const int C32[128] = {
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, -2, 26, 27, 28, 29, 30, 31, -2, -2, -2, -2, -2, -2, -2, -2,
       -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
       15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    };
    return decode_base32basic (str32, octets, C32, false);
}

// 7. Base 32 Encoding with Extended Hex Alphabet
bool
decode_base32hex (std::string const& str32, std::string& octets)
{
    static const int C32[128] = {
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -2, -2, -2, -2, -2, -2,
       -2, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
       25, 26, 27, 28, 29, 30, 31, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    };
    return decode_base32basic (str32, octets, C32, false);
}

// Various Base 32 Encoder
//
// arguments:
//
//  std::string const& in - input octets would be encoded
//  std::string const& b32 - Base 32 alphabets. Its size must be 32
//  int const padding - padding character '=', or without padding '\0'
//  std::string const& endline - endline string "\r\n", or without endline ""
//  int const width - columns in a line for folding, or unspecified -1
//
// results:
//  std::string - Base64 encoded text as a function value
//
std::string
encode_base32basic (std::string const& in, std::string const& b32,
    int const padding, std::string const& endline, int const width)
{
    std::string out;
    std::string::const_iterator s = in.cbegin ();
    std::string::const_iterator const e = in.cend ();
    int cols = 0;
    for (; s < e; s += 5) {
        //  aaaaabbb                                     -> AB======  n==2 8-n==6
        //  aaaaabbb bbcccccd                            -> ABCD====  n==4 8-n==4
        //  aaaaabbb bbcccccd ddddeeee                   -> ABCDE===  n==5 8-n==3
        //  aaaaabbb bbcccccd ddddeeee efffffgg          -> ABCDEFG=  n==7 8-n==1
        //  aaaaabbb bbcccccd ddddeeee efffffgg ggghhhhh -> ABCDEFGH  n==8 8-n==0
        int const d = e - s;
        int const n = 4 < d ? 8 : 1 == d ? 2 : 2 == d ? 4 : 3 == d ? 5 : 7;
        std::uint64_t u = static_cast<std::uint8_t> (s[0]);
        std::uint32_t const u1 = d > 1 ? static_cast<std::uint8_t> (s[1]) : 0;
        std::uint32_t const u2 = d > 2 ? static_cast<std::uint8_t> (s[2]) : 0;
        std::uint32_t const u3 = d > 3 ? static_cast<std::uint8_t> (s[3]) : 0;
        std::uint32_t const u4 = d > 4 ? static_cast<std::uint8_t> (s[4]) : 0;
        u = (u << 32) | (u1 << 24) | (u2 << 16) | (u3 << 8) | u4;
        for (int i = 0; i < n; ++i) {
            u = (u << 5) | (u >> 35);
            out.push_back (b32[u & 0x1f]);
        }
        if (padding && n < 8) {
            for (int i = 0; i < 8 - n; ++i) {
                out.push_back (padding);
            }
        }
        if (width > 0) {
            cols += 8;
            if (cols >= width) {
                out.append (endline);
                cols = 0;
            }
        }
    }
    if (width > 0 && cols > 0 && cols < width)
        out.append (endline);
    return out;
}

// Various Base 32 Decoder
//
// arguments:
//
//  std::string const& str32 - input base32 text would be decoded
//  std::string& octets - output octets decoded.
//  int const *c32 - Base 32 alphabet codes. Its size must be 128
//                   value >= 0, white space == -1, illegal == -2
//  bool const autopadding - if lost any padding characters,
//                           they are filled automatically.
//
// results:
//  bool - correctness of input base32 text, true or false as function value
//
// notes:
//
//  1. the padding character is fixed '='.
//  2. if exists some padding characters, check correctness on padding size.
//
bool
decode_base32basic (std::string const& str32, std::string& octets,
    int const *c32, bool const autopadding)
{
    std::string out;
    std::uint64_t u = 0;
    std::size_t k = 0;
    std::string::const_iterator s = str32.cbegin ();
    while (s < str32.cend () && '=' != *s) {
        //  ABCDEFGH -> aaaaabbb bbcccccd ddddeeee efffffgg ggghhhhh
        unsigned int ch = static_cast<std::uint8_t> (*s++);
        if (ch > 127 || c32[ch] < -1)
            return false;
        if (c32[ch] < 0)
            continue;
        u |= static_cast<std::uint64_t> (c32[ch]) << ((7 - k) * 5);
        if (++k > 7) {
            out.push_back ((u >> 32) & 0xff);
            out.push_back ((u >> 24) & 0xff);
            out.push_back ((u >> 16) & 0xff);
            out.push_back ((u >>  8) & 0xff);
            out.push_back ( u        & 0xff);
            k = 0;
            u = 0;
        }
    }
    std::size_t npadding = 0;
    while (s < str32.cend ()) {
        unsigned int ch = *s++;
        if ('=' == ch)
            ++npadding;
    }
    // k==2 AB====== -> aaaaabbb
    // k==4 ABCD==== -> aaaaabbb bbcccccd
    // k==5 ABCDE=== -> aaaaabbb bbcccccd ddddeeee
    // k==7 ABCDEFG= -> aaaaabbb bbcccccd ddddeeee efffffgg
    // k==8 ABCDEFGH -> aaaaabbb bbcccccd ddddeeee efffffgg ggghhhhh
    k = k == 0 ? 8 : k; // consistency for padding check when ! autopadding
    if (1 == k || 3 == k || 6 == k || npadding > 6)
        return false;
    if ((! autopadding || npadding > 0) && k + npadding != 8)
        return false;
    npadding = 8 - k;
    if (0 < npadding)
        out.push_back ((u >> 32) & 0xff);
    if (0 < npadding && npadding <= 4)
        out.push_back ((u >> 24) & 0xff);
    if (0 < npadding && npadding <= 3)
        out.push_back ((u >> 16) & 0xff);
    if (1 == npadding)
        out.push_back ((u >>  8) & 0xff);
    std::swap (octets, out);
    return true;
}

}//namespace mime

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
