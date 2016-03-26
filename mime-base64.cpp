#include <cstdint>
#include <string>
#include <algorithm>
#include "mime-base64.hpp"

namespace mime {
// RFC 4648 <http://tools.ietf.org/html/rfc4648>

// 4. Base 64 Encoding
std::string
encode_base64 (std::string const& in, std::string const& endline, int const width)
{
    static const std::string B64
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return encode_base64basic (in, B64, '=', endline, width);
}

// 5. Base 64 Encoding with URL and Filename Safe Alphabet
std::string
encode_base64url (std::string const& in)
{
    static const std::string B64
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    return encode_base64basic (in, B64, '=', "", -1);
}

// (not in RFC) Base64 Encoding for Cipher Text
std::string
encode_base64crypt (std::string const& in)
{
    static const std::string B64
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";
    return encode_base64basic (in, B64, '\0', "", -1);
}

// 4. Base 64 Encoding
bool
decode_base64 (std::string const& str64, std::string& octets)
{
    static const int C64[128] = {
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
       52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
       -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
       15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
       -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
       41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
    };
    return decode_base64basic (str64, octets, C64, false);
}

// 5. Base 64 Encoding with URL and Filename Safe Alphabet
bool
decode_base64url (std::string const& str64, std::string& octets)
{
    static const int C64[128] = {
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2,
       52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
       -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
       15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, 63,
       -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
       41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
    };
    return decode_base64basic (str64, octets, C64, true);
}

// (not in RFC) Base64 Encoding for Cipher Text
bool
decode_base64crypt (std::string const& str64, std::string& octets)
{
    static const int C64[128] = {
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, 63,
       52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
       -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
       15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
       -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
       41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
    };
    return decode_base64basic (str64, octets, C64, true);
}

// Various Base 64 Encoder
//
// arguments:
//
//  std::string const& in - input octets would be encoded
//  std::string const& b64 - Base 64 alphabets. Its size must be 64
//  int const padding - padding character '=', or without padding '\0'
//  std::string const& endline - endline string "\r\n", or without endline ""
//  int const width - columns in a line for folding 76, or unspecified -1
//
// results:
//  std::string - Base64 encoded text as a function value
//
std::string
encode_base64basic (std::string const& in, std::string const& b64,
    int const padding, std::string const& endline, int const width)
{
    std::string out;
    std::string::const_iterator s = in.cbegin ();
    std::string::const_iterator const e = in.cend ();
    int cols = 0;
    for (; s < e; s += 3) {
        int const d = e - s;
        int const n = d > 2 ? 4 : 1 == d ? 2 : 3;
        std::uint32_t u = static_cast<std::uint8_t> (s[0]);
        std::uint32_t const u1 = d > 1 ? static_cast<std::uint8_t> (s[1]) : 0;
        std::uint32_t const u2 = d > 2 ? static_cast<std::uint8_t> (s[2]) : 0;
        u = (u << 16) | (u1 << 8) | u2;
        for (int i = 0; i < n; ++i) {
            u = (u << 6) | (u >> 18);
            out.push_back (b64[u & 0x3f]);
        }
        if (padding && n < 4) {
            for (int i = 0; i < 4 - n; ++i) {
                out.push_back (padding);
            }
        }
        if (width > 0) {
            cols += 4;
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

// Various Base 64 Decoder
//
// arguments:
//
//  std::string const& str64 - input base64 text would be decoded
//  std::string& octets - output octets decoded.
//  int const *c64 - Base 64 alphabet codes. Its size must be 128
//                   value >= 0, white space == -1, illegal == -2
//  bool const autopadding - if lost any padding characters,
//                           they are filled automatically.
//
// results:
//  bool - correctness of input base64 text, true or false as function value
//
// notes:
//
//  1. the padding character is fixed '='.
//  2. if exists some padding characters, check correctness on padding size.
//
bool
decode_base64basic (std::string const& str64, std::string& octets,
    int const *c64, bool const autopadding)
{
    std::string out;
    std::uint32_t u = 0;
    std::size_t k = 0;
    std::string::const_iterator s = str64.cbegin ();
    while (s < str64.cend () && '=' != *s) {
        unsigned int ch = static_cast<std::uint8_t> (*s++);
        if (ch > 127 || c64[ch] < -1)
            return false;
        if (c64[ch] < 0)
            continue;
        u |= static_cast<std::uint32_t> (c64[ch]) << ((3 - k) * 6);
        if (++k > 3) {
            out.push_back ((u >> 16) & 0xff);
            out.push_back ((u >>  8) & 0xff);
            out.push_back ( u        & 0xff);
            k = 0;
            u = 0;
        }
    }
    std::size_t npadding = 0;
    while (s < str64.cend ()) {
        unsigned int ch = *s++;
        if ('=' == ch)
            ++npadding;
    }
    k = 0 == k ? 4 : k;
    if (k == 1 || npadding > 2 || ((! autopadding || npadding > 0) && k + npadding != 4))
        return false;
    npadding = 4 - k;
    if (1 == npadding || 2 == npadding)
        out.push_back ((u >> 16) & 0xff);
    if (1 == npadding)
        out.push_back ((u >>  8) & 0xff);
    std::swap (octets, out);
    return true;
}

}// namespace mime

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
