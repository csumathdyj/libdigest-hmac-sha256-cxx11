#include <cstdint>
#include <string>
#include <algorithm>
#include "mime-base16.hpp"

namespace mime {
// RFC 4648 <http://tools.ietf.org/html/rfc4648>

// 8. Base 16 Encoding: uppercase
std::string
encode_base16 (std::string const& in, std::string const& endline, int const width)
{
    static const std::string B16 = "0123456789ABCDEF";
    return encode_base16basic (in, B16, endline, width);
}

// (not in RFC) HEX Encoding for Cipher/Digest Text: lowercase
std::string
encode_hex (std::string const& in, std::string const& endline, int const width)
{
    static const std::string B16 = "0123456789abcdef";
    return encode_base16basic (in, B16, endline, width);
}

// 8. Base 16 Encoding: both uppercase and lowercase
bool
decode_base16 (std::string const& str16, std::string& octets)
{
    static const int C16[128] = {
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -2, -2, -2, -2, -2, -2,
       -2, 10, 11, 12, 13, 14, 15, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, 10, 11, 12, 13, 14, 15, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    };
    return decode_base16basic (str16, octets, C16);
}

// (not in RFC) HEX Encoding for Cipher/Digest Text: lowercase only
bool
decode_hex (std::string const& str16, std::string& octets)
{
    static const int C16[128] = {
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -2, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, 10, 11, 12, 13, 14, 15, -2, -2, -2, -2, -2, -2, -2, -2, -2,
       -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    };
    return decode_base16basic (str16, octets, C16);
}

// Various Base 16 Encoder
//
// arguments:
//
//  std::string const& in - input octets would be encoded
//  std::string const& b16 - Base 16 alphabets. Its size must be 16
//  std::string const& endline - endline string "\r\n", or without endline ""
//  int const width - columns in a line for folding 76, or unspecified -1
//
// results:
//  std::string - Base16 encoded text as a function value
//
std::string
encode_base16basic (std::string const& in, std::string const& b16,
    std::string const& endline, int const width)
{
    std::string out;
    std::string::const_iterator s = in.cbegin ();
    int cols = 0;
    while (s < in.cend ()) {
        std::size_t const u = static_cast<std::uint8_t> (*s++);
        out.push_back (b16[(u >> 4) & 0x0f]);
        out.push_back (b16[u & 0x0f]);
        if (width > 0) {
            cols += 2;
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

// Various Base 16 Decoder
//
// arguments:
//
//  std::string const& str16 - input base16 text would be decoded
//  std::string& octets - output octets decoded.
//  int const *c16 - Base 16 alphabet codes. Its size must be 128
//                   value >= 0, white space == -1, illegal == -2
//
// results:
//  bool - correctness of input base16 text, true or false as function value
//
bool
decode_base16basic (std::string const& str16, std::string& octets, int const *c16)
{
    std::string out;
    unsigned int u[2] = {0, 0};
    std::size_t k = 0;
    std::string::const_iterator s = str16.cbegin ();
    while (s < str16.cend ()) {
        unsigned int ch = static_cast<std::uint8_t> (*s++);
        if (ch > 127 || c16[ch] < -1)
            return false;
        if (c16[ch] < 0)
            continue;
        u[k++] = c16[ch];
        if (k >= 2) {
            out.push_back ((u[0] << 4) | u[1]);
            k = 0;
            u[0] = u[1] = 0;
        }
    }
    if (k != 0)
        return false;
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
