#include <cstdint>
#include <string>
#include <algorithm>
#include "mime-base64.hpp"

namespace mime {
// RFC 4648 <http://tools.ietf.org/html/rfc4648>

std::string
encode_base64 (std::string const& in)
{
    static const std::string B64
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return encode_base64basic (in, B64, '=', "\n", 76);
}

std::string
encode_base64 (std::string const& in, std::string const& endline)
{
    static const std::string B64
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return encode_base64basic (in, B64, '=', endline, 76);
}

std::string
encode_base64url (std::string const& in)
{
    static const std::string B64
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    return encode_base64basic (in, B64, '=', "", -1);
}

std::string
encode_base64crypt (std::string const& in)
{
    static const std::string B64
        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";
    return encode_base64basic (in, B64, '\0', "", -1);
}

bool
decode_base64 (std::string const& str64, std::string& octets)
{
    static const int C64[128] = {
       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
       52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
       -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
       15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
       -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
       41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    };
    return decode_base64basic (str64, octets, C64);
}

bool
decode_base64url (std::string const& str64, std::string& octets)
{
    static const int C64[128] = {
       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
       52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
       -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
       15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
       -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
       41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    };
    return decode_base64basic (str64, octets, C64);
}

bool
decode_base64crypt (std::string const& str64, std::string& octets)
{
    static const int C64[128] = {
       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
       -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, 63,
       52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
       -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
       15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
       -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
       41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    };
    return decode_base64basic (str64, octets, C64);
}

std::string
encode_base64basic (std::string const& in, std::string const& b64,
    int const padding, std::string const& endline, int const width)
{
    std::string out;
    std::string::const_iterator s = in.cbegin ();
    int cols = 0;
    while (s < in.cend ()) {
        std::size_t const u0 = static_cast<std::uint8_t> (s[0]);
        std::size_t const u1 = s + 1 < in.cend () ? static_cast<std::uint8_t> (s[1]) : 0;
        std::size_t const u2 = s + 2 < in.cend () ? static_cast<std::uint8_t> (s[2]) : 0;
        out.push_back (b64[(u0 >> 2) & 0x3f]);
        out.push_back (b64[((u0 << 4) | (u1 >> 4)) & 0x3f]);
        if (s + 1 < in.cend ())
            out.push_back (b64[((u1 << 2) | (u2 >> 6)) & 0x3f]);
        else if (padding)
            out.push_back (padding);
        if (s + 2 < in.cend ())
            out.push_back (b64[u2 & 0x3f]);
        else if (padding)
            out.push_back (padding);
        s = s + 2 < in.cend () ? s + 3 : in.cend ();
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

bool
decode_base64basic (std::string const& str64, std::string& octets, int const *c64)
{
    std::string out;
    unsigned int u[4] = {0, 0, 0, 0};
    std::size_t k = 0;
    std::string::const_iterator s = str64.cbegin ();
    while (s < str64.cend () && '=' != *s) {
        unsigned int ch = static_cast<std::uint8_t> (*s++);
        if (ch > 127 || c64[ch] < 0)
            continue;
        u[k++] = c64[ch];
        if (k >= 4) {
            out.push_back ((u[0] << 2) | (u[1] >> 4));
            out.push_back (((u[1] & 0x0f) << 4) | (u[2] >> 2));
            out.push_back (((u[2] & 0x03) << 6) | u[3]);
            k = 0;
            u[0] = u[1] = u[2] = u[3] = 0;
        }
    }
    std::size_t npadding = 0;
    while (s < str64.cend ()) {
        unsigned int ch = *s++;
        if ('=' == ch)
            ++npadding;
    }
    if (k == 1 || npadding > 2 || (npadding > 0 && k + npadding != 4))
        return false;
    npadding = 4 - k;
    if (1 == npadding || 2 == npadding)
        out.push_back ((u[0] << 2) | (u[1] >> 4));
    if (1 == npadding)
        out.push_back (((u[1] & 0x0f) << 4) | (u[2] >> 2));
    std::swap (octets, out);
    return true;
}

}// namespace mime
