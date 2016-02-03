#pragma once

#include <string>

namespace mime {

// RFC 4648 <http://tools.ietf.org/html/rfc4648>

// 8. Base 16 Encoding
//  The Base 16 Alphabet is uppercase.
std::string encode_base16 (std::string const& in);
std::string encode_base16 (std::string const& in, std::string const& endline);
bool decode_base16 (std::string const& str16, std::string& octets);

// (not in RFC) lowercase version for cipher/digest text
std::string encode_hex (std::string const& in);
std::string encode_hex (std::string const& in, std::string const& endline);
bool decode_hex (std::string const& str16, std::string& octets);

std::string encode_base16basic (std::string const& in, std::string const& b16,
    std::string const& endline, int const width);
bool decode_base16basic (std::string const& str16, std::string& octets,
    int const *c16);

}// namespace mime
