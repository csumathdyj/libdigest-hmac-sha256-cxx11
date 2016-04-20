#pragma once

#include <string>

namespace mime {

// RFC 4648 <http://tools.ietf.org/html/rfc4648>
std::string encode_base32 (std::string const& in,
    std::string const& endline = "\n", int const width = 76);
std::string encode_base32hex (std::string const& in,
    std::string const& endline = "\n", int const width = 76);

bool decode_base32 (std::string const& str32, std::string& octets);
bool decode_base32hex (std::string const& str32, std::string& octets);

std::string encode_base32basic (std::string const& in, std::string const& b32,
    int const padding, std::string const& endline, int const width);

bool decode_base32basic (std::string const& str32, std::string& octets,
    int const *c32, bool const autopadding);

}// namespace mime
