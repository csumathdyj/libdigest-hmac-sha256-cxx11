#ifndef MIME_BASE64_HPP
#define MIME_BASE64_HPP

#include <string>

namespace mime {

// RFC 4648 <http://tools.ietf.org/html/rfc4648>

std::string encode_base64 (std::string const& in);
std::string encode_base64 (std::string const& in, std::string const& endline);
std::string encode_base64url (std::string const& in);
std::string encode_base64crypt (std::string const& in);
bool decode_base64 (std::string const& str64, std::string& octets);
bool decode_base64url (std::string const& str64, std::string& octets);
bool decode_base64crypt (std::string const& str64, std::string& octets);

std::string encode_base64basic (std::string const& in, std::string const& b64,
    int const padding, std::string const& endline, int const width);
bool decode_base64basic (std::string const& str64, std::string& octets,
    int const *c64);

}// namespace mime

#endif
