#pragma once

#include <string>

namespace pbkdf2_sha256 {

std::string encrypt (std::string const& password);
std::string encrypt (std::string const& password, std::size_t const rounds);
std::string encrypt (std::string const& password, std::string const& salt);
std::string encrypt (std::string const& password, std::size_t const rounds, std::size_t const salt_size);
std::string encrypt (std::string const& password, std::size_t const rounds, std::string const& salt);

bool verify (std::string const& password, std::string const& pubkey);

void pbkdf2_sha256 (std::string const& secret, std::string const& salt, std::size_t const rounds, std::size_t keylen, std::string& dkout);

}//namespace pbkdf2_sha256
