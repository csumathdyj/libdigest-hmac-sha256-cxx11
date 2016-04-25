#pragma once

#include <cstdint>
#include <array>

namespace cipher {

class AES {
public:
    enum { BLOCKSIZE = 16 };
    using BLOCK = std::array<std::uint8_t,16>;
    AES () {}
    void set_encrypt_key128 (std::array<std::uint8_t,16> const& key);
    void set_encrypt_key192 (std::array<std::uint8_t,24> const& key);
    void set_encrypt_key256 (std::array<std::uint8_t,32> const& key);
    void set_decrypt_key128 (std::array<std::uint8_t,16> const& key);
    void set_decrypt_key192 (std::array<std::uint8_t,24> const& key);
    void set_decrypt_key256 (std::array<std::uint8_t,32> const& key);
    void encrypt (BLOCK const& plain, BLOCK& secret);
    void decrypt (BLOCK const& secret, BLOCK& plain);

private:
    int nrounds;
    std::uint32_t keys[60];
    std::uint32_t ikeys[60];

    void schedule_encrypt_keys (int const nk, int const nr, std::uint32_t *rk);
    void schedule_decrypt_keys (int const nk, int const nr, std::uint32_t *rk);
};

}//namespace cipher
