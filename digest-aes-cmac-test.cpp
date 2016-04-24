#include <cstdint>
#include <string>
#include <array>
#include <algorithm>
#include "digest-aes-cmac.hpp"
#include "mime-base16.hpp"
#include "taptests.hpp"

// NIST SP 800-38B and RFC 4493
struct spec_type {
    std::string key, plain, tag;
} spec[] = {
    {"2b7e1516 28aed2a6 abf71588 09cf4f3c",
     "",
     "bb1d6929 e9593728 7fa37d12 9b756746"},

    {"2b7e1516 28aed2a6 abf71588 09cf4f3c",
     "6bc1bee2 2e409f96 e93d7e11 7393172a",
     "070a16b4 6b4d4144 f79bdd9d d04a287c"},

    {"2b7e1516 28aed2a6 abf71588 09cf4f3c",

     "6bc1bee2 2e409f96 e93d7e11 7393172a"
     "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
     "30c81c46 a35ce411",

     "dfa66747 de9ae630 30ca3261 1497c827"},

    {"2b7e1516 28aed2a6 abf71588 09cf4f3c",

     "6bc1bee2 2e409f96 e93d7e11 7393172a"
     "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
     "30c81c46 a35ce411 e5fbc119 1a0a52ef"
     "f69f2445 df4f9b17 ad2b417b e66c3710",

     "51f0bebf 7e3b9d92fc49741779363cfe"},

    {"8e73b0f7 da0e6452 c810f32b 809079e5"
     "62f8ead2 522c6b7b",
     "",
     "d17ddf46 adaacde5 31cac483 de7a9367"},

    {"8e73b0f7 da0e6452 c810f32b 809079e5"
     "62f8ead2 522c6b7b",

     "6bc1bee2 2e409f96 e93d7e11 7393172a",

     "9e99a7bf 31e71090 0662f65e 617c5184"},

    {"8e73b0f7 da0e6452 c810f32b 809079e5"
     "62f8ead2 522c6b7b",

     "6bc1bee2 2e409f96 e93d7e11 7393172a"
     "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
     "30c81c46 a35ce411",

     "8a1de5be 2eb31aad 089a82e6 ee908b0e"},

    {"8e73b0f7 da0e6452 c810f32b 809079e5"
     "62f8ead2 522c6b7b",

     "6bc1bee2 2e409f96 e93d7e11 7393172a"
     "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
     "30c81c46 a35ce411 e5fbc119 1a0a52ef"
     "f69f2445 df4f9b17 ad2b417b e66c3710",

     "a1d5df0e ed790f79 4d775896 59f39a11"},

    {"603deb10 15ca71be 2b73aef0 857d7781"
     "1f352c07 3b6108d7 2d9810a3 0914dff4",
     "",
     "028962f6 1b7bf89e fc6b551f 4667d983"},

    {"603deb10 15ca71be 2b73aef0 857d7781"
     "1f352c07 3b6108d7 2d9810a3 0914dff4",

     "6bc1bee2 2e409f96 e93d7e11 7393172a",

     "28a7023f 452e8f82 bd4bf28d 8c37c35c"},

    {"603deb10 15ca71be 2b73aef0 857d7781"
     "1f352c07 3b6108d7 2d9810a3 0914dff4",

     "6bc1bee2 2e409f96 e93d7e11 7393172a"
     "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
     "30c81c46 a35ce411",

     "aaf3d8f1 de5640c2 32f5b169 b9c911e6"},

    {"603deb10 15ca71be 2b73aef0 857d7781"
     "1f352c07 3b6108d7 2d9810a3 0914dff4",

     "6bc1bee2 2e409f96 e93d7e11 7393172a"
     "ae2d8a57 1e03ac9c 9eb76fac 45af8e51"
     "30c81c46 a35ce411 e5fbc119 1a0a52ef"
     "f69f2445 df4f9b17 ad2b417b e66c3710",

     "e1992190 549f6ed5 696a2c05 6c315410"},
};

static const std::size_t NBLOCK = sizeof (spec) / sizeof (spec[0]);

std::string
decode_hex (std::string const& hex)
{
    std::string octets;
    mime::decode_hex (hex, octets);
    return std::move (octets);
}

int
main (int argc, char* argv[])
{
    test::simple ts (NBLOCK);
    for (int i = 0; i < NBLOCK; ++i) {
        std::string const keystr = decode_hex (spec[i].key);
        std::string const plain = decode_hex (spec[i].plain);
        std::string const tag = decode_hex (spec[i].tag);

        std::string got_cmac;

        digest::AES_CMAC aes_cmac;
        if (keystr.size () == 16) {
            std::array<std::uint8_t,16> key;
            std::copy (keystr.begin (), keystr.end (), key.begin ());
            aes_cmac.set_key128 (key);
        }
        else if (keystr.size () == 24) {
            std::array<std::uint8_t,24> key;
            std::copy (keystr.begin (), keystr.end (), key.begin ());
            aes_cmac.set_key192 (key);
        }
        else if (keystr.size () == 32) {
            std::array<std::uint8_t,32> key;
            std::copy (keystr.begin (), keystr.end (), key.begin ());
            aes_cmac.set_key256 (key);
        }

        aes_cmac.add (plain);
        ts.ok (aes_cmac.digest () == tag, "");
    }
    return ts.done_testing ();
}
