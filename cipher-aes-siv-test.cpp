#include <cstdint>
#include <string>
#include <array>
#include <algorithm>
#include <utility>
#include "cipher-aes-siv.hpp"
#include "mime-base16.hpp"
#include "taptests.hpp"

std::string
decode_hex (std::string const& s)
{
    std::string t;
    mime::decode_hex (s, t);
    return std::move (t);
}

std::array<std::uint8_t,32>
decode_key256 (std::string const& s)
{
    std::array<std::uint8_t,32> key;
    std::string t (decode_hex (s));
    std::copy (t.begin (), t.end (), key.begin ());
    return std::move (key);
}

//RFC 5297 Synthetic Initialization Vector (SIV) Authenticated Encryption
//         Using the Advanced Encryption Standard (AES)

//Appendix A. Test Vectors

//A.1. Deterministic Authenticated Encryption Example
void
test_a1_encrypt (test::simple& ts)
{
    std::array<std::uint8_t,32> input_key = decode_key256 (
        "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0"
        "f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff");
    std::string const input_authdata = decode_hex (
        "10111213 14151617 18191a1b 1c1d1e1f"
        "20212223 24252627");
    std::string const input_plaintext = decode_hex (
        "11223344 55667788 99aabbcc ddee");
    std::string const expected_ciphertext = decode_hex (
        "40c02b96 90c4dc04 daef7f6a fe5c");
    std::string const expected_authtag = decode_hex (
        "85632d07 c6e8f37f 950acd32 0a2ecc93");

    cipher::AES_SIV aes_siv;
    aes_siv.set_key256 (input_key);
    aes_siv.add_authdata (input_authdata);
    aes_siv.add (input_plaintext);

    aes_siv.encrypt ();
    std::string got_ciphertext = aes_siv.update (input_plaintext);
    std::string got_authtag = aes_siv.authtag ();

    ts.ok (expected_ciphertext == got_ciphertext, "deterministic encrypt ciphertext");
    ts.ok (expected_authtag == got_authtag, "deterministic encrypt authtag");
}

void
test_a1_decrypt (test::simple& ts)
{
    std::array<std::uint8_t,32> input_key = decode_key256 (
        "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0"
        "f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff");
    std::string const input_authtag = decode_hex (
        "85632d07 c6e8f37f 950acd32 0a2ecc93");
    std::string const input_authdata = decode_hex (
        "10111213 14151617 18191a1b 1c1d1e1f"
        "20212223 24252627");
    std::string const input_ciphertext = decode_hex (
        "40c02b96 90c4dc04 daef7f6a fe5c");
    std::string const expected_plaintext = decode_hex (
        "11223344 55667788 99aabbcc ddee");

    cipher::AES_SIV aes_siv;
    aes_siv.set_key256 (input_key);
    aes_siv.add_authdata (input_authdata);
    aes_siv.set_authtag (input_authtag);

    aes_siv.decrypt ();
    std::string got_plaintext = aes_siv.update (input_ciphertext);

    ts.ok (aes_siv.good (), "deterministic decrypt good");
    ts.ok (expected_plaintext == got_plaintext, "deterministic decrypt plaintext");
}

//A.2. Nonce-Based Authenticated Encryption Example
void
test_a2_encrypt (test::simple& ts)
{
    std::array<std::uint8_t,32> input_key = decode_key256 (
        "7f7e7d7c 7b7a7978 77767574 73727170"
        "40414243 44454647 48494a4b 4c4d4e4f");
    std::string const input_authdata1 = decode_hex (
        "00112233 44556677 8899aabb ccddeeff"
        "deaddada deaddada ffeeddcc bbaa9988"
        "77665544 33221100");
    std::string const input_authdata2 = decode_hex (
        "10203040 50607080 90a0");
    std::string const input_nonce = decode_hex (
        "09f91102 9d74e35b d84156c5 635688c0");
    std::string const input_plaintext = decode_hex (
        "74686973 20697320 736f6d65 20706c61"
        "696e7465 78742074 6f20656e 63727970"
        "74207573 696e6720 5349562d 414553");
    std::string const expected_authtag = decode_hex (
        "7bdb6e3b 432667eb 06f4d14b ff2fbd0f");
    std::string const expected_ciphertext = decode_hex (
        "cb900f2f ddbe4043 26601965 c889bf17"
        "dba77ceb 094fa663 b7a3f748 ba8af829"
        "ea64ad54 4a272e9c 485b62a3 fd5c0d");

    cipher::AES_SIV aes_siv;
    aes_siv.set_key256 (input_key);
    aes_siv.add_authdata (input_authdata1);
    aes_siv.add_authdata (input_authdata2);
    aes_siv.set_nonce (input_nonce);
    aes_siv.add (input_plaintext);

    aes_siv.encrypt ();
    std::string got_ciphertext = aes_siv.update (input_plaintext);
    std::string got_authtag = aes_siv.authtag ();

    ts.ok (expected_ciphertext == got_ciphertext, "nonce-based encrypt ciphertext");
    ts.ok (expected_authtag == got_authtag, "nonce-based encrypt authtag");
}

void
test_a2_decrypt (test::simple& ts)
{
    std::array<std::uint8_t,32> input_key = decode_key256 (
        "7f7e7d7c 7b7a7978 77767574 73727170"
        "40414243 44454647 48494a4b 4c4d4e4f");
    std::string const input_authtag = decode_hex (
        "7bdb6e3b 432667eb 06f4d14b ff2fbd0f");
    std::string const input_authdata1 = decode_hex (
        "00112233 44556677 8899aabb ccddeeff"
        "deaddada deaddada ffeeddcc bbaa9988"
        "77665544 33221100");
    std::string const input_authdata2 = decode_hex (
        "10203040 50607080 90a0");
    std::string const input_nonce = decode_hex (
        "09f91102 9d74e35b d84156c5 635688c0");
    std::string const input_ciphertext = decode_hex (
        "cb900f2f ddbe4043 26601965 c889bf17"
        "dba77ceb 094fa663 b7a3f748 ba8af829"
        "ea64ad54 4a272e9c 485b62a3 fd5c0d");
    std::string const expected_plaintext = decode_hex (
        "74686973 20697320 736f6d65 20706c61"
        "696e7465 78742074 6f20656e 63727970"
        "74207573 696e6720 5349562d 414553");

    cipher::AES_SIV aes_siv;
    aes_siv.set_key256 (input_key);
    aes_siv.add_authdata (input_authdata1);
    aes_siv.add_authdata (input_authdata2);
    aes_siv.set_nonce (input_nonce);
    aes_siv.set_authtag (input_authtag);

    aes_siv.decrypt ();
    std::string got_plaintext = aes_siv.update (input_ciphertext);

    ts.ok (aes_siv.good (), "nonce-based decrypt good");
    ts.ok (expected_plaintext == got_plaintext, "nonce-based decrypt plaintext");
}

int
main (int argc, char* argv[])
{
    test::simple ts;

    test_a1_encrypt (ts);
    test_a1_decrypt (ts);
    test_a2_encrypt (ts);
    test_a2_decrypt (ts);

    return ts.done_testing ();
}
