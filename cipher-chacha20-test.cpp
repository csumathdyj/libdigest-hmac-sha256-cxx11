#include <string>
#include <cstdint>
#include <array>
#include <algorithm>
#include "cipher-chacha20.hpp"
#include "mime-base16.hpp"
#include "taptests.hpp"

std::string
decode_hex (std::string const& hex)
{
    std::string octets;
    mime::decode_hex (hex, octets);
    return std::move (octets);    
}

std::array<std::uint8_t,32>
decode_key (std::string const& key_hex)
{
    std::string key_octets = decode_hex (key_hex);
    std::array<std::uint8_t,32> key;
    std::copy (key_octets.cbegin (), key_octets.cend (), key.begin ());
    return std::move (key);
}

void
test_chacha20_encrypt (test::simple& ts)
{
    // 2.4.2.  Example and Test Vector for the ChaCha20 Cipher
    std::string key_hex (
        "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:"
        "14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");
    std::string nonce_hex ("00:00:00:00:00:00:00:4a:00:00:00:00");
    std::string plain_text_hex (
        "4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c"
        "65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73"
        "73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63"
        "6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f"
        "6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20"
        "74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73"
        "63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69"
        "74 2e");
    std::string expected_cipher_text_hex (
        "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81"
        "e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b"
        "f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57"
        "16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8"
        "07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e"
        "52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36"
        "5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42"
        "87 4d");
    std::array<std::uint8_t,32> const key = decode_key (key_hex);
    std::string const nonce = decode_hex (nonce_hex);
    std::string const plain_text = decode_hex (plain_text_hex);
    std::string const expected_cipher_text = decode_hex (expected_cipher_text_hex);

    cipher::CHACHA20 chacha20;
    chacha20.set_key256 (key);
    chacha20.set_counter (1U);
    chacha20.set_nonce (nonce);
    chacha20.encrypt ();
    std::string got_cipher_text = chacha20.update (plain_text);
    ts.ok (expected_cipher_text == got_cipher_text, "2.4.2 test vector for chacha20");
}

void
test_chacha20_poly1305_key_gen (test::simple& ts)
{
    // 2.6.2.  Poly1305 Key Generation Test Vector
    std::string key_hex (
        "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f");
    std::string nonce_hex ("00 00 00 00 00 01 02 03 04 05 06 07");
    std::string expected_otk_hex (
        "8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71"
        "a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46");
    std::array<std::uint8_t,32> const key = decode_key (key_hex);
    std::string const nonce = decode_hex (nonce_hex);
    std::array<std::uint8_t,32> expected_otk = decode_key (expected_otk_hex);

    cipher::CHACHA20 chacha20;
    chacha20.set_key256 (key);
    chacha20.set_nonce (nonce);

    std::array<std::uint8_t,32> got_otk;
    chacha20.poly1305_key_gen (got_otk);
    ts.ok (expected_otk == got_otk, "2.6.2 poly1305 key generation test vector");
}

void
test_chacha20_poly1305_encrypt (test::simple& ts)
{
    // 2.8.2. Example and Test Vector for AEAD_CHACHA20_POLY1305
    std::string plain_text_hex (
        "4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c"
        "65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73"
        "73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63"
        "6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f"
        "6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20"
        "74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73"
        "63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69"
        "74 2e");
    std::string authdata_hex (
        "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");
    std::string key_hex (
        "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f");
    std::string iv_hex (
        "40 41 42 43 44 45 46 47");
    std::string constant_hex (
        "07 00 00 00");

    std::string expected_cipher_text_hex (
        "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2"
        "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6"
        "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b"
        "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36"
        "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58"
        "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc"
        "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b"
        "61 16");
    std::string expected_tag_hex (
        "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91");
    std::string const plain_text = decode_hex (plain_text_hex);
    std::string const authdata = decode_hex (authdata_hex);
    std::array<std::uint8_t,32> const key = decode_key (key_hex);
    std::string const iv = decode_hex (iv_hex);
    std::string const constant = decode_hex (constant_hex);
    std::string const expected_cipher_text = decode_hex (expected_cipher_text_hex);
    std::string const expected_tag = decode_hex (expected_tag_hex);

    cipher::CHACHA20 chacha20;
    chacha20.set_key256 (key);
    chacha20.add_authdata (authdata);
    chacha20.set_nonce (constant + iv);
    chacha20.encrypt ();
    std::string const got_cipher_text = chacha20.update (plain_text);
    std::string const got_tag = chacha20.authtag ();

    ts.ok (expected_cipher_text == got_cipher_text, "2.8.2 test vector for chacha20/poly1305 cipher text");
    ts.ok (expected_tag == got_tag, "2.8.2 test vector for chacha20/poly1305 tag");
}

// RFC 7539 Appendix A. Additional Test Vectors
// A.2. ChaCha20 Encryption
void
chacha20_encryption_test_vector_1 (test::simple& ts)
{
    std::string key_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string nonce_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00");
    uint32_t const init_block_counter = 0;
    std::string plain_text_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string expected_cipher_text_hex (
        "76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28"
        "bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7"
        "da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37"
        "6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86");
    std::array<std::uint8_t,32> const key = decode_key (key_hex);
    std::string const nonce = decode_hex (nonce_hex);
    std::string const plain_text = decode_hex (plain_text_hex);
    std::string const expected_cipher_text = decode_hex (expected_cipher_text_hex);

    cipher::CHACHA20 chacha20;
    chacha20.set_key256 (key);
    chacha20.set_counter (init_block_counter);
    chacha20.set_nonce (nonce);
    chacha20.encrypt ();
    std::string got_cipher_text = chacha20.update (plain_text);
    ts.ok (expected_cipher_text == got_cipher_text, "A.2 chacha20-1");
}

void
chacha20_encryption_test_vector_2 (test::simple& ts)
{
    std::string key_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01");
    std::string nonce_hex (
        "00 00 00 00 00 00 00 00 00 00 00 02");
    uint32_t const init_block_counter = 1U;
    std::string plain_text_hex (
        "41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74"
        "6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e"
        "64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72"
        "69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69"
        "63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72"
        "20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46"
        "20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20"
        "6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73"
        "74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69"
        "74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74"
        "20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69"
        "76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72"
        "65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74"
        "72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20"
        "73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75"
        "64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e"
        "74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69"
        "6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20"
        "77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63"
        "74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61"
        "74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e"
        "79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c"
        "20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65"
        "73 73 65 64 20 74 6f");
    std::string expected_cipher_text_hex (
        "a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70"
        "41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec"
        "2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05"
        "0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d"
        "40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e"
        "20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50"
        "42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c"
        "68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a"
        "d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66"
        "42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d"
        "c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28"
        "e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b"
        "08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f"
        "a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c"
        "cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84"
        "a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b"
        "c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0"
        "8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f"
        "58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62"
        "be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6"
        "98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85"
        "14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab"
        "7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd"
        "c4 fd 80 6c 22 f2 21");
    std::array<std::uint8_t,32> const key = decode_key (key_hex);
    std::string const nonce = decode_hex (nonce_hex);
    std::string const plain_text = decode_hex (plain_text_hex);
    std::string const expected_cipher_text = decode_hex (expected_cipher_text_hex);

    cipher::CHACHA20 chacha20;
    chacha20.set_key256 (key);
    chacha20.set_counter (init_block_counter);
    chacha20.set_nonce (nonce);
    chacha20.encrypt ();
    std::string got_cipher_text = chacha20.update (plain_text);
    ts.ok (expected_cipher_text == got_cipher_text, "A.2 chacha20-2");
}

void
chacha20_encryption_test_vector_3 (test::simple& ts)
{
    std::string key_hex (
        "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0"
        "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0");
    std::string nonce_hex (
        "00 00 00 00 00 00 00 00 00 00 00 02");
    uint32_t const init_block_counter = 42U;
    std::string plain_text_hex (
        "27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61"
        "6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f"
        "76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64"
        "20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77"
        "61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77"
        "65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65"
        "73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20"
        "72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e");
    std::string expected_cipher_text_hex (
        "62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df"
        "5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf"
        "16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71"
        "fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb"
        "f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6"
        "1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77"
        "04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1"
        "87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1");
    std::array<std::uint8_t,32> const key = decode_key (key_hex);
    std::string const nonce = decode_hex (nonce_hex);
    std::string const plain_text = decode_hex (plain_text_hex);
    std::string const expected_cipher_text = decode_hex (expected_cipher_text_hex);

    cipher::CHACHA20 chacha20;
    chacha20.set_key256 (key);
    chacha20.set_counter (init_block_counter);
    chacha20.set_nonce (nonce);
    chacha20.encrypt ();
    std::string got_cipher_text = chacha20.update (plain_text);
    ts.ok (expected_cipher_text == got_cipher_text, "A.2 chacha20-3");
}

// A.4 poly1305 key generation using chacha20
void
test_key_gen_test_vector_1 (test::simple& ts)
{
    std::string key_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string nonce_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00");
    std::string expected_otk_hex (
        "76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28"
        "bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7");
    std::array<std::uint8_t,32> const key = decode_key (key_hex);
    std::string const nonce = decode_hex (nonce_hex);
    std::array<std::uint8_t,32> expected_otk = decode_key (expected_otk_hex);

    cipher::CHACHA20 chacha20;
    chacha20.set_key256 (key);
    chacha20.set_nonce (nonce);

    std::array<std::uint8_t,32> got_otk;
    chacha20.poly1305_key_gen (got_otk);
    ts.ok (expected_otk == got_otk, "A.4 key-gen-1");
}

void
test_key_gen_test_vector_2 (test::simple& ts)
{
    std::string key_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01");
    std::string nonce_hex (
        "00 00 00 00 00 00 00 00 00 00 00 02");
    std::string expected_otk_hex (
        "ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76"
        "06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39");
    std::array<std::uint8_t,32> const key = decode_key (key_hex);
    std::string const nonce = decode_hex (nonce_hex);
    std::array<std::uint8_t,32> expected_otk = decode_key (expected_otk_hex);

    cipher::CHACHA20 chacha20;
    chacha20.set_key256 (key);
    chacha20.set_nonce (nonce);

    std::array<std::uint8_t,32> got_otk;
    chacha20.poly1305_key_gen (got_otk);
    ts.ok (expected_otk == got_otk, "A.4 key-gen-2");
}

void
test_key_gen_test_vector_3 (test::simple& ts)
{
    std::string key_hex (
        "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0"
        "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0");
    std::string nonce_hex (
        "00 00 00 00 00 00 00 00 00 00 00 02");
    std::string expected_otk_hex (
        "96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b"
        "13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae");
    std::array<std::uint8_t,32> const key = decode_key (key_hex);
    std::string const nonce = decode_hex (nonce_hex);
    std::array<std::uint8_t,32> expected_otk = decode_key (expected_otk_hex);

    cipher::CHACHA20 chacha20;
    chacha20.set_key256 (key);
    chacha20.set_nonce (nonce);

    std::array<std::uint8_t,32> got_otk;
    chacha20.poly1305_key_gen (got_otk);
    ts.ok (expected_otk == got_otk, "A.4 key-gen-3");
}

// A.5 chacha20-poly1305 AEAD decryption
void
test_chacha20_poly1305_decrypt (test::simple& ts)
{
    std::string key_hex (
        "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0"
        "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0");
    std::string cipher_text_hex (
        "64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd"
        "5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2"
        "4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0"
        "bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf"
        "33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81"
        "14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55"
        "97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38"
        "36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4"
        "b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9"
        "90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e"
        "af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a"
        "0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a"
        "0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e"
        "ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10"
        "49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30"
        "30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29"
        "a6 ad 5c b4 02 2b 02 70 9b");
    std::string nonce_hex (
        "00 00 00 00 01 02 03 04 05 06 07 08");
    std::string authdata_hex (
        "f3 33 88 86 00 00 00 00 00 00 4e 91");
    std::string tag_hex (
        "ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38");
    std::string expected_plain_text_hex (
        "49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20"
        "61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65"
        "6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20"
        "6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d"
        "6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65"
        "20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63"
        "65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64"
        "20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65"
        "6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e"
        "20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72"
        "69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65"
        "72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72"
        "65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61"
        "6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65"
        "6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20"
        "2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67"
        "72 65 73 73 2e 2f e2 80 9d");
    std::array<std::uint8_t,32> const key = decode_key (key_hex);
    std::string const cipher_text = decode_hex (cipher_text_hex);
    std::string const nonce = decode_hex (nonce_hex);
    std::string const authdata = decode_hex (authdata_hex);
    std::string const tag = decode_hex (tag_hex);
    std::string const expected_plain_text = decode_hex (expected_plain_text_hex);

    cipher::CHACHA20 chacha20;
    chacha20.set_key256 (key);
    chacha20.add_authdata (authdata);
    chacha20.set_nonce (nonce);
    chacha20.set_authtag (tag);
    chacha20.decrypt ();
    std::string const got_plain_text = chacha20.update (cipher_text);

    ts.ok (expected_plain_text == got_plain_text, "A.5 chacha20-poly1305 decrypt");
    ts.ok (chacha20.good (), "A.5 chacha20-poly1305 decrypt tag good");
}

int
main ()
{
    test::simple ts;

    test_chacha20_encrypt (ts);
    test_chacha20_poly1305_key_gen (ts);
    test_chacha20_poly1305_encrypt (ts);

    chacha20_encryption_test_vector_1 (ts);
    chacha20_encryption_test_vector_2 (ts);
    chacha20_encryption_test_vector_3 (ts);

    test_key_gen_test_vector_1 (ts);
    test_key_gen_test_vector_2 (ts);
    test_key_gen_test_vector_3 (ts);

    test_chacha20_poly1305_decrypt (ts);

    return ts.done_testing ();
}
