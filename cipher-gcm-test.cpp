#include <cstdint>
#include <string>
#include <array>
#include <algorithm>
#include "cipher-aes.hpp"
#include "cipher-gcm.hpp"
#include "mime-base16.hpp"
#include "taptests.hpp"

const int NBLOCK = 6;

// D. McGrew, J. Viega , ``The Galois/Counter Mode of Operation (GCM)'', NIST (2005)
// Appendix B AES Test Vectors
// for 128 bits key

struct spec_type {
    std::string key, plain, nonce, authdata, secret, authtag;
} spec[NBLOCK] = {
// Test Case 1
    {"00000000000000000000000000000000",

     "",

     "000000000000000000000000",

     "",

     "",

     "58e2fccefa7e3061367f1d57a4e7455a"},

// Test Case 2
    {"00000000000000000000000000000000",

     "00000000000000000000000000000000",

     "000000000000000000000000",

     "",

     "0388dace60b6a392f328c2b971b2fe78",

     "ab6e47d42cec13bdf53a67b21257bddf"},

// Test Case 3
    {"feffe9928665731c6d6a8f9467308308",

     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",

     "cafebabefacedbaddecaf888",
     "",

     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",

     "4d5c2af327cd64a62cf35abd2ba6fab4"},

// Test Case 4
    {"feffe9928665731c6d6a8f9467308308",

     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",

     "cafebabefacedbaddecaf888",

     "feedfacedeadbeeffeedfacedeadbeefabaddad2",

     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",

     "5bc94fbc3221a5db94fae95ae7121a47"},

// Test Case 5
    {"feffe9928665731c6d6a8f9467308308",

     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",

     "cafebabefacedbad",

     "feedfacedeadbeeffeedfacedeadbeefabaddad2",

     "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423"
     "73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",

     "3612d2e79e3b0785561be14aaca2fccb"},

// Test Case 6
    {"feffe9928665731c6d6a8f9467308308",

     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",

     "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
     "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",

     "feedfacedeadbeeffeedfacedeadbeefabaddad2",

     "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7"
     "01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",

     "619cc5aefffe0bfa462af43c1699d050"},
};

int
main (int argc, char* argv[])
{
    test::simple ts (NBLOCK * 2);
    for (int i = 0; i < NBLOCK; ++i) {
        std::string keystr;
        std::string plain;
        std::string nonce;
        std::string authdata;
        std::string secret;
        std::string authtag;

        std::string got_secret;
        std::string got_authtag;

        mime::decode_hex (spec[i].key, keystr);
        mime::decode_hex (spec[i].plain, plain);
        mime::decode_hex (spec[i].nonce, nonce);
        mime::decode_hex (spec[i].authdata, authdata);
        mime::decode_hex (spec[i].secret, secret);
        mime::decode_hex (spec[i].authtag, authtag);

        std::array<std::uint8_t,16> key;
        std::copy (keystr.begin (), keystr.end (), key.begin ());

        cipher::gcm_type<cipher::aes_type> gcm;
        gcm.set_key128 (key);
        gcm.set_nonce (nonce);
        gcm.set_authdata (authdata);

        gcm.encrypt (plain, got_secret);
        gcm.get_authtag (got_authtag);

        ts.ok (got_secret == secret, "secret");
        ts.ok (got_authtag == authtag, "tag");
    }
    return ts.done_testing ();
}
