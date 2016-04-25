#include <cstdint>
#include <string>
#include <array>
#include <algorithm>
#include "cipher-aes-gcm.hpp"
#include "mime-base16.hpp"
#include "taptests.hpp"

// D. McGrew, J. Viega , ``The Galois/Counter Mode of Operation (GCM)'', NIST (2005)
// Appendix B AES Test Vectors

struct spec_type {
    std::string name;
    std::string key, plaintext, authdata, nonce, ciphertext, authtag;
} spec[] = {
    {"test case 1",
     "00000000000000000000000000000000",
     "",
     "",
     "000000000000000000000000",
     "",
     "58e2fccefa7e3061367f1d57a4e7455a"},

    {"test case 2",
     "00000000000000000000000000000000",
     "00000000000000000000000000000000",
     "",
     "000000000000000000000000",
     "0388dace60b6a392f328c2b971b2fe78",
     "ab6e47d42cec13bdf53a67b21257bddf"},

    {"test case 3",
     "feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b391aafd255",
     "",
     "cafebabefacedbaddecaf888",
     "42831ec2217774244b7221b784d0d49c"
     "e3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa05"
     "1ba30b396a0aac973d58e091473f5985",
     "4d5c2af327cd64a62cf35abd2ba6fab4"},

    {"test case 4",
     "feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b39",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "cafebabefacedbaddecaf888",
     "42831ec2217774244b7221b784d0d49c"
     "e3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa05"
     "1ba30b396a0aac973d58e091",
     "5bc94fbc3221a5db94fae95ae7121a47"},

    {"test case 5",
     "feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b39",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "cafebabefacedbad",
     "61353b4c2806934a777ff51fa22a4755"
     "699b2a714fcdc6f83766e5f97b6c7423"
     "73806900e49f24b22b097544d4896b42"
     "4989b5e1ebac0f07c23f4598",
     "3612d2e79e3b0785561be14aaca2fccb"},

    {"test case 6",
     "feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b39",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "9313225df88406e555909c5aff5269aa"
     "6a7a9538534f7da1e4c303d2a318a728"
     "c3c0c95156809539fcf0e2429a6b5254"
     "16aedbf5a0de6a57a637b39b",
     "8ce24998625615b603a033aca13fb894"
     "be9112a5c3a211a8ba262a3cca7e2ca7"
     "01e4a9a4fba43c90ccdcb281d48c7c6f"
     "d62875d2aca417034c34aee5",
     "619cc5aefffe0bfa462af43c1699d050"},

    {"test case 7",
     "00000000000000000000000000000000"
     "0000000000000000",
     "",
     "",
     "000000000000000000000000",
     "",
     "cd33b28ac773f74ba00ed1f312572435"},

    {"test case 8",
     "00000000000000000000000000000000"
     "0000000000000000",
     "00000000000000000000000000000000",
     "",
     "000000000000000000000000",
     "98e7247c07f0fe411c267e4384b0f600",
     "2ff58d80033927ab8ef4d4587514f0fb"},

    {"test case 9",
     "feffe9928665731c6d6a8f9467308308"
     "feffe9928665731c",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b391aafd255",
     "",
     "cafebabefacedbaddecaf888",
     "3980ca0b3c00e841eb06fac4872a2757"
     "859e1ceaa6efd984628593b40ca1e19c"
     "7d773d00c144c525ac619d18c84a3f47"
     "18e2448b2fe324d9ccda2710acade256",
     "9924a7c8587336bfb118024db8674a14"},

    {"test case 10",
     "feffe9928665731c6d6a8f9467308308"
     "feffe9928665731c",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b39",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "cafebabefacedbaddecaf888",
     "3980ca0b3c00e841eb06fac4872a2757"
     "859e1ceaa6efd984628593b40ca1e19c"
     "7d773d00c144c525ac619d18c84a3f47"
     "18e2448b2fe324d9ccda2710",
     "2519498e80f1478f37ba55bd6d27618c"},

    {"test case 11",
     "feffe9928665731c6d6a8f9467308308"
     "feffe9928665731c",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b39",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "cafebabefacedbad",
     "0f10f599ae14a154ed24b36e25324db8"
     "c566632ef2bbb34f8347280fc4507057"
     "fddc29df9a471f75c66541d4d4dad1c9"
     "e93a19a58e8b473fa0f062f7",
     "65dcc57fcf623a24094fcca40d3533f8"},

    {"test case 12",
     "feffe9928665731c6d6a8f9467308308"
     "feffe9928665731c",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b39",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "9313225df88406e555909c5aff5269aa"
     "6a7a9538534f7da1e4c303d2a318a728"
     "c3c0c95156809539fcf0e2429a6b5254"
     "16aedbf5a0de6a57a637b39b",
     "d27e88681ce3243c4830165a8fdcf9ff"
     "1de9a1d8e6b447ef6ef7b79828666e45"
     "81e79012af34ddd9e2f037589b292db3"
     "e67c036745fa22e7e9b7373b",
     "dcf566ff291c25bbb8568fc3d376a6d9"},

    {"test case 13",
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "",
     "",
     "000000000000000000000000",
     "",
     "530f8afbc74536b9a963b4f1c4cb738b"},

    {"test case 14",
     "00000000000000000000000000000000"
     "00000000000000000000000000000000",
     "00000000000000000000000000000000",
     "",
     "000000000000000000000000",
     "cea7403d4d606b6e074ec5d3baf39d18",
     "d0d1c8a799996bf0265b98b5d48ab919"},

    {"test case 15",
     "feffe9928665731c6d6a8f9467308308"
     "feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b391aafd255",
     "",
     "cafebabefacedbaddecaf888",
     "522dc1f099567d07f47f37a32a84427d"
     "643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838"
     "c5f61e6393ba7a0abcc9f662898015ad",
     "b094dac5d93471bdec1a502270e3cc6c"},

    {"test case 16",
     "feffe9928665731c6d6a8f9467308308"
     "feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b39",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "cafebabefacedbaddecaf888",
     "522dc1f099567d07f47f37a32a84427d"
     "643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838"
     "c5f61e6393ba7a0abcc9f662",
     "76fc6ece0f4e1768cddf8853bb2d551b"},

    {"test case 17",
     "feffe9928665731c6d6a8f9467308308"
     "feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b39",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "cafebabefacedbad",
     "c3762df1ca787d32ae47c13bf19844cb"
     "af1ae14d0b976afac52ff7d79bba9de0"
     "feb582d33934a4f0954cc2363bc73f78"
     "62ac430e64abe499f47c9b1f",
     "3a337dbf46a792c45e454913fe2ea8f2"},

    {"test case 18",
     "feffe9928665731c6d6a8f9467308308"
     "feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a"
     "86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b39",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "9313225df88406e555909c5aff5269aa"
     "6a7a9538534f7da1e4c303d2a318a728"
     "c3c0c95156809539fcf0e2429a6b5254"
     "16aedbf5a0de6a57a637b39b",
     "5a8def2f0c9e53f1f75d7853659e2a20"
     "eeb2b22aafde6419a058ab4f6f746bf4"
     "0fc0c3b780f244452da3ebf1c5d82cde"
     "a2418997200ef82e44ae7e3f",
     "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"},
};

static const std::size_t NBLOCK = sizeof (spec) / sizeof (spec[0]);

std::string
decode_hex (std::string const& hex)
{
    std::string octets;
    mime::decode_hex (hex, octets);
    return std::move (octets);
}

std::array<std::uint8_t,16>
decode_key128 (std::string const& keyhex)
{
    std::string const octets = decode_hex (keyhex);
    std::array<std::uint8_t,16> key;
    std::copy (octets.cbegin (), octets.cend (), key.begin ());
    return key;
}

std::array<std::uint8_t,24>
decode_key192 (std::string const& keyhex)
{
    std::string const octets = decode_hex (keyhex);
    std::array<std::uint8_t,24> key;
    std::copy (octets.cbegin (), octets.cend (), key.begin ());
    return key;
}

std::array<std::uint8_t,32>
decode_key256 (std::string const& keyhex)
{
    std::string const octets = decode_hex (keyhex);
    std::array<std::uint8_t,32> key;
    std::copy (octets.cbegin (), octets.cend (), key.begin ());
    return key;
}

int
main (int argc, char* argv[])
{
    test::simple ts (NBLOCK * 4);

    for (int i = 0; i < NBLOCK; ++i) {
        cipher::AES_GCM gcm;
        if (spec[i].key.size () == 32) {
            gcm.set_key128 (decode_key128 (spec[i].key));
        }
        else if (spec[i].key.size () == 48) {
            gcm.set_key192 (decode_key192 (spec[i].key));
        }
        else {
            gcm.set_key256 (decode_key256 (spec[i].key));
        }
        std::string const plaintext = decode_hex (spec[i].plaintext);
        std::string const authdata = decode_hex (spec[i].authdata);
        std::string const nonce = decode_hex (spec[i].nonce);
        std::string const expected_ciphertext = decode_hex (spec[i].ciphertext);
        std::string const expected_authtag = decode_hex (spec[i].authtag);
        gcm.add_authdata (authdata);
        gcm.set_nonce (nonce);
        gcm.encrypt ();
        std::string const got_ciphertext = gcm.update (plaintext);
        std::string const got_authtag = gcm.authtag ();

        ts.ok (got_ciphertext == expected_ciphertext, spec[i].name + " cipher text");
        ts.ok (got_authtag == expected_authtag, spec[i].name + " encrypt authtag");
    }

    for (int i = 0; i < NBLOCK; ++i) {
        cipher::AES_GCM gcm;
        if (spec[i].key.size () == 32) {
            gcm.set_key128 (decode_key128 (spec[i].key));
        }
        else if (spec[i].key.size () == 48) {
            gcm.set_key192 (decode_key192 (spec[i].key));
        }
        else {
            gcm.set_key256 (decode_key256 (spec[i].key));
        }
        std::string const expected_plaintext = decode_hex (spec[i].plaintext);
        std::string const authdata = decode_hex (spec[i].authdata);
        std::string const nonce = decode_hex (spec[i].nonce);
        std::string const ciphertext = decode_hex (spec[i].ciphertext);
        std::string const authtag = decode_hex (spec[i].authtag);
        gcm.add_authdata (authdata);
        gcm.set_nonce (nonce);
        gcm.set_authtag (authtag);
        gcm.decrypt ();
        std::string const got_plaintext = gcm.update (ciphertext);

        ts.ok (got_plaintext == expected_plaintext, spec[i].name + " plain text");
        ts.ok (gcm.good (), spec[i].name + " decrypt good");
    }

    return ts.done_testing ();
}
