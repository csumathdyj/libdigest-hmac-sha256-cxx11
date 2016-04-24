#include <cstdint>
#include <string>
#include <array>
#include <algorithm>
#include "digest-ghash.hpp"
#include "mime-base16.hpp"
#include "taptests.hpp"

// D. A. McGrew, J. Viega, ``The Galois/Counter Mode of Operation (GCM)''
// Appendix B AES Test Vectors

struct spec_type {
    std::string hashkey, authdata, ciphertext, ghashsum;
} spec[] = {
    {"66e94bd4ef8a2c3b884cfa59ca342b2e",
     "",
     "",
     "00000000000000000000000000000000"},

    {"66e94bd4ef8a2c3b884cfa59ca342b2e",
     "",
     "0388dace60b6a392f328c2b971b2fe78",
     "f38cbb1ad69223dcc3457ae5b6b0f885"},

    {"b83b533708bf535d0aa6e52980d53b78",
     "",
     "42831ec2217774244b7221b784d0d49c"
     "e3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa05"
     "1ba30b396a0aac973d58e091473f5985",
     "7f1b32b81b820d02614f8895ac1d4eac"},

    {"b83b533708bf535d0aa6e52980d53b78",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "42831ec2217774244b7221b784d0d49c"
     "e3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa05"
     "1ba30b396a0aac973d58e091",
     "698e57f70e6ecc7fd9463b7260a9ae5f"},

    {"b83b533708bf535d0aa6e52980d53b78",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "61353b4c2806934a777ff51fa22a4755"
     "699b2a714fcdc6f83766e5f97b6c7423"
     "73806900e49f24b22b097544d4896b42"
     "4989b5e1ebac0f07c23f4598",
     "df586bb4c249b92cb6922877e444d37b"},

    {"b83b533708bf535d0aa6e52980d53b78",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "8ce24998625615b603a033aca13fb894"
     "be9112a5c3a211a8ba262a3cca7e2ca7"
     "01e4a9a4fba43c90ccdcb281d48c7c6f"
     "d62875d2aca417034c34aee5",
     "1c5afe9760d3932f3c9a878aac3dc3de"},

    {"aae06992acbf52a3e8f4a96ec9300bd7",
     "",
     "",
     "00000000000000000000000000000000"},

    {"aae06992acbf52a3e8f4a96ec9300bd7",
     "",
     "98e7247c07f0fe411c267e4384b0f600",
     "e2c63f0ac44ad0e02efa05ab6743d4ce"},

    {"466923ec9ae682214f2c082badb39249",
     "",
     "3980ca0b3c00e841eb06fac4872a2757"
     "859e1ceaa6efd984628593b40ca1e19c"
     "7d773d00c144c525ac619d18c84a3f47"
     "18e2448b2fe324d9ccda2710acade256",
     "51110d40f6c8fff0eb1ae33445a889f0"},

    {"466923ec9ae682214f2c082badb39249",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "3980ca0b3c00e841eb06fac4872a2757"
     "859e1ceaa6efd984628593b40ca1e19c"
     "7d773d00c144c525ac619d18c84a3f47"
     "18e2448b2fe324d9ccda2710",
     "ed2ce3062e4a8ec06db8b4c490e8a268"},

    {"466923ec9ae682214f2c082badb39249",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "0f10f599ae14a154ed24b36e25324db8"
     "c566632ef2bbb34f8347280fc4507057"
     "fddc29df9a471f75c66541d4d4dad1c9"
     "e93a19a58e8b473fa0f062f7",
     "1e6a133806607858ee80eaf237064089"},

    {"466923ec9ae682214f2c082badb39249",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "d27e88681ce3243c4830165a8fdcf9ff"
     "1de9a1d8e6b447ef6ef7b79828666e45"
     "81e79012af34ddd9e2f037589b292db3"
     "e67c036745fa22e7e9b7373b",
     "82567fb0b4cc371801eadec005968e94"},

    {"dc95c078a2408989ad48a21492842087",
     "",
     "",
     "00000000000000000000000000000000"},

    {"dc95c078a2408989ad48a21492842087",
     "",
     "cea7403d4d606b6e074ec5d3baf39d18",
     "83de425c5edc5d498f382c441041ca92"},

    {"acbef20579b4b8ebce889bac8732dad7",
     "",
     "522dc1f099567d07f47f37a32a84427d"
     "643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838"
     "c5f61e6393ba7a0abcc9f662898015ad",
     "4db870d37cb75fcb46097c36230d1612"},

    {"acbef20579b4b8ebce889bac8732dad7",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "522dc1f099567d07f47f37a32a84427d"
     "643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838"
     "c5f61e6393ba7a0abcc9f662",
     "8bd0c4d8aacd391e67cca447e8c38f65"},

    {"acbef20579b4b8ebce889bac8732dad7",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "c3762df1ca787d32ae47c13bf19844cb"
     "af1ae14d0b976afac52ff7d79bba9de0"
     "feb582d33934a4f0954cc2363bc73f78"
     "62ac430e64abe499f47c9b1f",
     "75a34288b8c68f811c52b2e9a2f97f63"},

    {"acbef20579b4b8ebce889bac8732dad7",
     "feedfacedeadbeeffeedfacedeadbeef"
     "abaddad2",
     "5a8def2f0c9e53f1f75d7853659e2a20"
     "eeb2b22aafde6419a058ab4f6f746bf4"
     "0fc0c3b780f244452da3ebf1c5d82cde"
     "a2418997200ef82e44ae7e3f",
     "d5ffcf6fc5ac4d69722187421a7f170b"},
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
decode_key (std::string const& keyhex)
{
    std::string const octets = decode_hex (keyhex);
    std::array<std::uint8_t,16> key;
    std::copy (octets.cbegin (), octets.cend (), key.begin ());
    return key;
}

int
main (int argc, char* argv[])
{
    test::simple ts (NBLOCK);
    for (int i = 0; i < NBLOCK; ++i) {
        std::array<std::uint8_t,16> const hashkey = decode_key (spec[i].hashkey);
        std::string const authdata = decode_hex (spec[i].authdata);
        std::string const ciphertext = decode_hex (spec[i].ciphertext);
        std::string const expected_ghash = decode_hex (spec[i].ghashsum);

        digest::GHASH ghash;
        ghash.set_key128 (hashkey);
        ghash.set_authdata (authdata);
        ghash.add (ciphertext);

        ts.ok (ghash.digest () == expected_ghash, "ghash " + std::to_string (i + 1));
    }
    return ts.done_testing ();
}
