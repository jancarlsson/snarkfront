#include <climits>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "snarkfront.hpp"

using namespace snarkfront;
using namespace cryptl;
using namespace std;

void printUsage(const char* exeName) {
    const string
        AES = " -b 128|192|256",
        KEY = " -k key_in_hex",
        ENC = " -e",
        DEC = " -d",
        INPUT = " -i hex_text",
        PAIR = " -p BN128|Edwards";

    cout << "encrypt: " << exeName << PAIR << AES << KEY << ENC << INPUT << endl
         << "decrypt: " << exeName << PAIR << AES << KEY << DEC << INPUT << endl;

    exit(EXIT_FAILURE);
}

template <typename A, typename B>
bool runTest(A dummyA,
             B dummyB,
             const vector<uint8_t>& key,
             const vector<uint8_t>& in)
{
    // A
    typename A::KeyType keyA;
    for (size_t i = 0; i < keyA.size(); ++i) keyA[i] = key[i];
    const auto& inA = in;
    const auto outA = ECB(dummyA, keyA, inA);

    // B
    typename B::KeyType keyB;
    for (size_t i = 0; i < keyB.size(); ++i) bless(keyB[i], key[i]);
    vector<typename B::VarType> inB(in.size());
    bless(inB, in);
    const auto outB = ECB(dummyB, keyB, inB);

    typename A::BlockType blockA;
    typename B::BlockType blockB;
    for (size_t i = 0; i < outA.size() / blockA.size(); ++i) {
        const size_t offset = i * blockA.size();

        for (size_t j = 0; j < blockA.size(); ++j) {
            blockA[j] = outA[j + offset];
            blockB[j] = outB[j + offset];
        }

        assert_true(blockA == blockB);
    }

    DataPusher<PrintHex<false>> hexpr(cout);
    bool ok = true;

    // compare output blocks
    for (size_t i = 0; i < outB.size(); ++i) {
        if (outB[i]->value() != outA[i]) {
            ok = false;
            cout << "output[" << i << "] error ";
            hexpr.push(outB[i]->value());
            cout << " != ";
            hexpr.push(outA[i]);
            cout << endl;
        }
    }

    if (ok) cout << "output: " << asciiHex(outA) << endl;

    return ok;
}

template <typename FR>
bool runTest(const bool encMode,
             const vector<uint8_t>& key,
             const vector<uint8_t>& in)
{
    switch (key.size() * CHAR_BIT) {
    case (128) :
        return encMode
            ? runTest(cryptl::AES128(), snarkfront::AES128<FR>(), key, in)
            : runTest(cryptl::UNAES128(), snarkfront::UNAES128<FR>(), key, in);

    case (192) :
        return encMode
            ? runTest(cryptl::AES192(), snarkfront::AES192<FR>(), key, in)
            : runTest(cryptl::UNAES192(), snarkfront::UNAES192<FR>(), key, in);

    case (256) :
        return encMode
            ? runTest(cryptl::AES256(), snarkfront::AES256<FR>(), key, in)
            : runTest(cryptl::UNAES256(), snarkfront::UNAES256<FR>(), key, in);
    }

    return false;
}

template <typename PAIRING>
bool runTest(const vector<uint8_t>& keyOctets,
             const bool encMode,
             const vector<uint8_t>& inOctets)
{
    reset<PAIRING>();

    const bool valueOK = runTest<typename PAIRING::Fr>(encMode, keyOctets, inOctets);
    cout << "variable count " << variable_count<PAIRING>() << endl;

    GenericProgressBar progress1(cerr), progress2(cerr, 50);

    cerr << "generate key pair";
    const auto key = keypair<PAIRING>(progress2);
    cerr << endl;

    const auto inp = input<PAIRING>();

    cerr << "generate proof";
    const auto prf = proof(key, progress2);
    cerr << endl;

    cerr << "verify proof ";
    const bool proofOK = verify(key, inp, prf, progress1);
    cerr << endl;

    return valueOK && proofOK;
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "pki", "b", "ed");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    const auto
        pairing = cmdLine.getString('p'),
        keyText = cmdLine.getString('k'),
        inText = cmdLine.getString('i');

    const auto aesBits = cmdLine.getNumber('b');

    const auto
        encMode = cmdLine.getFlag('e'),
        decMode = cmdLine.getFlag('d');

    if (!validPairingName(pairing) || !validAESName(aesBits) || !(encMode ^ decMode))
        printUsage(argv[0]);

    vector<uint8_t> key;
    if (!asciiHexToVector(keyText, key) || (aesBits != key.size() * CHAR_BIT)) {
        cerr << "error: malformed key " << keyText << endl;
        exit(EXIT_FAILURE);
    }

    vector<uint8_t> in;
    if (!asciiHexToVector(inText, in) || (128 != in.size() * CHAR_BIT)) {
        cerr << "error: malformed input " << inText << endl;
        exit(EXIT_FAILURE);
    }

    bool result;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        result = runTest<BN128_PAIRING>(key, encMode, in);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        result = runTest<EDWARDS_PAIRING>(key, encMode, in);
    }

    cout << "test " << (result ? "passed" : "failed") << endl;

    return EXIT_SUCCESS;
}
