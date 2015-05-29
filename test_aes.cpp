#include <climits>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "snarkfront.hpp"

using namespace snarkfront;
using namespace std;

void printUsage(const char* exeName) {
    const string
        AES = " -b 128|192|256",
        KEY = " -k key_in_hex",
        MODE = " -e|-d",
        ENC = " -e",
        DEC = " -d",
        INPUT = " -i hex_text",
        PAIR = " -p BN128|Edwards";

    cout << "encrypt: " << exeName << PAIR << AES << KEY << ENC << INPUT << endl
         << "decrypt: " << exeName << PAIR << AES << KEY << DEC << INPUT << endl;

    exit(EXIT_FAILURE);
}

template <typename FR>
bool runTest(const bool encMode,
             const vector<uint8_t>& keyOctets,
             const vector<uint8_t>& inOctets)
{
    typename zk::AES<FR>::BlockType zkOut;
    typename eval::AES::BlockType evalOut;

    const auto keySize = keyOctets.size() * CHAR_BIT;
    if (128 == keySize) {
        // AES-128
        zkOut = cipher(zk::AES128<FR>(), !encMode, inOctets, keyOctets);
        evalOut = cipher(eval::AES128(), !encMode, inOctets, keyOctets);

    } else if (192 == keySize) {
        // AES-192
        zkOut = cipher(zk::AES192<FR>(), !encMode, inOctets, keyOctets);
        evalOut = cipher(eval::AES192(), !encMode, inOctets, keyOctets);

    } else if (256 == keySize) {
        // AES-256
        zkOut = cipher(zk::AES256<FR>(), !encMode, inOctets, keyOctets);
        evalOut = cipher(eval::AES256(), !encMode, inOctets, keyOctets);
    }

    assert_true(zkOut == evalOut);

    DataBuffer<PrintHex> hexpr(cout, false);
    bool ok = true;

    // compare output blocks
    for (size_t i = 0; i < zkOut.size(); ++i) {
        if (zkOut[i]->value() != evalOut[i]) {
            ok = false;
            cout << "output[" << i << "] error zk: ";
            hexpr.push(zkOut[i]->value());
            cout << " eval: ";
            hexpr.push(evalOut[i]);
            cout << endl;
        }
    }

    if (ok) cout << "output: " << asciiHex(evalOut) << endl;

    return ok;
}

template <typename PAIRING>
bool runTest(const vector<uint8_t>& keyOctets,
             const bool encMode,
             const vector<uint8_t>& inOctets)
{
    reset<PAIRING>();

    typedef typename PAIRING::Fr FR;

    const bool valueOK = runTest<FR>(encMode, keyOctets, inOctets);

    cout << "variable count " << variable_count<PAIRING>() << endl;

    GenericProgressBar progress1(cerr), progress2(cerr, 50);

    cerr << "generate key pair";
    const auto key = keypair<PAIRING>(progress2);
    cerr << endl;

    const auto in = input<PAIRING>();

    cerr << "generate proof";
    const auto p = proof(key, progress2);
    cerr << endl;

    cerr << "verify proof ";
    const bool proofOK = verify(key, in, p, progress1);
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

    vector<uint8_t> keyOctets;
    if (!asciiHexToVector(keyText, keyOctets)) {
        cerr << "error: malformed key" << endl;
        exit(EXIT_FAILURE);
    }

    const auto keySize = keyOctets.size() * CHAR_BIT;
    if (aesBits != keySize) {
        cerr << "error: key size is " << keySize << " bits" << endl;
        exit(EXIT_FAILURE);
    }

    vector<uint8_t> inOctets;
    if (!asciiHexToVector(inText, inOctets)) {
        cerr << "error: malformed input" << endl;
        exit(EXIT_FAILURE);
    }

    const auto inSize = inOctets.size() * CHAR_BIT;
    if (128 != inSize) {
        cerr << "error: input size is " << inSize << " bits" << endl;
        exit(EXIT_FAILURE);
    }

    bool result;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        result = runTest<BN128_PAIRING>(keyOctets, encMode, inOctets);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        result = runTest<EDWARDS_PAIRING>(keyOctets, encMode, inOctets);
    }

    cout << "test " << (result ? "passed" : "failed") << endl;

    return EXIT_SUCCESS;
}
