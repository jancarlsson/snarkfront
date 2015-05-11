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

template <typename AES, typename KEY_BLOCK, typename SCHEDULE_BLOCK>
void runTest(const vector<uint8_t>& keyOctets,
             const vector<uint8_t>& inOctets,
             typename AES::BlockType& outBlock)
{
    typename AES::BlockType inBlock;
    KEY_BLOCK keyBlock;
    SCHEDULE_BLOCK scheduleBlock;

    DataBufferStream keyBuf(keyOctets), inBuf(inOctets);
    bless(inBlock, inBuf);
    bless(keyBlock, keyBuf);

    typename AES::KeyExpansion keyExpand;
    keyExpand(keyBlock, scheduleBlock);

    AES cipherAlgo;
    cipherAlgo(inBlock, outBlock, scheduleBlock);
}

template <typename ZK_AES, typename EVAL_AES>
bool runTest(const vector<uint8_t>& keyOctets,
             const vector<uint8_t>& inOctets)
{
    typename ZK_AES::BlockType zkOut;
    typename EVAL_AES::BlockType evalOut;

    const auto keySize = keyOctets.size() * CHAR_BIT;
    if (128 == keySize) {
        // AES-128
        runTest<ZK_AES,
                typename ZK_AES::KeyExpansion::Key128Type,
                typename ZK_AES::KeyExpansion::Schedule128Type>(
                    keyOctets,
                    inOctets,
                    zkOut);

        runTest<EVAL_AES,
                typename EVAL_AES::KeyExpansion::Key128Type,
                typename EVAL_AES::KeyExpansion::Schedule128Type>(
                    keyOctets,
                    inOctets,
                    evalOut);

    } else if (192 == keySize) {
        // AES-192
        runTest<ZK_AES,
                typename ZK_AES::KeyExpansion::Key192Type,
                typename ZK_AES::KeyExpansion::Schedule192Type>(
                    keyOctets,
                    inOctets,
                    zkOut);

        runTest<EVAL_AES,
                typename EVAL_AES::KeyExpansion::Key192Type,
                typename EVAL_AES::KeyExpansion::Schedule192Type>(
                    keyOctets,
                    inOctets,
                    evalOut);

    } else if (256 == keySize) {
        // AES-256
        runTest<ZK_AES,
                typename ZK_AES::KeyExpansion::Key256Type,
                typename ZK_AES::KeyExpansion::Schedule256Type>(
                    keyOctets,
                    inOctets,
                    zkOut);

        runTest<EVAL_AES,
                typename EVAL_AES::KeyExpansion::Key256Type,
                typename EVAL_AES::KeyExpansion::Schedule256Type>(
                    keyOctets,
                    inOctets,
                    evalOut);
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

    const bool valueOK = encMode
        ? runTest<zk::AES_Encrypt<FR>, eval::AES_Encrypt>(keyOctets, inOctets)
        : runTest<zk::AES_Decrypt<FR>, eval::AES_Decrypt>(keyOctets, inOctets);

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
