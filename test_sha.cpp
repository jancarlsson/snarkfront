#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <unistd.h>
#include "snarkfront.hpp"

using namespace snarkfront;
using namespace std;

void printUsage(const char* exeName) {
    cout << "usage: " << exeName
         << " -p BN128|Edwards -b 1|224|256|384|512|512_224|512_256 [-r]" << endl
         << endl
         << "text from standard input:" << endl
         << "echo \"abc\" | " << exeName
         << " -p BN128|Edwards -b 1|224|256|384|512|512_224|512_256" << endl
         << endl
         << "random data:" << endl
         << exeName
         << " -p BN128|Edwards -b 1|224|256|384|512|512_224|512_256 -r" << endl;

    exit(EXIT_FAILURE);
}

template <typename ZK_SHA, typename EVAL_SHA>
bool runTest(const bool stdInput)
{
    DataBufferStream buf;

    if (stdInput) {
        // fill message block(s) from standard input
        cin >> buf;

        ZK_SHA::padMessage(buf);

    } else {
        // fill entire message block with random data
        random_device rd;
        const size_t M = sizeof(typename EVAL_SHA::WordType) / sizeof(uint32_t);
        for (size_t i = 0; i < 16 * M; ++i)
            buf->push32(rd());

        // no padding is not SHA-2 standard (compression function only)
    }

    // print buffer
    HexDumper dump(cout);
    dump.print(buf);

    // compute message digest (adds padding if necessary)
    const auto zk_digest = digest(ZK_SHA(), buf);
    const auto eval_digest = digest(EVAL_SHA(), buf);

    assert(zk_digest.size() == eval_digest.size());

    DataBuffer<PrintHex> hexpr(cout, false);

    // compare message digest values
    bool ok = true;
    for (size_t i = 0; i < zk_digest.size(); ++i) {
        if (zk_digest[i]->value() != eval_digest[i]) {
            ok = false;
            cout << "digest[" << i << "] error zk: ";
            hexpr.push(zk_digest[i]->value());
            cout << " test: ";
            hexpr.push(eval_digest[i]);
            cout << endl;
        }
    }

    // message digest proof constraint
    assert_true(zk_digest == eval_digest);

    cout << "digest " << asciiHex(eval_digest, true) << endl;

    return ok;
}

template <typename PAIRING>
bool runTest(const string& shaBits, const bool stdInput)
{
    reset<PAIRING>();

    bool valueOK = false;
    typedef typename PAIRING::Fr FR;

    if ("1" == shaBits) {
        valueOK = runTest<zk::SHA1<FR>, eval::SHA1>(stdInput);
    } else if ("224" == shaBits) {
        valueOK = runTest<zk::SHA224<FR>, eval::SHA224>(stdInput);
    } else if ("256" == shaBits) {
        valueOK = runTest<zk::SHA256<FR>, eval::SHA256>(stdInput);
    } else if ("384" == shaBits) {
        valueOK = runTest<zk::SHA384<FR>, eval::SHA384>(stdInput);
    } else if ("512" == shaBits) {
        valueOK = runTest<zk::SHA512<FR>, eval::SHA512>(stdInput);
    } else if ("512_224" == shaBits) {
        valueOK = runTest<zk::SHA512_224<FR>, eval::SHA512_224>(stdInput);
    } else if ("512_256" == shaBits) {
        valueOK = runTest<zk::SHA512_256<FR>, eval::SHA512_256>(stdInput);
    }

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
    // command line switches
    string pairing, shaBits;
    bool stdInput = true;
    int opt;
    while (-1 != (opt = getopt(argc, argv, "p:b:r"))) {
        switch (opt) {
        case ('p') :
            pairing = optarg;
            break;
        case ('b') :
            shaBits = optarg;
            break;
        case ('r') :
            stdInput = false; // use random data
            break;
        }
    }

    bool result;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        result = runTest<BN128_PAIRING>(shaBits, stdInput);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        result = runTest<EDWARDS_PAIRING>(shaBits, stdInput);

    } else {
        // no elliptic curve specified
        printUsage(argv[0]);
    }

    cout << "test " << (result ? "passed" : "failed") << endl;

    exit(EXIT_SUCCESS);
}
