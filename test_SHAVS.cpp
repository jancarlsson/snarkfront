#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>
#include "FoundationDSL.hpp"
#include "GenericProgressBar.hpp"
#include "HexUtil.hpp"
#include "MainEC.hpp"
#include "SHA_1.hpp"
#include "SHA_224.hpp"
#include "SHA_256.hpp"
#include "SHA_384.hpp"
#include "SHA_512.hpp"

using namespace snarkfront;
using namespace std;

void printUsage(const char* exeName) {
    cout << "usage: cat NIST_SHAVS_byte_test_vector_file | " << exeName
         << " -c BN128|Edwards -b 1|224|256|384|512 [-i Len|COUNT] [-p]" << endl
         << endl
         << "example: SHA1 short messages" << endl
         << "cat SHA1ShortMsg.rsp | " << exeName << " -c BN128 -b 1" << endl
         << endl
         << "example: SHA256 long messages with proof" << endl
         << "cat SHA256LongMsg.rsp | " << exeName << " -c Edwards -b 256 -p" << endl
         << endl
         << "example: SHA512 Monte Carlo mode" << endl
         << "cat SHA512Monte.txt | " << exeName << " -c BN128 -b 512" << endl
         << endl
         << "example: SHA224 short messages, only Len = 464 test case" << endl
         << "cat SHA224ShortMsg.rsp | " << exeName << " -c Edwards -b 224 -i 464" << endl
         << endl
         << "example: SHA384 Monte Carlo mode, only COUNT = 75 test case" << endl
         << "cat SHA384Monte.txt | " << exeName << " -c BN128 -b 384 -i 75" << endl;

    exit(EXIT_FAILURE);
}

// short and long message tests
template <typename ZK_SHA, typename EVAL_SHA>
bool runHash(const string& msg, const string& MD)
{
    // convert hexadecimal message text to binary
    vector<uint8_t> v;
    if ("00" != msg && !asciiHexToVector(msg, v)) // 00 is null msg
        return false;

    // compute message digest
    const auto zk_digest = digest(ZK_SHA(), v);
    const auto eval_digest = digest(EVAL_SHA(), v);

    assert(zk_digest.size() == eval_digest.size());

    // compare message zk and eval digest values
    bool valueOK = true;
    for (size_t i = 0; i < zk_digest.size(); ++i) {
        if (zk_digest[i]->value() != eval_digest[i])
            valueOK = false;
    }

    // message digest proof constraint
    assert_true(zk_digest == eval_digest);

    // compare eval digest and SHAVS test case MD
    if (MD != asciiHex(eval_digest))
        valueOK = false;

    return valueOK;
}

// Monte Carlo tests
template <typename EVAL_SHA>
bool runMC(const string& prevMD, const string& MD)
{
    // prevMD is message digest input
    vector<typename EVAL_SHA::WordType> v0, v1, v2;
    if (!asciiHexToVector(prevMD, v2)) return false;
    v0 = v1 = v2;

    for (size_t i = 3; i < 1003; ++i) {
        // compute message digest
        // message is concatenation of last three digests
        const auto eval_digest = digest(EVAL_SHA(), v0, v1, v2);

        // rotate message digests
        v0 = v1;
        v1 = v2;
        assert(eval_digest.size() == v2.size());
        for (size_t j = 0; j < v2.size(); ++j)
            v2[j] = eval_digest[j];
    }

    // compare final message digest with test case MD
    return MD == asciiHex(v2);
}

bool readAssignment(const string& line, string& lhs, string& rhs)
{
    stringstream ss(line);

    // left hand side
    if (!ss.eof())
        ss >> lhs;

    // should be =
    string op;
    if (!!ss && !ss.eof() && !lhs.empty())
        ss >> op;

    // right hand side
    if (!!ss && !ss.eof() && ("=" == op))
        ss >> rhs;

    // true if lhs and rhs both defined and op is =
    return !!ss && !lhs.empty() && !rhs.empty();
}

template <typename PAIRING>
void readLoop(const size_t shaBits, const size_t testCase, const bool zkProof)
{
    typedef typename PAIRING::Fr FR;

    stringstream ss;
    ss << testCase;
    const auto testCaseStr = ss.str(); // specific test case by Len/COUNT

    string line, count, seed, len, msg, MD;
    while (!cin.eof() && getline(cin, line)) {
        // skip empty lines and comments
        if (line.empty() || '#' == line[0])
            continue;

        string lhs, rhs;
        if (! readAssignment(line, lhs, rhs))
            continue;

        if ("Len" == lhs) {
            // length of message
            len = rhs;

        } else if ("Msg" == lhs) {
            // message
            msg = rhs;

        } else if ("MD" == lhs) {
            // message digest
            MD = rhs;

        } else if ("COUNT" == lhs) {
            // Monte-Carlo mode
            count = rhs;

        } else if ("Seed" == lhs) {
            // Monte-Carlo mode
            seed = rhs;

            // warning message if zero knowledge proof mode selected
            if (zkProof) {
                cout << "warning: proof generation disabled for Monte Carlo tests (too expensive)"
                     << endl;
            }
        }

        if (seed.empty()) {
            // short and long message modes
            if (!len.empty() && !msg.empty() && !MD.empty()) {
                if (-1 == testCase || testCaseStr == len) {
                    reset<PAIRING>();

                    bool result;

                    if (1 == shaBits) {
                        result = runHash<zk::SHA1<FR>, eval::SHA1>(msg, MD);
                    } else if (224 == shaBits) {
                        result = runHash<zk::SHA224<FR>, eval::SHA224>(msg, MD);
                    } else if (256 == shaBits) {
                        result = runHash<zk::SHA256<FR>, eval::SHA256>(msg, MD);
                    } else if (384 == shaBits) {
                        result = runHash<zk::SHA384<FR>, eval::SHA384>(msg, MD);
                    } else if (512 == shaBits) {
                        result = runHash<zk::SHA512<FR>, eval::SHA512>(msg, MD);
                    }

                    if (zkProof) {
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

                        if (! proofOK) result = false;
                    }

                    cout << (result ? "OK" : "FAIL") << " "
                         << len << " " << MD << endl;
                }

                len.clear();
                msg.clear();
                MD.clear();
            }

        } else {
            // Monte-Carlo mode
            if (!MD.empty()) {
                if (-1 == testCase || testCaseStr == count) {
                    bool result;

                    if (1 == shaBits) {
                        result = runMC<eval::SHA1>(seed, MD);
                    } else if (224 == shaBits) {
                        result = runMC<eval::SHA224>(seed, MD);
                    } else if (256 == shaBits) {
                        result = runMC<eval::SHA256>(seed, MD);
                    } else if (384 == shaBits) {
                        result = runMC<eval::SHA384>(seed, MD);
                    } else if (512 == shaBits) {
                        result = runMC<eval::SHA512>(seed, MD);
                    }

                    cout << (result ? "OK" : "FAIL") << " "
                         << count << " " << seed << " " << MD << endl;
                }

                seed = MD;
                MD.clear();
            }
        }
    }
}

int main(int argc, char *argv[])
{
    // command line switches
    string ellipticCurve;
    std::size_t shaBits = 0, testCase = -1;
    bool zkProof = false;
    int opt;
    while (-1 != (opt = getopt(argc, argv, "c:b:i:p"))) {
        switch (opt) {
        case ('c') :
            ellipticCurve = optarg;
            break;
        case ('b') :
            {
                stringstream ss(optarg);
                ss >> shaBits;
                if (!ss) printUsage(argv[0]);
            }
            break;
        case ('i') :
            {
                stringstream ss(optarg);
                ss >> testCase;
                if (!ss) printUsage(argv[0]);
            }
            break;
        case ('p') :
            zkProof = true;
            break;
        }
    }

    // check for valid SHA bits
    if (1 != shaBits &&
        224 != shaBits &&
        256 != shaBits &&
        384 != shaBits &&
        512 != shaBits)
        printUsage(argv[0]);

    if ("BN128" == ellipticCurve) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        readLoop<BN128_PAIRING>(shaBits, testCase, zkProof);

    } else if ("Edwards" == ellipticCurve) {
        // Edwards 80 bits
        init_Edwards();
        readLoop<EDWARDS_PAIRING>(shaBits, testCase, zkProof);

    } else {
        // no elliptic curve specified
        printUsage(argv[0]);
    }

    exit(EXIT_SUCCESS);
}
