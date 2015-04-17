#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include "snarkfront.hpp"

using namespace snarkfront;
using namespace std;

void printUsage(const char* exeName) {
    const string
        SHA = " -b 1|224|256|384|512|512_224|512_256",
        PAIR = " -p BN128|Edwards",
        R = " -r",
        DIG = " -d digest",
        EQ = " -e pattern",
        NEQ = " -n pattern",
        optPAIR = " [-p BN128|Edwards]",
        optR = " [-r]",
        optDIG = " [-d hex_digest]",
        optEQ = " [-e equal_pattern]",
        optNEQ = " [-n not_equal_pattern]";

    cout << "usage: " << exeName << SHA << optPAIR << optR << optDIG << optEQ << optNEQ << endl
         << endl
         << "text from standard input:" << endl
         << "echo \"abc\" | " << exeName << PAIR << SHA << endl
         << endl
         << "pre-image pattern and hash:" << endl
         << "echo \"abc\" | " << exeName << PAIR << SHA << DIG << EQ << NEQ << endl
         << endl
         << "hash only, skip zero knowledge proof:" << endl
         << "echo \"abc\" | " << exeName << SHA << endl
         << endl
         << "random data:" << endl
         << exeName << PAIR << SHA << R << endl;

    exit(EXIT_FAILURE);
}

template <typename ZK_SHA, typename EVAL_SHA>
bool runTest(const bool stdInput,
             const bool hashOnly,
             const string& hashDig,
             const string& eqPattern,
             const string& neqPattern)
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

    if (!hashOnly) {
        // print buffer
        HexDumper dump(cout);
        dump.print(buf);
    }

    // compute message digest (adds padding if necessary)
    typename ZK_SHA::DigType zk_digest;
    if (eqPattern.empty() && neqPattern.empty()) {
        // just hash the buffer data
        zk_digest = digest(ZK_SHA(), buf);

    } else {
        // additional constraints on pre-image
        // must expose buffer as variables
        std::size_t idx = 0;

        ZK_SHA hashAlgo;

        auto bufCopy = buf;
        while (! bufCopy.empty()) {
            typename ZK_SHA::MsgType msg;
            bless(msg, bufCopy);
            hashAlgo.msgInput(msg);

            // pre-image buffer variables as octets
            typename ZK_SHA::PreType preimg;
            bless(preimg, msg);

            PrintHex pr(cout, false);

            // constraints on pre-image, if any
            for (std::size_t i = 0; i < preimg.size(); ++i) {
                // equal
                if ((idx < eqPattern.size()) && ('?' != eqPattern[idx])) {
                    assert_true(preimg[i] == eqPattern[idx]);

                    cout << "constrain preimage[" << idx << "] == ";
                    pr.pushOctet(eqPattern[idx]);
                    cout << endl;
                }

                // not equal
                if ((idx < neqPattern.size()) && ('?' != neqPattern[idx])) {
                    assert_true(preimg[i] != neqPattern[idx]);

                    cout << "constrain preimage[" << idx << "] != ";
                    pr.pushOctet(neqPattern[idx]);
                    cout << endl;
                }

                ++idx;
            }
        }

        hashAlgo.computeHash();
        zk_digest = hashAlgo.digest();
    }

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
            cout << " eval: ";
            hexpr.push(eval_digest[i]);
            cout << endl;
        }
    }

    // message digest proof constraint
    if (hashDig.empty()) {
        // hash digest calculated by SHA template
        assert_true(zk_digest == eval_digest);

    } else {
        // hash digest specified as ASCII hex string
        vector<uint8_t> v;
        if (!asciiHexToVector(hashDig, v)) {
            ok = false;

        } else {
            // check that hash digest is correct size
            const size_t N = sizeof(typename EVAL_SHA::DigType);
            if (v.size() != N) {
                ok = false;
                cout << "error: hash digest " << hashDig
                     << " must be for " << N << " octets"
                     << endl;

            } else {
                DataBufferStream digBuf(v);

                typename ZK_SHA::DigType dig;
                bless(dig, digBuf);

                assert_true(zk_digest == dig);
            }
        }
    }

    if (!hashOnly) cout << "digest ";
    cout << asciiHex(eval_digest, !hashOnly) << endl;

    return ok;
}

template <typename PAIRING>
bool runTest(const string& shaBits,
             const bool stdInput,
             const bool hashOnly,
             const string& hashDig,
             const string& eqPattern,
             const string& neqPattern)
{
    reset<PAIRING>();

    bool valueOK = false;
    typedef typename PAIRING::Fr FR;

    if ("1" == shaBits) {
        valueOK = runTest<zk::SHA1<FR>, eval::SHA1>(stdInput, hashOnly,
                                                    hashDig, eqPattern, neqPattern);
    } else if ("224" == shaBits) {
        valueOK = runTest<zk::SHA224<FR>, eval::SHA224>(stdInput, hashOnly,
                                                        hashDig, eqPattern, neqPattern);
    } else if ("256" == shaBits) {
        valueOK = runTest<zk::SHA256<FR>, eval::SHA256>(stdInput, hashOnly,
                                                        hashDig, eqPattern, neqPattern);
    } else if ("384" == shaBits) {
        valueOK = runTest<zk::SHA384<FR>, eval::SHA384>(stdInput, hashOnly,
                                                        hashDig, eqPattern, neqPattern);
    } else if ("512" == shaBits) {
        valueOK = runTest<zk::SHA512<FR>, eval::SHA512>(stdInput, hashOnly,
                                                        hashDig, eqPattern, neqPattern);
    } else if ("512_224" == shaBits) {
        valueOK = runTest<zk::SHA512_224<FR>, eval::SHA512_224>(stdInput, hashOnly,
                                                                hashDig, eqPattern, neqPattern);
    } else if ("512_256" == shaBits) {
        valueOK = runTest<zk::SHA512_256<FR>, eval::SHA512_256>(stdInput, hashOnly,
                                                                hashDig, eqPattern, neqPattern);
    }

    // special case for hash only, skip zero knowledge proof
    if (hashOnly) return valueOK;

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
    Getopt cmdLine(argc, argv, "pbden", "", "r");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    auto pairing = cmdLine.getString('p');

    const auto
        shaBits = cmdLine.getString('b'),
        hashDig = cmdLine.getString('d'),
        eqPattern = cmdLine.getString('e'),
        neqPattern = cmdLine.getString('n');

    const auto stdInput = !cmdLine.getFlag('r');

    // special case for hash only, skip zero knowledge proof
    const bool hashOnly = pairing.empty() && validSHA2Name(shaBits) && stdInput;
    if (hashOnly) pairing = "BN128"; // elliptic curve pairing is arbitrary

    if (!validPairingName(pairing) || !validSHA2Name(shaBits))
        printUsage(argv[0]);

    bool result;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        result = runTest<BN128_PAIRING>(shaBits,
                                        stdInput,
                                        hashOnly,
                                        hashDig,
                                        eqPattern,
                                        neqPattern);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        result = runTest<EDWARDS_PAIRING>(shaBits,
                                          stdInput,
                                          hashOnly,
                                          hashDig,
                                          eqPattern,
                                          neqPattern);
    }

    if (!hashOnly) {
        cout << "test " << (result ? "passed" : "failed") << endl;
    }

    return EXIT_SUCCESS;
}
