#include <climits>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "snarkfront.hpp"

using namespace snarkfront;
using namespace cryptl;
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

    cout << "usage: " << exeName
         << SHA << optPAIR << optR << optDIG << optEQ << optNEQ << endl
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

template <typename A, typename B>
bool runTest(const bool stdInput,
             const bool hashOnly,
             const string& hashDig,
             const string& eqPattern,
             const string& neqPattern)
{
    stringstream preImage;
    size_t lengthBits = 0;

    // initialize pre-image message
    if (stdInput) {
        // fill message block(s) from standard input
        char c;
        while (!cin.eof() && cin.get(c)) {
            preImage.put(c);
            lengthBits += CHAR_BIT;
        }

        A::padMessage(preImage, lengthBits);

    } else {
        // fill entire message block with random data
        random_device rd;
        while (lengthBits < 16 * sizeof(typename A::WordType) * CHAR_BIT) {
            const unsigned int r = rd();
            for (size_t i = 0; i < sizeof(unsigned int); ++i) {
                preImage.put((r >> (i * CHAR_BIT)) & 0xff);
                lengthBits += CHAR_BIT;
            }
        }

        // no padding is not SHA-2 standard (compression function only)
    }

    if (!hashOnly) {
        // print pre-image message
        HexDumper dump(cout);
        stringstream ss(preImage.str());
        dump.print(ss);
    }

    // compute message digest in zero knowledge
    typename B::DigType outB;
    if (eqPattern.empty() && neqPattern.empty()) {
        // just hash the message data
        stringstream ss(preImage.str());
        outB = digest(B(), ss);

    } else {
        // additional constraints on pre-image
        // must expose buffer as variables
        B hashAlgo;
        typename B::MsgType msg;

        size_t idx = 0;
        stringstream ss(preImage.str());
        while (!ss.eof() && bless(msg, ss)) {
            hashAlgo.msgInput(msg);

            // pre-image buffer variables as octets
            typename B::PreType preimg;
            bless(preimg, msg);

            DataPusher<PrintHex<false>> pr(cout);

            // constraints on pre-image, if any
            for (std::size_t i = 0; i < preimg.size(); ++i) {
                // equal
                if ((idx < eqPattern.size()) && ('?' != eqPattern[idx])) {
                    assert_true(preimg[i] == eqPattern[idx]);

                    cout << "constrain preimage[" << idx << "] == ";
                    pr.push8(eqPattern[idx]);
                    cout << endl;
                }

                // not equal
                if ((idx < neqPattern.size()) && ('?' != neqPattern[idx])) {
                    assert_true(preimg[i] != neqPattern[idx]);

                    cout << "constrain preimage[" << idx << "] != ";
                    pr.push8(neqPattern[idx]);
                    cout << endl;
                }

                ++idx;
            }
        }

        hashAlgo.computeHash();
        outB = hashAlgo.digest();
    }

    // compute message digest value
    stringstream ss(preImage.str());
    const auto outA = digest(A(), ss);

    // digest output should always be the same size
    assert(outA.size() == outB.size());

    bool ok = true;

    // compare message digest values
    DataPusher<PrintHex<false>> hexpr(cout);
    for (size_t i = 0; i < outB.size(); ++i) {
        if (outB[i]->value() != outA[i]) {
            ok = false;
            cout << "digest[" << i << "] error ";
            hexpr.push(outB[i]->value());
            cout << " != ";
            hexpr.push(outA[i]);
            cout << endl;
        }
    }

    // message digest proof constraint
    if (hashDig.empty()) {
        // hash digest calculated by SHA template
        assert_true(outA == outB);

    } else {
        // hash digest specified as ASCII hex string
        vector<uint8_t> v;
        if (!asciiHexToVector(hashDig, v)) {
            ok = false;

        } else {
            // check that hash digest is correct size
            const size_t N = sizeof(typename A::DigType);
            if (v.size() != N) {
                ok = false;
                cout << "error: hash digest " << hashDig
                     << " must be for " << N << " octets"
                     << endl;

            } else {
                stringstream ss;
                for (const auto& c : v) ss.put(c);

                typename B::DigType dig;
                bless(dig, ss);

                assert_true(outB == dig);
            }
        }
    }

    if (!hashOnly) cout << "digest ";
    cout << asciiHex(outA, !hashOnly) << endl;

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
        valueOK = runTest<cryptl::SHA1, snarkfront::SHA1<FR>>(
            stdInput, hashOnly, hashDig, eqPattern, neqPattern);

    } else if ("224" == shaBits) {
        valueOK = runTest<cryptl::SHA224, snarkfront::SHA224<FR>>(
            stdInput, hashOnly, hashDig, eqPattern, neqPattern);

    } else if ("256" == shaBits) {
        valueOK = runTest<cryptl::SHA256, snarkfront::SHA256<FR>>(
            stdInput, hashOnly, hashDig, eqPattern, neqPattern);

    } else if ("384" == shaBits) {
        valueOK = runTest<cryptl::SHA384, snarkfront::SHA384<FR>>(
            stdInput, hashOnly, hashDig, eqPattern, neqPattern);

    } else if ("512" == shaBits) {
        valueOK = runTest<cryptl::SHA512, snarkfront::SHA512<FR>>(
            stdInput, hashOnly, hashDig, eqPattern, neqPattern);

    } else if ("512_224" == shaBits) {
        valueOK = runTest<cryptl::SHA512_224, snarkfront::SHA512_224<FR>>(
            stdInput, hashOnly, hashDig, eqPattern, neqPattern);

    } else if ("512_256" == shaBits) {
        valueOK = runTest<cryptl::SHA512_256, snarkfront::SHA512_256<FR>>(
            stdInput, hashOnly, hashDig, eqPattern, neqPattern);
    }

    // special case for hash only, skip zero knowledge proof
    if (hashOnly) return valueOK;

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
