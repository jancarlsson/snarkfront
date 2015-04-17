#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include "snarkfront.hpp"

using namespace snarkfront;
using namespace snarklib;
using namespace std;

void printUsage(const char* exeName) {
    cerr << "Usage: " << exeName << " [options] file..." << endl
         << "Options:" << endl
         << "  -e <number>       Partition G1 exponentiation table into <number> windows" << endl
         << "  -n <number>       Partition query vectors into <number> blocks" << endl
         << "  -o <file_prefix>  Place the output into <file_prefix>" << endl
         << "  -v <file>         Verify zero knowledge proof in <file>" << endl
         << endl
         << "Generate proving/verification key pair from constraint system:" << endl
         << " " << exeName << " -o keypair_prefix [-e num] [-n num] r1cs_index_file" << endl
         << endl
         << "Generate proof from key pair and witness:" << endl
         << " " << exeName << " -o proof_file keypair_prefix witness_file" << endl
         << endl
         << "Verify proof with key pair and input:" << endl
         << " " << exeName << " -v proof_file keypair_prefix input_file" << endl;

    exit(EXIT_FAILURE);
}

template <typename T>
void checkQuery(const T& obj, const string& s) {
    if (!obj) {
        cerr << s << endl;
        exit(EXIT_FAILURE);
    } else {
        cerr << endl;
    }
}

template <typename PAIRING>
void generate_key_pair(const string& r1cs,
                       const size_t numwins,
                       const size_t numblks,
                       const string& keypair_prefix)
{
    typedef typename PAIRING::Fr FR;

    // randomness
    PPZK_LagrangePoint<FR> lgrng(0);
    PPZK_BlindGreeks<FR, FR> grks(0);

    const string
        qapA = keypair_prefix + ".qapA",
        qapB = keypair_prefix + ".qapB",
        qapC = keypair_prefix + ".qapC",
        qapH = keypair_prefix + ".qapH",
        qapK = keypair_prefix + ".qapK",
        qapIC = keypair_prefix + ".qapIC";

    // QAP query ABCH
    QAP_query_ABCH<PAIRING> qap_ABCH(numblks, r1cs, lgrng);
    checkQuery(qap_ABCH, string("ERROR: constraint system index file ") + r1cs);

    // QAP query A
    cerr << "QAP query A";
    qap_ABCH.A(qapA);
    checkQuery(qap_ABCH, " ERROR");

    // QAP query B
    cerr << "QAP query B";
    qap_ABCH.B(qapB);
    checkQuery(qap_ABCH, " ERROR");

    // QAP query C
    cerr << "QAP query C";
    qap_ABCH.C(qapC);
    checkQuery(qap_ABCH, " ERROR");

    // QAP query H
    cerr << "QAP query H";
    qap_ABCH.H(qapH);
    checkQuery(qap_ABCH, " ERROR");

    // exponentiation counts
    const size_t
        g1_exp_count = qap_ABCH.g1_exp_count(qapA, qapB, qapC, qapH),
        g2_exp_count = qap_ABCH.g2_exp_count(qapB);
    cerr << "G1: " << g1_exp_count << " G2: " << g2_exp_count << endl;

    // QAP query K
    QAP_query_K<PAIRING> qap_K(qapA, qapB, qapC, r1cs, lgrng, grks);
    cerr << "QAP query K";
    qap_K.K(qapK, -1);
    checkQuery(qap_K, " ERROR");

    // QAP query IC
    QAP_query_IC<PAIRING> qap_IC(qapA, r1cs, lgrng);
    cerr << "QAP query input consistency";
    qap_IC.IC(qapIC);
    checkQuery(qap_IC, " ERROR");

    const string
        pkA = keypair_prefix + ".pkA",
        pkB = keypair_prefix + ".pkB",
        pkC = keypair_prefix + ".pkC",
        pkH = keypair_prefix + ".pkH",
        pkK = keypair_prefix + ".pkK",
        vk = keypair_prefix + ".vk";

    GenericProgressBar progress(cerr, 50);

    // PPZK query A
    cerr << endl << "proving key A" << endl;
    PPZK_query_AC<PAIRING> ppzk_A(g1_exp_count, numwins, qapA, lgrng, grks);
    for (size_t i = 0; i < numblks; ++i) {
        cerr << pkA << i;
        ppzk_A.A(pkA, i, addressof(progress));
        checkQuery(ppzk_A, "ERROR");
    }

    // PPZK query B
    cerr << endl << "proving key B" << endl;
    PPZK_query_B<PAIRING> ppzk_B(g1_exp_count, numwins, g2_exp_count, qapB, lgrng, grks);
    for (size_t i = 0; i < numblks; ++i) {
        cerr << pkB << i;
        ppzk_B.B(pkB, i, addressof(progress));
        checkQuery(ppzk_B, "ERROR");
    }

    // PPZK query C
    cerr << endl << "proving key C" << endl;
    PPZK_query_AC<PAIRING> ppzk_C(g1_exp_count, numwins, qapC, lgrng, grks);
    for (size_t i = 0; i < numblks; ++i) {
        cerr << pkC << i;
        ppzk_C.C(pkC, i, addressof(progress));
        checkQuery(ppzk_C, "ERROR");
    }

    // PPZK query H
    cerr << endl << "proving key H" << endl;
    PPZK_query_HK<PAIRING> ppzk_H(g1_exp_count, numwins, qapH);
    for (size_t i = 0; i < numblks; ++i) {
        cerr << pkH << i;
        ppzk_H.H(pkH, i, addressof(progress));
        checkQuery(ppzk_H, "ERROR");
    }

    // PPZK query K
    cerr << endl << "proving key K" << endl;
    PPZK_query_HK<PAIRING> ppzk_K(g1_exp_count, numwins, qapK);
    for (size_t i = 0; i < numblks; ++i) {
        cerr << pkK << i;
        ppzk_K.K(pkK, i, addressof(progress));
        checkQuery(ppzk_K, "ERROR");
    }

    // PPZK query IC
    cerr << endl << "verification key";
    PPZK_verification_key<PAIRING> ppzk_IC(g1_exp_count, numwins, qapIC, r1cs, lgrng, grks);
    checkQuery(ppzk_IC, " ERROR");
    cerr << vk;
    ppzk_IC.writeFiles(vk, addressof(progress));
    checkQuery(ppzk_IC, "ERROR");

    // read the constraint system index file
    HugeSystem<FR> hugeSystem(r1cs);
    if (!hugeSystem.loadIndex()) {
        cerr << "ERROR: constraint system index file " << r1cs << endl;
        exit(EXIT_FAILURE);
    }

    // create key pair index file
    ofstream ofs(keypair_prefix);
    if (!ofs) {
        cerr << "ERROR: key pair index file " << keypair_prefix << endl;
        exit(EXIT_FAILURE);
    } else {
        // key pair index file points to the constraint system
        hugeSystem.writeIndexFile(ofs);

        // index space partitioning
        ofs << numwins << endl
            << numblks << endl;
    }
}

template <typename T>
void witnessLoop(T& obj,
                 const string& s,
                 const size_t numblks,
                 ProgressCallback& progress)
{
    progress.majorSteps(numblks);
    for (size_t i = 0; i < numblks; ++i) {
        cerr << s << i;
        obj.accumQuery(s, i, addressof(progress));
        checkQuery(obj, " ERROR");
    }
}

template <typename T>
void witnessVal(const T& obj, ostream& os) {
    if (!obj) {
        cerr << "ERROR" << endl;
        exit(EXIT_FAILURE);
    } else {
        obj.val().marshal_out_raw(os);
    }
}

template <typename PAIRING>
void generate_proof(const string& proof,
                    const string& keypair_prefix,
                    const string& witness)
{
    typedef typename PAIRING::Fr FR;

    // key pair index file
    HugeSystem<FR> hugeSys;
    string r1cs;
    size_t numwins, numblks;
    {
        ifstream ifs(keypair_prefix);
        if (!ifs || !hugeSys.loadIndex(ifs) || !(ifs >> numwins) || !(ifs >> numblks)) {
            cerr << "ERROR: kay pair index file " << keypair_prefix << endl;
            exit(EXIT_FAILURE);
        } else {
            r1cs = hugeSys.filePrefix();
            cerr << "constraint system index file: " << r1cs << endl
                 << "G1 exponentiation table partitions: " << numwins << endl
                 << "query vector partitions: " << numblks << endl;
        }
    }

    // randomness
    PPZK_ProofRandomness<FR> prf(0);

    const string qapW = keypair_prefix + ".qapW";

    // QAP witness
    cerr << "QAP witness";
    QAP_witness_ABCH<PAIRING> qap_ABCH(numblks, r1cs, prf, witness);
    qap_ABCH.writeFiles(qapW);
    checkQuery(qap_ABCH, " ERROR");

    const string
        pkA = keypair_prefix + ".pkA",
        pkB = keypair_prefix + ".pkB",
        pkC = keypair_prefix + ".pkC",
        pkH = keypair_prefix + ".pkH",
        pkK = keypair_prefix + ".pkK";

    // output proof file
    ofstream ofs(proof);
    if (!ofs) {
        cerr << "ERROR: output proof file " << proof << endl;
        exit(EXIT_FAILURE);
    }

    GenericProgressBar progress(cerr, 50);

    // PPZK witness A
    cerr << endl << "proof witness A" << endl;
    PPZK_witness_ABC<PPZK_WitnessA<PAIRING>, PAIRING> ppzk_A(r1cs, prf, witness);
    ppzk_A.initA();
    witnessLoop(ppzk_A, pkA, numblks, progress);
    witnessVal(ppzk_A, ofs);

    // PPZK witness B
    cerr << endl << "proof witness B" << endl;
    PPZK_witness_ABC<PPZK_WitnessB<PAIRING>, PAIRING> ppzk_B(r1cs, prf, witness);
    ppzk_B.initB();
    witnessLoop(ppzk_B, pkB, numblks, progress);
    witnessVal(ppzk_B, ofs);

    // PPZK witness C
    cerr << endl << "proof witness C" << endl;
    PPZK_witness_ABC<PPZK_WitnessC<PAIRING>, PAIRING> ppzk_C(r1cs, prf, witness);
    ppzk_C.initC();
    witnessLoop(ppzk_C, pkC, numblks, progress);
    witnessVal(ppzk_C, ofs);

    // PPZK witness H
    cerr << endl << "proof witness H" << endl;
    PPZK_witness_H<PAIRING> ppzk_H(qapW);
    witnessLoop(ppzk_H, pkH, numblks, progress);
    witnessVal(ppzk_H, ofs);

    // PPZK witness K
    cerr << endl << "proof witness K" << endl;
    PPZK_witness_K<PAIRING> ppzk_K(prf, witness);
    witnessLoop(ppzk_K, pkK, numblks, progress);
    witnessVal(ppzk_K, ofs);
}

template <typename T>
bool marshal_in(T& obj, const string& filename) {
    ifstream ifs(filename);
    return !!ifs && obj.marshal_in(ifs);
}

template <typename T>
bool marshal_in_raw(T& obj, const string& filename) {
    ifstream ifs(filename);
    return !!ifs && obj.marshal_in_raw(ifs);
}

template <typename T>
bool marshal_in_raw(T& obj, std::istream& is) {
    return !!is && obj.marshal_in_raw(is);
}

template <typename PAIRING>
bool verify_proof(const string& proof,
                  const string& keypair_prefix,
                  const string& input)
{
    PPZK_VerificationKey<PAIRING> vk;
    R1Witness<typename PAIRING::Fr> r1input;
    typename PPZK_WitnessA<PAIRING>::Val pA;
    typename PPZK_WitnessB<PAIRING>::Val pB;
    typename PPZK_WitnessC<PAIRING>::Val pC;
    typename PAIRING::G1 pH, pK;

    ifstream ifs(proof);
    if (!ifs) {
        cerr << "ERROR: zero knowledge proof file " << proof << endl;
        exit(EXIT_FAILURE);
    }

    return
        marshal_in_raw(vk, keypair_prefix + ".vk") &&
        marshal_in(r1input, input) &&
        marshal_in_raw(pA, ifs) &&
        marshal_in_raw(pB, ifs) &&
        marshal_in_raw(pC, ifs) &&
        marshal_in_raw(pH, ifs) &&
        marshal_in_raw(pK, ifs) &&
        strongVerify(vk, r1input, PPZK_Proof<PAIRING>(pA, pB, pC, pH, pK));
}

string hugeSysPairing(const string& a)
{
    HugeSystem<typename BN128_PAIRING::Fr> BN128(a);
    HugeSystem<typename EDWARDS_PAIRING::Fr> Edwards(a);
    const bool
        useBN128 = BN128.loadIndex(),
        useEdwards = Edwards.loadIndex();

    if (useBN128 && !useEdwards)
        return "BN128";
    else if (useEdwards && !useBN128)
        return "Edwards";
    else
        return string();
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "ov", "en", "");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    const auto
        outfile = cmdLine.getString('o'),
        vfile = cmdLine.getString('v');

    auto
        numwins = cmdLine.getNumber('e'),
        numblks = cmdLine.getNumber('n');

    const auto& args = cmdLine.getArgs();

    init_BN128(); // Barreto-Naehrig 128 bits
    init_Edwards(); // Edwards 80 bits

    if (1 == args.size() && !outfile.empty()) {
        // constraint system index file
        cerr << "constraint system index file: " << args[0];
        ifstream ifs(args[0]);
        if (!ifs) {
            cerr << " ERROR" << endl;
            exit(EXIT_FAILURE);
        } else {
            cerr << endl;
        }

        // exponentiation table partitioning
        if (-1 == numwins) numwins = 1;
        cerr << "G1 exponentiation table partitions: " << numwins;
        if (0 == numwins) {
            cerr << " ERROR" << endl;
            exit(EXIT_FAILURE);
        } else {
            cerr << endl;
        }

        // query vector partitioning
        if (-1 == numblks) numblks = 1;
        cerr << "query vector partitions: " << numblks;
        if (0 == numblks) {
            cerr << " ERROR" << endl;
            exit(EXIT_FAILURE);
        } else {
            cerr << endl;
        }

        // proving/verification key pair prefix
        cerr << "proving/verification key pair prefix: " << outfile << endl;

        // determine BN128 or Edwards pairing
        const auto pairing = hugeSysPairing(args[0]);
        cerr << "elliptic curve pairing: " << pairing;
        if (pairingBN128(pairing)) {
            cerr << endl;
            generate_key_pair<BN128_PAIRING>(args[0], numwins, numblks, outfile);
        } else if (pairingEdwards(pairing)) {
            cerr << endl;
            generate_key_pair<EDWARDS_PAIRING>(args[0], numwins, numblks, outfile);
        } else {
            cerr << " ERROR" << endl;
            exit(EXIT_FAILURE);
        }

    } else if (2 == args.size()) {
        // pairing, keypair prefix and either input or witness
        string pairing, keypair_prefix, infile;
        for (size_t i = 0; i < 2; ++i) {
            // determine BN128 or Edwards pairing
            const auto tmp_pairing = hugeSysPairing(args[i]);
            if (tmp_pairing.empty()) {
                infile = args[i];
            } else {
                keypair_prefix = args[i];
                pairing = pairing.empty() ? tmp_pairing : "ERROR";
            }
        }

        cerr << "key pair prefix: " << keypair_prefix;
        if (keypair_prefix.empty()) {
            cerr << " ERROR" << endl;
            exit(EXIT_FAILURE);
        } else {
            cerr << endl;
        }

        cerr << (outfile.empty() ? "input" : "witness") << " file: " << infile;
        if (infile.empty()) {
            cerr << " ERROR" << endl;
            exit(EXIT_FAILURE);
        } else {
            cerr << endl;
        }

        cerr << "elliptic curve pairing: " << pairing;
        if (pairingBN128(pairing)) {
            cerr << endl;

            if (!outfile.empty() && vfile.empty()) {
                generate_proof<BN128_PAIRING>(outfile, keypair_prefix, infile);

            } else if (!vfile.empty() && outfile.empty()) {
                if (verify_proof<BN128_PAIRING>(vfile, keypair_prefix, infile)) {
                    cerr << "PASS" << endl;
                } else {
                    cerr << "FAIL" << endl;
                    exit(EXIT_FAILURE);
                }

            } else {
                // invalid command line
                printUsage(argv[0]);
            }

        } else if (pairingEdwards(pairing)) {
            cerr << endl;

            if (!outfile.empty() && vfile.empty()) {
                generate_proof<EDWARDS_PAIRING>(outfile, keypair_prefix, infile);

            } else if (!vfile.empty() && outfile.empty()) {
                if (verify_proof<EDWARDS_PAIRING>(vfile, keypair_prefix, infile)) {
                    cerr << "PASS" << endl;
                } else {
                    cerr << "FAIL" << endl;
                    exit(EXIT_FAILURE);
                }

            } else {
                // invalid command line
                printUsage(argv[0]);
            }

        } else {
            cerr << " ERROR" << endl;
            exit(EXIT_FAILURE);
        }

    } else {
        // invalid command line
        printUsage(argv[0]);
    }

    return EXIT_SUCCESS;
}
