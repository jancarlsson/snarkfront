#include <cstdlib>
#include <iostream>
#include <string>
#include "CompilePPZK.hpp"
#include "Getopt.hpp"
#include "snarkfront.hpp"

using namespace snarkfront;
using namespace snarklib;
using namespace std;

void printUsage(const char* exeName) {
    const string
        PAIR = " -p BN128|Edwards",
        SYS = " -s constraint_system_file",
        R = " -r randomness_file",
        M = " -m start_block",
        N = " -n number_blocks",
        G1 = " -1 g1_exp_count",
        G2 = " -2 g2_exp_count",
        OUT = " -o output_file",
        A = " -a qap_file",
        B = " -b qap_file",
        C = " -c qap_file",
        H = " -h qap_file",
        K = " -k qap_file",
        IC = " -i qap_file";

    cout << endl << "PPZK query generation (proving key):" << endl
         << "  A: " << exeName << PAIR << R << G1 << OUT << A << M << N << endl
         << "  B: " << exeName << PAIR << R << G1 << G2 << OUT << B << M << N << endl
         << "  C: " << exeName << PAIR << R << G1 << OUT << C << M << N << endl
         << "  H: " << exeName << PAIR << G1 << OUT << H << M << N << endl
         << "  K: " << exeName << PAIR << G1 << OUT << K << M << N << endl
         << endl << "PPZK input consistency (verification key):" << endl
         << "  key: " << exeName << PAIR << SYS << R << G1 << OUT << IC << endl;

    exit(EXIT_FAILURE);
}

template <typename PAIRING>
bool queryA(const size_t g1_exp,
            const string& afile,
            const string& randfile,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt)
{
    PPZK_query_AC<PAIRING> query(g1_exp, afile, randfile);
    for (size_t i = 0; i < blockcnt; ++i) query.A(outfile, i + startblock);
    return !!query;
}

template <typename PAIRING>
bool queryB(const size_t g1_exp,
            const size_t g2_exp,
            const string& bfile,
            const string& randfile,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt)
{
    PPZK_query_B<PAIRING> query(g1_exp, g2_exp, bfile, randfile);
    for (size_t i = 0; i < blockcnt; ++i) query.B(outfile, i + startblock);
    return !!query;
}

template <typename PAIRING>
bool queryC(const size_t g1_exp,
            const string& cfile,
            const string& randfile,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt)
{
    PPZK_query_AC<PAIRING> query(g1_exp, cfile, randfile);
    for (size_t i = 0; i < blockcnt; ++i) query.C(outfile, i + startblock);
    return !!query;
}

template <typename PAIRING>
bool queryH(const size_t g1_exp,
            const string& hfile,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt)
{
    PPZK_query_HK<PAIRING> query(g1_exp, hfile);
    for (size_t i = 0; i < blockcnt; ++i) query.H(outfile, i + startblock);
    return !!query;
}

template <typename PAIRING>
bool queryK(const size_t g1_exp,
            const string& kfile,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt)
{
    PPZK_query_HK<PAIRING> query(g1_exp, kfile);
    for (size_t i = 0; i < blockcnt; ++i) query.K(outfile, i + startblock);
    return !!query;
}

template <typename PAIRING>
bool queryIC(const size_t g1_exp,
             const string& icfile,
             const string& sysfile,
             const string& randfile,
             const string& outfile)
{
    PPZK_verification_key<PAIRING> query(g1_exp, icfile, sysfile, randfile);
    query.writeFiles(outfile);
    return !!query;
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "psroabchki", "mn12", "");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    const auto
        pairing = cmdLine.getString('p'),
        sysfile = cmdLine.getString('s'),
        randfile = cmdLine.getString('r'),
        outfile = cmdLine.getString('o'),
        afile = cmdLine.getString('a'),
        bfile = cmdLine.getString('b'),
        cfile = cmdLine.getString('c'),
        hfile = cmdLine.getString('h'),
        kfile = cmdLine.getString('k'),
        icfile = cmdLine.getString('i');

    const auto
        start = cmdLine.getNumber('m'),
        cnt = cmdLine.getNumber('n'),
        g1_exp = cmdLine.getNumber('1'),
        g2_exp = cmdLine.getNumber('2');

    if (!validPairingName(pairing)) {
        cerr << "error: elliptic curve pairing " << pairing << endl;
        exit(EXIT_FAILURE);
    }

    bool ok = false;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        typedef BN128_PAIRING PAIR;

        if (!afile.empty()) ok = queryA<PAIR>(g1_exp, afile, randfile, outfile, start, cnt);
        if (!bfile.empty()) ok = queryB<PAIR>(g1_exp, g2_exp, bfile, randfile, outfile, start, cnt);
        if (!cfile.empty()) ok = queryC<PAIR>(g1_exp, cfile, randfile, outfile, start, cnt);
        if (!hfile.empty()) ok = queryH<PAIR>(g1_exp, hfile, outfile, start, cnt);
        if (!kfile.empty()) ok = queryK<PAIR>(g1_exp, kfile, outfile, start, cnt);
        if (!icfile.empty()) ok = queryIC<PAIR>(g1_exp, icfile, sysfile, randfile, outfile);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        typedef EDWARDS_PAIRING PAIR;

        if (!afile.empty()) ok = queryA<PAIR>(g1_exp, afile, randfile, outfile, start, cnt);
        if (!bfile.empty()) ok = queryB<PAIR>(g1_exp, g2_exp, bfile, randfile, outfile, start, cnt);
        if (!cfile.empty()) ok = queryC<PAIR>(g1_exp, cfile, randfile, outfile, start, cnt);
        if (!hfile.empty()) ok = queryH<PAIR>(g1_exp, hfile, outfile, start, cnt);
        if (!kfile.empty()) ok = queryK<PAIR>(g1_exp, kfile, outfile, start, cnt);
        if (!icfile.empty()) ok = queryIC<PAIR>(g1_exp, icfile, sysfile, randfile, outfile);
    }

    if (!ok) {
        cerr << "ERROR" << endl;
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
