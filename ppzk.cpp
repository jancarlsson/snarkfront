#include <cstdlib>
#include <iostream>
#include <fstream>
#include <functional>
#include <memory>
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
        E = " -e exp_blocks",
        OUT = " -o output_file",
        A = " -a file",
        B = " -b file",
        C = " -c file",
        H = " -h file",
        K = " -k file",
        IC = " -i file",
        Q = " -q qap_witness_file",
        WIT = " -w witness_file",
        V = " [-v]";

    cout << endl << "PPZK query generation (proving key):" << endl
         << "  A: " << exeName << PAIR << R << G1 << E << OUT << A << M << N << V << endl
         << "  B: " << exeName << PAIR << R << G1 << E << G2 << OUT << B << M << N << V << endl
         << "  C: " << exeName << PAIR << R << G1 << E << OUT << C << M << N << V << endl
         << "  H: " << exeName << PAIR << G1 << E << OUT << H << M << N << V << endl
         << "  K: " << exeName << PAIR << G1 << E << OUT << K << M << N << V << endl
         << endl << "PPZK input consistency (verification key):" << endl
         << "  key: " << exeName << PAIR << SYS << R << G1 << E << OUT << IC << V << endl
         << endl << "PPZK witness generation (proof):" << endl
         << "  A: " << exeName << PAIR << SYS << R << WIT << OUT << A << M << N << V << endl
         << "  B: " << exeName << PAIR << SYS << R << WIT << OUT << B << M << N << V << endl
         << "  C: " << exeName << PAIR << SYS << R << WIT << OUT << C << M << N << V << endl
         << "  H: " << exeName << PAIR << OUT << H << Q << M << N << V << endl
         << "  K: " << exeName << PAIR << R << WIT << OUT << K << M << N << V << endl;

    exit(EXIT_FAILURE);
}

void ppzkLoop(function<void (const string&, size_t, ProgressCallback*)> func,
               const string& fileprefix,
               const size_t startblock,
               const size_t blockcnt,
               const bool verbose)
{
    GenericProgressBar progress(cerr, 50);
    progress.majorSteps(blockcnt); // needed for witnesses only
                                   // queries will override

    for (size_t block = startblock; block < startblock + blockcnt; ++block) {
        if (verbose) {
            cerr << endl << fileprefix << block;
            func(fileprefix, block, std::addressof(progress));
        } else {
            func(fileprefix, block, nullptr);
        }
    }

    if (verbose) cerr << endl;
}

template <typename PAIRING>
bool queryA(const size_t g1_exp,
            const size_t g1_blks,
            const string& afile,
            const string& randfile,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt,
            const bool verbose)
{
    PPZK_query_AC<PAIRING> query(g1_exp, g1_blks, afile, randfile);

    ppzkLoop(
        [&query] (const string& outfile, size_t block, ProgressCallback* callback) {
            query.A(outfile, block, callback);
        },
        outfile,
        startblock,
        blockcnt,
        verbose);

    return !!query;
}

template <typename PAIRING>
bool queryB(const size_t g1_exp,
            const size_t g1_blks,
            const size_t g2_exp,
            const string& bfile,
            const string& randfile,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt,
            const bool verbose)
{
    PPZK_query_B<PAIRING> query(g1_exp, g1_blks, g2_exp, bfile, randfile);

    ppzkLoop(
        [&query] (const string& outfile, size_t block, ProgressCallback* callback) {
            query.B(outfile, block, callback);
        },
        outfile,
        startblock,
        blockcnt,
        verbose);

    return !!query;
}

template <typename PAIRING>
bool queryC(const size_t g1_exp,
            const size_t g1_blks,
            const string& cfile,
            const string& randfile,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt,
            const bool verbose)
{
    PPZK_query_AC<PAIRING> query(g1_exp, g1_blks, cfile, randfile);

    ppzkLoop(
        [&query] (const string& outfile, size_t block, ProgressCallback* callback) {
            query.C(outfile, block, callback);
        },
        outfile,
        startblock,
        blockcnt,
        verbose);

    return !!query;
}

template <typename PAIRING>
bool queryH(const size_t g1_exp,
            const size_t g1_blks,
            const string& hfile,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt,
            const bool verbose)
{
    PPZK_query_HK<PAIRING> query(g1_exp, g1_blks, hfile);

    ppzkLoop(
        [&query] (const string& outfile, size_t block, ProgressCallback* callback) {
            query.H(outfile, block, callback);
        },
        outfile,
        startblock,
        blockcnt,
        verbose);

    return !!query;
}

template <typename PAIRING>
bool queryK(const size_t g1_exp,
            const size_t g1_blks,
            const string& kfile,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt,
            const bool verbose)
{
    PPZK_query_HK<PAIRING> query(g1_exp, g1_blks, kfile);

    ppzkLoop(
        [&query] (const string& outfile, size_t block, ProgressCallback* callback) {
            query.K(outfile, block, callback);
        },
        outfile,
        startblock,
        blockcnt,
        verbose);

    return !!query;
}

template <typename PAIRING>
bool queryIC(const size_t g1_exp,
             const size_t g1_blks,
             const string& icfile,
             const string& sysfile,
             const string& randfile,
             const string& outfile,
             const bool verbose)
{
    PPZK_verification_key<PAIRING> query(g1_exp, g1_blks, icfile, sysfile, randfile);

    GenericProgressBar progress(cerr, 50);
    progress.majorSteps(g1_blks);

    query.writeFiles(outfile, verbose ? std::addressof(progress) : nullptr);

    return !!query;
}

template <typename WIT>
bool witnessVal(WIT& wit,
                const std::string& outfile)
{
    if (!wit) return false;

    std::ofstream ofs(outfile);
    if (!ofs) {
        return false;
    } else {
        wit.val().marshal_out(ofs);
    }

    return true;
}

template <typename PAIRING>
bool witnessA(const string& afile,
              const string& sysfile,
              const string& randfile,
              const string& witfile,
              const string& outfile,
              const size_t startblock,
              const size_t blockcnt,
              const bool verbose)
{
    PPZK_witness_ABC<PPZK_WitnessA<PAIRING>, PAIRING> wit(sysfile, randfile, witfile);
    wit.initA();

    ppzkLoop(
        [&wit] (const string& infile, size_t block, ProgressCallback* callback) {
            wit.accumQuery(infile, block, callback);
        },
        afile,
        startblock,
        blockcnt,
        verbose);

    return witnessVal(wit, outfile);
}

template <typename PAIRING>
bool witnessB(const string& bfile,
              const string& sysfile,
              const string& randfile,
              const string& witfile,
              const string& outfile,
              const size_t startblock,
              const size_t blockcnt,
              const bool verbose)
{
    PPZK_witness_ABC<PPZK_WitnessB<PAIRING>, PAIRING> wit(sysfile, randfile, witfile);
    wit.initB();

    ppzkLoop(
        [&wit] (const string& infile, size_t block, ProgressCallback* callback) {
            wit.accumQuery(infile, block, callback);
        },
        bfile,
        startblock,
        blockcnt,
        verbose);

    return witnessVal(wit, outfile);
}

template <typename PAIRING>
bool witnessC(const string& cfile,
              const string& sysfile,
              const string& randfile,
              const string& witfile,
              const string& outfile,
              const size_t startblock,
              const size_t blockcnt,
              const bool verbose)
{
    PPZK_witness_ABC<PPZK_WitnessC<PAIRING>, PAIRING> wit(sysfile, randfile, witfile);
    wit.initC();

    ppzkLoop(
        [&wit] (const string& infile, size_t block, ProgressCallback* callback) {
            wit.accumQuery(infile, block, callback);
        },
        cfile,
        startblock,
        blockcnt,
        verbose);

    return witnessVal(wit, outfile);
}

template <typename PAIRING>
bool witnessH(const string& hfile,
              const string& qapABCH,
              const string& outfile,
              const size_t startblock,
              const size_t blockcnt,
              const bool verbose)
{
    PPZK_witness_H<PAIRING> wit(qapABCH);

    ppzkLoop(
        [&wit] (const string& infile, size_t block, ProgressCallback* callback) {
            wit.accumQuery(infile, block, callback);
        },
        hfile,
        startblock,
        blockcnt,
        verbose);

    return witnessVal(wit, outfile);
}

template <typename PAIRING>
bool witnessK(const string& kfile,
              const string& randfile,
              const string& witfile,
              const string& outfile,
              const size_t startblock,
              const size_t blockcnt,
              const bool verbose)
{
    PPZK_witness_K<PAIRING> wit(randfile, witfile);

    ppzkLoop(
        [&wit] (const string& infile, size_t block, ProgressCallback* callback) {
            wit.accumQuery(infile, block, callback);
        },
        kfile,
        startblock,
        blockcnt,
        verbose);

    return witnessVal(wit, outfile);
}

template <typename PAIRING>
bool cmdSwitch(const string& sysfile,
               const string& randfile,
               const string& outfile,
               const string& afile,
               const string& bfile,
               const string& cfile,
               const string& hfile,
               const string& kfile,
               const string& icfile,
               const string& qfile,
               const string& witfile,
               const size_t start,
               const size_t cnt,
               const size_t g1_exp,
               const size_t g2_exp,
               const size_t g1_blks,
               const bool verb)
{
    bool ok = false;

    if (!qfile.empty()) {
        ok = witnessH<PAIRING>(hfile, qfile, outfile, start, cnt, verb);

    } else if (!witfile.empty()) {
        if (!afile.empty())
            ok = witnessA<PAIRING>(afile, sysfile, randfile, witfile, outfile, start, cnt, verb);

        if (!bfile.empty())
            ok = witnessB<PAIRING>(bfile, sysfile, randfile, witfile, outfile, start, cnt, verb);

        if (!cfile.empty())
            ok = witnessC<PAIRING>(cfile, sysfile, randfile, witfile, outfile, start, cnt, verb);

        if (!kfile.empty())
            ok = witnessK<PAIRING>(kfile, randfile, witfile, outfile, start, cnt, verb);

    } else {
        if (!afile.empty())
            ok = queryA<PAIRING>(g1_exp, g1_blks, afile, randfile, outfile, start, cnt, verb);

        if (!bfile.empty())
            ok = queryB<PAIRING>(g1_exp, g1_blks, g2_exp, bfile, randfile, outfile, start, cnt, verb);

        if (!cfile.empty())
            ok = queryC<PAIRING>(g1_exp, g1_blks, cfile, randfile, outfile, start, cnt, verb);

        if (!hfile.empty())
            ok = queryH<PAIRING>(g1_exp, g1_blks, hfile, outfile, start, cnt, verb);

        if (!kfile.empty())
            ok = queryK<PAIRING>(g1_exp, g1_blks, kfile, outfile, start, cnt, verb);

        if (!icfile.empty())
            ok = queryIC<PAIRING>(g1_exp, g1_blks, icfile, sysfile, randfile, outfile, verb);
    }

    return ok;
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "psroabchkiqw", "mn12e", "v");
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
        icfile = cmdLine.getString('i'),
        qfile = cmdLine.getString('q'),
        witfile = cmdLine.getString('w');

    const auto
        start = cmdLine.getNumber('m'),
        cnt = cmdLine.getNumber('n'),
        g1_exp = cmdLine.getNumber('1'),
        g2_exp = cmdLine.getNumber('2'),
        g1_blks = cmdLine.getNumber('e');

    const auto verb = cmdLine.getFlag('v');

    if (!validPairingName(pairing)) {
        cerr << "error: elliptic curve pairing " << pairing << endl;
        exit(EXIT_FAILURE);
    }

    bool ok = false;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        ok = cmdSwitch<BN128_PAIRING>(sysfile, randfile, outfile,
                                      afile, bfile, cfile, hfile, kfile, icfile,
                                      qfile,
                                      witfile,
                                      start, cnt,
                                      g1_exp, g2_exp, g1_blks,
                                      verb);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        ok = cmdSwitch<EDWARDS_PAIRING>(sysfile, randfile, outfile,
                                        afile, bfile, cfile, hfile, kfile, icfile,
                                        qfile,
                                        witfile,
                                        start, cnt,
                                        g1_exp, g2_exp, g1_blks,
                                        verb);
    }

    if (!ok) {
        cerr << "ERROR" << endl;
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
