#include <cstdlib>
#include <iostream>
#include <fstream>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
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
        V = " [-v]",
        optBLIND = " [-B]",
        BLIND = " -B";

    std::stringstream ss;
    ss << exeName << PAIR << OUT;
    const auto& PRE = ss.str();

    cout << endl << "PPZK query generation (proving key):" << endl
         << "  A: " << PRE << G1 << E << A << M << N << R << optBLIND << V << endl
         << "  B: " << PRE << G1 << E << G2 << B << M << N << R << optBLIND << V << endl
         << "  C: " << PRE << G1 << E << C << M << N << R << optBLIND << V << endl
         << "  H: " << PRE << G1 << E << H << M << N << V << endl
         << "  K: " << PRE << G1 << E << K << M << N << V << endl
         << "  K: " << PRE << G1 << E << A << B << C << M << N << R << BLIND << V << endl
         << endl << "PPZK input consistency (verification key):" << endl
         << "  key: " << PRE << SYS << G1 << E << IC << R << optBLIND << V << endl
         << endl << "PPZK witness generation (proof):" << endl
         << "  A: " << PRE << SYS << R << WIT << A << M << N << V << endl
         << "  B: " << PRE << SYS << R << WIT << B << M << N << V << endl
         << "  C: " << PRE << SYS << R << WIT << C << M << N << V << endl
         << "  H: " << PRE << H << Q << M << N << V << endl
         << "  K: " << PRE << R << WIT << K << M << N << V << endl;

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
            const bool blind,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt,
            const bool verbose)
{
    PPZK_query_AC<PAIRING> Q(g1_exp, g1_blks, afile, randfile, blind);

    ppzkLoop(
        [&Q] (const string& outfile, size_t block, ProgressCallback* callback) {
            Q.A(outfile, block, callback);
        },
        outfile,
        startblock,
        blockcnt,
        verbose);

    return !!Q;
}

template <typename PAIRING>
bool queryB(const size_t g1_exp,
            const size_t g1_blks,
            const size_t g2_exp,
            const string& bfile,
            const string& randfile,
            const bool blind,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt,
            const bool verbose)
{
    PPZK_query_B<PAIRING> Q(g1_exp, g1_blks, g2_exp, bfile, randfile, blind);

    ppzkLoop(
        [&Q] (const string& outfile, size_t block, ProgressCallback* callback) {
            Q.B(outfile, block, callback);
        },
        outfile,
        startblock,
        blockcnt,
        verbose);

    return !!Q;
}

template <typename PAIRING>
bool queryC(const size_t g1_exp,
            const size_t g1_blks,
            const string& cfile,
            const string& randfile,
            const bool blind,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt,
            const bool verbose)
{
    PPZK_query_AC<PAIRING> Q(g1_exp, g1_blks, cfile, randfile, blind);

    ppzkLoop(
        [&Q] (const string& outfile, size_t block, ProgressCallback* callback) {
            Q.C(outfile, block, callback);
        },
        outfile,
        startblock,
        blockcnt,
        verbose);

    return !!Q;
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
    PPZK_query_HK<PAIRING> Q(g1_exp, g1_blks, hfile);

    ppzkLoop(
        [&Q] (const string& outfile, size_t block, ProgressCallback* callback) {
            Q.H(outfile, block, callback);
        },
        outfile,
        startblock,
        blockcnt,
        verbose);

    return !!Q;
}

template <typename PAIRING>
bool queryK(const size_t g1_exp,
            const size_t g1_blks,
            const string& afile,
            const string& bfile,
            const string& cfile,
            const string& kfile,
            const string& randfile,
            const bool blind,
            const string& outfile,
            const size_t startblock,
            const size_t blockcnt,
            const bool verbose)
{
    if (blind) {
        PPZK_query_K<PAIRING> Q(g1_exp, g1_blks, afile, bfile, cfile, randfile);

        ppzkLoop(
            [&Q] (const string& outfile, size_t block, ProgressCallback* callback) {
                Q.K(outfile, block, callback);
            },
            outfile,
            startblock,
            blockcnt,
            verbose);

        return !!Q;

    } else {
        PPZK_query_HK<PAIRING> Q(g1_exp, g1_blks, kfile);

        ppzkLoop(
            [&Q] (const string& outfile, size_t block, ProgressCallback* callback) {
                Q.K(outfile, block, callback);
            },
            outfile,
            startblock,
            blockcnt,
            verbose);

        return !!Q;
    }
}

template <typename PAIRING>
bool queryIC(const size_t g1_exp,
             const size_t g1_blks,
             const string& icfile,
             const string& sysfile,
             const string& randfile,
             const bool blind,
             const string& outfile,
             const bool verbose)
{
    PPZK_verification_key<PAIRING> Q(g1_exp, g1_blks, icfile, sysfile, randfile, blind);

    GenericProgressBar progress(cerr, 50);

    Q.writeFiles(
        outfile,
        verbose ? std::addressof(progress) : nullptr);

    return !!Q;
}

template <typename WIT>
bool witnessVal(const WIT& wit,
                const std::string& outfile)
{
    if (!wit) return false;

    std::ofstream ofs(outfile);
    if (!ofs) {
        return false;
    } else {
        wit.val().marshal_out_raw(ofs);
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
    PPZK_witness_ABC<PPZK_WitnessA<PAIRING>, PAIRING> W(sysfile, randfile, witfile);
    W.initA();

    ppzkLoop(
        [&W] (const string& infile, size_t block, ProgressCallback* callback) {
            W.accumQuery(infile, block, callback);
        },
        afile,
        startblock,
        blockcnt,
        verbose);

    return witnessVal(W, outfile);
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
    PPZK_witness_ABC<PPZK_WitnessB<PAIRING>, PAIRING> W(sysfile, randfile, witfile);
    W.initB();

    ppzkLoop(
        [&W] (const string& infile, size_t block, ProgressCallback* callback) {
            W.accumQuery(infile, block, callback);
        },
        bfile,
        startblock,
        blockcnt,
        verbose);

    return witnessVal(W, outfile);
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
    PPZK_witness_ABC<PPZK_WitnessC<PAIRING>, PAIRING> W(sysfile, randfile, witfile);
    W.initC();

    ppzkLoop(
        [&W] (const string& infile, size_t block, ProgressCallback* callback) {
            W.accumQuery(infile, block, callback);
        },
        cfile,
        startblock,
        blockcnt,
        verbose);

    return witnessVal(W, outfile);
}

template <typename PAIRING>
bool witnessH(const string& hfile,
              const string& qapABCH,
              const string& outfile,
              const size_t startblock,
              const size_t blockcnt,
              const bool verbose)
{
    PPZK_witness_H<PAIRING> W(qapABCH);

    ppzkLoop(
        [&W] (const string& infile, size_t block, ProgressCallback* callback) {
            W.accumQuery(infile, block, callback);
        },
        hfile,
        startblock,
        blockcnt,
        verbose);

    return witnessVal(W, outfile);
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
    PPZK_witness_K<PAIRING> W(randfile, witfile);

    ppzkLoop(
        [&W] (const string& infile, size_t block, ProgressCallback* callback) {
            W.accumQuery(infile, block, callback);
        },
        kfile,
        startblock,
        blockcnt,
        verbose);

    return witnessVal(W, outfile);
}

template <typename PAIRING>
bool cmdSwitch(const string& sysfile,
               const string& randfile,
               const bool blind,
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
    if (!qfile.empty()) {
        return witnessH<PAIRING>(
            hfile, qfile, outfile,
            start, cnt, verb);

    } else if (!witfile.empty()) {
        if (!afile.empty()) {
            return witnessA<PAIRING>(
                afile, sysfile, randfile, witfile, outfile,
                start, cnt, verb);
        }

        if (!bfile.empty()) {
            return witnessB<PAIRING>(
                bfile, sysfile, randfile, witfile, outfile,
                start, cnt, verb);
        }

        if (!cfile.empty()) {
            return witnessC<PAIRING>(
                cfile, sysfile, randfile, witfile, outfile,
                start, cnt, verb);
        }

        if (!kfile.empty()) {
            return witnessK<PAIRING>(
                kfile, randfile, witfile, outfile,
                start, cnt, verb);
        }

    } else {
        if (!kfile.empty() ||
            (kfile.empty() && !afile.empty() && !bfile.empty() && !cfile.empty())) {
            return queryK<PAIRING>(
                g1_exp, g1_blks,
                afile, bfile, cfile, kfile, randfile, blind, outfile,
                start, cnt, verb);
        }

        if (!afile.empty()) {
            return queryA<PAIRING>(
                g1_exp, g1_blks,
                afile, randfile, blind, outfile,
                start, cnt, verb);
        }

        if (!bfile.empty()) {
            return queryB<PAIRING>(
                g1_exp, g1_blks, g2_exp,
                bfile, randfile, blind, outfile,
                start, cnt, verb);
        }

        if (!cfile.empty()) {
            return queryC<PAIRING>(
                g1_exp, g1_blks,
                cfile, randfile, blind, outfile,
                start, cnt, verb);
        }

        if (!hfile.empty()) {
            return queryH<PAIRING>(
                g1_exp, g1_blks,
                hfile, outfile,
                start, cnt, verb);
        }

        if (!icfile.empty()) {
            return queryIC<PAIRING>(
                g1_exp, g1_blks,
                icfile, sysfile, randfile, blind, outfile,
                verb);
        }
    }

    return false;
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "psroabchkiqw", "mn12e", "vB");
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

    const auto
        verb = cmdLine.getFlag('v'),
        blind = cmdLine.getFlag('B');

    if (!validPairingName(pairing)) {
        cerr << "error: elliptic curve pairing " << pairing << endl;
        exit(EXIT_FAILURE);
    }

    bool ok = false;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        ok = cmdSwitch<BN128_PAIRING>(sysfile, randfile, blind, outfile,
                                      afile, bfile, cfile, hfile, kfile, icfile,
                                      qfile,
                                      witfile,
                                      start, cnt,
                                      g1_exp, g2_exp, g1_blks,
                                      verb);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        ok = cmdSwitch<EDWARDS_PAIRING>(sysfile, randfile, blind, outfile,
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

    return EXIT_SUCCESS;
}
