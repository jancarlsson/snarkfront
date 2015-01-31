#include <cstdlib>
#include <iostream>
#include <string>
#include "CompileQAP.hpp"
#include "Getopt.hpp"
#include "snarkfront.hpp"

using namespace snarkfront;
using namespace std;

void printUsage(const char* exeName) {
    const string
        PAIR = " -p BN128|Edwards",
        SYS = " -s constraint_system_file",
        R = " -r randomness_file",
        N = " -n block_number",
        optN = " [-n block_number]",
        QUERY = " -q",
        EXP = " -e",
        A = " -a file",
        B = " -b file",
        C = " -c file",
        H = " -h file",
        K = " -k file",
        IC = " -i file";

    cout << endl << "QAP query generation:" << endl
         << "  A:  " << exeName << PAIR << SYS << R << QUERY << A << N << endl
         << "  B:  " << exeName << PAIR << SYS << R << QUERY << B << N << endl
         << "  C:  " << exeName << PAIR << SYS << R << QUERY << C << N << endl
         << "  H:  " << exeName << PAIR << SYS << R << QUERY << H << N << endl
         << "  K:  " << exeName << PAIR << SYS << R << QUERY << A << B << C << K << optN << endl
         << "  IC: " << exeName << PAIR << SYS << R << QUERY << A << IC << endl
         << endl << "window table exponent count:" << endl
         << "  g1_exp_count: " << exeName << PAIR << SYS << R << EXP << A << B << C << H << endl
         << "  g2_exp_count: " << exeName << PAIR << SYS << R << EXP << B << endl;

    exit(EXIT_FAILURE);
}

template <typename PAIRING>
bool queryABCH(const std::string& afile,
               const std::string& bfile,
               const std::string& cfile,
               const std::string& hfile,
               const std::size_t blocknum,
               const std::string& sysfile,
               const std::string& randfile)
{
    QAP_query_ABCH<PAIRING> query(blocknum, sysfile, randfile);

    if (!afile.empty()) query.A(afile);
    if (!bfile.empty()) query.B(bfile);
    if (!cfile.empty()) query.C(cfile);
    if (!hfile.empty()) query.H(hfile);

    return !!query;
}

template <typename PAIRING>
bool queryK(const std::string& afile,
            const std::string& bfile,
            const std::string& cfile,
            const std::string& kfile,
            const std::size_t blocknum,
            const std::string& sysfile,
            const std::string& randfile)
{
    QAP_query_K<PAIRING> query(afile, bfile, cfile, sysfile, randfile);
    query.K(kfile, blocknum);
    return !!query;
}

template <typename PAIRING>
bool queryIC(const std::string& afile,
             const std::string& icfile,
             const std::string& sysfile,
             const std::string& randfile)
{
    QAP_query_IC<PAIRING> query(afile, sysfile, randfile);
    query.IC(icfile);
    return !!query;
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "psrabchki", "n", "qe");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    const auto
        pairing = cmdLine.getString('p'),
        sysfile = cmdLine.getString('s'),
        randfile = cmdLine.getString('r'),
        afile = cmdLine.getString('a'),
        bfile = cmdLine.getString('b'),
        cfile = cmdLine.getString('c'),
        hfile = cmdLine.getString('h'),
        kfile = cmdLine.getString('k'),
        icfile = cmdLine.getString('i');

    const auto blocknum = cmdLine.getNumber('n');

    const auto
        is_query = cmdLine.getFlag('q'),
        is_exp = cmdLine.getFlag('e');

    if (!validPairingName(pairing)) {
        cerr << "error: elliptic curve pairing " << pairing << endl;
        exit(EXIT_FAILURE);
    }

    bool ok = false;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        typedef BN128_PAIRING PAIR;

        if (is_query) {
            if (!kfile.empty()) {
                ok = queryK<PAIR>(afile, bfile, cfile, kfile, blocknum, sysfile, randfile);
            } else if (!icfile.empty()) {
                ok = queryIC<PAIR>(afile, icfile, sysfile, randfile);
            } else {
                ok = queryABCH<PAIR>(afile, bfile, cfile, hfile, blocknum, sysfile, randfile);
            }
        } else if (is_exp) {
            QAP_query_ABCH<PAIR> query(0, sysfile, randfile);
            size_t count = 0;
            if (!afile.empty() && !bfile.empty() && !cfile.empty() && !hfile.empty()) {
                count = query.g1_exp_count(afile, bfile, cfile, hfile);
                ok = !!query;
            } else {
                count = query.g2_exp_count(bfile);
                ok = !!query;
            }
            if (ok) cout << count << endl;
        }

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        typedef EDWARDS_PAIRING PAIR;

        if (is_query) {
            if (!kfile.empty()) {
                ok = queryK<PAIR>(afile, bfile, cfile, kfile, blocknum, sysfile, randfile);
            } else if (!icfile.empty()) {
                ok = queryIC<PAIR>(afile, icfile, sysfile, randfile);
            } else {
                ok = queryABCH<PAIR>(afile, bfile, cfile, hfile, blocknum, sysfile, randfile);
            }
        } else if (is_exp) {
            QAP_query_ABCH<PAIR> query(0, sysfile, randfile);
            size_t count = 0;
            if (!afile.empty() && !bfile.empty() && !cfile.empty() && !hfile.empty()) {
                count = query.g1_exp_count(afile, bfile, cfile, hfile);
                ok = !!query;
            } else {
                count = query.g2_exp_count(bfile);
                ok = !!query;
            }
            if (ok) cout << count << endl;
        }
    }

    if (!ok) {
        cerr << "ERROR" << endl;
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
