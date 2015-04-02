#include <cstdlib>
#include <iostream>
#include <string>
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
        A = " -a file",
        B = " -b file",
        C = " -c file",
        H = " -h file",
        K = " -k file",
        IC = " -i file",
        WIT = " -w witness_file";

    cout << endl << "QAP query generation:" << endl
         << "  A:  " << exeName << PAIR << SYS << R << A << N << endl
         << "  B:  " << exeName << PAIR << SYS << R << B << N << endl
         << "  C:  " << exeName << PAIR << SYS << R << C << N << endl
         << "  H:  " << exeName << PAIR << SYS << R << H << N << endl
         << "  K:  " << exeName << PAIR << SYS << R << A << B << C << K << optN << endl
         << "  IC: " << exeName << PAIR << SYS << R << A << IC << endl
         << endl << "window table exponent count:" << endl
         << "  g1_exp_count: " << exeName << PAIR << SYS << A << B << C << H << endl
         << "  g2_exp_count: " << exeName << PAIR << SYS << B << endl
         << endl << "QAP witness generation:" << endl
         << "  ABCH: " << exeName << PAIR << SYS << R << WIT << H << N << endl;

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

template <typename PAIRING>
bool witnessABCH(const std::string& hfile,
                 const std::size_t blocknum,
                 const std::string& sysfile,
                 const std::string& randfile,
                 const std::string& witfile)
{
    QAP_witness_ABCH<PAIRING> query(blocknum, sysfile, randfile, witfile);
    query.writeFiles(hfile);
    return !!query;
}

template <typename PAIRING>
bool cmdSwitch(const string& sysfile,
               const string& randfile,
               const string& afile,
               const string& bfile,
               const string& cfile,
               const string& hfile,
               const string& kfile,
               const string& icfile,
               const string& witfile,
               const size_t blocknum)
{
    bool ok = false;

    if (! witfile.empty()) {
        ok = witnessABCH<PAIRING>(hfile, blocknum, sysfile, randfile, witfile);

    } else if (! kfile.empty()) {
        ok = queryK<PAIRING>(afile, bfile, cfile, kfile, blocknum, sysfile, randfile);

    } else if (! icfile.empty()) {
        ok = queryIC<PAIRING>(afile, icfile, sysfile, randfile);

    } else if (-1 != blocknum) {
        ok = queryABCH<PAIRING>(afile, bfile, cfile, hfile, blocknum, sysfile, randfile);

    } else {
        QAP_query_ABCH<PAIRING> query(sysfile);
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

    return ok;
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "psrabchkiw", "n", "");
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
        icfile = cmdLine.getString('i'),
        witfile = cmdLine.getString('w');

    const auto blocknum = cmdLine.getNumber('n');

    if (!validPairingName(pairing)) {
        cerr << "error: elliptic curve pairing " << pairing << endl;
        exit(EXIT_FAILURE);
    }

    bool ok = false;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        ok = cmdSwitch<BN128_PAIRING>(sysfile, randfile,
                                      afile, bfile, cfile, hfile, kfile, icfile,
                                      witfile,
                                      blocknum);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        ok = cmdSwitch<EDWARDS_PAIRING>(sysfile, randfile,
                                        afile, bfile, cfile, hfile, kfile, icfile,
                                        witfile,
                                        blocknum);
    }

    if (!ok) {
        cerr << "ERROR" << endl;
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
