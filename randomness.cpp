#include <cstdlib>
#include <fstream>
#include <iostream>
#include <ostream>
#include <string>
#include "Getopt.hpp"
#include "snarkfront.hpp"

using namespace snarkfront;
using namespace snarklib;
using namespace std;

void printUsage(const char* exeName) {
    const string
        PAIR = " -p BN128|Edwards",
        CLEAR_KEY = " -k",
        BLIND_KEY = " -B clear_file",
        OUT = " [-o output_file]";

    // note: random sample point for Lagrange coefficients is not blinded

    cout << "generate key pair entropy: " << exeName << PAIR << CLEAR_KEY << OUT << endl
         << "blind key pair entropy:    " << exeName << PAIR << BLIND_KEY << OUT << endl
         << "proof entropy:             " << exeName << PAIR << OUT << endl;

    exit(EXIT_FAILURE);
}

template <typename PAIRING>
void writeEntropy(ostream& os,
                  const bool is_clear_keypair,
                  const string& blind)
{
    typedef typename PAIRING::Fr Fr;
    typedef typename PAIRING::G1 G1;
    typedef typename PAIRING::G2 G2;

    if (is_clear_keypair) {
        PPZK_LagrangePoint<Fr> lagrangeRand(0);
        PPZK_BlindGreeks<Fr, Fr> blindRand(0);
        os << lagrangeRand << blindRand;

    } else if (!blind.empty()) {
        PPZK_LagrangePoint<Fr> lagrangePoint;
        PPZK_BlindGreeks<Fr, Fr> clearGreeks;

        ifstream ifs(blind);
        if (!ifs || !lagrangePoint.marshal_in(ifs) || !clearGreeks.marshal_in(ifs)) {
            cerr << "error: corrupt key pair" << endl;
            exit(EXIT_FAILURE);
        }

        const PPZK_BlindGreeks<Fr, Pairing<G1, G2>> blindGreeks(clearGreeks);
        os << lagrangePoint << blindGreeks;

    } else {
        PPZK_ProofRandomness<typename PAIRING::Fr> entropy(0);
        os << entropy;
    }
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "poB", "", "k");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    const auto pairing = cmdLine.getString('p');
    const auto outfile = cmdLine.getString('o');
    const auto blind = cmdLine.getString('B');
    const auto is_clear_keypair = cmdLine.getFlag('k');

    if (!validPairingName(pairing)) {
        cerr << "error: elliptic curve pairing " << pairing << endl;
        exit(EXIT_FAILURE);
    }

    if (is_clear_keypair && !blind.empty()) {
        cerr << "error: generate and blind are mutually exclusive" << endl;
        exit(EXIT_FAILURE);
    }

    ofstream ofs(outfile);
    if (!outfile.empty() && !ofs) {
        cerr << "error: output file " << outfile << endl;
        exit(EXIT_FAILURE);
    }

    ostream& os = outfile.empty() ? cout : ofs;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        writeEntropy<BN128_PAIRING>(os, is_clear_keypair, blind);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        writeEntropy<EDWARDS_PAIRING>(os, is_clear_keypair, blind);
    }

    exit(EXIT_SUCCESS);
}
