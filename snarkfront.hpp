#ifndef _SNARKFRONT_HPP_
#define _SNARKFRONT_HPP_

////////////////////////////////////////////////////////////////////////////////
// this header file includes everything applications need
//

// not part of the EDSL but convenient for command line applications
#include <snarkfront/CompilePPZK_query.hpp>
#include <snarkfront/CompilePPZK_witness.hpp>
#include <snarkfront/CompileQAP.hpp>
#include <snarkfront/Getopt.hpp>

// read and write useful types for applications
#include <snarkfront/Serialize.hpp>

// the basic language
#include <snarkfront/DSL_algo.hpp>
#include <snarkfront/DSL_base.hpp>
#include <snarkfront/DSL_bless.hpp>
#include <snarkfront/DSL_identity.hpp>
#include <snarkfront/DSL_ppzk.hpp>
#include <snarkfront/DSL_utility.hpp>

// progress bar for proof generation and verification
#include <snarkfront/GenericProgressBar.hpp>

// input and printing of hexadecimal text
#include <snarkfront/HexDumper.hpp>

// initialize elliptic curves
#include <snarkfront/InitPairing.hpp>

// Merkle tree
#include <snarkfront/MerkleAuthPath.hpp>
#include <snarkfront/MerkleBundle.hpp>
#include <snarkfront/MerkleTree.hpp>

#endif
