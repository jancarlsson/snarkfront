#!/bin/bash

case $# in
  5) PAIRING=$1 ; SHA_BITS=$2 ; DEPTH=$3 ; VEC_BLOCKS=$4 ; WIN_BLOCKS=$5 ;;
  6) PAIRING=$1 ; SHA_BITS=$2 ; DEPTH=$3 ; VEC_BLOCKS=$4 ; WIN_BLOCKS=$5 ; OPT=$6 ;;
  *) echo "usage: "$0" BN128|Edwards 256|512 <tree_depth> <vector_blocks> <window_blocks> [clearonly]" ;
     exit
esac

case $PAIRING in
  BN128) ;;
  Edwards) ;;
  *) echo "ERROR: invalid pairing "$PAIRING ;
     exit
esac

case $SHA_BITS in
  256) ;;
  512) ;;
  *) echo "ERROR: invalid number of SHA-2 bits "$SHA_BITS ;
     exit
esac

DIR=.
TMP=tmp_test_cli
VERBOSE=-v

CONSTRAINT_SYSTEM=$TMP.system
PROOF_INPUT=$TMP.input
PROOF_WITNESS=$TMP.witness
KEY_RAND=$TMP.keyrand
PROOF_RAND=$TMP.proofrand
MERKLE=$TMP.merkle
QAP_QUERY=$TMP.qapquery
PK_QUERY=$TMP.pkquery
QAP_WITNESS=$TMP.qapwitness
PK_WITNESS=$TMP.pkwitness

################################################################################
# create Merkle tree with a commitment leaf
#

echo create merkle tree
$DIR/test_bundle -p $PAIRING -b $SHA_BITS -t $MERKLE -d $DEPTH

CM_TEXT="some secret text"
CM_HASH=`echo $CM_TEXT | $DIR/test_sha -b $SHA_BITS`

echo add commitment leaf
$DIR/test_bundle -p $PAIRING -b $SHA_BITS -t $MERKLE -c $CM_HASH -k

################################################################################
# generate constraints from Merkle tree
#

echo generate constraint system \(may take a while\)
CONSTRAINTS_PER_FILE=250000
$DIR/test_bundle -p $PAIRING -b $SHA_BITS -t $MERKLE -s $CONSTRAINT_SYSTEM -n $CONSTRAINTS_PER_FILE

echo generate proof inputs
$DIR/test_bundle -p $PAIRING -b $SHA_BITS -t $MERKLE -i $PROOF_INPUT

echo generate proof witness
$DIR/test_bundle -p $PAIRING -b $SHA_BITS -t $MERKLE -w $PROOF_WITNESS

################################################################################
# sample entropy for key pair
#

echo key randomness \*\*\*destroy $KEY_RAND after use\*\*\*
$DIR/randomness -p $PAIRING -k -o $KEY_RAND

case $OPT in
  clearonly) ;;
  *) echo key randomness \(mostly blinded\) ;
     $DIR/randomness -p $PAIRING -B $KEY_RAND -o $KEY_RAND".blind"
esac

################################################################################
# quadratic arithmetic program ABCH query vectors
#

echo qap query A
$DIR/qap -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND -a $QAP_QUERY"A" -n $VEC_BLOCKS

echo qap query B
$DIR/qap -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND -b $QAP_QUERY"B" -n $VEC_BLOCKS

echo qap query C
$DIR/qap -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND -c $QAP_QUERY"C" -n $VEC_BLOCKS

echo qap query H
$DIR/qap -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND -h $QAP_QUERY"H" -n $VEC_BLOCKS

################################################################################
# window table dimensions
#

G1_EXP_COUNT=`$DIR/qap -p $PAIRING -s $CONSTRAINT_SYSTEM -a $QAP_QUERY"A" -b $QAP_QUERY"B" -c $QAP_QUERY"C" -h $QAP_QUERY"H"`
echo g1_exp_count $G1_EXP_COUNT

G2_EXP_COUNT=`$DIR/qap -p $PAIRING -s $CONSTRAINT_SYSTEM -b $QAP_QUERY"B"`
echo g2_exp_count $G2_EXP_COUNT

################################################################################
# quadratic arithmetic program K and input consistency query vectors
#

echo qap query K
$DIR/qap -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND -a $QAP_QUERY"A" -b $QAP_QUERY"B" -c $QAP_QUERY"C" -k $QAP_QUERY"K"

#
# note: side effect!
# QAP query vector A is modified by input consistency calculation
# this affects PPZK query vector K which reduces queries A, B, C
#

# make copy of query A before input consistency changes it
cp $QAP_QUERY"A" $QAP_QUERY"A.afterIC"
IDX=0
while [ $IDX -lt $VEC_BLOCKS ]
do
  cp $QAP_QUERY"A"$IDX $QAP_QUERY"A.afterIC"$IDX
  IDX=$[$IDX+1]
done

echo qap query input consistency
$DIR/qap -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND -a $QAP_QUERY"A.afterIC" -i $QAP_QUERY"IC"

################################################################################
echo
echo "***** PROVING KEY *****"

echo
echo -n ppzk query A
$DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND -1 $G1_EXP_COUNT -e $WIN_BLOCKS -o $PK_QUERY"A" -a $QAP_QUERY"A.afterIC" -m 0 -n $VEC_BLOCKS $VERBOSE

case $OPT in
  clearonly) ;;
  *) echo ; echo -n ppzk query A \(mostly blinded\) ;
     $DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND".blind" -1 $G1_EXP_COUNT -e $WIN_BLOCKS -o $PK_QUERY"A.blind" -a $QAP_QUERY"A.afterIC" -m 0 -n $VEC_BLOCKS $VERBOSE -B
esac

echo
echo -n ppzk query B
$DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND -1 $G1_EXP_COUNT -e $WIN_BLOCKS -2 $G2_EXP_COUNT -o $PK_QUERY"B" -b $QAP_QUERY"B" -m 0 -n $VEC_BLOCKS $VERBOSE

case $OPT in
  clearonly) ;;
  *) echo ; echo -n ppzk query B \(mostly blinded\) ;
     $DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND".blind" -1 $G1_EXP_COUNT -e $WIN_BLOCKS -2 $G2_EXP_COUNT -o $PK_QUERY"B.blind" -b $QAP_QUERY"B" -m 0 -n $VEC_BLOCKS $VERBOSE -B
esac

echo
echo -n ppzk query C
$DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND -1 $G1_EXP_COUNT -e $WIN_BLOCKS -o $PK_QUERY"C" -c $QAP_QUERY"C" -m 0 -n $VEC_BLOCKS $VERBOSE

case $OPT in
  clearonly) ;;
  *) echo ; echo -n ppzk query C \(mostly blinded\) ;
     $DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND".blind" -1 $G1_EXP_COUNT -e $WIN_BLOCKS -o $PK_QUERY"C.blind" -c $QAP_QUERY"C" -m 0 -n $VEC_BLOCKS $VERBOSE -B
esac

echo
echo -n ppzk query H
$DIR/ppzk -p $PAIRING -1 $G1_EXP_COUNT -e $WIN_BLOCKS -o $PK_QUERY"H" -h $QAP_QUERY"H" -m 0 -n $VEC_BLOCKS $VERBOSE

echo
echo -n ppzk query K
$DIR/ppzk -p $PAIRING -1 $G1_EXP_COUNT -e $WIN_BLOCKS -o $PK_QUERY"K" -k $QAP_QUERY"K" -m 0 -n $VEC_BLOCKS $VERBOSE

case $OPT in
  clearonly) ;;
  *) echo ; echo -n ppzk query K \(mostly blinded\) ;
     $DIR/ppzk -p $PAIRING -r $KEY_RAND".blind" -1 $G1_EXP_COUNT -e $WIN_BLOCKS -o $PK_QUERY"K.blind" -a $QAP_QUERY"A" -b $QAP_QUERY"B" -c $QAP_QUERY"C" -m 0 -n $VEC_BLOCKS $VERBOSE -B
esac

################################################################################
echo
echo "***** VERIFICATION KEY *****"

echo
echo -n ppzk query IC
$DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND -1 $G1_EXP_COUNT -e $WIN_BLOCKS -o $PK_QUERY"IC" -i $QAP_QUERY"IC" $VERBOSE
echo

case $OPT in
  clearonly) ;;
  *) echo ; echo -n ppzk query IC \(mostly blinded\) ;
     $DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $KEY_RAND".blind" -1 $G1_EXP_COUNT -e $WIN_BLOCKS -o $PK_QUERY"IC.blind" -i $QAP_QUERY"IC" $VERBOSE -B ;
     echo
esac

################################################################################
# reminder about key pair randomness
#
echo
echo \*\*\*$KEY_RAND no longer needed\*\*\*

################################################################################
echo
echo "***** PROOF *****"
echo

# sample entropy for proof
echo proof randomness \*\*\*destroy $PROOF_RAND after use\*\*\*
$DIR/randomness -p $PAIRING -o $PROOF_RAND
echo

echo qap witness
$DIR/qap -p $PAIRING -s $CONSTRAINT_SYSTEM -r $PROOF_RAND -w $PROOF_WITNESS -h $QAP_WITNESS -n $VEC_BLOCKS
echo

echo -n ppzk witness A
$DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $PROOF_RAND -w $PROOF_WITNESS -o $PK_WITNESS"A" -a $PK_QUERY"A" -m 0 -n $VEC_BLOCKS $VERBOSE
echo

case $OPT in
  clearonly) ;;
  *) echo -n ppzk witness A \(mostly blinded\) ;
     $DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $PROOF_RAND -w $PROOF_WITNESS -o $PK_WITNESS"A.blind" -a $PK_QUERY"A.blind" -m 0 -n $VEC_BLOCKS $VERBOSE ;
     echo
esac

echo -n ppzk witness B
$DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $PROOF_RAND -w $PROOF_WITNESS -o $PK_WITNESS"B" -b $PK_QUERY"B" -m 0 -n $VEC_BLOCKS $VERBOSE
echo

case $OPT in
  clearonly) ;;
  *) echo -n ppzk witness B \(mostly blinded\) ;
     $DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $PROOF_RAND -w $PROOF_WITNESS -o $PK_WITNESS"B.blind" -b $PK_QUERY"B.blind" -m 0 -n $VEC_BLOCKS $VERBOSE ;
     echo
esac

echo -n ppzk witness C
$DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $PROOF_RAND -w $PROOF_WITNESS -o $PK_WITNESS"C" -c $PK_QUERY"C" -m 0 -n $VEC_BLOCKS $VERBOSE
echo

case $OPT in
  clearonly) ;;
  *) echo -n ppzk witness C \(mostly blinded\) ;
     $DIR/ppzk -p $PAIRING -s $CONSTRAINT_SYSTEM -r $PROOF_RAND -w $PROOF_WITNESS -o $PK_WITNESS"C.blind" -c $PK_QUERY"C.blind" -m 0 -n $VEC_BLOCKS $VERBOSE ;
     echo
esac

echo -n ppzk witness H
$DIR/ppzk -p $PAIRING -o $PK_WITNESS"H" -h $PK_QUERY"H" -q $QAP_WITNESS -m 0 -n $VEC_BLOCKS $VERBOSE
echo

echo -n ppzk witness K
$DIR/ppzk -p $PAIRING -r $PROOF_RAND -w $PROOF_WITNESS -o $PK_WITNESS"K" -k $PK_QUERY"K" -m 0 -n $VEC_BLOCKS $VERBOSE
echo

case $OPT in
  clearonly) ;;
  *) echo -n ppzk witness K \(mostly blinded\) ;
     $DIR/ppzk -p $PAIRING -r $PROOF_RAND -w $PROOF_WITNESS -o $PK_WITNESS"K.blind" -k $PK_QUERY"K.blind" -m 0 -n $VEC_BLOCKS $VERBOSE ;
     echo
esac

echo \*\*\*$PROOF_RAND no longer needed\*\*\*

################################################################################
echo
echo "***** VERIFY *****"
echo

OK=`$DIR/verify -p $PAIRING -v $PK_QUERY"IC" -i $PROOF_INPUT -a $PK_WITNESS"A" -b $PK_WITNESS"B" -c $PK_WITNESS"C" -h $PK_WITNESS"H" -k $PK_WITNESS"K"`
case $OK in
  0) echo FAIL key pair entropy in clear ;;
  *) echo PASS key pair entropy in clear
esac

case $OPT in
  clearonly) ;;
  *) OKblind=`$DIR/verify -p $PAIRING -v $PK_QUERY"IC.blind" -i $PROOF_INPUT -a $PK_WITNESS"A.blind" -b $PK_WITNESS"B.blind" -c $PK_WITNESS"C.blind" -h $PK_WITNESS"H" -k $PK_WITNESS"K.blind"` ;
     case $OKblind in
       0) echo FAIL mostly blinded key pair entropy ;;
       *) echo PASS mostly blinded key pair entropy
    esac
esac
