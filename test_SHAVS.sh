#!/bin/bash

case $# in
  1) DIR=$1 ;;
  0) echo "usage: "$0" path_to_SHAVS_byte_test_vector_files"
     exit
esac

for BITS in 1 224 256 384 512
do
  echo
  echo "SHA"$BITS" Monte Carlo"
  cat $DIR"/SHA"$BITS"Monte.txt" | ./test_SHAVS -p BN128 -b $BITS
done

for BITS in 1 224 256 384 512
do
  echo
  echo "SHA"$BITS" short messages"
  cat $DIR"/SHA"$BITS"ShortMsg.rsp" | ./test_SHAVS -p BN128 -b $BITS
done

for BITS in 1 224 256 384 512
do
  echo
  echo "SHA"$BITS" long messages"
  cat $DIR"/SHA"$BITS"LongMsg.rsp" | ./test_SHAVS -p BN128 -b $BITS
done
