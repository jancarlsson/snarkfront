#!/bin/bash

rm -f keygen.txt input.txt proof.txt

echo
time ./test_proof -m keygen > keygen.txt
ls -l keygen.txt

echo
time ./test_proof -m input > input.txt
ls -l input.txt

echo
time cat keygen.txt input.txt | ./test_proof -m proof > proof.txt
ls -l proof.txt

echo
time cat keygen.txt input.txt proof.txt | ./test_proof -m verify
