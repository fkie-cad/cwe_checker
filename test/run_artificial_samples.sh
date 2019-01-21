#!/bin/bash

function printf_new() {
 v=$(printf "%-80s" "-")
 echo "${v// /-}"
}

function run_arch() {
    echo
    echo
    echo "Running architecture:" $1
    printf_new
    echo "cwe_190_$1"
    printf_new
    bap artificial_samples/build/cwe_190_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json
    printf_new
    echo "cwe_243_$1"
    printf_new
    bap artificial_samples/build/cwe_243_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json
    printf_new
    echo "cwe_243_$1 (clean)"
    printf_new
    bap artificial_samples/build/cwe_243_clean_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json
    printf_new
    echo "cwe_248_$1"
    printf_new
    bap artificial_samples/build/cwe_248_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json
    printf_new
    echo "cwe_323_$1"
    printf_new
    bap artificial_samples/build/cwe_332_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json 
    printf_new
    echo "cwe_367_$1"
    printf_new
    bap artificial_samples/build/cwe_367_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json 
    printf_new
    echo "cwe_415_$1"
    printf_new
    bap artificial_samples/build/cwe_415_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json 
    printf_new 
    echo "cwe_426_$1"
    printf_new
    bap artificial_samples/build/cwe_426_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json
    printf_new
    echo "cwe_457_$1"
    printf_new
    bap artificial_samples/build/cwe_457_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json
    printf_new
    echo "cwe_467_$1"
    printf_new
    bap artificial_samples/build/cwe_467_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json 
    printf_new
    echo "cwe_476_$1"
    printf_new
    bap artificial_samples/build/cwe_476_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json
    printf_new
    if [ $1 == "x64" ]; then
    echo "cwe_782_$1"
    printf_new
    bap artificial_samples/build/cwe_782_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json
    printf_new
    fi
    echo "c_constructs_$1"
    printf_new
    bap artificial_samples/build/c_constructs_$1.out  --pass=callsites,cwe-checker --cwe-checker-config=../src/config.json 
    printf_new
}

function run_all_arch() {
run_arch x86
run_arch x64
run_arch arm
run_arch mips
run_arch ppc
}

function main() {
    if [ -z "$1" ]; then
	run_all_arch
    else
	run_arch $1
    fi 
}

main "$@"
