#!/bin/bash

set -euo pipefail

git clone https://github.com/trailofbits/cb-multios
cd cb-multios; git checkout ad6695055cbfc13d8daf1def79f44f0c6e4cb858
mv challenges all-challenges; mkdir -p challenges/Palindrome; cp -r all-challenges/Palindrome challenges
mkdir obj-aflgo; mkdir obj-aflgo/temp
export TMP_DIR=$PWD/obj-aflgo/temp
export CC=$AFLGO/instrument/aflgo-clang; export CXX=$AFLGO/instrument/aflgo-clang++
export LDFLAGS=-lpthread
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
echo $'service.c:65' > $TMP_DIR/BBtargets.txt
LINK=STATIC CFLAGS="$ADDITIONAL" CXXFLAGS="$ADDITIONAL" ./build.sh
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt
cd build/challenges/Palindrome; $AFLGO/distance/gen_distance_orig.sh $PWD $TMP_DIR Palindrome
cd -; rm -rf build; LINK=STATIC CFLAGS="-g -distance=$TMP_DIR/distance.cfg.txt" CXXFLAGS="-g -distance=$TMP_DIR/distance.cfg.txt" ./build.sh
cd -; mkdir in; echo "" > in/in
$AFLGO/afl-2.57b/afl-fuzz -m none -z exp -c 45m -i in -o out ./Palindrome