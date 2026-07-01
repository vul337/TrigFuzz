#!/bin/bash

set -euo pipefail

git clone https://github.com/cesanta/mjs.git mjs-issues-57
cd mjs-issues-57; git checkout d6c06a6
mkdir obj-aflgo; mkdir obj-aflgo/temp
export TMP_DIR=$PWD/obj-aflgo/temp
export CC=$AFLGO/instrument/aflgo-clang; export CXX=$AFLGO/instrument/aflgo-clang++
export LDFLAGS=-lpthread
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
echo $'mjs.c:13732' > $TMP_DIR/BBtargets.txt
$CC -DMJS_MAIN mjs.c $ADDITIONAL -ldl -g -o mjs-bin
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt
$AFLGO/distance/gen_distance_orig.sh $PWD $TMP_DIR mjs-bin
$CC -DMJS_MAIN mjs.c -distance=$TMP_DIR/distance.cfg.txt -ldl -g -o mjs-bin
cd obj-aflgo; mkdir in; echo "" > in/in
$AFLGO/afl-2.57b/afl-fuzz -m none -z exp -c 45m -i in -o out ../mjs-bin -f @@
# mkdir out; for i in {1..10}; do timeout -sHUP 180m $AFLGO/afl-2.57b/afl-fuzz -m none -z exp -c 45m -i in -o "out/out_$i" ../mjs-bin -f @@ > /dev/null 2>&1 & done