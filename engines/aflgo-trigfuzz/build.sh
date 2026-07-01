#!/bin/bash

if command -v sudo &> /dev/null
then
    apt_get="sudo apt-get"
else
    apt_get="apt-get"
fi

set -euo pipefail # exit on error

cd $( dirname "${BASH_SOURCE[0]}" ) # go to where build.sh is located

######################################
### Build and install clang & LLVM ###
######################################

export DEBIAN_FRONTEND=noninteractive # jump over "Configuring tzdata"
export LC_ALL=C

$apt_get update

LLVM_DEP_PACKAGES="build-essential make cmake ninja-build git binutils-gold binutils-dev curl wget python3"
$apt_get install -y $LLVM_DEP_PACKAGES

export CXX=g++
export CC=gcc
unset CFLAGS
unset CXXFLAGS

pushd instrument

mkdir -p llvm_tools

pushd llvm_tools

wget -O llvm-11.0.0.src.tar.xz https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0/llvm-11.0.0.src.tar.xz
tar -xf llvm-11.0.0.src.tar.xz
mv      llvm-11.0.0.src        llvm

wget -O  clang-11.0.0.src.tar.xz https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0/clang-11.0.0.src.tar.xz
tar -xf  clang-11.0.0.src.tar.xz
mv       clang-11.0.0.src        clang

wget -O compiler-rt-11.0.0.src.tar.xz https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0/compiler-rt-11.0.0.src.tar.xz
tar -xf compiler-rt-11.0.0.src.tar.xz
mv      compiler-rt-11.0.0.src        compiler-rt

mkdir -p build

pushd build

cmake -G "Ninja" \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_TARGETS_TO_BUILD="X86" \
      -DLLVM_BINUTILS_INCDIR=/usr/include \
      -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" \
      -DLLVM_BUILD_TESTS=OFF \
      -DLLVM_INCLUDE_TESTS=OFF \
      -DLLVM_BUILD_BENCHMARKS=OFF \
      -DLLVM_INCLUDE_BENCHMARKS=OFF \
      ../llvm
ninja; ninja install

popd # go to llvm_tools

popd # go to instrument

popd # go to where build.sh is located

#######################################
### Install LLVMgold in bfd-plugins ###
#######################################

mkdir -p /usr/lib/bfd-plugins
cp /usr/local/lib/libLTO.so /usr/lib/bfd-plugins
cp /usr/local/lib/LLVMgold.so /usr/lib/bfd-plugins

#############################
### Install some packages ###
#############################

$apt_get install -y python3-dev python3-pip pkg-config autoconf automake libtool-bin gawk libboost-all-dev

# See https://networkx.org/documentation/stable/release/index.html
case `python3 -c 'import sys; print(sys.version_info[:][1])'` in
    [01])
        python3 -m pip install 'networkx<1.9';;
    2)
        python3 -m pip install 'networkx<1.11';;
    3)
        python3 -m pip install 'networkx<2.0';;
    4)
        python3 -m pip install 'networkx<2.2';;
    5)
        python3 -m pip install 'networkx<2.5';;
    6)
        python3 -m pip install 'networkx<2.6';;
    7)
        python3 -m pip install 'networkx<2.7';;
    8)
        python3 -m pip install 'networkx<=3.1';;
    *)
        python3 -m pip install networkx;;
esac
python3 -m pip install pydot pydotplus

##############################
### Build AFLGo components ###
##############################

export CXX=`which clang++`
export CC=`which clang`
export LLVM_CONFIG=`which llvm-config`

pushd afl-2.57b
make clean all
popd

pushd instrument
make clean all
popd

pushd distance/distance_calculator
cmake ./
cmake --build ./
popd

echo -e '\x1b[0;36mAFLGo (yeah!) \x1b[0;32mbuild is done \x1b[0m'
#########   cCYA   #############    cGRN   ############# cRST ###
