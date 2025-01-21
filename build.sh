#!/usr/bin/bash

file=${1:-"main.cpp"}

CELLAR="/home/mhrima/.brew/Cellar"
OPENSSL="$CELLAR/openssl@3/3.4.0"
# BOOST="$CELLAR/boost/1.87.0"
# BASE64="$CELLAR/base64/1.5"
 
INCLUDES="-I$OPENSSL/include/ -L$OPENSSL/lib -lssl -lcrypto "
FLAGS="-std=c++11"

c++ "$file" $FLAGS $INCLUDES


# brew install openssl@3