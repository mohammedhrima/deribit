#!/usr/bin/bash

FILE="main.cpp api.cpp request.cpp server.cpp utils.cpp"

CELLAR="$HOME/.brew/Cellar"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$HOME/.brew/Cellar/boost/1.87.0/lib"

OPENSSL="$CELLAR/openssl@3/3.4.0"
BOOST="$CELLAR/boost/1.87.0"
NLOHMANN="$CELLAR/nlohmann-json/3.11.3"

INCLUDES=""
INCLUDES+="-I$OPENSSL/include/ "
INCLUDES+="-I$BOOST/include/ "
INCLUDES+="-I$NLOHMANN/include/ " 

LIBS=""
LIBS+="-L$OPENSSL/lib " 
# LIBS+="-L$BOOST/lib -lboost_json "
LIBS+=" -lssl -lcrypto "

FLAGS="-fsanitize=address -fsanitize=null -g3"

# Compile the code
rm -rf a.out
c++ $FLAGS $FILE $INCLUDES $LIBS
