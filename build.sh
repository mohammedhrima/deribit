#!/usr/bin/bash

# use Wall Werror Wextra
CELLAR="/home/mhrima/.brew/Cellar"
OPENSSL="$CELLAR/openssl@3/3.4.0"

c++ main.cpp -I$OPENSSL/include/ -L$OPENSSL/lib -lssl -lcrypto -L$CELLAR/base64/1.5/bin