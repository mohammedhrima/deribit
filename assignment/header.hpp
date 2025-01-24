#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>
#include <random>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <nlohmann/json.hpp>

#define PORT 5000
#define MAX_CONNECTIONS 10

#define BUFFERSIZE 4096
#define CLIENT_ID ""
#define CLIENT_SECRET ""
#define DERIBIT_URL "test.deribit.com"
#define DERIBIT_PATH "/ws/api/v2"
#define DERIBIT_PORT 443

typedef struct timeval timeval;
typedef struct hostent hostent;
typedef struct sockaddr_in sockaddr_in;
