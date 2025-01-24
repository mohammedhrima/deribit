#pragma once

#include <iostream>
#include <cstring>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fstream>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <thread>
#include <random>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <nlohmann/json.hpp>

#define PORT 17000
#define BUFFERSIZE 8192
#define MAX_EPOLL_EVENTS 10
// #define MAX_CONNECTIONS 10

#define CLIENT_ID "6ljNdSET"
#define CLIENT_SECRET "R08jkZ_yC7yzHfrl1o0MXxIlSZwmJ-AaboLOJqcNCgM"
#define DERIBIT_URL "test.deribit.com"
#define DERIBIT_PATH "/ws/api/v2"
#define DERIBIT_PORT 443

// COLORS
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define CYAN "\033[0;36m"
#define RESET "\033[0m"

using json = nlohmann::json;


class Error : public std::exception
{
private:
    std::string message;

public:
    Error(const char *msg) : message(msg) {};
    const char *what() const noexcept
    {
        return message.c_str();
    }
};

class Random
{
private:
    static constexpr char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static std::string base64Encode(const unsigned char *bytes_to_encode, size_t in_len)
    {
        std::string ret;
        int i = 0;
        int j = 0;
        unsigned char chars0[3];
        unsigned char chars1[4];
        while (in_len--)
        {
            chars0[i++] = *(bytes_to_encode++);
            if (i == 3)
            {
                chars1[0] = (chars0[0] & 0xfc) >> 2;
                chars1[1] = ((chars0[0] & 0x03) << 4) + ((chars0[1] & 0xf0) >> 4);
                chars1[2] = ((chars0[1] & 0x0f) << 2) + ((chars0[2] & 0xc0) >> 6);
                chars1[3] = chars0[2] & 0x3f;
                for (i = 0; i < 4; i++)
                    ret += base64_chars[chars1[i]];
                i = 0;
            }
        }
        if (i)
        {
            for (j = i; j < 3; j++)
                chars0[j] = '\0';
            chars1[0] = (chars0[0] & 0xfc) >> 2;
            chars1[1] = ((chars0[0] & 0x03) << 4) + ((chars0[1] & 0xf0) >> 4);
            chars1[2] = ((chars0[1] & 0x0f) << 2) + ((chars0[2] & 0xc0) >> 6);
            chars1[3] = chars0[2] & 0x3f;
            for (j = 0; j < i + 1; j++)
                ret += base64_chars[chars1[j]];
            while (i++ < 3)
                ret += '=';
        }
        return ret;
    }

public:
    static std::string key()
    {
        unsigned char random_bytes[16];
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (int i = 0; i < 16; ++i)
            random_bytes[i] = static_cast<unsigned char>(dis(gen));

        return base64Encode(random_bytes, sizeof(random_bytes));
    }
};