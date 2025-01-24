#pragma once

#include "./header.hpp"


using json = nlohmann::json;
typedef struct timeval timeval;
typedef struct hostent hostent;
typedef struct sockaddr_in sockaddr_in;

class Error : public std::exception
{
private:
    std::string message;

public:
    explicit Error(const char *msg);
    const char *what() const noexcept override;
};


class Random
{
private:
    static constexpr char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static std::string base64Encode(const unsigned char *bytes_to_encode, size_t in_len);

public:
    static std::string key();
};

bool starts_with(const std::string &str, const std::string &prefix);
std::string trim(const std::string s);
std::map<std::string, std::string> parse_query_string(const std::string &query);
std::string generate_html(int status_code, const std::string &cause);
std::string get_mime_type(const std::string &path);
double to_double(const std::string &str);