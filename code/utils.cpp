#include "./includes/header.hpp"

Error::Error(const char *msg) : message(msg) {}

const char *Error::what() const noexcept
{
    return message.c_str();
}

std::string Random::base64Encode(const unsigned char *bytes_to_encode, size_t in_len)
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

std::string Random::key()
{
    unsigned char random_bytes[16];
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 16; ++i)
        random_bytes[i] = static_cast<unsigned char>(dis(gen));

    return base64Encode(random_bytes, sizeof(random_bytes));
}

bool starts_with(const std::string &str, const std::string &prefix)
{
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

std::string trim(const std::string s)
{
    size_t start = s.find_first_not_of(" \t\n");
    size_t end = s.find_last_not_of(" \t\n");
    return (start == std::string::npos) ? s : s.substr(start, end - start + 1);
}

std::map<std::string, std::string> parse_query_string(const std::string &query)
{
    std::map<std::string, std::string> params;

    size_t start = 0;
    size_t end = query.find('&');

    while (end != std::string::npos)
    {
        std::string pair = query.substr(start, end - start);

        size_t equal_pos = pair.find('=');
        if (equal_pos != std::string::npos)
        {
            std::string key = pair.substr(0, equal_pos);
            std::string value = pair.substr(equal_pos + 1);
            params[key] = value;
        }

        start = end + 1;
        end = query.find('&', start);
    }

    std::string last_pair = trim(query.substr(start));
    size_t equal_pos = last_pair.find('=');
    if (equal_pos != std::string::npos)
    {
        std::string key = last_pair.substr(0, equal_pos);
        std::string value = last_pair.substr(equal_pos + 1);
        params[key] = value;
    }
    std::cout << RED << "queries: <" << query << ">" << RESET << std::endl;
    return params;
}

std::string generate_html(int status_code, const std::string &cause)
{
    std::ostringstream html;

    html << "<!DOCTYPE html>\n"
         << "<html lang=\"en\">\n"
         << "<head>\n"
         << "    <meta charset=\"UTF-8\">\n"
         << "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
         << "    <title>" << status_code << "</title>\n"
         << "    <style>\n"
         << "        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }\n"
         << "        .container { text-align: center; padding: 50px; }\n"
         << "        h1 { font-size: 50px; color: #333; }\n"
         << "        p { font-size: 20px; color: #666; }\n"
         << "    </style>\n"
         << "</head>\n"
         << "<body>\n"
         << "    <div class=\"container\">\n";

    // Correctly handle the conditional logic
    if (status_code > 200)
        html << "        <h1>Error " << status_code << "</h1>\n";
    else
        html << "        <h1>" << status_code << "</h1>\n";

    html << "        <p>" << cause << "</p>\n"
         << "    </div>\n"
         << "</body>\n"
         << "</html>\n";

    return html.str();
}

std::string get_mime_type(const std::string &path)
{
    size_t dot_pos = path.rfind('.');
    if (dot_pos == std::string::npos)
        return "application/octet-stream";

    std::string extension = path.substr(dot_pos);

    if (extension == ".html")
        return "text/html";
    if (extension == ".css")
        return "text/css";
    if (extension == ".js")
        return "application/javascript";
    if (extension == ".json")
        return "application/json";
    if (extension == ".jpg" || extension == ".jpeg")
        return "image/jpeg";
    if (extension == ".png")
        return "image/png";
    if (extension == ".gif")
        return "image/gif";
    if (extension == ".svg")
        return "image/svg+xml";

    return "application/octet-stream";
}

double to_double(const std::string &str)
{
    std::istringstream iss(str);
    double value = 0.0;
    iss >> value;
    return value;
}