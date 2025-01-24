#include "./includes/header.hpp"

int main()
{
    try
    {
        Api api(DERIBIT_PATH, DERIBIT_URL, DERIBIT_PORT);
        api.init();
        api.handshake();

        Server server(PORT);
        server.init();
        server.start(api);
    }
    catch (Error &error)
    {
        std::cerr << "Error: " << error.what() << std::endl;
    }
}
