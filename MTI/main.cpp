#include "dispatcher.h"

void funcListener(Dispatcher& App) {
    while (true) {
        App.tryToGetEncryptedMessage();
    }
}

void funcSender(Dispatcher& App) {
    std::string message;

    while (true) {
        std::cout << MY_PREFIX;
        std::getline(std::cin, message);

        App.sendEncryptedMessage(message);
    }
}

void getOptions(int argc, char* argv[], std::string& address, unsigned long& listenPort, unsigned long& sendPort) {
    if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        std::cout << "Flags:" << std::endl << std::endl;
        std::cout << "1. IP-address of second abonent" << std::endl;
        std::cout << "2. Port to recieve data (from 2nd abonent)" << std::endl;
        std::cout << "3. Port to send data (to 2nd abonent)" << std::endl;
        std::cout << std::endl << "Example of usage:" << std::endl << std::endl;
        std::cout << ".\\MTI.exe 127.0.0.1 12341 12342" << std::endl;
    }
    else
    if (argc == 4) {
        address = std::string(argv[1]);
        listenPort = std::stoi(argv[2]);
        sendPort = std::stoi(argv[3]);
    }
}

int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "Russian");

    // Разбор аргументов
    unsigned long listenPort = 0, sendPort = 0;
    std::string address = "";

    getOptions(argc, argv, address, listenPort, sendPort);

    if (listenPort == 0 || sendPort == 0 || address.empty())
        return 0;

    // Создание сокетов и начало прослушивания
    Dispatcher dispatcher(address, listenPort, sendPort);

    std::thread detachedListener(funcListener, std::ref(dispatcher));
    funcSender(dispatcher);

    return 0;
}