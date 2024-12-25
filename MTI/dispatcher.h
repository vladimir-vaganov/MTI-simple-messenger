#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/dh.h>

#define MY_PREFIX       "[ YOU -> OTHER ] "
#define FOREIGN_PREFIX  "[ OTHER -> YOU ] "

#pragma comment(lib, "Ws2_32.lib")

#define BUFFER_SIZE 1024

class Dispatcher {
private:
    SOCKET serverSocket;
    std::string address;

    unsigned long listenPort, sendPort;
    BIGNUM* g;
    BIGNUM* p;
    BIGNUM* myPublicKey;
    BIGNUM* foreignPublicKey;
    BIGNUM* myPrivateKey;
    BIGNUM* myRandomNumber;
    BIGNUM* myPartOfSecretKey;
    BIGNUM* foreignPartOfSecretKey;
    BIGNUM* commonSecretKey;
    BIGNUM* encryptionKey;
    BN_CTX* ctx;

    void createListenSocket();
    void waitForSecondAbonent();

    void setPreMtiParameters();
    void sendMyPublicKey();
    void getForeignPublicKey();
    void sendPartOfSecretKey();
    void getForeignPartOfSecretKey();
    void formSecretKey();

    std::string encryptMessage(const std::string& plaintext);
    std::string decryptMessage(const std::string& ciphertext);

public:
    Dispatcher(std::string address, unsigned long listenPort, unsigned long sendPort);
    ~Dispatcher();

    void sendPlainMessage(const std::string& msg);
    void sendEncryptedMessage(const std::string& msg);

    void tryToGetEncryptedMessage();
};
