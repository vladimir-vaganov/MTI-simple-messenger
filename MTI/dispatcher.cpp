#include "dispatcher.h"

static BIGNUM* hashBigNum(BIGNUM* input) {
    // �������� ������ �������� ����� � ������
    int numBytes = BN_num_bytes(input);

    // �������� ������ ��� ������ ���� ��� ������������� �����
    unsigned char* data = new unsigned char[numBytes];

    // ������������ ����� � �������� ������
    BN_bn2bin(input, data);

    // �������� ������ � �������������� SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, numBytes, hash);

    // ����������� ���������� ����� ������
    delete[] data;

    // ������� ����� BIGNUM ��� �������� ����������
    BIGNUM* result = BN_new();

    // ������������ ��� ������� � BIGNUM
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, result);

    return result;
}

static void printBnHex(const BIGNUM* num) {
    char* hexStr = BN_bn2hex(num);
    std::cout << hexStr << std::endl;
    OPENSSL_free(hexStr);
}

static void printBnDec(const BIGNUM* num) {
    char* hexStr = BN_bn2dec(num);
    std::cout << hexStr << std::endl;
    OPENSSL_free(hexStr);
}

Dispatcher::Dispatcher(std::string address, unsigned long listenPort, unsigned long sendPort) {
    // ������������� OpenSSL
    OpenSSL_add_all_algorithms();

    // ������������� ���������� WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "������ ������������� WinSock." << std::endl;
    }

    this->setPreMtiParameters();

    serverSocket = 0;

    this->listenPort = listenPort;
    this->sendPort = sendPort;

    this->createListenSocket();
    this->waitForSecondAbonent();
    this->sendMyPublicKey();
    this->getForeignPublicKey();
    this->sendPartOfSecretKey();
    this->getForeignPartOfSecretKey();
    this->formSecretKey();
}

Dispatcher::~Dispatcher() {
    closesocket(serverSocket);
    // ���������� ������ � ����������� WinSock
    WSACleanup();
}

void Dispatcher::setPreMtiParameters() {
    ctx = BN_CTX_new();

    g = BN_new();
    p = BN_new();
    myPublicKey = BN_new();
    foreignPublicKey = BN_new();
    myPrivateKey = BN_new();
    myRandomNumber = BN_new();
    myPartOfSecretKey = BN_new();
    foreignPartOfSecretKey = BN_new();
    commonSecretKey = BN_new();

    // ������� ����� p RSA-617
    BN_dec2bn(&p, "22701801293785014193580405120204586741061235962766583907094021879215171483119139894870133091111044901683400949483846818299518041763507948922590774925466088171879259465921026597046700449819899096862039460017743094473811056991294128542891880855362707407670722593737772666973440977361243336397308051763091506836310795312607239520365290032105848839507981452307299417185715796297454995023505316040919859193718023307414880446217922800831766040938656344571034778553457121080530736394535923932651866030515041060966437313323672831539323500067937107541955437362433248361242525945868802353916766181532375855504886901432221349733");  // ������ �������� ����� p = 17

    // ����������� ������� g ������ Zp
    BN_dec2bn(&g, "8899392726716985012063889918058762837525207704320505965401875702626699056966707734469473823640144121411234364248580448082896546406492251415381255327375977759567669183797381701077853858233798428497414228358352129056465124894768728928407579592224435044676603520268903898733521644289612700788672335661583677984629345286127696935022130027333313720902509509725366779413949886383644564731598317985248403145794628982918336281564650142020032406841555252580054416580474709341486128628201418757573368910979745736391962862742857546329613198445654245463558045656251974442471243214667799788571273672866760570370870928604617814367");

    // ��������� ��������� �����
    BN_rand(myPrivateKey, 2048, 0, 0);

    // ��������� ��������� �����
    BN_mod_exp(myPublicKey, g, myPrivateKey, p, ctx);

    // ��������� ���������� �����
    BN_rand(myRandomNumber, 2048, 0, 0);

    // ����������� ��������� �� ��������
    BN_mod_exp(myPartOfSecretKey, g, myRandomNumber, p, ctx);
}

void Dispatcher::createListenSocket()
{
    // �������� ������
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "�� ������� ������� �����: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return;
    }

    // ��������� ������ ��������������� ������
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(listenPort);

    // �������� ������ � ������
    if (bind(serverSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "������ �������� ������: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    // ������� � ����� �������������
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "������ ��� �������� � ����� �������������: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return;
    }
}

void Dispatcher::waitForSecondAbonent()
{
    // �������� ������
    SOCKET secondAbonentSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (secondAbonentSocket == INVALID_SOCKET) {
        std::cerr << "�� ������� ������� �����: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return;
    }

    // ��������� ������ ������� ��������
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(sendPort);

    std::cout << "������� ����������� ������� ��������..." << std::endl;

    // �������� ������� ��������
    while (true) {
        if (connect(secondAbonentSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
            continue;
        else
            break;
    }

    std::cout << "���������� � ������� ��������!" << std::endl;

    closesocket(secondAbonentSocket);

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
}

void Dispatcher::sendPlainMessage(const std::string& msg) {
    // �������� ��������� ������� ������������

    // �������� ������
    SOCKET secondAbonentSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (secondAbonentSocket == INVALID_SOCKET) {
        std::cerr << "�� ������� ������� �����: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return;
    }

    // ��������� ������ ������� ��������
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(sendPort);

    if (connect(secondAbonentSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cout << "������ �������� ���������" << std::endl;
        return;
    }

    if (send(secondAbonentSocket, msg.c_str(), msg.length(), 0) == SOCKET_ERROR) {
        std::cerr << "������ �������� ������: " << WSAGetLastError() << std::endl;
    }
}

void Dispatcher::sendEncryptedMessage(const std::string& msg) {
    std::string encryptedMessage = this->encryptMessage(msg);
    this->sendPlainMessage(encryptedMessage);
}

void Dispatcher::tryToGetEncryptedMessage() {
    // �������� ������ ����������
    SOCKET tmpSocket = accept(serverSocket, NULL, NULL);
    if (tmpSocket == INVALID_SOCKET) {
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytesReceived;

    memset(buffer, 0, BUFFER_SIZE);
    bytesReceived = recv(tmpSocket, buffer, BUFFER_SIZE, 0);

    if (bytesReceived > 0) {
        std::string message = decryptMessage(std::string(buffer));
        std::cout << "\r\r" << FOREIGN_PREFIX << message << std::endl;
        std::cout << MY_PREFIX;

        // �������� ���������� � ��������
        closesocket(tmpSocket);
        return;
    }
}

void Dispatcher::sendMyPublicKey() {
    char* pbPublicKey = BN_bn2dec(myPublicKey);

    this->sendPlainMessage(std::string(pbPublicKey));

    OPENSSL_free(pbPublicKey);
}

void Dispatcher::getForeignPublicKey() {
    // ��� ������ ���������� � ��������� ������ ������, ����������� �� ��� �������� ���� ������� ��������

    while (true) {
        // �������� ������ ����������
        SOCKET tmpSocket = accept(serverSocket, NULL, NULL);
        if (tmpSocket == INVALID_SOCKET) {
            continue;
        }

        char buffer[BUFFER_SIZE];
        int bytesReceived;

        // ��������� ��������� �� �������
        do {
            memset(buffer, 0, BUFFER_SIZE);
            bytesReceived = recv(tmpSocket, buffer, BUFFER_SIZE, 0);
            if (bytesReceived > 0) {
                BN_dec2bn(&foreignPublicKey, buffer);
                closesocket(tmpSocket);
                return;
            }

        } while (bytesReceived > 0);

        // �������� ���������� � ��������
        closesocket(tmpSocket);
    }
}

void Dispatcher::sendPartOfSecretKey() {
    char* pbPartOfSecretKey = BN_bn2dec(myPartOfSecretKey);

    this->sendPlainMessage(std::string(pbPartOfSecretKey));

    OPENSSL_free(pbPartOfSecretKey);
}

void Dispatcher::getForeignPartOfSecretKey() {
    // ��� ������ ���������� � ��������� ������ ������, ����������� �� ��� ����� ������ ����� �� ������� ��������

    while (true) {
        // �������� ������ ����������
        SOCKET tmpSocket = accept(serverSocket, NULL, NULL);
        if (tmpSocket == INVALID_SOCKET) {
            continue;
        }

        char buffer[BUFFER_SIZE];
        int bytesReceived;

        // ��������� ��������� �� �������
        do {
            memset(buffer, 0, BUFFER_SIZE);
            bytesReceived = recv(tmpSocket, buffer, BUFFER_SIZE, 0);
            if (bytesReceived > 0) {
                BN_dec2bn(&foreignPartOfSecretKey, buffer);
                closesocket(tmpSocket);
                return;
            }

        } while (bytesReceived > 0);

        // �������� ���������� � ��������
        closesocket(tmpSocket);
        return;
    }
}

std::string Dispatcher::encryptMessage(const std::string& plaintext) {
    unsigned char* tmpKey = (unsigned char*)BN_bn2hex(this->encryptionKey);

    // ������� �������� ����������
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // ����������� �������� �� ������������� AES-256-ECB
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, tmpKey, nullptr);

    // ����� ��� �������� ������������� ������
    std::string ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH, '\0');

    // ������� ������
    int len1 = 0, len2 = 0;
    EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext.data(), &len1, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
    EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext.data() + len1, &len2);

    // ����������� ������ �� �������� ����� ������������� ������
    ciphertext.resize(len1 + len2);

    // ������� ��������
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

std::string Dispatcher::decryptMessage(const std::string& ciphertext) {
    unsigned char* tmpKey = (unsigned char*)BN_bn2hex(this->encryptionKey);

    // ������� �������� ������������
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // ����������� �������� �� ������������� AES-256-ECB
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, tmpKey, nullptr);

    // ����� ��� �������� �������������� ������
    std::string plaintext(ciphertext.size(), '\0');

    // ��������� ������
    int len1 = 0, len2 = 0;
    EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &len1, (unsigned char*)ciphertext.data(), ciphertext.size());
    EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext.data() + len1, &len2);

    // ����������� ������ �� �������� ����� �������������� ������
    plaintext.resize(len1 + len2);

    // ������� ��������
    EVP_CIPHER_CTX_free(ctx);

    // ����������� ��������� � ������
    return plaintext;
}

void Dispatcher::formSecretKey() {
    BIGNUM* tmp1 = BN_new();
    BIGNUM* tmp2 = BN_new();

    BN_mod_exp(tmp1, foreignPublicKey, myRandomNumber, p, ctx);
    BN_mod_exp(tmp2, foreignPartOfSecretKey, myPrivateKey, p, ctx);

    BN_mod_mul(commonSecretKey, tmp1, tmp2, p, ctx);

    BN_free(tmp1);
    BN_free(tmp2);

    encryptionKey = hashBigNum(commonSecretKey);
    std::cout << "����� ���� ����������:" << std::endl;
    printBnHex(encryptionKey);
    std::cout << std::endl;
}
