#include <iostream>
#include "aes.h"

int main() {
    // ----- 1. Kiểm thử một khối với test vector của FIPS-197 -----
    uint8_t key[16], plain[16], cipher[16], decrypted[16];
    for (int i = 0; i < 16; ++i) {
        key[i]   = static_cast<uint8_t>(i);          // 00 01 02 ... 0f
        plain[i] = static_cast<uint8_t>(i * 0x11);   // 00 11 22 ... ff
    }

    AES128 aes(key);
    aes.encryptBlock(plain, cipher);
    aes.decryptBlock(cipher, decrypted);

    std::cout << "Ban ro   : " << toHex(plain, 16)     << "\n";
    std::cout << "Ban ma   : " << toHex(cipher, 16)    << "\n";
    std::cout << "Giai ma  : " << toHex(decrypted, 16) << "\n";
    std::cout << "Ky vong  : 69c4e0d86a7b0430d8cdb78070b4c55a\n\n";

    // ----- 2. Mã hoá chuỗi bất kỳ bằng CBC + PKCS#7 -----
    const uint8_t iv[16] = {0};  // Chỉ để minh hoạ. Thực tế IV phải NGẪU NHIÊN cho mỗi lần mã hoá
    std::string msg = "An toan va bao mat thong tin - AES-128 CBC";
    std::vector<uint8_t> data(msg.begin(), msg.end());

    std::vector<uint8_t> enc = aes.encryptCBC(data, iv);
    std::vector<uint8_t> dec = aes.decryptCBC(enc, iv);

    std::cout << "Van ban goc : " << msg << "\n";
    std::cout << "Ban ma (hex): " << toHex(enc.data(), enc.size()) << "\n";
    std::cout << "Sau giai ma : " << std::string(dec.begin(), dec.end()) << "\n";
    return 0;
}