#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>

// ---------- Tiện ích chuyển đổi hex ----------
inline std::string toHex(const uint8_t* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < len; ++i) {
        s += hex[data[i] >> 4];
        s += hex[data[i] & 0x0F];
    }
    return s;
}

class AES128 {
public:
    explicit AES128(const uint8_t key[16]) { keyExpansion(key); }

    // Mã hoá một khối 16 byte
    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        std::memcpy(s, in, 16);

        addRoundKey(s, 0);
        for (int r = 1; r < 10; ++r) {
            subBytes(s);
            shiftRows(s);
            mixColumns(s);
            addRoundKey(s, r);
        }
        subBytes(s);
        shiftRows(s);
        addRoundKey(s, 10);

        std::memcpy(out, s, 16);
    }

    // Giải mã một khối 16 byte
    void decryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        std::memcpy(s, in, 16);

        addRoundKey(s, 10);
        for (int r = 9; r >= 1; --r) {
            invShiftRows(s);
            invSubBytes(s);
            addRoundKey(s, r);
            invMixColumns(s);
        }
        invShiftRows(s);
        invSubBytes(s);
        addRoundKey(s, 0);

        std::memcpy(out, s, 16);
    }

    // Mã hoá CBC + đệm PKCS#7
    std::vector<uint8_t> encryptCBC(const std::vector<uint8_t>& plain,
                                    const uint8_t iv[16]) const {
        size_t pad = 16 - plain.size() % 16;
        std::vector<uint8_t> data(plain);
        data.insert(data.end(), pad, static_cast<uint8_t>(pad));

        std::vector<uint8_t> out(data.size());
        uint8_t prev[16];
        std::memcpy(prev, iv, 16);

        for (size_t i = 0; i < data.size(); i += 16) {
            uint8_t blk[16];
            for (int j = 0; j < 16; ++j) blk[j] = data[i + j] ^ prev[j];
            encryptBlock(blk, &out[i]);
            std::memcpy(prev, &out[i], 16);
        }
        return out;
    }

    // Giải mã CBC + bỏ đệm PKCS#7
    std::vector<uint8_t> decryptCBC(const std::vector<uint8_t>& cipher,
                                    const uint8_t iv[16]) const {
        if (cipher.empty() || cipher.size() % 16 != 0)
            throw std::runtime_error("Do dai ban ma khong hop le");

        std::vector<uint8_t> out(cipher.size());
        uint8_t prev[16];
        std::memcpy(prev, iv, 16);

        for (size_t i = 0; i < cipher.size(); i += 16) {
            uint8_t blk[16];
            decryptBlock(&cipher[i], blk);
            for (int j = 0; j < 16; ++j) out[i + j] = blk[j] ^ prev[j];
            std::memcpy(prev, &cipher[i], 16);
        }

        uint8_t pad = out.back();
        if (pad == 0 || pad > 16) throw std::runtime_error("Dem PKCS#7 khong hop le");
        out.resize(out.size() - pad);
        return out;
    }

private:
    uint8_t roundKey[176];  // 11 khoá vòng x 16 byte

    // ----- Bảng S-box được tính từ định nghĩa toán học -----
    struct Tables {
        uint8_t sbox[256];
        uint8_t inv[256];

        static uint8_t rotl8(uint8_t x, int s) {
            return static_cast<uint8_t>((x << s) | (x >> (8 - s)));
        }

        Tables() {
            uint8_t p = 1, q = 1;
            do {
                // p <- p * 3 trong GF(2^8)
                p = p ^ (p << 1) ^ ((p & 0x80) ? 0x1B : 0);
                // q <- q / 3 trong GF(2^8)
                q ^= q << 1;
                q ^= q << 2;
                q ^= q << 4;
                if (q & 0x80) q ^= 0x09;
                // q lúc này là nghịch đảo của p; áp dụng biến đổi affine
                uint8_t x = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
                sbox[p] = x ^ 0x63;
            } while (p != 1);
            sbox[0] = 0x63;

            for (int i = 0; i < 256; ++i) inv[sbox[i]] = static_cast<uint8_t>(i);
        }
    };

    static const Tables& tables() {
        static const Tables t;
        return t;
    }

    // ----- Phép toán trong GF(2^8) -----
    static uint8_t xtime(uint8_t x) {
        return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
    }

    static uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        while (b) {
            if (b & 1) p ^= a;
            a = xtime(a);
            b >>= 1;
        }
        return p;
    }

    // ----- Sinh khoá vòng -----
    void keyExpansion(const uint8_t key[16]) {
        const Tables& T = tables();
        std::memcpy(roundKey, key, 16);
        uint8_t rcon = 0x01;

        for (int i = 16; i < 176; i += 4) {
            uint8_t t[4] = { roundKey[i - 4], roundKey[i - 3],
                             roundKey[i - 2], roundKey[i - 1] };
            if (i % 16 == 0) {
                // RotWord + SubWord + Rcon
                uint8_t tmp = t[0];
                t[0] = T.sbox[t[1]] ^ rcon;
                t[1] = T.sbox[t[2]];
                t[2] = T.sbox[t[3]];
                t[3] = T.sbox[tmp];
                rcon = xtime(rcon);
            }
            for (int j = 0; j < 4; ++j)
                roundKey[i + j] = roundKey[i - 16 + j] ^ t[j];
        }
    }

    // ----- Các phép biến đổi của mỗi vòng -----
    // State lưu theo cột: s[r + 4*c] là phần tử hàng r, cột c
    void addRoundKey(uint8_t* s, int round) const {
        for (int i = 0; i < 16; ++i) s[i] ^= roundKey[round * 16 + i];
    }

    static void subBytes(uint8_t* s) {
        const Tables& T = tables();
        for (int i = 0; i < 16; ++i) s[i] = T.sbox[s[i]];
    }

    static void invSubBytes(uint8_t* s) {
        const Tables& T = tables();
        for (int i = 0; i < 16; ++i) s[i] = T.inv[s[i]];
    }

    static void shiftRows(uint8_t* s) {
        uint8_t t[16];
        for (int c = 0; c < 4; ++c)
            for (int r = 0; r < 4; ++r)
                t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
        std::memcpy(s, t, 16);
    }

    static void invShiftRows(uint8_t* s) {
        uint8_t t[16];
        for (int c = 0; c < 4; ++c)
            for (int r = 0; r < 4; ++r)
                t[r + 4 * ((c + r) % 4)] = s[r + 4 * c];
        std::memcpy(s, t, 16);
    }

    static void mixColumns(uint8_t* s) {
        for (int c = 0; c < 4; ++c) {
            uint8_t* a = s + 4 * c;
            uint8_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];
            a[0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
            a[1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
            a[2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
            a[3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
        }
    }

    static void invMixColumns(uint8_t* s) {
        for (int c = 0; c < 4; ++c) {
            uint8_t* a = s + 4 * c;
            uint8_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];
            a[0] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
            a[1] = gmul(a0, 9)  ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
            a[2] = gmul(a0, 13) ^ gmul(a1, 9)  ^ gmul(a2, 14) ^ gmul(a3, 11);
            a[3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9)  ^ gmul(a3, 14);
        }
    }
};

