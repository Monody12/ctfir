// ctfir PoC Linux — M0 兼容探针
// 自实现 SHA-256（FIPS 180-4 标准算法，K 表为标准常量）+ UTF-8 输出自检
// 构建：docker alpine g++ -static（见同目录命令，正式构建入 CMake/脚本）
#include <cstdio>
#include <cstring>
#include <cstdint>

namespace sha256 {

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t Rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

struct Ctx {
    uint32_t h[8];
    uint8_t buf[64];
    size_t fill;
    uint64_t total;
    void Init() {
        h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
        h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
        fill = 0; total = 0;
    }
    void Transform(const uint8_t* p) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 |
                   (uint32_t)p[i*4+2] << 8 | (uint32_t)p[i*4+3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = Rotr(w[i-15],7) ^ Rotr(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = Rotr(w[i-2],17) ^ Rotr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = Rotr(e,6) ^ Rotr(e,11) ^ Rotr(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = Rotr(a,2) ^ Rotr(a,13) ^ Rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void Update(const void* data, size_t len) {
        const uint8_t* p = (const uint8_t*)data;
        total += len;
        while (len > 0) {
            size_t n = 64 - fill; if (n > len) n = len;
            memcpy(buf + fill, p, n);
            fill += n; p += n; len -= n;
            if (fill == 64) { Transform(buf); fill = 0; }
        }
    }
    void Final(uint8_t out[32]) {
        uint64_t bits = total * 8;
        uint8_t pad = 0x80;
        Update(&pad, 1);
        uint8_t zero = 0;
        while (fill != 56) Update(&zero, 1);
        uint8_t lenb[8];
        for (int i = 0; i < 8; ++i) lenb[i] = (uint8_t)(bits >> (56 - i*8));
        Update(lenb, 8);
        for (int i = 0; i < 8; ++i) {
            out[i*4]   = (uint8_t)(h[i] >> 24);
            out[i*4+1] = (uint8_t)(h[i] >> 16);
            out[i*4+2] = (uint8_t)(h[i] >> 8);
            out[i*4+3] = (uint8_t)(h[i]);
        }
    }
};

}  // namespace sha256

int main() {
    printf("ctfir-poc-linux 0.0.1 (M0 probe, static musl, x86_64 baseline)\n");
    printf("utf8-check: 账户 计划任务 启动项 hosts 进程 证据链\n");

    sha256::Ctx c;
    c.Init();
    c.Update("abc", 3);
    uint8_t d[32];
    c.Final(d);
    char hex[65];
    static const char kHex[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hex[i*2] = kHex[d[i] >> 4];
        hex[i*2+1] = kHex[d[i] & 0xF];
    }
    hex[64] = 0;
    printf("sha256(\"abc\") = %s\n", hex);
    int ok = strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0;
    printf("sha256-selftest: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 2;
}
