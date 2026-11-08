// ctfir PoC CLI — M0 兼容探针（只读、无网络、无写动作）
// 验证：/MT 静态 CRT、/utf-8 中文输出、BCrypt SHA256 自检
// 构建：见 build_poc.bat
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

static const char kSelftestInput[] = "abc";
static const char kSelftestSha256[] =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

static int Sha256Selftest(void) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    unsigned char digest[32];
    DWORD cbHash = 0, cbData = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st != 0) return 1;
    st = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash,
                           sizeof(cbHash), &cbData, 0);
    if (st != 0 || cbHash != 32) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 2;
    }
    st = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 3;
    }
    st = BCryptHashData(hHash, (PUCHAR)kSelftestInput,
                        (ULONG)(sizeof(kSelftestInput) - 1), 0);
    if (st != 0) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 4;
    }
    st = BCryptFinishHash(hHash, digest, sizeof(digest), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (st != 0) return 5;

    static const char kHex[] = "0123456789abcdef";
    char hex[65];
    for (int i = 0; i < 32; ++i) {
        hex[i * 2] = kHex[digest[i] >> 4];
        hex[i * 2 + 1] = kHex[digest[i] & 0xF];
    }
    hex[64] = 0;
    printf("sha256(\"abc\") = %s\n", hex);
    return strcmp(hex, kSelftestSha256) == 0 ? 0 : 6;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("ctfir-poc-cli 0.0.1 (M0 probe, Win7 SP1+ x64, /MT static CRT)\n");
    printf("utf8-check: 账户 计划任务 启动项 hosts 进程 证据链\n");
    int rc = Sha256Selftest();
    printf("sha256-selftest: %s\n", rc == 0 ? "PASS" : "FAIL");
    return rc == 0 ? 0 : 2;
}
