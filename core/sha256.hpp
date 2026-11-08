#pragma once
// SHA-256（FIPS 180-4 标准算法，K 表为标准常量——非自创算法，ADR-009：全平台统一实现，
// 以 NIST 测试向量交叉验证；Windows 另在单测中比对 BCrypt 结果。
#include <cstdint>
#include <string>

namespace ctfir {

class Sha256 {
public:
    Sha256();                       // 自动 Init
    void update(const void* data, size_t len);  // 可分块调用（流式）
    void final(unsigned char out[32]);          // 结算（对象随后不可复用）

    // 便捷：一次哈希 + 十六进制小写
    static std::string hex_of(const void* data, size_t len);
    static std::string hex_of_file_chunks(const std::string& content); // 占位：与 hex_of 等价

private:
    void transform(const unsigned char* p);
    uint32_t h_[8];
    unsigned char buf_[64];
    size_t fill_;
    uint64_t total_;
};

} // namespace ctfir
