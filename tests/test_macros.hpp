// 极简单测框架（零依赖）：注册式用例 + 计数断言
#pragma once
#include <cstdio>
#include <string>
#include <vector>

namespace ctfir_test {

struct TestCase {
    const char* name;
    void (*fn)();
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

inline int& failures() {
    static int f = 0;
    return f;
}

inline const char*& current_name() {
    static const char* n = "?";
    return n;
}

inline void check(bool cond, const char* file, int line, const std::string& msg) {
    if (!cond) {
        ++failures();
        std::printf("  [FAIL] %s @ %s:%d : %s\n", current_name(), file, line, msg.c_str());
    }
}

} // namespace ctfir_test

#define CTFIR_TEST(name)                                                        \
    static void test_##name();                                                  \
    static const bool reg_##name = (ctfir_test::registry().push_back(           \
                                        {#name, &test_##name}),                 \
                                    true);                                      \
    static void test_##name()

#define CHECK(cond) ctfir_test::check(static_cast<bool>(cond), __FILE__, __LINE__, #cond)
#define CHECK_MSG(cond, msg) ctfir_test::check(static_cast<bool>(cond), __FILE__, __LINE__, msg)
#define CHECK_EQ(a, b)                                                          \
    do {                                                                        \
        auto va_ = (a);                                                         \
        auto vb_ = (b);                                                         \
        if (!(va_ == vb_))                                                      \
            ctfir_test::check(false, __FILE__, __LINE__,                        \
                              std::string(#a) + " != " + #b);                   \
    } while (0)
