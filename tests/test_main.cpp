// 测试主程序（框架在 test_macros.hpp；用例在 test_engine.cpp）
#include "test_macros.hpp"

int main() {
    int total = 0;
    for (const auto& t : ctfir_test::registry()) {
        ctfir_test::current_name() = t.name;
        int before = ctfir_test::failures();
        t.fn();
        ++total;
        std::printf("[%s] %s\n",
                    ctfir_test::failures() == before ? "PASS" : "FAILED", t.name);
    }
    std::printf("== tests: %d, failures: %d ==\n", total, ctfir_test::failures());
    return ctfir_test::failures() == 0 ? 0 : 1;
}
