#include "test_macros.hpp"
#include "core/compat.hpp"

using namespace ctfir;

CTFIR_TEST(compat_win7_sp1_ok) {
    auto h = evaluate_host_compat_from("Windows 7 Ultimate", "6.1.7601 SP1", "x64", "x64");
    CHECK_EQ(h.level, std::string("ok"));
    CHECK(h.note.empty());
    CHECK_EQ(h.binary_arch, std::string("x64"));
}

CTFIR_TEST(compat_win7_rtm_warn) {
    auto h = evaluate_host_compat_from("Windows 7 Ultimate", "6.1.7600", "x64", "x64");
    CHECK_EQ(h.level, std::string("warn"));
    CHECK(h.note.find("7600") != std::string::npos);
}

CTFIR_TEST(compat_win11_ok) {
    auto h = evaluate_host_compat_from("Windows 11 Pro", "10.0.26100", "x64", "x64");
    CHECK_EQ(h.level, std::string("ok"));
}

CTFIR_TEST(compat_2008r2_sp1_ok) {
    auto h = evaluate_host_compat_from("Windows Server 2008 R2", "6.1.7601 Service Pack 1", "x64", "x64");
    CHECK_EQ(h.level, std::string("ok"));
}

CTFIR_TEST(compat_x64_bin_on_x86_os) {
    auto h = evaluate_host_compat_from("Windows 7 Ultimate", "6.1.7601 SP1", "x86", "x64");
    CHECK_EQ(h.level, std::string("warn"));
    CHECK(h.note.find("32") != std::string::npos);
}

CTFIR_TEST(compat_x86_bin_on_x64_os_wow64) {
    auto h = evaluate_host_compat_from("Windows 7 Ultimate", "6.1.7601 SP1", "x64", "x86");
    CHECK_EQ(h.level, std::string("warn"));
    CHECK(h.note.find("WOW64") != std::string::npos);
}

CTFIR_TEST(compat_linux_x86_64_centos7_ok) {
    auto h = evaluate_host_compat_from("CentOS Linux 7 (Core)", "3.10.0-1160.el7.x86_64", "x86_64", "x86_64");
    CHECK_EQ(h.level, std::string("ok"));
    CHECK(h.note.empty());
}

CTFIR_TEST(compat_linux_32bit_os) {
    auto h = evaluate_host_compat_from("CentOS", "3.10.0-1160.el7.i686", "i686", "x86_64");
    CHECK_EQ(h.level, std::string("warn"));
}

CTFIR_TEST(compat_linux_kernel_not_parsed_as_winbuild) {
    // 内核 6.6.87 第三段是 87，绝不能当成 Win build < 7601。
    auto h = evaluate_host_compat_from("Ubuntu 24.04", "6.6.87.2-microsoft-standard-WSL2", "x86_64", "x86_64");
    CHECK_EQ(h.level, std::string("ok"));
}
