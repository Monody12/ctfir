#include "fixengine.hpp"
#include "util.hpp"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

namespace ctfir {

static void journal(FixContext& fx, const std::string& line) {
    std::ofstream of(fs::path(fx.session_dir) / "fix-journal.jsonl", std::ios::app);
    of << "{\"ts_utc\":\"" << now_utc_iso8601() << "\"," << line << "}\n";
}

static bool run_cmd(const std::string& cmd) {
    int rc = std::system(cmd.c_str());
    return rc == 0;
}

// 内置：按行号删除文件中的一行（hosts 类）
static bool delete_line_in_file(const std::string& utf8_path, int line_no) {
    ReadResult r = read_text_file(utf8_path, 8 * 1024 * 1024);
    if (!r.ok) return false;
    auto lines = split_lines(r.content);
    if (line_no < 1 || line_no > static_cast<int>(lines.size())) return false;
    std::string out;
    for (int i = 1; i <= static_cast<int>(lines.size()); ++i) {
        if (i == line_no) continue;
        out += lines[static_cast<size_t>(i - 1)] + "\n";
    }
#if defined(_WIN32)
    FILE* f = _wfopen(fs::path(fs::u8path(utf8_path)).c_str(), L"wb");
#else
    FILE* f = fopen(utf8_path.c_str(), "wb");
#endif
    if (!f) return false;
    fwrite(out.data(), 1, out.size(), f);
    fclose(f);
    return true;
}

// 内置：注释掉文件中的一行（行首加 #）
static bool comment_line_in_file(const std::string& utf8_path, int line_no) {
    ReadResult r = read_text_file(utf8_path, 8 * 1024 * 1024);
    if (!r.ok) return false;
    auto lines = split_lines(r.content);
    if (line_no < 1 || line_no > static_cast<int>(lines.size())) return false;
    std::string& target = lines[static_cast<size_t>(line_no - 1)];
    if (!target.empty() && target[0] != '#') target = "# ctfir-fixed: " + target;
    std::string out;
    for (const auto& l : lines) out += l + "\n";
#if defined(_WIN32)
    FILE* f = _wfopen(fs::path(fs::u8path(utf8_path)).c_str(), L"wb");
#else
    FILE* f = fopen(utf8_path.c_str(), "wb");
#endif
    if (!f) return false;
    fwrite(out.data(), 1, out.size(), f);
    fclose(f);
    return true;
}

// 内置：文件隔离（移到会话 fix-backup/）
static bool quarantine_file(const std::string& utf8_path, const std::string& backup_dir) {
    std::error_code ec;
    fs::path src = fs::u8path(utf8_path);
    if (!fs::exists(src, ec)) return false;
    fs::create_directories(fs::u8path(backup_dir), ec);
    std::string fname = src.filename().string();
    fs::path dst = fs::u8path(backup_dir) / (fname + ".quarantine");
    fs::rename(src, dst, ec);
    if (ec) {
        fs::copy(src, dst, fs::copy_options::overwrite_existing, ec);
        if (ec) return false;
        fs::remove(src, ec);
    }
    return true;
}

#if !defined(_WIN32)
// 内置（Linux）：UID0 非 root 账户处置——逐个停用+删除
static int lnx_disable_uid0() {
    int n = 0;
    FILE* f = fopen("/etc/passwd", "r");
    if (!f) return 0;
    char line[1024];
    std::vector<std::string> names;
    while (fgets(line, sizeof(line), f)) {
        std::string t = trim(line);
        int p1 = static_cast<int>(t.find(':'));
        int p2 = static_cast<int>(t.find(':', p1 + 1));
        int p3 = static_cast<int>(t.find(':', p2 + 1));
        if (p1 <= 0 || p2 < 0 || p3 < 0) continue;
        std::string name = t.substr(0, p1);
        int uid = std::atoi(t.substr(p2 + 1, p3 - p2 - 1).c_str());
        if (uid == 0 && name != "root") names.push_back(name);
    }
    fclose(f);
    for (const auto& name : names) {
        std::string d = "usermod -L \"" + name + "\" 2>/dev/null";
        std::system(d.c_str());
        std::string del = "userdel -rf \"" + name + "\" 2>/dev/null || userdel -f \"" + name + "\" 2>/dev/null";
        int rc = std::system(del.c_str());
        if (rc != 0) {
            // userdel 被占用进程阻塞（rc=8）→ 直接从 passwd/shadow 移除条目
            std::string sed = "sed -i '/^" + name + ":/d' /etc/passwd /etc/shadow 2>/dev/null";
            int rc2 = std::system(sed.c_str());
            std::cout << "    [UID0] " << name << " userdel rc=" << rc
                      << " → 直接移除 passwd/shadow 条目 (rc=" << rc2 << ")\n";
        } else {
            std::cout << "    [UID0] " << name << " deleted\n";
        }
        ++n;
    }
    return n;
}
#endif

bool run_remediation(const Finding& f, const RemediationPlan& plan, FixContext& fx) {
    std::cout << "\n[*] " << f.rule_id << " @ " << f.object_ref << "\n";
    if (!plan.supported) {
        std::cout << "    不支持一键修复: " << plan.reason << "\n";
        ++fx.unsupported;
        journal(fx, "\"event\":\"unsupported\",\"rule\":\"" + f.rule_id + "\"");
        return false;
    }
    std::cout << "    处置步骤:\n";
    for (const auto& s : plan.backups) std::cout << "      [备份] " << s << "\n";
    for (const auto& s : plan.steps) std::cout << "      [执行] " << s << "\n";
    std::cout << "    回滚: " << plan.rollback_note << "\n";
    if (fx.dry_run) {
        std::cout << "    (dry-run，未执行)\n";
        return true;
    }
    if (!fx.assume_yes) {
        std::cout << "    执行该修复? [y/N] ";
        std::string ans;
        std::getline(std::cin, ans);
        if (ans != "y" && ans != "Y" && ans == "n") { // 仅明确 n 跳过；回车默认跳过
            if (ans != "y" && ans != "Y") {
                std::cout << "    跳过\n";
                ++fx.skipped;
                journal(fx, "\"event\":\"skipped\",\"rule\":\"" + f.rule_id + "\"");
                return false;
            }
        }
    }
    // 1) 备份命令
    for (const auto& cmd : plan.backups) {
        std::string out = cmd + " > \"" + fx.backup_dir + "/backup_" +
                          std::to_string(static_cast<long long>(std::time(nullptr))) + ".txt\" 2>&1";
        std::system(out.c_str());
    }
    // 2) 原生操作
    for (const auto& op : plan.native_ops) {
        bool ok = false;
        if (starts_with(op, "hosts_delete_line:")) {
            std::string obj = op.substr(strlen("hosts_delete_line:"));
            std::string file = obj.substr(0, obj.rfind(':'));
            int no = std::atoi(obj.c_str() + obj.rfind(':') + 1);
            ok = delete_line_in_file(file, no);
        } else if (starts_with(op, "linux_comment_line:")) {
            std::string obj = op.substr(strlen("linux_comment_line:"));
            std::string file = obj.substr(0, obj.rfind(':'));
            int no = std::atoi(obj.c_str() + obj.rfind(':') + 1);
            ok = comment_line_in_file(file, no);
        } else if (starts_with(op, "quarantine:")) {
            ok = quarantine_file(op.substr(strlen("quarantine:")), fx.backup_dir);
        }
#if !defined(_WIN32)
        else if (op == "__LNX_DISABLE_UID0__") {
            int n = lnx_disable_uid0();
            ok = n > 0;
            std::cout << "    [UID0] processed " << n << " accounts\n";
        } else if (op == "__LNX_DELETE_UID0__") {
            ok = true;
        }
#endif
        journal(fx, "\"event\":\"native\",\"op\":\"" + op + "\",\"ok\":" + (ok ? "true" : "false"));
        std::cout << "    " << (ok ? "[完成] " : "[失败] ") << op << "\n";
    }
    // 3) 命令步骤（__ 前缀 = 引擎内置操作，不经 shell）
    bool ok_flag = false;
    for (const auto& cmd : plan.steps) {
        if (starts_with(cmd, "__LNX_DISABLE_UID0__")) {
#if !defined(_WIN32)
            int n0 = lnx_disable_uid0();
            ok_flag = n0 > 0;
#else
            ok_flag = false;
#endif
            journal(fx, "\"event\":\"native_uid0_disable\",\"ok\":" + std::string(ok_flag ? "true" : "false"));
            continue;
        }
        if (starts_with(cmd, "__LNX_DELETE_UID0__")) {
            ok_flag = true; // disable 阶段已一并删除
            continue;
        }
        std::cout << "    [执行] " << cmd << "\n";
        ok_flag = run_cmd(cmd);
        journal(fx, "\"event\":\"cmd\",\"cmd\":\"" + sanitize_utf8(cmd) + "\",\"ok\":" + std::string(ok_flag ? "true" : "false"));
    }
    ++fx.executed;
    return true;
}

} // namespace ctfir
