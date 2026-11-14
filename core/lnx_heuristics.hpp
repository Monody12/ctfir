#pragma once
// Linux 文本启发式（无 POSIX 依赖，Windows 单测可跑）
#include "util.hpp"

#include <cctype>
#include <string>
#include <sstream>
#include <vector>

namespace ctfir {

// PAM 后门：pam_exec、临时目录、绝对路径不在发行版 security 目录、非 pam_*.so 短名。
// 发行版短名（pam_unix.so / pam_deny.so）不报。
inline bool pam_line_is_backdoor(const std::string& line) {
    std::string t = trim(line);
    if (t.empty() || t[0] == '#') return false;
    if (t.find("pam_exec.so") != std::string::npos) return true;
    if (t.find("/tmp/") != std::string::npos) return true;
    if (t.find("/dev/shm") != std::string::npos) return true;
    if (t.find("/var/tmp/") != std::string::npos) return true;

    size_t so = t.find(".so");
    if (so == std::string::npos) return false;
    size_t start = so;
    while (start > 0 && t[start - 1] != ' ' && t[start - 1] != '\t') --start;
    std::string tok = t.substr(start, so + 3 - start);

    auto in_std_security = [](const std::string& s) {
        return s.find("/security/pam_") != std::string::npos ||
               s.find("/lib/security/") != std::string::npos ||
               s.find("/lib64/security/") != std::string::npos;
    };
    if (!tok.empty() && tok[0] == '/')
        return !in_std_security(tok);

    size_t sl = tok.rfind('/');
    std::string base = sl == std::string::npos ? tok : tok.substr(sl + 1);
    if (base.size() >= 8 && base.compare(0, 4, "pam_") == 0) return false;
    return !base.empty();
}

inline bool ldso_path_is_unusual(const std::string& line) {
    std::string t = trim(line);
    if (t.empty() || t[0] == '#') return false;
    if (starts_with(t, "include ") || starts_with(t, "include\t")) return false;
    if (t[0] != '/') return true;
    for (const char* dir : {"/usr/lib", "/usr/lib64", "/usr/lib32", "/usr/libx32", "/lib", "/lib64", "/lib32", "/libx32", "/usr/local/lib"})
        if (t == dir || starts_with(t, std::string(dir) + "/")) return false;
    return true;
}

// Bounded static command inspection: never execute or expand shell syntax.
inline bool linux_hidden_path(const std::string& p) {
    size_t at = 0;
    while ((at = p.find("/.", at)) != std::string::npos) {
        size_t end = p.find('/', at + 1);
        std::string part = p.substr(at + 1, end == std::string::npos ? end : end - at - 1);
        if (part != "." && part != "..") return true;
        at += 2;
    }
    return false;
}
inline std::vector<std::string> linux_command_paths(std::string text) {
    if (starts_with(trim(text), "Exec")) {
        size_t eq = text.find('=');
        if (eq != std::string::npos) text = text.substr(eq + 1);
    }
    std::vector<std::string> words;
    std::string word;
    char quote = 0;
    for (char c : text.substr(0, 16384)) {
        if ((c == '\'' || c == '"') && (!quote || quote == c)) { quote = quote ? 0 : c; continue; }
        if (!quote && (std::isspace(static_cast<unsigned char>(c)) || c == ';' || c == '|' || c == '&')) {
            if (!word.empty()) { words.push_back(word); word.clear(); }
            if (c == ';' || c == '|' || c == '&') words.push_back(";");
        } else word += c;
    }
    if (!word.empty()) words.push_back(word);
    size_t begin = 0;
    if (!words.empty() && words[0][0] == '@') begin = 1;
    else if (words.size() >= 6 && (words[0][0] == '*' || std::isdigit(static_cast<unsigned char>(words[0][0])))) begin = 5;
    // Optional system-crontab username, but not a bare executable.
    if (begin && begin + 1 < words.size() && words[begin].find('/') == std::string::npos &&
        !words[begin + 1].empty() && words[begin + 1][0] == '/') ++begin;
    std::vector<std::string> paths;
    bool command = true, script = false;
    for (size_t i = begin; i < words.size() && paths.size() < 8; ++i) {
        std::string w = words[i];
        if (w == ";") { command = true; script = false; continue; }
        while (command && !w.empty() && (w[0] == '-' || w[0] == '+' || w[0] == '!' || w[0] == ':')) w.erase(0, 1);
        if (w.empty()) continue;
        if (command && w.find('=') != std::string::npos) continue;
        bool absolute = w[0] == '/';
        if (absolute && (command || script)) {
            // -c payload is parsed recursively, not treated as a pathname.
            if (w.find_first_of("\n\r") == std::string::npos) paths.push_back(w);
        }
        std::string base = w.substr(w.find_last_of('/') == std::string::npos ? 0 : w.find_last_of('/') + 1);
        bool interpreter = base == "sh" || base == "bash" || base == "dash" || base == "python" ||
                           starts_with(base, "python3") || base == "perl";
        if (command) { command = base == "env" || base == "exec"; script = interpreter; }
        else if (script && w[0] != '-') script = false;
        if (i > begin && words[i - 1] == "-c") {
            auto nested = linux_command_paths(w);
            for (const auto& p : nested) if (paths.size() < 8) paths.push_back(p);
        }
    }
    return paths;
}
inline int linux_command_risk(const std::string& text) {
    std::string t = trim(text);
    if (t.empty() || t[0] == '#') return 0;
    if (contains_ci(t, "/dev/tcp/") || contains_ci(t, "stratum+") || contains_ci(t, "xmrig") ||
        ((contains_ci(t, "nc ") || contains_ci(t, "ncat ") || contains_ci(t, "netcat ")) &&
         (contains_ci(t, " -e ") || contains_ci(t, " --exec ") || contains_ci(t, " -c /bin/"))) ||
        ((contains_ci(t, "curl ") || contains_ci(t, "wget ") || contains_ci(t, "base64 -d")) &&
         (contains_ci(t, "| sh") || contains_ci(t, "|sh") || contains_ci(t, "| bash") || contains_ci(t, "|bash")))) return 3;
    for (const auto& p : linux_command_paths(t))
        if (linux_hidden_path(p) || starts_with(p, "/tmp/") || starts_with(p, "/var/tmp/") || starts_with(p, "/dev/shm/")) return 2;
    return 0; // curl/base64/python words alone are not malicious evidence.
}

// Dirty Pipe CVE-2022-0847：仅 5.8–5.16.11
inline bool dirtypipe_version_affected(int a, int b, int c) {
    if (a != 5) return false;
    if (b < 8 || b > 16) return false;
    if (b == 10 && c >= 102) return false;  // stable backport
    if (b == 15 && c >= 25) return false;   // stable backport
    if (b == 16 && c >= 12) return false;
    return true;
}

// Dirty Cow CVE-2016-5195：4.8.3 之前（含 3.10 CentOS7 线索）
inline bool dirtycow_version_affected(int a, int b, int c) {
    if (a < 4) return true;
    if (a > 4) return false;
    if (b < 8) return true;
    if (b > 8) return false;
    return c < 3;
}

inline bool cap_name_expected(const std::string& name) {
    static const char* k[] = {
        "ping", "ping4", "ping6", "ping.iputils",
        "mtr", "mtr-packet", "traceroute", "traceroute6", "traceroute6.iputils",
        "arping", "clockdiff", "dumpcap",
        "newgidmap", "newuidmap", "suexec",
        nullptr
    };
    for (int i = 0; k[i]; ++i)
        if (name == k[i]) return true;
    return false;
}

// pipewire-pulse / pipewire、systemd-xxx / systemd 视为包装名，不是伪装
inline bool proc_claimed_matches_exe(const std::string& claimed, const std::string& exe_name) {
    if (claimed.empty() || exe_name.empty()) return true;
    if (claimed[0] == '[') return false;
    if (to_lower(claimed) == to_lower(exe_name) || claimed == "-" + exe_name) return true;
    if ((claimed == "init" || claimed == "(sd-pam)") && exe_name == "systemd") return true;
    if (claimed == "systemd-udevd" && exe_name == "udevadm") return true;
    if (starts_with(claimed, exe_name + " ") || starts_with(claimed, exe_name + ":")) return true;
    if (claimed.size() > exe_name.size() &&
        claimed.compare(0, exe_name.size(), exe_name) == 0 &&
        (claimed[exe_name.size()] == '-' || claimed[exe_name.size()] == '.'))
        return true;
    if (exe_name.size() > claimed.size() &&
        exe_name.compare(0, claimed.size(), claimed) == 0 &&
        (exe_name[claimed.size()] == '-' || exe_name[claimed.size()] == '.'))
        return true;
    if (starts_with(exe_name, "python") || starts_with(exe_name, "perl") ||
        starts_with(exe_name, "busybox") || starts_with(exe_name, "java") ||
        starts_with(exe_name, "ruby") || starts_with(exe_name, "node"))
        return true;
    // /bin/sh → bash/dash/ash 是发行版默认，不是伪装
    if (claimed == "sh" || claimed == "-sh") {
        if (exe_name == "bash" || exe_name == "dash" || exe_name == "ash" ||
            exe_name == "busybox" || exe_name == "zsh" || exe_name == "ksh")
            return true;
    }
    if ((claimed == "bash" || claimed == "-bash") &&
        (exe_name == "sh" || exe_name == "dash"))
        return true;
    return false;
}

inline bool history_line_is_clue(const std::string& line) {
    std::string t = trim(line);
    if (t.empty() || t[0] == '#') return false;
    static const char* always[] = {
        "/dev/tcp", "bash -i", "/bin/bash -i", "nc -e", "ncat -e", "ncat -l",
        "python -c", "perl -e", "mkfifo", "chmod 777", "chmod +s",
        "base64 -d", "stratum+tcp", "xmrig", "kdevtmpfsi", "kinsing",
        "sshpass -p", "history -c", "useradd ", "userdel ",
        "echo * >>", "authorized_keys", "ld.so.preload",
        nullptr
    };
    for (int i = 0; always[i]; ++i)
        if (contains_ci(t, always[i])) return true;

    bool dl = contains_ci(t, "curl ") || contains_ci(t, "wget ");
    if (!dl) return false;
    if (t.find('|') != std::string::npos) return true;
    if (contains_ci(t, "/tmp") || contains_ci(t, "/dev/shm") || contains_ci(t, "/var/tmp"))
        return true;
    if (contains_ci(t, " -o ") || contains_ci(t, " -O ")) return true;
    size_t http = to_lower(t).find("http://");
    if (http != std::string::npos && http + 7 < t.size() &&
        std::isdigit(static_cast<unsigned char>(t[http + 7])))
        return true;
    return false;
}

// alias ls='ls --color' 放过；alias ssh='木马' / alias ls='curl|sh' 报。
inline bool profile_alias_is_hijack(const std::string& line) {
    std::string t = trim(line);
    if (!starts_with(t, "alias ")) return false;
    std::string rest = trim(t.substr(6));
    size_t eq = rest.find('=');
    if (eq == std::string::npos || eq == 0) return false;
    std::string name = trim(rest.substr(0, eq));
    std::string val = trim(rest.substr(eq + 1));
    if (name.size() >= 2 && ((name.front() == '\'' && name.back() == '\'') ||
                             (name.front() == '"' && name.back() == '"')))
        name = name.substr(1, name.size() - 2);
    if (!val.empty() && (val.front() == '\'' || val.front() == '"')) {
        char q = val.front();
        if (val.size() >= 2 && val.back() == q) val = val.substr(1, val.size() - 2);
        else val = val.substr(1);
    }
    if (contains_ci(val, "curl") || contains_ci(val, "wget") || contains_ci(val, "nc ") ||
        contains_ci(val, "/tmp") || contains_ci(val, "/dev/shm") || contains_ci(val, "/dev/tcp") ||
        contains_ci(val, "python -c") || contains_ci(val, "perl -e") || contains_ci(val, "bash -i") ||
        contains_ci(val, "base64"))
        return true;
    static const char* cmds[] = {
        "ls", "ssh", "sudo", "su", "ps", "netstat", "ss", "find", "id", "whoami",
        "crontab", "passwd", "login", "cat", "grep", "chmod", "chown", "kill",
        "iptables", "ifconfig", "top", "wget", "curl", "vim", "vi", "nano",
        nullptr
    };
    bool watch = false;
    for (int i = 0; cmds[i]; ++i)
        if (name == cmds[i]) { watch = true; break; }
    if (!watch) return false;
    if (val == name || starts_with(val, name + " ") || starts_with(val, name + "\t"))
        return false;
    return true;
}

inline bool initd_line_is_backdoor(const std::string& line) {
    std::string t = trim(line);
    if (t.empty() || t[0] == '#') return false;
    if (contains_ci(t, "curl ") || contains_ci(t, "wget ") || contains_ci(t, "nc -e") ||
        contains_ci(t, "ncat ") || contains_ci(t, "bash -i") || contains_ci(t, "/dev/tcp") ||
        contains_ci(t, "python -c") || contains_ci(t, "perl -e") || contains_ci(t, "base64 -d") ||
        contains_ci(t, "stratum+tcp"))
        return true;
    return false;
}

inline bool xinetd_line_is_backdoor(const std::string& line) {
    std::string t = trim(line);
    if (t.empty() || t[0] == '#') return false;
    if (t.find("/tmp/") != std::string::npos) return true;
    if (t.find("/dev/shm") != std::string::npos) return true;
    if (t.find("/var/tmp/") != std::string::npos) return true;
    if (contains_ci(t, "/dev/tcp")) return true;
    if (contains_ci(t, "nc -e") || contains_ci(t, "ncat ") || contains_ci(t, "bash -i"))
        return true;
    if (contains_ci(t, "python -c") || contains_ci(t, "perl -e")) return true;
    return false;
}

} // namespace ctfir
