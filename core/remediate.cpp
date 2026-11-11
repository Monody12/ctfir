#include "remediate.hpp"
#include "util.hpp"

#include <algorithm>

namespace ctfir {

// 取 object_ref 的 tail 段（最后一个分隔符之后）
static std::string after(const std::string& s, const std::string& sep) {
    size_t p = s.rfind(sep);
    return p == std::string::npos ? "" : s.substr(p + sep.size());
}

RemediationPlan plan_remediation(const Finding& f) {
    RemediationPlan p;
    const std::string& rid = f.rule_id;
    const std::string& obj = f.object_ref;

    // ---------- Windows 账户 ----------
    if (rid == "WIN.ACC.CUSTOM.001" || rid == "WIN.ACC.DOLLAR.001" ||
        rid == "WIN.ACC.ADMIN.001") {
        std::string name = after(obj, ":");
        if (name.empty()) { p.reason = "无法从 object_ref 解析账户名"; return p; }
        p.supported = true;
        p.backups.push_back("net user \"" + name + "\"");            // 属性留证
        p.steps.push_back("net user \"" + name + "\" /active:no");   // 停用
        p.steps.push_back("net user \"" + name + "\" /delete");      // 删除（确认后）
        p.rollback_note = "按备份输出重建账户（net user <名> <密码> /add + 属性恢复）；删除前必须停用观察";
        return p;
    }
    // ---------- 登录界面隐藏值 ----------
    if (rid == "WIN.ACC.LOGIN_HIDE.001") {
        std::string name = after(obj, "\\"); // HKLM\...\UserList\<name>
        if (name.empty()) { p.reason = "无法解析值名"; return p; }
        p.supported = true;
        p.backups.push_back("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /v \"" + name + "\"");
        p.steps.push_back("reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /v \"" + name + "\" /f");
        p.rollback_note = "reg add 原值（数据 0）即可恢复；仅删同名值，不动整个键";
        return p;
    }
    // ---------- 自启动注册表值 ----------
    if (starts_with(rid, "WIN.AUTORUN.")) {
        // object_ref = "<label>\<valuename>"；label → 真实键路径映射
        std::string label = obj.substr(0, obj.rfind('\\'));
        std::string vname = after(obj, "\\");
        std::string key;
        if (label.find("Run(64)") != std::string::npos || label.find("Run(32") != std::string::npos)
            key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        else if (label.find("RunOnce") != std::string::npos)
            key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
        else if (label.find("Wow6432Node") != std::string::npos)
            key = "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
        else if (label.find("HKU\\") == 0 && label.find("\\Run") != std::string::npos) {
            // HKU\<SID>\Run
            size_t p1 = label.find("HKU\\");
            size_t p2 = label.find("\\Run");
            key = label.substr(p1, p2 - p1 + 4); // HKU\<SID>\Run
            // 展开为真实路径
            key = "HKU\\" + after(label.substr(0, p2), "HKU\\") + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        }
        if (key.empty() || vname.empty()) {
            p.reason = "该自启动位置暂不支持一键修复（" + label + "）——按手册手工处理";
            return p;
        }
        p.supported = true;
        p.backups.push_back("reg query \"" + key + "\" /v \"" + vname + "\"");
        p.steps.push_back("reg delete \"" + key + "\" /v \"" + vname + "\" /f");
        p.rollback_note = "按备份的值数据 reg add 恢复；引用文件取证后另行隔离";
        return p;
    }
    // ---------- netsh portproxy 转发规则 ----------
    if (rid == "WIN.PORTPROXY.001") {
        // object_ref = "PortProxy\<v4tov4...>\<tcp|udp>\<value_name>"
        std::vector<std::string> parts;
        size_t cur = 0;
        while (cur <= obj.size()) {
            size_t nx = obj.find('\\', cur);
            if (nx == std::string::npos) { parts.push_back(obj.substr(cur)); break; }
            parts.push_back(obj.substr(cur, nx - cur));
            cur = nx + 1;
        }
        // parts: [PortProxy, proto, tcp/udp, value_name]
        if (parts.size() < 4 || parts[0] != "PortProxy") {
            p.reason = "无法解析 portproxy 规则标识";
            return p;
        }
        std::string key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\" +
                          parts[1] + "\\" + parts[2];
        p.supported = true;
        p.backups.push_back("netsh interface portproxy show all");
        p.steps.push_back("reg delete \"" + key + "\" /v \"" + parts[3] + "\" /f");
        p.rollback_note = "netsh interface portproxy add " + parts[1] + " " + parts[2] +
                          " 原参数即可恢复；确认无业务依赖后删除";
        return p;
    }
    // ---------- 计划任务 ----------
    if (starts_with(rid, "WIN.TASK.")) {
        std::string path = after(obj, "Task"); // "Task<path>" → <path>
        if (path.empty() || path == obj) { p.reason = "无法解析任务路径"; return p; }
        p.supported = true;
        p.backups.push_back("schtasks /query /tn \"" + path + "\" /xml");  // XML 留证
        p.steps.push_back("schtasks /change /tn \"" + path + "\" /disable");
        p.steps.push_back("schtasks /delete /tn \"" + path + "\" /f");
        p.rollback_note = "按备份 XML `schtasks /create /xml <文件> /tn <路径>` 重建；先停用观察";
        return p;
    }
    // ---------- 服务 ----------
    if (rid == "WIN.SVC.SUSPECT.001" || rid == "WIN.SVC.UNQUOTED.001") {
        std::string name = after(obj, "Services\\");
        if (name.empty()) { p.reason = "无法解析服务名"; return p; }
        p.supported = true;
        p.backups.push_back("sc qc \"" + name + "\"");
        p.steps.push_back("sc config \"" + name + "\" start= disabled");
        p.steps.push_back("sc delete \"" + name + "\"");
        p.rollback_note = "按备份 qc 原值 `sc config ... start= auto/demand` + binPath 恢复；二进制文件先隔离";
        return p;
    }
    // ---------- 进程（挖矿/可疑命令行） ----------
    if (rid == "WIN.PROC.CMDLINE.001" || rid == "WIN.PROC.MINER.001") {
        std::string pid = after(obj, "PID ");
        if (pid.empty()) { p.reason = "PID 已失效（进程快照为历史）——请重扫后处置"; return p; }
        p.supported = true;
        p.steps.push_back("taskkill /PID " + pid + " /F");
        p.rollback_note = "进程终止不可逆——先确认样本已取证（哈希/文件复制）";
        return p;
    }
    // ---------- hosts（Windows） ----------
    if (rid == "WIN.HOSTS.MAP.001" || rid == "WIN.HOSTS.LOOPBACK.001") {
        // object_ref = "<file>:<line>"
        std::string file = obj.substr(0, obj.rfind(':'));
        p.supported = true;
        p.native_ops.push_back("hosts_delete_line:" + obj);
        p.rollback_note = "hosts 已整文件备份于证据；按行内容回加即可恢复";
        return p;
    }

    // ---------- Linux 账户 ----------
    if (rid == "LNX.ACC.UID0.001" || rid == "LNX.ACC.DUPUID.001") {
        // live 查找 UID0 非 root 账户（object_ref 是行号，live 解析更可靠）
        p.supported = true;
        p.backups.push_back("getent passwd");   // 全量留证
        p.steps.push_back("__LNX_DISABLE_UID0__");   // 引擎内置：usermod -L + nologin（逐个）
        p.steps.push_back("__LNX_DELETE_UID0__");    // 引擎内置：userdel -r（逐个）
        p.rollback_note = "按 getent passwd 备份重建；家目录内容先归档";
        return p;
    }
    if (rid == "LNX.ACC.SUDOERS.001" || rid == "LNX.BASE.EMPTYPWD.001" ||
        rid == "LNX.BASE.WEAKPWD.001" || rid == "LNX.BASE.SYSACCT.001") {
        // object_ref: sudoers=file:line / shadow:name / passwd:name
        std::string name = after(obj, ":");
        if (name.empty()) { p.reason = "无法解析账户名"; return p; }
        // 红线：root 与系统内置账户绝不允许一键删除
        if (name == "root" || name == "daemon" || name == "bin" || name == "sys" ||
            name == "sshd" || name == "nobody") {
            if (rid == "LNX.BASE.WEAKPWD.001") {
                p.supported = true;
                p.steps.push_back("passwd -l \"" + name + "\"   # 锁定口令（不删除！）；随后人工 passwd 设置强口令");
                p.rollback_note = "passwd -u 解锁；root 弱口令只能改密/锁密，绝不可 userdel";
                return p;
            }
            p.reason = "账户 " + name + " 为系统关键账户——不提供一键删除，按手册人工处置";
            return p;
        }
        p.supported = true;
        p.backups.push_back("getent passwd \"" + name + "\"; grep \"^" + name + ":\" /etc/shadow | sed 's/\\$[^$]*\\$/\\$HIDDEN\\$/g'");
        p.steps.push_back("usermod -L \"" + name + "\" 2>/dev/null; usermod -s /usr/sbin/nologin \"" + name + "\" 2>/dev/null || usermod -s /sbin/nologin \"" + name + "\"");
        if (rid != "LNX.BASE.SYSACCT.001" && rid != "LNX.BASE.WEAKPWD.001") {
            // 红线二：home 指向关键目录时禁止 -r（userdel -r 会递归删除家目录——
            // 家目录=/tmp 的账户会清空整个 /tmp，含工具自身会话与备份）
            p.steps.push_back(
                "h=$(getent passwd \"" + name + "\" | cut -d: -f6); case \"$h\" in "
                "\"/\"|\"/tmp\"|\"/var\"|\"/etc\"|\"/usr\"|\"/bin\"|\"/sbin\"|\"/root\"|\"/dev\"|\"/proc\"|\"/sys\"|\"/boot\"|\"\") "
                "userdel \"" + name + "\" 2>/dev/null ;; "
                "*) userdel -r \"" + name + "\" 2>/dev/null || userdel \"" + name + "\" ;; esac");
        }
        p.rollback_note = "按备份重建账户；shadow 哈希不在备份中（隐私），需重新设置口令";
        return p;
    }
    // ---------- Linux cron/at/preload/profile 行级 ----------
    if (starts_with(rid, "LNX.PERSIST.CRON") || rid == "LNX.PERSIST.AT.001" ||
        rid == "LNX.PERSIST.PROFILE.001" || rid == "LNX.PERSIST.PRELOAD.001") {
        // object_ref = "<file>:<line>"
        std::string file = obj.substr(0, obj.rfind(':'));
        if (file.empty()) { p.reason = "无法解析文件"; return p; }
        p.supported = true;
        p.backups.push_back("cp \"" + file + "\" \"${CTFIR_BACKUP_DIR:-/tmp}/\"");
        p.native_ops.push_back("linux_comment_line:" + obj);
        p.rollback_note = "去掉行首 # 即恢复；备份副本在会话 fix-backup/";
        return p;
    }
    // ---------- Linux systemd unit ----------
    if (rid == "LNX.PERSIST.SYSTEMD.001" || rid == "LNX.TIMER.FACT.001") {
        std::string unit = obj; // 单元文件完整路径
        if (unit.empty()) { p.reason = "无法解析单元文件"; return p; }
        p.supported = true;
        p.backups.push_back("cp \"" + unit + "\" \"${CTFIR_BACKUP_DIR:-/tmp}/\"; systemctl list-unit-files | grep -i \"$(basename " + unit + ")\" || true");
        p.steps.push_back("systemctl stop \"$(basename " + unit + ")\" 2>/dev/null; systemctl disable \"$(basename " + unit + ")\" 2>/dev/null");
        p.steps.push_back("mv \"" + unit + "\" \"" + unit + ".ctfir-quarantine\"");
        p.steps.push_back("systemctl daemon-reload");
        p.rollback_note = "去掉 .ctfir-quarantine 后缀移回 + systemctl enable --now 即恢复";
        return p;
    }
    // ---------- Linux 关键文件权限（恢复 644/600） ----------
    if (rid == "LNX.BASE.FILEPERM.001") {
        std::string fp = obj; // 文件路径
        if (fp.empty()) { p.reason = "无法解析文件路径"; return p; }
        p.supported = true;
        p.backups.push_back("stat \"" + fp + "\"");
        p.steps.push_back("chmod 644 \"" + fp + "\"");
        p.rollback_note = "按备份的 stat 原模式 chmod 恢复";
        return p;
    }
    // ---------- Linux 进程 ----------
    if (rid == "LNX.PROC.MINER.001") {
        std::string pid = after(obj, "PID ");
        if (pid.empty()) { p.reason = "PID 已失效——请重扫后处置"; return p; }
        p.supported = true;
        p.steps.push_back("kill -STOP " + pid + " && sleep 1 && kill -9 " + pid);
        p.rollback_note = "先 STOP 取证窗口再 KILL；不可逆，确认样本已取证";
        return p;
    }
    // ---------- SUID 权限收敛（去掉 SUID 位） ----------
    if (rid == "LNX.SUID.UNEXPECTED.001") {
        if (obj.empty()) { p.reason = "无法解析文件路径"; return p; }
        p.supported = true;
        p.backups.push_back("stat \"" + obj + "\"");
        p.steps.push_back("chmod u-s \"" + obj + "\"");
        p.rollback_note = "chmod u+s 恢复；仅去掉 SUID 位不删文件";
        return p;
    }
    // ---------- Linux 进程从临时目录运行（终止进程） ----------
    if (rid == "LNX.PROC.TMPDIR.001") {
        std::string pid = after(obj, "PID ");
        if (pid.empty()) { p.reason = "PID 已失效——请重扫后处置"; return p; }
        p.supported = true;
        p.steps.push_back("kill -9 " + pid);
        p.rollback_note = "进程终止不可逆——先取证 exe 路径和哈希";
        return p;
    }
    // ---------- Linux XDG autostart ----------
    if (rid == "LNX.PERSIST.XDG.001") {
        if (obj.empty()) { p.reason = "无法解析文件"; return p; }
        p.supported = true;
        p.native_ops.push_back("quarantine:" + obj.substr(0, obj.rfind(":")));
        p.rollback_note = "从 fix-backup/ 移回即恢复";
        return p;
    }
    // ---------- Linux Python startup hook ----------
    if (rid == "LNX.PERSIST.PYHOOK.001") {
        if (obj.empty()) { p.reason = "无法解析文件"; return p; }
        p.supported = true;
        p.native_ops.push_back("quarantine:" + obj);
        p.rollback_note = "从 fix-backup/ 移回即恢复";
        return p;
    }
    // ---------- Linux bashrc 函数后门 ----------
    if (rid == "LNX.PERSIST.BASHFUNC.001") {
        std::string file = obj.substr(0, obj.rfind(':'));
        if (file.empty()) { p.reason = "无法解析文件"; return p; }
        p.supported = true;
        p.native_ops.push_back("linux_comment_line:" + obj);
        p.rollback_note = "去掉 # ctfir-fixed: 前缀即恢复";
        return p;
    }
    // ---------- Linux Udev rule ----------
    if (rid == "LNX.PERSIST.UDEV.001") {
        if (obj.empty()) { p.reason = "无法解析文件"; return p; }
        p.supported = true;
        p.native_ops.push_back("quarantine:" + obj.substr(0, obj.rfind(":")));
        p.rollback_note = "从 fix-backup/ 移回即恢复";
        return p;
    }
    // ---------- webshell / 可疑文件隔离（双平台） ----------
    if (rid == "LNX.WEB.SHELL.001" || rid == "WIN.WEB.WEBSHELL.001" ||
        rid == "WIN.FILES.DOUBLEEXT.001" || rid == "MID.WEB.BACKUP.001" ||
        rid == "MID.PHP.PHPINFO.001") {
        if (obj.empty()) { p.reason = "无法解析文件路径"; return p; }
        p.supported = true;
        p.native_ops.push_back("quarantine:" + obj);
        p.rollback_note = "从会话 fix-backup/ 移回原路径即恢复；确认误报后再恢复";
        return p;
    }
    // ---------- R10-R14 新规则修复白名单 ----------
    // 进程名伪装 → kill（同 MINER 模式）
    if (rid == "LNX.PROC.NAMEMISMATCH.001") {
        std::string pid = after(obj, "PID ");
        if (pid.empty()) { p.reason = "PID 已失效——请重扫后处置"; return p; }
        p.supported = true;
        p.steps.push_back("kill -STOP " + pid + " && sleep 1 && kill -9 " + pid);
        p.rollback_note = "先 STOP 留取证窗口再 KILL；不可逆，确认 /proc/PID/exe 样本已取证";
        return p;
    }
    // SSH 非标端口 / ProxyCommand 后门 → 配置行注释（同 cron 行级模式）
    if (rid == "LNX.SSH.PORT.001" || rid == "LNX.SSH.PROXYCMD.001") {
        std::string file = obj.substr(0, obj.rfind(':'));
        if (file.empty()) { p.reason = "无法解析文件"; return p; }
        p.supported = true;
        p.backups.push_back("cp \"" + file + "\" \"${CTFIR_BACKUP_DIR:-/tmp}/\"; grep -n Port \"" + file + "\"");
        p.native_ops.push_back("linux_comment_line:" + obj);
        p.rollback_note = "去掉行首 # 即恢复；注意：若业务确实走该端口需改回并 systemctl reload sshd";
        return p;
    }
    // PAM 后门行 → 注释（pam_exec 注入行）
    if (rid == "LNX.PERSIST.PAM.001") {
        std::string file = obj.substr(0, obj.rfind(':'));
        if (file.empty()) { p.reason = "无法解析文件"; return p; }
        p.supported = true;
        p.backups.push_back("cp \"" + file + "\" \"${CTFIR_BACKUP_DIR:-/tmp}/\"");
        p.native_ops.push_back("linux_comment_line:" + obj);
        p.rollback_note = "去掉行首 # 即恢复；PAM 配置错误可致全系统无法登录——改前务必备份";
        return p;
    }
    // 隐藏密钥 / 攻击工具 / 勒索痕迹 / UDF / .git / 凭据文件 → 隔离
    if (rid == "LNX.SSH.HIDDENKEY.001" || rid == "LNX.TOOLS.ARTIFACT.001" ||
        rid == "LNX.TOOLS.FRPCFG.001" || rid == "WIN.TOOLS.ARTIFACT.001" ||
        rid == "WIN.TOOLS.FRPCFG.001" || rid == "LNX.RANSOM.TRACE.001" ||
        rid == "WIN.RANSOM.TRACE.001" || rid == "MID.MYSQL.UDF.001" ||
        rid == "MID.WEB.CREDS.001" || rid == "MID.WEB.GITLEAK.001" ||
        rid == "LNX.RANSOM.SCRIPT.001") {
        if (obj.empty()) { p.reason = "无法解析对象路径"; return p; }
        std::string target = obj;
        if (target.back() == '/') target.pop_back(); // .git/ 目录形态
        p.supported = true;
        p.native_ops.push_back("quarantine:" + target);
        if (rid == "MID.MYSQL.UDF.001")
            p.steps.push_back("mysql -N -e \"SELECT * FROM mysql.func;\" 2>/dev/null  # 若有 sys_exec/sys_eval 需 DROP FUNCTION 后重启 mysqld");
        if (rid == "MID.WEB.GITLEAK.001")
            p.rollback_note = "整个 .git 目录移入 fix-backup/；站点如依赖 git 部署需确认后再操作";
        else
            p.rollback_note = "从会话 fix-backup/ 移回原路径即恢复；确认误报后再恢复";
        return p;
    }
    // 壁纸篡改 → 删除注册表值恢复默认
    if (rid == "WIN.RANSOM.WALLPAPER.001") {
        p.supported = true;
        p.backups.push_back("reg query \"HKCU\\Control Panel\\Desktop\" /v Wallpaper");
        p.steps.push_back("reg delete \"HKCU\\Control Panel\\Desktop\" /v Wallpaper /f");
        p.rollback_note = "reg add Wallpaper 原值即恢复；删除后重启资源管理器生效";
        return p;
    }

    p.reason = "该规则暂不在一键修复白名单（可按处置手册人工执行）";
    return p;
}

} // namespace ctfir
