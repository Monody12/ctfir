#include "display_action.hpp"
#include "advice.hpp"
#include "util.hpp"
#include <algorithm>
#include <cctype>
namespace ctfir {
static bool safe_object(const std::string& s) {
    return s.find_first_of("\"'`$\r\n;&|<>%!^") == std::string::npos;
}
static bool digits(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(),s.end(),[](unsigned char c){return std::isdigit(c);});
}
DisplayAction display_action(const Finding& f) {
    DisplayAction a;
    a.title=title_zh_of(f); a.bucket=bucket_of(f);
    a.contest_note="只读取证预览；证据不等于已定性，未执行清理。保留业务、备用控制台和审计日志。";
    std::string safety_object=f.object_ref;
    if(starts_with(f.rule_id,"WIN.ACC.") && !safety_object.empty() && safety_object.back()=='$') safety_object.pop_back();
    if (!safe_object(safety_object)) return a;
    a.command="仅取证预览：核对报告中的精确对象、原始证据与业务依赖；本版不生成修改命令。";
    const auto& r=f.rule_id; const auto& obj=f.object_ref;
    if (starts_with(r,"LNX.PROC.") && starts_with(obj,"PID ")) {
        std::string pid=obj.substr(4);
        if (digits(pid)) a.command="ps -p "+pid+" -o pid,ppid,user,args\nreadlink /proc/"+pid+"/exe";
    } else if (starts_with(r,"LNX.ACC.") || r=="LNX.BASE.EMPTYPWD.001" || r=="LNX.BASE.WEAKPWD.001" || r=="LNX.BASE.SYSACCT.001") {
        size_t p=obj.rfind(':'); std::string name=p==std::string::npos?"":obj.substr(p+1);
        bool valid=!name.empty() && std::all_of(name.begin(),name.end(),[](unsigned char c){return std::isalnum(c)||c=='_'||c=='-'||c=='.';});
        if (valid && !digits(name)) a.command="getent passwd \""+name+"\" | cut -d: -f1,3,4,6,7\nid \""+name+"\"";
        else a.command="getent passwd | cut -d: -f1,3,4,6,7";
        a.contest_note="同UID是同一内核安全身份：名称不隔离进程/文件。不能按UID杀进程、递归删home或批量改账户数据库；不能改受保护root凭据。核实本地/NSS和共享home，先保留有效管理员与备用控制台。";
    } else if (r=="LNX.PERSIST.SYSTEMD.001" || r=="LNX.TIMER.FACT.001") {
        std::string unit=obj.substr(obj.find_last_of('/')==std::string::npos?0:obj.find_last_of('/')+1);
        bool valid=!unit.empty() && std::all_of(unit.begin(),unit.end(),[](unsigned char c){return std::isalnum(c)||c=='_'||c=='-'||c=='.'||c=='@'||c==':';});
        if (valid) a.command="systemctl cat -- \""+unit+"\"\nsystemctl show --property=Id,FragmentPath,DropInPaths,ExecStart,Triggers,TriggeredBy -- \""+unit+"\"";
        a.contest_note="timer事实不是后门证明；核对timer→service→ExecStart、drop-in、enable链接、来源/日志与业务依赖，不停用全部服务。";
    } else if (starts_with(obj,"/")) {
        std::string path=obj; size_t colon=path.rfind(':');
        if(colon!=std::string::npos && digits(path.substr(colon+1))) path.resize(colon);
        a.command="stat -- \""+path+"\"";
    } else if (starts_with(r,"WIN.ACC.")) {
        size_t colon=obj.rfind(':');std::string name=colon==std::string::npos?"":obj.substr(colon+1);
        if(!name.empty() && name[0]!='/' && name[0]!='-') a.command="net user \""+name+"\"";
    }
    return a;
}
std::string instantiate_advice_body(const Finding& f) {
    const Advice* a=find_advice(f.advice_id);
    return a?std::string("【")+a->title+"】\n"+a->text:"仅取证预览；证据不足不应直接清理。";
}
std::string instantiate_advice(const Finding& f) {
    auto a=display_action(f);
    return std::string("【一条命令（只读预览）】")+a.command+"\n"+instantiate_advice_body(f)+"\n"+a.contest_note;
}
void write_checklist(FILE* fp, const std::vector<Finding>& fds, int limit) {
    if (!fp) return;
    KpiCounts k = count_kpi(fds);
    std::fprintf(fp, "[处置清单] 复核 %d  Web %d  溯源 %d  加固 %d  清单 %d  合计 %d\n",
                 k.clear, k.web, k.trace, k.harden, k.inventory, k.total);
    auto idx = sorted_finding_indices(fds);
    int shown = 0, n = 0;
    for (auto i : idx) {
        const Finding& f = fds[i];
        Triage t = triage_of(f);
        ++n;
        if (shown >= limit) continue;
        DisplayAction da = display_action(f);
        std::fprintf(fp, "%2d. [%s/%s] %s  %s\n    %s\n",
                     n, t.bucket_zh, f.severity.c_str(), da.title.c_str(),
                     f.object_ref.c_str(), da.command.c_str());
        ++shown;
    }
    if (n > shown)
        std::fprintf(fp, "  … 其余 %d 条见报告 HTML\n", n - shown);
}

} // namespace ctfir
