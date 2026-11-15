#include "remediate.hpp"
namespace ctfir {
RemediationPlan plan_remediation(const Finding&) {
    RemediationPlan p;
    p.supported = false;
    p.reason = "0.8.6 安全收紧：自动修改白名单为空，仅取证/预览；共享UID/home、业务依赖和实际有效配置须核实，不能按UID终止进程或批量清账户。";
    p.rollback_note = "没有执行任何修改，无需回滚；不能把预览记作已清理。";
    return p;
}
}
