#include "fixengine.hpp"
#include <iostream>
namespace ctfir {
// Independent deny-all execution boundary. Never trust caller-supplied/stale plans.
// No shell, native operation, backup command, stdin prompt, journal or target write.
bool run_remediation(const Finding&, const RemediationPlan&, FixContext& fx) {
    ++fx.unsupported;
    std::cout << "[BLOCKED] 自动修改白名单为空；未执行计划、备份命令或原生操作。\n";
    return false;
}
}
