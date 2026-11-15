# 0.8.7 账户范围与兼容边界

自动修改白名单继续为空。fix/apply/repair与旧、伪造、混合计划仍拒绝；本版增加识别、证据和分系统只读预览，不恢复自动删除。

## Windows Server 2016

- 目标最低API/PE基线兼容x64 Server2016（build14393），并不等于Server2016真机已实测。CI实际OS、PowerShell版本在日志中打印；Server2022 hosted CI不能写成2016实测。
- ProductType=WinNT/ServerNT才枚举本地SAM；LanmanNT域控及未知角色在账户API前SKIPPED，不把AD当本地SAM。ServerNT可能独立或域成员，不能仅此判断域加入。
- 原生API收集每个本地账户的SID/RID；RID500改名仍标内置受保护管理员，不按Administrator名字判断。RID1000及以上列自建账户事实；管理员组按S-1-5-32-544定位，成员用level0只取SID，不远程解析域名字。普通管理员/服务账户不因权限而判恶意。
- account-review.ps1是PS5.1只读辅助，先判角色，CIM→WMI→仅本地net查询回退；不依赖LocalAccounts模块，32位shell不会因此假PASS。SID取不到就明确不完整，不授权删除。-Dependencies额外只读核对服务StartName/任务Principal；组主体/间接依赖/会话需人工核实。
- 使用：在程序解压目录运行 `powershell.exe -NoProfile -File .\account-review.ps1 -Name "待核实名" -Dependencies`。脚本不禁用、不删用户、不删profile、不注销会话、不停服务，不带域参数或远程目标。

人类审核后的处置顺序：确认合法独立管理员与控制台可登录→证据/配置备份→确认非RID500等内置账户，名称+完整SID再次匹配→核对服务/任务/会话与精确重建源→先人工禁用观察、业务验证→必要时再次核对同一SID后人工删除，保留profile/证据与可回滚方案。若LocalAccounts模块不可用，不跳过SID核验；可换本机64位PS，或每步核对SID后由管理员使用本地net工具。域控/域账户须另行明确授权AD域范围与工具，本工具不自动代办。题目保护的管理员凭据不得擅改。

## CentOS 7 / 8 / Stream

- Linux扫描只读取本地passwd/group/NSS策略文件，不运行getent或查询SSSD/LDAP/NIS。外部NSS提供者写入范围缺口；本地模块完成不代表排除外部账号。
- 严格解析UID/GID，空值、非数字、溢出、compat条目不能被atoi误当UID0。合法普通服务账户、非root UID0别名、共享UID须分开；UID0事实不单独证明恶意。
- UID0别名共享root内核身份。先保留有效root/SSH/控制台、0700目录/0600账户备份、核对共享home及NSS；人审后使用vipw与vipw -s的原生持锁编辑，只删精确名字记录，不动root、不按UID结束进程、不删共享home、不手写覆盖账户库。
- 普通本地账户也先核实业务/精确重建源，人工禁用观察后按需精确处理；额外组、gshadow、subID要单独审计，不删共享组或按UID0清映射。外部账号不能靠改本地文件解决。
- cron/timer高频、注释或自定义脚本只属线索，先核对实际unit/drop-in/ExecStart/引用脚本与来源，确认恶意后才审核精确再生源处理；不清空全部cron，不停全部服务。
- CentOS用户态容器不等于对应内核或完整systemd/SSH真机；7/8/Stream各版本只按实测记录声称覆盖。32位Linux/Windows不在x64包支持范围。

已知边界：完整systemd有效drop-in合并、外部NSS/LDAP/SSSD目录账户枚举、AD域清理、所有业务应用依赖不在本次验证保证范围。本轮CentOS7.9用户态 shadow-utils4.6-5.el7：唯一锁定/过期/nologin UID0别名，普通删除rc8；vipw精确passwd/shadow删除rc0/0；六份账户库逐字节一致，PID1/root目录与自建哨兵保留，pwck-r rc2前后相同无新增警告。Docker共享6.12.113+内核，不等于CentOS3.10或完整SSH/systemd验证。CentOS Stream9用户态 shadow-utils4.9-17.el9同法实测，六库SHA256相同、PID1与root目录保留、pwck无新增警告；首次因容器没有cmp导致复核中断，随后改用SHA256比较重跑通过，失败日志也保留。CentOS8/Stream8未实测。真实CI数字与环境见Release及实测附件，不承诺跨环境100%有效。
