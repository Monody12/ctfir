#pragma once
// 展示用处置命令：只生成文本，不执行。与 ADR-009 执行白名单分离。
#include "model.hpp"
#include "triage.hpp"

#include <string>
#include <vector>
#include <cstdio>

namespace ctfir {

struct DisplayAction {
    std::string title;
    std::string command;       // 一条已填对象的命令（可多行）
    std::string contest_note;  // 空=无决赛特别说明
    Bucket bucket = Bucket::Trace;
};

DisplayAction display_action(const Finding& f);

// 六步手册中的 <账户名> 等占位符换成 object_ref 解析结果（含一条命令）
std::string instantiate_advice(const Finding& f);
// 仅手册正文（已替换占位符，不含命令头）
std::string instantiate_advice_body(const Finding& f);

// 扫描结束写 stderr / GUI 状态：最多 limit 条默认可见项
void write_checklist(FILE* fp, const std::vector<Finding>& fds, int limit = 30);

} // namespace ctfir
