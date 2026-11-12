# -*- coding: utf-8 -*-
# 扫描 C++ 字符串字面量中的非法转义（单个反斜杠+大写字母 = Python heredoc 吞噬痕迹）
# 判定规则：逐字符扫描，\\ 成对跳过；单 \ 后跟大写字母 → 损坏（\A-\Z 全部非法转义）
import sys

files = [
    'platform/win/mod_w.cpp', 'platform/win/mod_w2.cpp',
    'platform/win/mod_w3.cpp', 'platform/win/mod_w4.cpp',
    'platform/win/win_common.hpp', 'platform/win/win_common.cpp',
    'platform/linux/mod_d.cpp', 'platform/linux/mod_f.cpp',
    'platform/linux/mod_h.cpp', 'platform/linux/lnx_common.hpp',
    'core/model.cpp', 'core/report.cpp', 'core/log_attack.hpp',
]

def corrupt_segments(literal):
    """返回字面量中 '\X'（X=大写）且该 \ 未被转义的位置列表"""
    hits = []
    i = 0
    while i < len(literal):
        if literal[i] == '\\':
            if i + 1 < len(literal) and literal[i + 1] == '\\':
                i += 2  # 转义的反斜杠，跳过一对
                continue
            if i + 1 < len(literal) and literal[i + 1].isupper():
                hits.append(i)
        i += 1
    return hits

total = 0
for f in files:
    try:
        s = open(f, encoding='utf-8').read()
    except OSError:
        continue
    for i, line in enumerate(s.split('\n'), 1):
        # 粗提字符串字面量段（简化：引号间的内容，处理跨行 L"..." 拼接时够用）
        j = 0
        while True:
            a = line.find('"', j)
            if a < 0:
                break
            b = a + 1
            while b < len(line):
                if line[b] == '\\':
                    b += 2
                    continue
                if line[b] == '"':
                    break
                b += 1
            seg = line[a + 1:min(b, len(line))]
            if corrupt_segments(seg):
                print(f'{f}:{i}: {line.strip()[:130]}')
                total += 1
                break
            j = b + 1
print(f'--- total: {total} ---')

