import re
p = r'C:\Users\Administrator\Documents\zcode-projects\ctfir\platform\win\mod_w4.cpp'
s = open(p, encoding='utf-8', newline='').read()
# 修复：L"..." 内部单反斜杠 → 双反斜杠（只修不正确的 \大写 路径）
fixes = [
    ('L"SOFTWARE\\Microsoft\\NetSh"', 'L"SOFTWARE\\\\Microsoft\\\\NetSh"'),
    ('L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components"', 'L"SOFTWARE\\\\Microsoft\\\\Active Setup\\\\Installed Components"'),
    ('L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"', 'L"SYSTEM\\\\CurrentControlSet\\\\Control\\\\Session Manager\\\\Environment"'),
    ('L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"', 'L"SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Exclusions\\\\Paths"'),
    ('L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions"', 'L"SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Exclusions\\\\Extensions"'),
    ('L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes"', 'L"SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Exclusions\\\\Processes"'),
    ('L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors"', 'L"SYSTEM\\\\CurrentControlSet\\\\Control\\\\Print\\\\Monitors"'),
    ('L"SYSTEM\\CurrentControlSet\\Services\\BITS"', 'L"SYSTEM\\\\CurrentControlSet\\\\Services\\\\BITS"'),
    ('L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BITS"', 'L"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\BITS"'),
]
for old, new in fixes:
    if old in s and new not in s:
        s = s.replace(old, new)
        print(f'fixed: {old[:50]}')
open(p, 'w', encoding='utf-8', newline='').write(s)
print('done')
