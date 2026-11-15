#!/usr/bin/env python3
"""Static scope guards, NOT a live domain-controller test."""
from pathlib import Path
import re
root=Path(__file__).resolve().parent.parent
w=(root/'platform/win/mod_w.cpp').read_text()
b=(root/'platform/win/mod_w4.cpp').read_text()
checks=0
def check(ok,label):
 global checks
 checks+=1
 assert ok,label
check(w.index('if(!account_local_sam_allowed(role))')<w.index('NetUserEnum('),'main account collector guard before API')
check('if(account_local_sam_allowed(role))return true;' in b and 'ModuleStatus::SKIPPED' in b,'shared baseline role guard')
for func,api in [('mod_base_accounts','NetUserEnum('),('mod_base_password','NetUserModalsGet(')]:
 body=b.split('void '+func+'(ModuleCtx& ctx) {',1)[1]
 check(body.index('if(!local_sam_scope(ctx))return;')<body.index(api),func+' role guard before account API')
check('NetLocalGroupGetMembers(nullptr,admin_group.c_str(),0,' in w,'group members SID-only, no remote resolution')
ps=(root/'packaging/account-review.ps1').read_text()
check(ps.index("if($policy -ne 'LocalSAMOnly')")<ps.index('Get-CimInstance -ClassName Win32_UserAccount'),'PS role guard before account query')
check(re.search(r'(?i)(?:^|\s)/domain\b',ps) is None and '-computername' not in ps.lower(),'no domain/remote parameters')
print(f'ACCOUNT_SCOPE_STATIC checks={checks} failures=0; not live DC evidence')
