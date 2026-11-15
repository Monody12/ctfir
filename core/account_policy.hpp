#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <cstdint>
namespace ctfir {
inline bool account_uint32(const std::string& text, std::uint32_t& value) {
    if(text.empty()) return false;
    std::uint64_t n=0;
    for(unsigned char c:text) { if(c<'0'||c>'9')return false; n=n*10+(c-'0'); if(n>=4294967295ULL)return false; }
    value=static_cast<std::uint32_t>(n); return true;
}
inline bool account_sid_rid(const std::string& sid,std::uint32_t& rid) {
    const std::string prefix="S-1-5-21-";
    if(sid.compare(0,prefix.size(),prefix)!=0)return false;
    std::istringstream in(sid.substr(prefix.size())); std::string part;unsigned n=0;std::uint32_t v=0;
    while(std::getline(in,part,'-')) {if(!account_uint32(part,v))return false;++n;}
    if(n!=4 || sid.back()=='-')return false;rid=v;return true;
}
inline bool account_protected_admin(const std::string& sid) {std::uint32_t rid=0;return account_sid_rid(sid,rid)&&rid==500;}
inline bool account_admin_group_sid(const std::string& sid) {return sid=="S-1-5-32-544";}
inline bool account_local_sam_allowed(const std::string& product_type) {return product_type=="WinNT"||product_type=="ServerNT";}
struct LocalPasswdRecord {std::string name,home,shell;std::uint32_t uid=0,gid=0;};
inline bool parse_local_passwd(const std::string& text,LocalPasswdRecord& out) {
    if(text.empty()||text[0]=='#'||text[0]=='+'||text[0]=='-'||text.find('\0')!=std::string::npos)return false;
    std::vector<std::string> fields;std::size_t a=0,b;
    while((b=text.find(':',a))!=std::string::npos) {fields.push_back(text.substr(a,b-a));a=b+1;}
    fields.push_back(text.substr(a));if(fields.size()!=7||fields[0].empty())return false;
    LocalPasswdRecord r;if(!account_uint32(fields[2],r.uid)||!account_uint32(fields[3],r.gid))return false;
    r.name=fields[0];r.home=fields[5];r.shell=fields[6];out=r;return true;
}
inline bool account_nss_has_external(std::string line) {
    bool bracket=false;std::string plain;
    for(char c:line) {if(c=='[')bracket=true;else if(c==']')bracket=false;else if(!bracket)plain+=c;}
    auto colon=plain.find(':');if(colon!=std::string::npos)plain=plain.substr(colon+1);
    std::istringstream in(plain);std::string token;
    while(in>>token) {if(token[0]=='#')break;if(token!="files"&&token!="systemd")return true;}
    return false;
}
}
