#pragma once
// Windows Event Log XML (EvtRender EventXml) lightweight parser: no XML library.
// Covers Vista/Server 2008 R2 (EventID Qualifiers attribute) through Win10/11.
#include <string>
#include <cstdlib>

namespace ctfir {

// <Data Name="ServiceName">value</Data> (2008 R2 and Win10 share this schema)
inline std::string evt_xml_data(const std::string& x, const char* name) {
    if (!name || !*name) return "";
    std::string pat = std::string("Name=\"") + name + "\">";
    size_t p = x.find(pat);
    if (p == std::string::npos) {
        pat = std::string("Name='") + name + "'>";
        p = x.find(pat);
        if (p == std::string::npos) return "";
    }
    size_t s = p + pat.size(), e = x.find('<', s);
    return (e == std::string::npos) ? "" : x.substr(s, e - s);
}

// SystemTime="2012-03-15T08:00:00.000000000Z" -> 19 chars + Z (for beijing_time_str)
inline std::string evt_xml_time(const std::string& x) {
    size_t p = x.find("SystemTime=\"");
    if (p == std::string::npos) return "";
    size_t s = p + 12, e = x.find('"', s);
    std::string t = (e == std::string::npos) ? "" : x.substr(s, e - s);
    if (t.size() >= 19) t = t.substr(0, 19) + "Z";
    return t;
}

// <EventID>4697</EventID> and <EventID Qualifiers="16384">7045</EventID>
// (Qualifiers form is common on 2008 R2 System-channel classic sources)
inline int evt_xml_event_id(const std::string& x) {
    size_t p = 0;
    while ((p = x.find("<EventID", p)) != std::string::npos) {
        if (p + 8 < x.size() && (x[p + 8] == '>' || x[p + 8] == ' ' || x[p + 8] == '\t')) {
            size_t gt = x.find('>', p);
            if (gt == std::string::npos) return 0;
            return std::atoi(x.c_str() + static_cast<int>(gt) + 1);
        }
        p += 8;
    }
    return 0;
}

} // namespace ctfir
