// Server 2008 R2 / Vista Event XML 合成夹具：不依赖 2008 R2 真机或 Windows 容器。
// 覆盖 EventID Qualifiers、Name 属性 Data、时间戳规整。
#include "test_macros.hpp"
#include "core/evt_xml.hpp"

using ctfir::evt_xml_data;
using ctfir::evt_xml_time;
using ctfir::evt_xml_event_id;

// 2008 R2 System 7045（经典源，EventID 带 Qualifiers）
static const char kXml2008R2_7045[] =
    "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
    "<System>"
    "<Provider Name=\"Service Control Manager\" EventSourceName=\"Service Control Manager\"/>"
    "<EventID Qualifiers=\"16384\">7045</EventID>"
    "<Level>4</Level>"
    "<TimeCreated SystemTime=\"2012-03-15T08:00:00.123456789Z\"/>"
    "<Channel>System</Channel>"
    "</System>"
    "<EventData>"
    "<Data Name=\"ServiceName\">ctfir-marker-svc</Data>"
    "<Data Name=\"ImagePath\">C:\\Users\\Public\\ctfir-marker-svc.exe</Data>"
    "<Data Name=\"ServiceType\">user mode service</Data>"
    "<Data Name=\"StartType\">demand start</Data>"
    "<Data Name=\"AccountName\">LocalSystem</Data>"
    "</EventData>"
    "</Event>";

// 2008 R2 Security 4697
static const char kXml2008R2_4697[] =
    "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
    "<System>"
    "<Provider Name=\"Microsoft-Windows-Security-Auditing\"/>"
    "<EventID>4697</EventID>"
    "<TimeCreated SystemTime=\"2012-03-15T08:01:02.000Z\"/>"
    "<Channel>Security</Channel>"
    "</System>"
    "<EventData>"
    "<Data Name=\"ServiceName\">ctfir-marker-svc</Data>"
    "<Data Name=\"ServiceFileName\">C:\\Temp\\ctfir-marker-svc.exe</Data>"
    "<Data Name=\"ServiceType\">0x10</Data>"
    "<Data Name=\"ServiceStartType\">3</Data>"
    "<Data Name=\"ServiceAccount\">LocalSystem</Data>"
    "</EventData>"
    "</Event>";

// Win10/11 形态：无 Qualifiers 的 EventID + 4625
static const char kXmlWin11_4625[] =
    "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
    "<System>"
    "<EventID>4625</EventID>"
    "<TimeCreated SystemTime=\"2026-11-12T08:00:00.0000000Z\"/>"
    "<Channel>Security</Channel>"
    "</System>"
    "<EventData>"
    "<Data Name=\"TargetUserName\">ctfir-marker-nouser</Data>"
    "<Data Name=\"IpAddress\">10.66.66.66</Data>"
    "</EventData>"
    "</Event>";

CTFIR_TEST(evtxml_2008r2_7045_qualifiers_and_fields) {
    CHECK(evt_xml_event_id(kXml2008R2_7045) == 7045);
    CHECK(evt_xml_data(kXml2008R2_7045, "ServiceName") == "ctfir-marker-svc");
    CHECK(evt_xml_data(kXml2008R2_7045, "ImagePath") == "C:\\Users\\Public\\ctfir-marker-svc.exe");
    CHECK(evt_xml_time(kXml2008R2_7045) == "2012-03-15T08:00:00Z");
}

CTFIR_TEST(evtxml_2008r2_4697_servicefilename) {
    CHECK(evt_xml_event_id(kXml2008R2_4697) == 4697);
    CHECK(evt_xml_data(kXml2008R2_4697, "ServiceFileName") == "C:\\Temp\\ctfir-marker-svc.exe");
    CHECK(evt_xml_data(kXml2008R2_4697, "ImagePath") == ""); // 4697 用 ServiceFileName
    CHECK(evt_xml_time(kXml2008R2_4697) == "2012-03-15T08:01:02Z");
}

CTFIR_TEST(evtxml_win11_4625_no_qualifiers) {
    CHECK(evt_xml_event_id(kXmlWin11_4625) == 4625);
    CHECK(evt_xml_data(kXmlWin11_4625, "TargetUserName") == "ctfir-marker-nouser");
    CHECK(evt_xml_data(kXmlWin11_4625, "IpAddress") == "10.66.66.66");
}

CTFIR_TEST(evtxml_negative_missing_and_empty) {
    CHECK(evt_xml_event_id("") == 0);
    CHECK(evt_xml_event_id("<Event></Event>") == 0);
    CHECK(evt_xml_data(kXml2008R2_7045, "NotAField") == "");
    CHECK(evt_xml_data("", "ServiceName") == "");
    CHECK(evt_xml_time("") == "");
}

// 单引号 Name 变体
CTFIR_TEST(evtxml_single_quote_name_variant) {
    const char* x = "<Data Name='ServiceName'>quoted-svc</Data><EventID>1</EventID>";
    CHECK(evt_xml_data(x, "ServiceName") == "quoted-svc");
    CHECK(evt_xml_event_id(x) == 1);
}
