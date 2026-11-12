// AD/Server 文本判定：GPP cpassword / NTDS 路径 / GPO 脚本 / 委派（1 正 + 2 负 + 变体）
#include "test_macros.hpp"
#include "core/ad_detect.hpp"

using namespace ctfir;

CTFIR_TEST(ad_gpp_cpassword_positive) {
    const char* xml =
        "<Groups><User name=\"ctfir-marker-gpp\">"
        "<Properties action=\"U\" cpassword=\"edBAC4BrVL9OM5JY8wCNKA\" userName=\"ctfir-marker-gpp\"/>"
        "</User></Groups>";
    CHECK(xml_has_cpassword(xml));
}

CTFIR_TEST(ad_gpp_cpassword_spaced_variant) {
    CHECK(xml_has_cpassword("<x cpassword = \"AAAA\" />"));
    CHECK(xml_has_cpassword("<x CPassword='BBBB'/>"));
}

CTFIR_TEST(ad_gpp_cpassword_negative_absent) {
    CHECK(!xml_has_cpassword("<Groups><User name=\"ok\"/></Groups>"));
}

CTFIR_TEST(ad_gpp_cpassword_negative_empty) {
    CHECK(!xml_has_cpassword("<x cpassword=\"\" userName=\"a\"/>"));
    CHECK(!xml_has_cpassword("<x cpassword=''/>"));
}

CTFIR_TEST(ad_gpp_cpassword_negative_word_only) {
    CHECK(!xml_has_cpassword("the cpassword field was removed by MS14-025"));
}

CTFIR_TEST(ad_gpo_exec_positive) {
    CHECK(xml_has_gpo_exec("<Exec><Command>C:\\Windows\\Temp\\ctfir-marker-gpo.bat</Command></Exec>"));
}

CTFIR_TEST(ad_gpo_exec_negative) {
    CHECK(!xml_has_gpo_exec("<ScheduledTasks clsid=\"{x}\"/>"));
    CHECK(!xml_has_gpo_exec("command documentation only"));
}

CTFIR_TEST(ad_ntds_live_vs_copy_vs_ifm) {
    CHECK(classify_ntds_path("C:\\Windows\\NTDS\\ntds.dit", "C:\\Windows") == NtdsClass::Live);
    CHECK(classify_ntds_path("C:\\windows\\ntds\\NTDS.DIT", "C:\\WINDOWS") == NtdsClass::Live);
    CHECK(classify_ntds_path("C:\\Windows\\Temp\\ntds.dit", "C:\\Windows") == NtdsClass::Copy);
    CHECK(classify_ntds_path("C:\\Windows\\NTDS\\ntds.dit.bak", "C:\\Windows") == NtdsClass::Copy);
    CHECK(classify_ntds_path("C:\\Windows\\Temp\\ctfir-marker-ntds.dit", "C:\\Windows") == NtdsClass::Copy);
    CHECK(classify_ntds_path("C:\\Windows\\Temp\\ntds-copy.dit", "C:\\Windows") == NtdsClass::Copy);
    CHECK(classify_ntds_path("C:\\Windows\\Temp\\ctfir-marker-ifm\\Active Directory\\ntds.dit",
                             "C:\\Windows") == NtdsClass::Ifm);
    CHECK(classify_ntds_path("C:\\Windows\\Temp\\note.txt", "C:\\Windows") == NtdsClass::None);
    CHECK(classify_ntds_path("C:\\Windows\\NTDS\\edb.log", "C:\\Windows") == NtdsClass::None);
    CHECK(classify_ntds_path("C:\\Windows\\Windows.edb", "C:\\Windows") == NtdsClass::None);
}

CTFIR_TEST(ad_sysvol_script_name) {
    CHECK(is_sysvol_script_name("C:\\Windows\\SYSVOL\\sysvol\\d\\scripts\\ctfir-marker.bat"));
    CHECK(is_sysvol_script_name("x.PS1"));
    CHECK(!is_sysvol_script_name("C:\\Windows\\SYSVOL\\sysvol\\d\\scripts\\readme.txt"));
    CHECK(path_looks_like_sysvol_scripts("C:\\Windows\\SYSVOL\\sysvol\\ctfir.local\\scripts\\a.bat"));
    CHECK(!path_looks_like_sysvol_scripts("C:\\Windows\\Temp\\a.bat"));
}

CTFIR_TEST(ad_gptmpl_default_admins_negative) {
    const char* inf =
        "[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\n"
        "SeEnableDelegationPrivilege = *S-1-5-32-544\r\n";
    CHECK(!gptmpl_extra_delegation(inf));
}

CTFIR_TEST(ad_gptmpl_extra_sid_positive) {
    const char* inf =
        "SeEnableDelegationPrivilege = *S-1-5-32-544,ctfir-marker-deleg\r\n";
    std::string extra;
    CHECK(gptmpl_extra_delegation(inf, &extra));
    CHECK(extra.find("ctfir-marker-deleg") != std::string::npos);
}

CTFIR_TEST(ad_gptmpl_full_fixture_positive) {
    const char* inf =
        "[Unicode]\nUnicode=yes\n[Version]\nsignature=\"$CHICAGO$\"\nRevision=1\n"
        "[Privilege Rights]\n"
        "SeEnableDelegationPrivilege = *S-1-5-32-544,ctfir-marker-deleg\n"
        "SeDebugPrivilege = *S-1-5-32-544,ctfir-marker-debug\n";
    std::string extra;
    CHECK(gptmpl_extra_delegation(inf, &extra));
    CHECK(extra.find("ctfir-marker-deleg") != std::string::npos);
    std::string all;
    CHECK(gptmpl_dangerous_extra(inf, &all));
    CHECK(all.find("SeDebugPrivilege") != std::string::npos);
}

CTFIR_TEST(ad_gptmpl_utf16le_without_bom) {
    const char* ascii = "SeEnableDelegationPrivilege = *S-1-5-32-544,evil\n";
    std::string u16;
    for (const char* p = ascii; *p; ++p) {
        u16.push_back(*p);
        u16.push_back('\0');
    }
    CHECK(gptmpl_extra_delegation(u16));
}

CTFIR_TEST(ad_gpp_local_admin_positive) {
    CHECK(xml_has_gpp_local_admin(
        "<Group name=\"Administrators\"><Properties groupName=\"Administrators\" "
        "userName=\"ctfir-marker-gpp\" action=\"U\"/></Group>"));
}

CTFIR_TEST(ad_gpp_local_admin_negative) {
    CHECK(!xml_has_gpp_local_admin("<Groups><User name=\"bob\"/></Groups>"));
    CHECK(!xml_has_gpp_local_admin("mention Administrators in a comment only"));
}

CTFIR_TEST(ad_file_candidate_filter) {
    CHECK(ad_file_candidate("C:\\Windows\\Temp\\ctfir-marker-ntds.dit"));
    CHECK(ad_file_candidate("C:\\Windows\\SYSVOL\\x\\Groups.xml"));
    CHECK(ad_file_candidate("C:\\Windows\\SYSVOL\\x\\GptTmpl.inf"));
    CHECK(ad_file_candidate("C:\\Windows\\Temp\\sam.save"));
    CHECK(ad_file_candidate("C:\\Windows\\Temp\\lsass.dmp"));
    CHECK(!ad_file_candidate("C:\\ProgramData\\random.log"));
    CHECK(!ad_file_candidate("C:\\Windows\\Temp\\ctfir-marker-drop.exe"));
}

CTFIR_TEST(ad_hive_copy_positive_and_live_negative) {
    CHECK(looks_like_hive_copy_path("C:\\Windows\\Temp\\sam.save"));
    CHECK(looks_like_hive_copy_path("C:\\Windows\\Temp\\system.save"));
    CHECK(looks_like_hive_copy_path("C:\\Windows\\Temp\\ctfir-marker-ifm\\registry\\SYSTEM"));
    CHECK(looks_like_hive_copy_path("C:\\Users\\Public\\sam.save"));
    CHECK(!looks_like_hive_copy_path("C:\\Windows\\System32\\config\\SAM"));
    CHECK(!looks_like_hive_copy_path("C:\\Windows\\System32\\config\\RegBack\\SYSTEM"));
    CHECK(!looks_like_hive_copy_path("C:\\Windows\\repair\\SAM"));
    CHECK(!looks_like_hive_copy_path("C:\\Windows\\Temp\\note.txt"));
}

CTFIR_TEST(ad_lsass_dump_name) {
    CHECK(looks_like_lsass_dump("C:\\Windows\\Temp\\lsass.dmp"));
    CHECK(looks_like_lsass_dump("C:\\Temp\\lsass.exe.646.dmp"));
    CHECK(!looks_like_lsass_dump("C:\\Windows\\System32\\lsass.exe"));
    CHECK(!looks_like_lsass_dump("C:\\Windows\\Temp\\app.dmp"));
}

CTFIR_TEST(ad_gptmpl_comment_negative) {
    CHECK(!gptmpl_extra_delegation("; SeEnableDelegationPrivilege = evil\r\n"));
}

CTFIR_TEST(ad_scripts_ini_positive) {
    const char* ini = "[Logon]\r\n0CmdLine=ctfir-marker.bat\r\n0Parameters=\r\n";
    std::string cmd;
    CHECK(scripts_ini_has_cmdline(ini, &cmd));
    CHECK_EQ(cmd, std::string("ctfir-marker.bat"));
}

CTFIR_TEST(ad_scripts_ini_negative_empty) {
    CHECK(!scripts_ini_has_cmdline("[Logon]\r\n0CmdLine=\r\n"));
    CHECK(!scripts_ini_has_cmdline("[Unicode]\r\nUnicode=yes\r\n"));
}
