#include <security/pam_modules.h>
#include <syslog.h>

__attribute__ ((visibility ("default")))
int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    syslog(LOG_AUTH, "pam_sm_authenticate stub\n");
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    syslog(LOG_AUTH, "pam_sm_setcred stub\n");
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    syslog(LOG_AUTH, "pam_sm_acct_mgmt stub\n");
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    syslog(LOG_AUTH, "pam_sm_open_session stub\n");
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_close_session(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    syslog(LOG_AUTH, "pam_sm_close_session stub\n");
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_chauthtok(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    syslog(LOG_AUTH, "pam_sm_chauthtok stub\n");
    return PAM_IGNORE;
}
