#include <unistd.h>
#include <sys/types.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <syslog.h>

__attribute__ ((visibility ("default")))
int pam_sm_authenticate(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                        __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_setcred(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                   __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_acct_mgmt(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                     __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_open_session(pam_handle_t* pamh, __attribute__((unused)) int flags,
                        __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    const char* user_name;
    int ret;
    struct passwd* pwd;

    ret = pam_get_item(pamh, PAM_USER, (const void**)&user_name);
    if (ret != PAM_SUCCESS || !user_name || *user_name == '\0') {
        pam_syslog(pamh, LOG_ERR, "open_session - error recovering username");
        return PAM_SESSION_ERR;
    }

    pwd = pam_modutil_getpwnam(pamh, user_name);
    if (!pwd) {
        pam_syslog(pamh, LOG_ERR, "open_session - error recovering uid");
        return PAM_SESSION_ERR;
    }

    pam_syslog(pamh, LOG_INFO, "pam_sm_open_session stub (uid = %u)\n", pwd->pw_uid);

    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_close_session(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                         __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    pam_syslog(pamh, LOG_INFO, "pam_sm_close_session stub\n");
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_chauthtok(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                     __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}
