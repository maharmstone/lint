#include <unistd.h>
#include <sys/types.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    uid_t uid;
    unsigned int num_sessions;
} entry;

typedef struct {
    _Atomic uint32_t ticket;
    uint32_t turn;
    uint32_t num_entries;
    entry entries[1];
} shared;

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

static shared* get_shared(pam_handle_t* pamh) {
    int fd, ret;
    void* mem;

    fd = open("/dev/shm/pam_muw", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        pam_syslog(pamh, LOG_ERR, "failed to open shared memory (error %i)", fd);
        return NULL;
    }

    if (lseek(fd, 0, SEEK_END) == 0) { // new file
        ret = ftruncate(fd, 4096);
        if (ret == -1) {
            pam_syslog(pamh, LOG_ERR, "ftruncate failed (error %i)", errno);
            close(fd);
            return NULL;
        }
    }

    mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        pam_syslog(pamh, LOG_ERR, "mmap failed (error %i)", errno);
        close(fd);
        return NULL;
    }

    // FIXME - what if we need more than 4,096 bytes?

    close(fd);

    return (shared*)mem;
}

static void release_shared(shared* sh) {
    munmap(sh, 4096);
}

static void get_spinlock(shared* sh) {
    uint32_t turn = sh->ticket++;

    while (turn != sh->turn) { }
}

static void release_spinlock(shared* sh) {
    sh->turn++;
}

static void first_session(pam_handle_t* pamh, entry* ent) {
    // FIXME - call NtLoadKey etc.
    pam_syslog(pamh, LOG_INFO, "pam_sm_open_session: FIXME, call NtLoadKey for uid %u\n", ent->uid);
}

__attribute__ ((visibility ("default")))
int pam_sm_open_session(pam_handle_t* pamh, __attribute__((unused)) int flags,
                        __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    const char* user_name;
    int ret;
    struct passwd* pwd;
    shared* sh;
    bool found = false;

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

    sh = get_shared(pamh);
    if (!sh)
        return PAM_SESSION_ERR;

    get_spinlock(sh);

    for (unsigned int i = 0; i < sh->num_entries; i++) {
        if (sh->entries[i].uid == pwd->pw_uid) {
            sh->entries[i].num_sessions++;
            found = true;
        }
    }

    if (!found) {
        entry* ent = &sh->entries[sh->num_entries];

        ent->uid = pwd->pw_uid;
        ent->num_sessions = 1;

        first_session(pamh, ent);

        sh->num_entries++;
    }

    // FIXME - better if we have per-user locks as well, so that NtLoadKey doesn't block everybody?

    release_spinlock(sh);

    release_shared(sh);

    return PAM_IGNORE;
}

static void last_session(pam_handle_t* pamh, entry* ent) {
    // FIXME - call NtUnloadKey etc.
    pam_syslog(pamh, LOG_INFO, "pam_sm_close_session: FIXME, call NtUnloadKey for uid %u\n", ent->uid);
}

__attribute__ ((visibility ("default")))
int pam_sm_close_session(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                         __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    const char* user_name;
    struct passwd* pwd;
    shared* sh;
    int ret;

    ret = pam_get_item(pamh, PAM_USER, (const void**)&user_name);
    if (ret != PAM_SUCCESS || !user_name || *user_name == '\0') {
        pam_syslog(pamh, LOG_ERR, "close_session - error recovering username");
        return PAM_SESSION_ERR;
    }

    pwd = pam_modutil_getpwnam(pamh, user_name);
    if (!pwd) {
        pam_syslog(pamh, LOG_ERR, "close_session - error recovering uid");
        return PAM_SESSION_ERR;
    }

    sh = get_shared(pamh);
    if (!sh)
        return PAM_SESSION_ERR;

    get_spinlock(sh);

    for (unsigned int i = 0; i < sh->num_entries; i++) {
        if (sh->entries[i].uid == pwd->pw_uid) {
            sh->entries[i].num_sessions--;

            if (sh->entries[i].num_sessions == 0) {
                entry ent;

                memcpy(&ent, &sh->entries[i], sizeof(entry));

                // remove from list
                memcpy(&sh->entries[i], &sh->entries[i+1], sizeof(entry) * (sh->num_entries - i - 1));
                sh->num_entries--;

                last_session(pamh, &ent);
            }

            break;
        }
    }

    release_spinlock(sh);

    release_shared(sh);

    return PAM_SUCCESS;
}

__attribute__ ((visibility ("default")))
int pam_sm_chauthtok(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                     __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}
