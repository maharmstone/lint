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
#include <atomic>
#include <string>
#include <muw.h>

using namespace std;

typedef struct {
    uid_t uid;
    unsigned int num_sessions;
} entry;

typedef struct {
    atomic<uint32_t> ticket;
    uint32_t turn;
    uint32_t num_entries;
    entry entries[1];
} shared;

// muw.cpp
u16string get_nt_path(const string_view& s);
void mount_hive(const u16string_view& key, const u16string_view& file);
void unmount_hive(const u16string_view& key);
void create_reg_key(const u16string_view& key, bool is_volatile);
void create_reg_symlink(const u16string_view& src, const u16string_view& dest);
void delete_key(const u16string_view& key);

extern "C"
__attribute__ ((visibility ("default")))
int pam_sm_authenticate(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                        __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}

extern "C"
__attribute__ ((visibility ("default")))
int pam_sm_setcred(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                   __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}

extern "C"
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

static void first_session(pam_handle_t* pamh, struct passwd* pwd) {
    if (pwd->pw_uid != 1000)
        return; // FIXME

    u16string sidstr = u"S-1-5-21-0-0-0-1000"; // FIXME - derive from uid

    try {
        create_reg_key(u"\\Registry\\User\\" + sidstr, true);

        // FIXME - make paths to hives customizable?
        // FIXME - if doesn't exist, create new hive (copy from DEFAULT and recursively change SIDs)
        mount_hive(u"\\Registry\\User\\" + sidstr, get_nt_path(string(pwd->pw_dir) + "/.wine/NTUSER.DAT"));

        create_reg_key(u"\\Registry\\User\\" + sidstr + u"_Classes", true);

        // FIXME - if doesn't exist, initialize blank hive(?)
        mount_hive(u"\\Registry\\User\\" + sidstr + u"_Classes", get_nt_path(string(pwd->pw_dir) + "/.wine/UsrClass.dat"));

        create_reg_key(u"\\Registry\\User\\" + sidstr + u"\\Software", false); // should already exist
        create_reg_symlink(u"\\Registry\\User\\" + sidstr + u"\\Software\\Classes",
                           u"\\Registry\\User\\" + sidstr + u"_Classes");
    } catch (const exception& e) {
        pam_syslog(pamh, LOG_ERR, "first_session: %s\n", e.what());
    }

    close_muwine();
}

extern "C"
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

        first_session(pamh, pwd);

        sh->num_entries++;
    }

    // FIXME - better if we have per-user locks as well, so that NtLoadKey doesn't block everybody?

    release_spinlock(sh);

    release_shared(sh);

    return PAM_IGNORE;
}

static void last_session(pam_handle_t* pamh, struct passwd* pwd) {
    if (pwd->pw_uid != 1000)
        return; // FIXME

    u16string sidstr = u"S-1-5-21-0-0-0-1000"; // FIXME - derive from uid

    try {
        unmount_hive(u"\\Registry\\User\\" + sidstr + u"_Classes");

        delete_key(u"\\Registry\\User\\" + sidstr + u"_Classes");
    } catch (const exception& e) {
        pam_syslog(pamh, LOG_ERR, "last_session: %s\n", e.what());
    }

    try {
        unmount_hive(u"\\Registry\\User\\" + sidstr);

        delete_key(u"\\Registry\\User\\" + sidstr);
    } catch (const exception& e) {
        pam_syslog(pamh, LOG_ERR, "last_session: %s\n", e.what());
    }

    close_muwine();
}

extern "C"
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

                last_session(pamh, pwd);
            }

            break;
        }
    }

    release_spinlock(sh);

    release_shared(sh);

    return PAM_SUCCESS;
}

extern "C"
__attribute__ ((visibility ("default")))
int pam_sm_chauthtok(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                     __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}
