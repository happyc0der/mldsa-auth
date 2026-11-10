#include "authd_secret.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "authd_config.h"
#include "secure_mem.h"

const char *authd_secret_status_name(authd_secret_status_t st)
{
    switch (st) {
    case AUTHD_SECRET_OK:               return "ok";
    case AUTHD_SECRET_ERR_ARG:          return "bad-argument";
    case AUTHD_SECRET_ERR_OPEN:         return "cannot-open";
    case AUTHD_SECRET_ERR_NOT_REGULAR:  return "not-a-regular-file";
    case AUTHD_SECRET_ERR_OWNER:        return "not-owned-by-this-user";
    case AUTHD_SECRET_ERR_PERMISSIONS:  return "unsafe-permissions";   /* the key-file reader's name (F126) */
    case AUTHD_SECRET_ERR_SIZE:         return "empty-or-too-large";
    case AUTHD_SECRET_ERR_READ:         return "short-read";
    case AUTHD_SECRET_ERR_CRYPTO:       return "allocation-failed";
    }
    return "unknown";
}

void authd_secret_free(uint8_t *p, size_t len)
{
    if (p != NULL) {
        secure_mem_free(p, len);
    }
}

/* Is path a file DIRECTLY inside creds_dir? Textual on purpose: the caller
 * opened path with O_NOFOLLOW, and creds_dir is systemd's own absolute path.
 * "/run/credentials/a.service" must not admit "/run/credentials/a.serviceX/p"
 * nor ".../a.service/sub/p". */
static int in_creds_dir(const char *path, const char *creds_dir)
{
    if (path == NULL || creds_dir == NULL || creds_dir[0] != '/') {
        return 0;
    }
    size_t n = strlen(creds_dir);
    while (n > 1u && creds_dir[n - 1u] == '/') {
        n--;
    }
    if (strncmp(path, creds_dir, n) != 0 || path[n] != '/') {
        return 0;
    }
    const char *base = path + n + 1u;
    return base[0] != '\0' && strchr(base, '/') == NULL;
}

authd_secret_status_t authd_secret_custody(const char *path, uid_t uid, gid_t gid, mode_t mode,
                                           uid_t euid, const char *creds_dir)
{
    /* systemd's credential (see the header): root:root, the group bits are
     * the ACL mask, so only group WRITE and every "other" bit are refused. */
    if (uid == (uid_t)0 && gid == (gid_t)0 && in_creds_dir(path, creds_dir)) {
        if ((mode & 027) != 0) {
            return AUTHD_SECRET_ERR_PERMISSIONS;
        }
        return AUTHD_SECRET_OK;
    }
    /* Owner check, which the pre-V4-9b daemon helper did not make. Spec 12
     * applies it to the key file; a passphrase deserves it at least as much. */
    if (uid != euid) {
        return AUTHD_SECRET_ERR_OWNER;
    }
    if ((mode & 077) != 0) {
        return AUTHD_SECRET_ERR_PERMISSIONS;
    }
    return AUTHD_SECRET_OK;
}

authd_secret_status_t authd_secret_read(const char *path, uint8_t **out, size_t *out_len)
{
    if (path == NULL || out == NULL || out_len == NULL) {
        return AUTHD_SECRET_ERR_ARG;
    }
    *out = NULL;
    *out_len = 0;

    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return AUTHD_SECRET_ERR_OPEN;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        (void)close(fd);
        return AUTHD_SECRET_ERR_NOT_REGULAR;
    }
    {
        const authd_secret_status_t cs = authd_secret_custody(path, st.st_uid, st.st_gid, st.st_mode,
                                                              geteuid(), getenv("CREDENTIALS_DIRECTORY"));
        if (cs != AUTHD_SECRET_OK) {
            (void)close(fd);
            return cs;
        }
    }
    if (st.st_size <= 0 || (uintmax_t)st.st_size > (uintmax_t)AUTHD_PASSPHRASE_MAX) {
        (void)close(fd);
        return AUTHD_SECRET_ERR_SIZE;
    }

    const size_t want = (size_t)st.st_size;
    uint8_t *buf = secure_mem_alloc(want);
    if (buf == NULL) {
        (void)close(fd);
        return AUTHD_SECRET_ERR_CRYPTO;
    }
    size_t got = 0;
    while (got < want) {
        const ssize_t n = read(fd, buf + got, want - got);
        if (n <= 0) {
            break;
        }
        got += (size_t)n;
    }
    (void)close(fd);
    if (got != want) {
        secure_mem_free(buf, want);
        return AUTHD_SECRET_ERR_READ;
    }
    /* Exactly one trailing newline, and only one: see the header. */
    if (got > 0u && buf[got - 1u] == (uint8_t)'\n') {
        got--;
    }
    if (got == 0u) {
        secure_mem_free(buf, want);
        return AUTHD_SECRET_ERR_SIZE;
    }
    *out = buf;
    *out_len = got;
    return AUTHD_SECRET_OK;
}
