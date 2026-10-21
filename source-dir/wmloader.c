/* wmloader v2
 *
 * Key design change from v1: instead of decrypting and handing the source
 * straight to zend_compile_string() (which - like eval() - opcache never
 * caches), this version decrypts into the SAME file_handle->buf slot that
 * zend_stream_fixup() already filled with the ciphertext, then calls
 * through to whatever compile_file handler was previously registered.
 *
 * If opcache is loaded, that "previous handler" is opcache's own
 * persistent_compile function - the exact same one normal .php files go
 * through. Opcache's SHM cache is keyed by path+mtime, so:
 *   - cache hit  -> opcache returns the cached op_array directly; the
 *                   compiled bytecode for this request never touches our
 *                   decrypted buffer at all.
 *   - cache miss -> opcache calls the real compiler on our decrypted
 *                   buffer once, then stores the result in SHM for every
 *                   later request/worker on the box.
 * Net effect: decryption still runs every request (cheap - microseconds),
 * but full re-parsing/re-compilation of protected scripts on every single
 * request (v1's behavior) is eliminated wherever opcache is enabled.
 *
 * Versioned keys: each encrypted file embeds a 1-byte key version. The
 * secret directory can hold several <version>.key files at once, so a
 * compromised or aging key can be rotated without breaking files still
 * encrypted under the old one - re-encrypt them at your own pace, then
 * remove the old key file once nothing references it.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "Zend/zend_compile.h"
#include "Zend/zend_stream.h"
#include "php_wmloader.h"
#include "wmcrypto.h"
#include <unistd.h>
#include <time.h>
#include <sys/file.h>

ZEND_DECLARE_MODULE_GLOBALS(wmloader)

static zend_op_array *(*wm_original_compile_file)(zend_file_handle *file_handle, int type);

PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("wmloader.secret_dir", "/etc/wmcyber/secrets", PHP_INI_SYSTEM,
                       OnUpdateString, secret_dir, zend_wmloader_globals, wmloader_globals)
    STD_PHP_INI_ENTRY("wmloader.anti_debug", "0", PHP_INI_SYSTEM,
                       OnUpdateBool, anti_debug, zend_wmloader_globals, wmloader_globals)
    STD_PHP_INI_ENTRY("wmloader.identity", "", PHP_INI_SYSTEM,
                       OnUpdateString, identity, zend_wmloader_globals, wmloader_globals)
    STD_PHP_INI_ENTRY("wmloader.audit_log", "", PHP_INI_SYSTEM,
                       OnUpdateString, audit_log, zend_wmloader_globals, wmloader_globals)
PHP_INI_END()

/* Appends one tab-separated line per failure to wmloader.audit_log, if set.
 * Deliberately a flat text file rather than a DB write: this must never
 * itself become a reason for a request to fail (no DB connection to
 * manage, nothing that can throw), and is trivial for an existing log
 * pipeline (e.g. wmcyber-waf's own audit log ingestion) to tail and
 * import. Uses flock() since multiple php-fpm workers write concurrently. */
static void wm_audit(const char *event, const char *file, int version, const char *reason)
{
    const char *path = WMLOADER_G(audit_log);
    if (!path || !*path) return;

    FILE *f = fopen(path, "a");
    if (!f) return;

    int fd = fileno(f);
    if (fd >= 0) flock(fd, LOCK_EX);

    time_t now = time(NULL);
    char ts[32];
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv);

    fprintf(f, "%s\twmloader\t%s\tfile=%s\tkey_version=%d\treason=%s\n",
            ts, event, file ? file : "", version, reason ? reason : "");

    if (fd >= 0) flock(fd, LOCK_UN);
    fclose(f);
}

/* The identity string used to satisfy a file's optional binding: an
 * explicit wmloader.identity override if set (recommended - container
 * hostnames are often random unless explicitly pinned, which is exactly
 * the kind of false-positive ionCube-style binding has been criticized
 * for), otherwise the OS hostname. Returns length written into buf. */
static size_t wm_local_identity(char *buf, size_t buf_size)
{
    const char *override = WMLOADER_G(identity);
    if (override && *override) {
        size_t n = strlen(override);
        if (n >= buf_size) n = buf_size - 1;
        memcpy(buf, override, n);
        buf[n] = '\0';
        return n;
    }
    if (gethostname(buf, buf_size) == 0) {
        buf[buf_size - 1] = '\0';
        return strlen(buf);
    }
    buf[0] = '\0';
    return 0;
}

/* Non-invasive tracer detection: reads /proc/self/status's TracerPid field.
 * Unlike the classic "ptrace(PTRACE_TRACEME)" self-trace trick, this has no
 * side effects on the process's own trace state, so it's safe to call from
 * a long-lived php-fpm worker without risking interference with the parent
 * process's own signal/wait handling. Linux-only (matches the Docker/Azure
 * deployment target); harmlessly reports "not traced" on other platforms.
 * This raises the bar against casual `gdb -p <pid>` memory dumping; it is
 * not, and cannot be, a guarantee against a determined attacker (see the
 * threat-model notes in the README). */
static int wm_tracer_attached(void)
{
#if defined(__linux__)
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0; /* fail open, never block execution on an unrelated I/O error */
    char line[256];
    int traced = 0;
    while (fgets(line, sizeof(line), f)) {
        long pid;
        if (sscanf(line, "TracerPid: %ld", &pid) == 1) {
            traced = (pid != 0);
            break;
        }
    }
    fclose(f);
    return traced;
#else
    return 0;
#endif
}

/* Reads <secret_dir>/<version>.key. Returns 1 on success. */
static int wm_read_secret(int version, unsigned char **out, size_t *out_len)
{
    const char *dir = WMLOADER_G(secret_dir);
    if (!dir || !*dir || version <= 0) return 0;

    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/%d.key", dir, version);
    if (n <= 0 || (size_t)n >= sizeof(path)) return 0;

    php_stream *stream = php_stream_open_wrapper(path, "rb", REPORT_ERRORS | USE_PATH, NULL);
    if (!stream) return 0;

    zend_string *contents = php_stream_copy_to_mem(stream, PHP_STREAM_COPY_ALL, 0);
    php_stream_close(stream);
    if (!contents) return 0;

    if (ZSTR_LEN(contents) < 32) {
        zend_string_release(contents);
        return 0;
    }

    *out = emalloc(ZSTR_LEN(contents));
    memcpy(*out, ZSTR_VAL(contents), ZSTR_LEN(contents));
    *out_len = ZSTR_LEN(contents);
    zend_string_release(contents);
    return 1;
}

static zend_op_array *wm_compile_file(zend_file_handle *file_handle, int type)
{
    char *buf = NULL;
    size_t len = 0;

    if (zend_stream_fixup(file_handle, &buf, &len) == FAILURE) {
        return wm_original_compile_file(file_handle, type);
    }

    if (len <= WM_HEADER_LEN || memcmp(buf, WM_MAGIC, WM_MAGIC_LEN) != 0) {
        /* Not one of ours - the buffer is already fixed up, so this does
         * not re-read the file; opcache (if loaded) handles it as usual. */
        return wm_original_compile_file(file_handle, type);
    }

    const char *display_name = file_handle->filename ? ZSTR_VAL(file_handle->filename) : "wmloader";
    int version = (int)(unsigned char)buf[WM_MAGIC_LEN];
    int bind_flag = (int)(unsigned char)buf[WM_MAGIC_LEN + WM_VER_LEN];

    if (WMLOADER_G(anti_debug) && wm_tracer_attached()) {
        WMLOADER_G(files_failed)++;
        wm_audit("blocked", display_name, version, "tracer_attached");
        zend_error(E_ERROR,
            "wmloader: refusing to decrypt '%s' - a debugger/tracer is attached to this process",
            display_name);
        return NULL;
    }

    char identity[256];
    size_t identity_len = 0;
    if (bind_flag) {
        identity_len = wm_local_identity(identity, sizeof(identity));
    }

    unsigned char *secret = NULL;
    size_t secret_len = 0;
    if (!wm_read_secret(version, &secret, &secret_len)) {
        WMLOADER_G(files_failed)++;
        wm_audit("blocked", display_name, version, "key_unreadable");
        zend_error(E_ERROR,
            "wmloader: cannot read key version %d for '%s' (check wmloader.secret_dir and its permissions)",
            version, display_name);
        return NULL;
    }

    size_t blob_len = len - WM_HEADER_LEN;
    size_t cap = blob_len + ZEND_MMAP_AHEAD; /* plaintext is always <= ciphertext length for GCM */
    unsigned char *plaintext = emalloc(cap);
    size_t plain_len = wm_decrypt_aad(secret, secret_len,
                                       (const unsigned char *)identity, identity_len,
                                       (const unsigned char *)buf + WM_HEADER_LEN, blob_len,
                                       plaintext);

    OPENSSL_cleanse(secret, secret_len);
    efree(secret);

    if (plain_len == 0) {
        efree(plaintext);
        WMLOADER_G(files_failed)++;
        wm_audit("blocked", display_name, version, "decrypt_failed_or_tampered_or_binding_mismatch");
        zend_error(E_ERROR,
            "wmloader: decryption failed for '%s' (key version %d wrong/missing on this server, "
            "identity binding mismatch, or the file was tampered with)",
            display_name, version);
        return NULL;
    }
    memset(plaintext + plain_len, 0, ZEND_MMAP_AHEAD);
    WMLOADER_G(files_decrypted)++;

    /* Swap the fixed-up buffer: free the ciphertext buf the engine already
     * allocated for us, and install our decrypted plaintext in its place.
     * The engine's normal zend_file_handle_dtor() will efree() this new
     * buffer for us - we must not free it ourselves. */
    if (file_handle->buf) {
        efree(file_handle->buf);
    }
    file_handle->buf = (char *)plaintext;
    file_handle->len = plain_len;

    /* Hand off to the previously-registered compiler (opcache, if loaded,
     * or the plain Zend compiler otherwise). It will call zend_stream_fixup
     * again internally, see file_handle->buf already set, and use it as-is. */
    return wm_original_compile_file(file_handle, type);
}

PHP_FUNCTION(wmloader_diagnostics)
{
    if (zend_parse_parameters_none() == FAILURE) {
        return;
    }
    array_init(return_value);
    add_assoc_string(return_value, "version", PHP_WMLOADER_VERSION);
    add_assoc_string(return_value, "secret_dir", WMLOADER_G(secret_dir) ? WMLOADER_G(secret_dir) : "");
    add_assoc_string(return_value, "audit_log", WMLOADER_G(audit_log) ? WMLOADER_G(audit_log) : "(disabled)");
    add_assoc_bool(return_value, "anti_debug_enabled", WMLOADER_G(anti_debug));
    {
        char id[256];
        wm_local_identity(id, sizeof(id));
        add_assoc_string(return_value, "effective_identity", id);
        add_assoc_bool(return_value, "identity_overridden", WMLOADER_G(identity) && *WMLOADER_G(identity));
    }
    add_assoc_long(return_value, "files_decrypted", (zend_long)WMLOADER_G(files_decrypted));
    add_assoc_long(return_value, "files_failed", (zend_long)WMLOADER_G(files_failed));

    /* Enumerate which key versions are actually present and readable. */
    zval versions;
    array_init(&versions);
    const char *dir = WMLOADER_G(secret_dir);
    if (dir && *dir) {
        for (int v = 1; v <= 255; v++) {
            char path[4096];
            snprintf(path, sizeof(path), "%s/%d.key", dir, v);
            zend_stat_t st;
            if (VCWD_STAT(path, &st) == 0) {
                zval info;
                array_init(&info);
                add_assoc_bool(&info, "readable", VCWD_ACCESS(path, R_OK) == 0);
                add_assoc_long(&info, "size_bytes", (zend_long)st.st_size);
                add_assoc_long(&info, "mode", (zend_long)(st.st_mode & 0777));
                add_index_zval(&versions, v, &info);
            }
        }
    }
    add_assoc_zval(return_value, "key_versions", &versions);

    char current_path[4096];
    int current = 0;
    if (dir && *dir) {
        snprintf(current_path, sizeof(current_path), "%s/current", dir);
        php_stream *s = php_stream_open_wrapper(current_path, "rb", REPORT_ERRORS, NULL);
        if (s) {
            zend_string *c = php_stream_copy_to_mem(s, 16, 0);
            php_stream_close(s);
            if (c) {
                current = atoi(ZSTR_VAL(c));
                zend_string_release(c);
            }
        }
    }
    add_assoc_long(return_value, "current_key_version", current);
}

ZEND_BEGIN_ARG_INFO(arginfo_wmloader_diagnostics, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry wmloader_functions[] = {
    PHP_FE(wmloader_diagnostics, arginfo_wmloader_diagnostics)
    PHP_FE_END
};

PHP_MINIT_FUNCTION(wmloader)
{
    REGISTER_INI_ENTRIES();
    WMLOADER_G(files_decrypted) = 0;
    WMLOADER_G(files_failed) = 0;
    wm_original_compile_file = zend_compile_file;
    zend_compile_file = wm_compile_file;
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(wmloader)
{
    zend_compile_file = wm_original_compile_file;
    UNREGISTER_INI_ENTRIES();
    return SUCCESS;
}

PHP_MINFO_FUNCTION(wmloader)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "wmloader support", "enabled");
    php_info_print_table_row(2, "Version", PHP_WMLOADER_VERSION);
    php_info_print_table_row(2, "Secret dir", WMLOADER_G(secret_dir));
    php_info_print_table_end();
    DISPLAY_INI_ENTRIES();
}

zend_module_entry wmloader_module_entry = {
    STANDARD_MODULE_HEADER,
    "wmloader",
    wmloader_functions,
    PHP_MINIT(wmloader),
    PHP_MSHUTDOWN(wmloader),
    NULL,
    NULL,
    PHP_MINFO(wmloader),
    PHP_WMLOADER_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_WMLOADER
ZEND_GET_MODULE(wmloader)
#endif
