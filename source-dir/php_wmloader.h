#ifndef PHP_WMLOADER_H
#define PHP_WMLOADER_H

extern zend_module_entry wmloader_module_entry;
#define phpext_wmloader_ptr &wmloader_module_entry

#define PHP_WMLOADER_VERSION "0.2.0"

#ifdef PHP_WIN32
#	define PHP_WMLOADER_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_WMLOADER_API __attribute__ ((visibility("default")))
#else
#	define PHP_WMLOADER_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

ZEND_BEGIN_MODULE_GLOBALS(wmloader)
    char *secret_dir;
    char *identity;
    char *audit_log;
    zend_bool anti_debug;
    zend_ulong files_decrypted;   /* lifetime counter for this worker process, for diagnostics */
    zend_ulong files_failed;
ZEND_END_MODULE_GLOBALS(wmloader)

#ifdef ZTS
#define WMLOADER_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(wmloader, v)
#else
#define WMLOADER_G(v) (wmloader_globals.v)
#endif

PHP_FUNCTION(wmloader_diagnostics);

#endif
