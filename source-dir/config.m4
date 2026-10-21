PHP_ARG_ENABLE([wmloader], [whether to enable wmloader support], [AS_HELP_STRING([--enable-wmloader], [Enable wmloader support])], [no])

if test "$PHP_WMLOADER" != "no"; then PHP_SUBST(WMLOADER_SHARED_LIBADD) PHP_ADD_LIBRARY(crypto, 1, WMLOADER_SHARED_LIBADD) PHP_NEW_EXTENSION(wmloader, wmloader.c, $ext_shared) fi
