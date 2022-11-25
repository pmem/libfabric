dnl Configury specific to the libfabric sharp provider

dnl Called to configure this provider
dnl
dnl Arguments:
dnl
dnl $1: action if configured successfully
dnl $2: action if not configured successfully
dnl
AC_DEFUN([FI_SHARP_CONFIGURE],[
	# Determine if we can support the sharp provider
	sharp_happy=0
	AS_IF([test x"$enable_sharp" != x"no"], [sharp_happy=1])
        AS_IF([test $sharp_happy -eq 1], [$1], [$2])
])
