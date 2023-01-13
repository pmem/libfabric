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

	AS_IF([test $sharp_happy -eq 1 && test $sharp_mocked -eq 0],
	      [AC_CHECK_LIB(sharp_coll, sharp_coll_init, [],
			AC_MSG_ERROR([The libsharp_coll library not found (set LDFLAGS to point the location)]), [])])

	AS_IF([test $sharp_happy -eq 1 && test $sharp_mocked -eq 0],
	      [AC_CHECK_LIB(sharp, sharp_init_session, [],
			AC_MSG_ERROR([The libsharp library not found (set LDFLAGS to point the location)]), [])])

        AS_IF([test $sharp_happy -eq 1], [$1], [$2])
])
