#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([glueless], [0.1], [ray@isc.org])
AC_PREREQ([2.69])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRC_DIR([src/base.cc])

AM_INIT_AUTOMAKE([foreign subdir-object])
LT_INIT

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET

# Checks for compiler flags.

DESIRED_FLAGS="-std=c99"
for flag in $DESIRED_FLAGS; do
  AS_COMPILER_FLAG([$flag], [CFLAGS="$CFLAGS $flag"])
done

DESIRED_FLAGS="-std=c++11"
for flag in $DESIRED_FLAGS; do
  AS_CXX_COMPILER_FLAG([$flag], [CXXFLAGS="$CXXFLAGS $flag"])
done
#
# Checks for required extra libraries
#

# ldns
AC_MSG_CHECKING(for ldns library)
AC_ARG_WITH(ldns,
[ --with-ldns[=PATH]  build with ldns library [path]],
  use_ldns="$withval",  use_ldns="auto")

have_ldns=""
case "$use_ldns" in
	auto|yes)
		for d in /usr /usr/local /opt/local
		do
			if test -f "${d}/include/ldns/ldns.h"
			then
				if test ${d} != /usr
				then
					CPPFLAGS="$CPPFLAGS -I${d}/include"
					LIBS="$LIBS -L${d}/lib"
				fi
				have_ldns="yes"
				AC_MSG_RESULT(yes)
			fi
		done
		;;
	*)
		if test -f "${use_ldns}/include/ldns/ldns.h"
		then
			CPPFLAGS="$CPPFLAGS -I${use_ldns}/include"
			LIBS="$LIBS -L${use_ldns}/lib"
			have_ldns="yes"
			AC_MSG_RESULT(yes)
		else
			AC_MSG_ERROR([$use_ldns/include/ldns/ldns.h not found.])
		fi
		;;
esac
AC_CHECK_LIB([ldns], [ldns_dname_match_wildcard], [], AC_MSG_ERROR([libldns unusable]))

# evldns
AC_MSG_CHECKING(for evldns library)
AC_ARG_WITH(evldns,
[ --with-evldns[=PATH]  build with evldns library [path]],
  use_evldns="$withval",  use_evldns="auto")

have_evldns=""
case "$use_evldns" in
	auto|yes)
		for d in /usr /usr/local /opt/local
		do
			if test -f "${d}/include/evldns.h"
			then
				if test ${d} != /usr
				then
					CPPFLAGS="$CPPFLAGS -I${d}/include"
					LIBS="$LIBS -L${d}/lib"
				fi
				have_evldns="yes"
				AC_MSG_RESULT(yes)
			fi
		done
		;;
	*)
		if test -f "${use_evldns}/include/evldns.h"
		then
			CPPFLAGS="$CPPFLAGS -I${use_evldns}/include"
			LIBS="$LIBS -L${use_evldns}/lib"
			have_evldns="yes"
			AC_MSG_RESULT(yes)
		else
			AC_MSG_ERROR([$use_evldns/include/evldns.h not found.])
		fi
		;;
esac
AC_CHECK_LIB([evldns], [evldns_init], [], AC_MSG_ERROR([libevldns unusable]),[-levent])

#
# Checks for system libraries.
#
AC_CHECK_LIB([event], [event_base_new])
AC_CHECK_LIB([pthread], [pthread_setaffinity_np])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for standard library functions.
AC_CHECK_FUNCS([])

# Enable extra warnings
WARNING_FLAGS="-fdiagnostics-show-option -Wall -Wextra -Wno-unused-parameter -Wstrict-prototypes -Wundef -Wformat=2 -Wmissing-include-dirs -Wformat-nonliteral -Wold-style-definition -Wpointer-arith -Waggregate-return -Winit-self -Wpacked -Wc++-compat -Wno-long-long -Wno-overlength-strings -Wdeclaration-after-statement -Wredundant-decls -Wmissing-noreturn -Wshadow -Wendif-labels -Wcast-qual -Wwrite-strings -fno-common"
for flag in $WARNING_FLAGS; do
  AS_COMPILER_FLAG([$flag], [CFLAGS="$CFLAGS $flag"])
done

AC_OUTPUT
