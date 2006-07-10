#!/bin/sh
# Obtain appropriate cc options for building cryptlib.  This used to be done
# in the makefile, but with the introduction of gcc 4.x with its idiotic
# default of enabling masses of pointless warnings with no easy way to turn
# them off (the excessive warnings weren't added until 4.x so the option to
# disable them didn't exist before then either, with the result that using it
# with earlier versions causes them to die), it became too complex to handle
# in the makefile, so this shell script is used instead.

CCARGS=""
OSNAME=""

# Make sure that we've been given either single argument consisting of the
# compiler name or the compiler name and an OS name for the shared-lib cc
# options.

if [ "$1" = "" ] ; then
	echo "$0: Missing compiler name." >&2 ;
	exit 1 ;
fi
if [ $# -eq 2 ] ; then
	if [ "$2" = "autodetect" ] ; then
		OSNAME=`uname` ;
	else
		OSNAME=$2 ;
	fi ;
else
	if [ $# -ne 1 ] ; then
		echo "$0: Can only supply 1 arg." >&2 ;
		exit 1 ;
	fi ;
fi

# Juggle the args around to get them the way that we want them.

CC=$1

# Determine the CPU endianness by building and executing the endianness-
# detection program.  Note that we have to use -s rather than the more
# obvious -e since this doesn't exist under the Slowaris sh.

if [ ! -s ./tools/endian ] ; then
	if gcc -v > /dev/null 2>&1 ; then
		gcc tools/endian.c -o tools/endian > /dev/null ;
	elif [ `uname` = "NONSTOP_KERNEL" ] ; then
		c89 tools/endian.c -o tools/endian > /dev/null ;
	else
		$CC tools/endian.c -o tools/endian > /dev/null ;
	fi ;
	strip tools/endian ;
fi

CCARGS="`./tools/endian`"

# Determine whether various optional system features are installed and
# enable their use if they're present.  Since these additional libs are
# dynamically loaded, we only check for them on systems with dynamic
# loading support.

if [ "$OSNAME" = "Darwin" -o "$OSNAME" = "Linux" -o "$OSNAME" = "FreeBSD" -o \
	 \( "$OSNAME" = "SunOS" -a `uname -r | cut -f 1 -d '.'` -gt 4 \) ] ; then
	if [ -f /usr/include/sql.h ] ; then
		CCARGS="$CCARGS -DUSE_ODBC" ;
	fi
	if [ -f /usr/include/ldap.h ] ; then
		CCARGS="$CCARGS -DUSE_LDAP" ;
	fi
fi

# If we're building a shared lib, set up the necessary additional cc args.
# The IRIX cc and Cygwin gcc (and specifically Cygwin-native, not a cross-
# development toolchain hosted under Cygwin) don't recognise -fPIC, but
# generate PIC by default anyway.  The PHUX compiler requires +z for PIC,
# and Solaris cc requires -KPIC for PIC.  OS X generates PIC by default, but
# doesn't mind having -fPIC specified anyway.
#
# For the PIC options, the only difference between -fpic and -fPIC is that
# the latter generates large-displacement jumps while the former doesn't,
# bailing out with an error if a large-displacement jump would be required.
# As a side-effect, -fPIC code is slightly less efficient because of the use
# of large-displacement jumps, so if you're tuning the code for size/speed
# you can try -fpic to see if you get any improvement.

if [ "$OSNAME" != "" ] ; then
	case $OSNAME in
		'CYGWIN_NT-5.0'|'CYGWIN_NT-5.1'|'IRIX'|'IRIX64')
			;;

		'HP-UX')
			CCARGS="$CCARGS +z" ;;

		'SunOS')
			if [ `$CC -v 2>&1 | grep -c "gcc"` = '0' ] ; then
				CCARGS="$CCARGS -KPIC" ;
			else
				CCARGS="$CCARGS -fPIC" ;
			fi ;;

		*)
			CCARGS="$CCARGS -fPIC" ;;
	esac ;
fi

# If we're not using gcc, we're done.  This isn't as simple as a straight
# name comparison of cc vs. gcc, sometimes gcc is installed as cc so we
# have to check whether the compiler is really gcc even if it's referred to
# as cc.  In addition we have to be careful about which strings we check for
# because i18n of the gcc -v output makes many strings changeable.  The
# safest value to check for is "gcc", hopefully this won't yield any false
# positives.

if [ `$CC -v 2>&1 | grep -c "gcc"` = '0' ] ; then
	echo $CCARGS ;
	exit 0 ;
fi

# gcc changed its CPU architecture-specific tuning option from -mcpu to
# -march in about 2003, so when using gcc to build for x86 systems (where
# we specify the architecture as P5 rather than the default 386) we have
# to use an intermediate build rule that changes the compiler arguments
# based on compiler version info.  The reason for the change was to
# distinguish -march (choice of instruction set used) from -mtune
# (scheduling of instructions), so for example -march=pentium
# -mtune=pentium4 would generate instructions from the pentium instruction
# set but scheduled for the P4 CPU.
#
# (The changeover is in fact somewhat messier than that, newer 2.9.x versions
# (as well as 3.x onwards) recognised -march (depending on the CPU they
# targeted and patch level) and all versions still recognise -mcpu, however
# as of about 3.4.x the compiler complains about deprecated options whenever
# it sees -mcpu used, which is why we use -march for 3.x and newer).
#
# The detection of the CPU type is made more complex by a pile of *BSE's
# which, along with antideluvian tools like an as that doesn't recognise 486
# opcodes, they report the CPU type as i386, so we assume that if the CPU is
# reported as i386 then it's some *BSE which is actually running on a P4 or
# Athlon or something similar (unfortunately there's no real way to detect
# this, but it's 99.9% likely that it's not actually still running on an
# 80386).
#
# The check for the gcc version is equally complicated by the fact that a
# (rare) few localised gcc's don't use a consistent version number string.
# Almost all versions print "gcc version", but the French localisation has
# "version gcc" (we can't use just "gcc" by itself since this appears
# elsewhere in the gcc -v output).

if [ `uname -m | grep "i[3,4,5,6]86"` > /dev/null ] ; then
	if [ `gcc --version 2>&1 | head -n 1 | tr -d '[A-Za-z]. ()' | cut -c 1` -gt 2 ] ; then
		CCARGS="$CCARGS -march=pentium" ;
	else
		CCARGS="$CCARGS -mcpu=pentium" ;
	fi
fi

# Check for gcc 4.x with its stupid default setting of -Wpointer-sign,
# which leads to endless warnings about signed vs.unsigned char problems -
# you can't even call strlen() without getting warnings.

if [ $CC -Wno-pointer-sign -S -o /dev/null -xc /dev/null > /dev/null 2>&1 ] ;
  then CCARGS="$CCARGS -Wno-pointer-sign" ;
fi

# The AES code uses 64-bit data types, which gcc doesn't support (at least
# via limits.h) unless it's operating in C99 mode.  So in order to have the
# AES auto-config work, we have to explicitly run gcc in C99 mode, which
# isn't the default for teh gcc 3.x versions.  Since the code also uses gcc
# extensions, we have to specify the mode as gcc + C99, not just C99.

CCARGS="$CCARGS -std=gnu99"

# Enable additional compiler diagnostics if we're building on the usual
# development box.  We only enable it on this one system to avoid having
# users complain about getting warnings when they build it.
#
# An even higher level of noise can be enabled with -Wall, however in this
# case -Wno-switch is necessary because all cryptlib attributes are declared
# from a single pool of enums, but only the values for a particular object
# class are used in the object-specific code, leading to huge numbers of
# warnings about unhandled enum values in case statements.  So the extra
# flags are "-Wall -Wno-switch".
#
# The warnings are:
#
# -Wcast-align: Warn whenever a pointer is cast such that the required
#		alignment of the target is increased, for example if a "char *" is
#		cast to an "int *".
#
# -Wendif-labels: Warn if an endif is followed by text.
#
# -Wformat: Check calls to "printf" etc to make sure that the args supplied
#		have types appropriate to the format string.
#
# -Wformat-nonliteral: Check whether a format string is not a string literal,
#		i.e. argPtr vs "%s".
#
# -Wformat-security: Check for potential security problems in format strings.
#
# -Wmissing-braces: Warn if an array initialiser isn't fully bracketed, e.g.
#		int a[2][2] = { 0, 1, 2, 3 }.
#
# -Wpointer-arith: Warn about anything that depends on the sizeof a
#		function type or of void.
#
# -Wredundant-decls: Warn if anything is declared more than once in the same
#		scope.
#
# -Wshadow: Warn whenever a local variable shadows another local variable,
#		parameter or global variable (that is, a local of the same name as
#		an existing variable is declared in a nested scope).  Note that this
#		leads to some false positives as gcc treats forward declarations of
#		functions within earlier functions that have the same parameters as
#		the function they're declared within as shadowing.  This can be
#		usually detected in the output by noting that a pile of supposedly
#		shadow declarations occur within a few lines of one another.
#
# -Wstrict-prototypes: Warn if a function is declared or defined K&R-style.
#
# -Wunused-function: Warn if a static function isn't used.
#
# -Wunused-label: Warn if a label isn't used.
#
# -Wunused-variable: Warn if a local variable isn't used.
#
# -Wundef: Warn if an undefined identifier is used in a #if.
#
# -Wwrite-strings: Warn on attempts to assign/use a constant string value
#		with a non-const pointer.
#
# Note that some of these require the use of at least -O2 in order to be
# detected because they require the use of various levels of data flow
# analysis by the compiler.  However, when this is used the optimiser
# interacts badly with -Wunreachable-code due to statements rearranged by
# the optimiser being declared unreachable, so we don't enable this warning.

if [ `uname -n` = "medusa01" ] ; then
	CCARGS="$CCARGS -Wcast-align -Wendif-labels -Wformat -Wformat-nonliteral \
					-Wformat-security -Wmissing-braces -Wpointer-arith \
					-Wredundant-decls -Wshadow -Wstrict-prototypes \
					-Wunused-function -Wunused-label -Wunused-variable -Wundef \
					-Wwrite-strings" ;
fi

# Finally, report what we've found

echo $CCARGS
