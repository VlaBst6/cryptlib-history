#!/bin/sh
# Obtain the OS version.

# Make sure that we've been given a single argument consisting of the OS
# name.

if [ "$1" = "" ] ; then
	echo "$0: Missing OS name." >&2 ;
	exit 1 ;
fi
if [ $# -ne 1 ] ; then
	echo "$0: Can only supply 1 arg." >&2 ;
	exit 1 ;
fi

# Juggle the args around to get them the way that we want them.

if [ "$1" = "autodetect" ] ; then
	OSNAME=`uname` ;
else
	OSNAME=$1 ;
fi

# Determine the OS version.  The means of doing this varies wildly across
# OSes.  Aches has a broken uname, which reports the OS minor version with
# uname -r instead of the major version.  The alternative command oslevel
# reports the full version number, which we can extract in the standard
# manner.  Similarly, QNX uses -v instead of -r for the version, and also
# has a broken 'cut'.  PHUX returns the version as something like 'B.11.11',
# so we have to carefully extract the thing that looks most like a version
# number from this.
#
# We also check for the various cross-compile environments and return either
# an appropriate version number (defaulting to '1' if there's no real
# distinction between versions) or an error code if there's no useful
# default available, in which case use requires manual editing of the config
# as we can't automatically detect the OS version.

case $OSNAME in
	'AIX')
		echo `oslevel | cut -d'.' -f1` ;;

	'AMX')
		echo 1 ;;

	'Atmel')
		exit 1 ;;

	'BeOS')
		echo `uname -r | sed 's/^[A-Z]//' | cut -b 1` ;;

	'CHORUS')
		echo 5 ;;

	'eCOS')
		echo 1 ;;

	'HP-UX')
		echo `uname -r | sed 's/^[A-Z]\.//' | cut -d'.' -f1` ;;

	'MinGW')
		echo 5 ;;

	'PalmOS'|'PalmOS-PRC')
		echo 6 ;;

	'QNX')
		echo `uname -v | sed 's/^[A-Z]//' | cut -c 1` ;;

	'SunOS')
		echo `uname -r | sed 's/^[A-Z]//' | cut -b 1` ;;

	'ucLinux')
		echo 2 ;;

	'UCOS')
		echo 2 ;;

	'VxWorks')
		echo 1 ;;

	'XMK')
		echo 3 ;;

	*)
		echo `uname -r | cut -c 1` ;;
esac
