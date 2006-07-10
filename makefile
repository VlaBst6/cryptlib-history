#****************************************************************************
#*																			*
#*							Makefile for cryptlib 3.2						*
#*						Copyright Peter Gutmann 1995-2006					*
#*																			*
#****************************************************************************

# This makefile contains extensive amounts of, uhh, business logic which,
# alongside further logic in the cryptlib OS-specific header files, ensures
# that cryptlib auto-configures itself and builds out of the box on most
# systems.  Before you ask about redoing the makefile using autoconf, have a
# look at what it would take to move all of this logic across to another
# build mechanism.
#
# "The makefile is looking really perverse.  You're getting the hang of it"
#														- Chris Wedgwood.
# At least it doesn't pipe itself through sed yet.
#
# (Note that as of 3.1 beta 3, it does pipe itself through sed on non-Unix
#  systems to retarget Unix-specific files to OS-specific ones and perform
#  various other operations that aren't easily possible by adding another
#  level of recursion).
#
# The self-test program pulls in parts of cryptlib to ensure that the self-
# configuration works.  Because this is handled by the makefile, you can't
# just 'make testlib' after making changes, you need to use 'make; make
# testlib'.

# Naming information: Major and minor version numbers and project and library
# names (static lib, shared lib, and OS X dylib).  The patch level is always
# zero because patches imply bugs and my code is perfect.

MAJ		= 3
MIN		= 2
PLV		= 3
PROJ	= cl
LIBNAME	= lib$(PROJ).a
SLIBNAME = lib$(PROJ).so.$(MAJ).$(MIN).$(PLV)
DYLIBNAME = lib$(PROJ).$(MAJ).$(MIN).dylib

# Compiler options.  By default this builds the release version of the code,
# to build the debug version (which is useful for finding compiler bugs and
# system-specific peculiarities) remove the NDEBUG define.  Many problems
# will now trigger an assertion at the point of failure rather than returning
# an error status from 100 levels down in the code.
#
# Note that the gcc build uses -fomit-frame-pointer to free up an extra
# register on x86 (which desperately needs it), this will screw up gdb if
# you try and debug a version compiled with this option.
#
# If the OS supports it, the multithreaded version of cryptlib will be built.
# To specifically disable this, add -DNO_THREADS.
#
# Further cc flags are gathered dynamically at runtime via the ccopts.sh
# script.

CFLAGS		= -c -D__UNIX__ -DNDEBUG -I.

# To link the self-test code with a key database, uncomment the following
# and substitute the name or names of the database libraries you'll be using.

# TESTLIB	= -lodbc
# TESTLIB	= -lmysql
# TESTLIB	= -L/oracle/product/server/9i/lib -lclient9

# Paths and command names.  We have to be careful with comments attached to
# path defines because some makes don't strip trailing spaces.
#
# The reason for the almost-identical defines for path and dir is because of
# the braindamaged BSDI mkdir (and rmdir) that break if the path ends in a
# '/', it's easier to have separate defines than to drop a '/' into every
# path.

STATIC_OBJ_PATH = ./static-obj/
STATIC_OBJ_DIR = ./static-obj
SHARED_OBJ_PATH = ./shared-obj/
SHARED_OBJ_DIR = ./shared-obj
CPP			= $(CC) -E
LD			= $(CC)
AR			= ar
SHELL		= /bin/sh
OSNAME		= `uname`
LINKFILE	= link.tmp

# Default target and obj file path.  This is changed depending on whether
# we're building the static or shared library, the default is to build the
# static library.

TARGET		= $(LIBNAME)
OBJPATH		= $(STATIC_OBJ_PATH)

# Some makes don't pass defines down when they recursively invoke make, so we
# need to manually pass them along.  The following macro contains all defines
# that we want to pass to recursive calls to make.

DEFINES		= $(TARGET) OBJPATH=$(OBJPATH) OSNAME=$(OSNAME)

# Cross-compilation/non-Unix options, which are just the standard ones with
# Unix-specific entries (-D__UNIX__, use of uname to identify the system)
# removed.  The actual values are explicitly given in the rules for each non-
# Unix target.

XCFLAGS		= -c -DNDEBUG -I.
XDEFINES	= $(TARGET) OBJPATH=$(OBJPATH) CROSSCOMPILE=1

# Cross-compilation paths.  The Palm SDK under Cygwin only understands
# heavily-escaped absolute MSDOS pathnames, so it's necessary to specify
# (for example)
# -I"c:/Program\\\ Files/PalmSource/Palm\\\ OS\\\ Developer\\\ Suite/sdk-6/"
# as the SDK path.  In practice it's easier to dump all the files in their
# own partition, which is what the Palm SDK target below assumes.  Note that
# if you change this you'll also have to change the path value in
# tools/buildlib.sh.

PALMSDK_PATH	= "d:/Palm\\\ SDK/sdk-6"

#****************************************************************************
#*																			*
#*								Common Dependencies							*
#*																			*
#****************************************************************************

# The object files that make up cryptlib.

ASMOBJS		= $(OBJPATH)md5asm.o $(OBJPATH)rmdasm.o $(OBJPATH)sha1asm.o

BNOBJS		= $(OBJPATH)bn_add.o $(OBJPATH)bn_asm.o $(OBJPATH)bn_ctx.o \
			  $(OBJPATH)bn_div.o $(OBJPATH)bn_exp.o $(OBJPATH)bn_exp2.o \
			  $(OBJPATH)bn_gcd.o $(OBJPATH)bn_lib.o $(OBJPATH)bn_mod.o \
			  $(OBJPATH)bn_mont.o $(OBJPATH)bn_mul.o $(OBJPATH)bn_recp.o \
			  $(OBJPATH)bn_shift.o $(OBJPATH)bn_sqr.o $(OBJPATH)bn_word.o

CERTOBJS	= $(OBJPATH)certrev.o $(OBJPATH)certschk.o $(OBJPATH)certsign.o \
			  $(OBJPATH)certval.o $(OBJPATH)chain.o $(OBJPATH)chk_cert.o \
			  $(OBJPATH)chk_chn.o $(OBJPATH)chk_use.o $(OBJPATH)comp_get.o \
			  $(OBJPATH)comp_set.o $(OBJPATH)dn.o $(OBJPATH)dnstring.o \
			  $(OBJPATH)ext.o $(OBJPATH)ext_add.o $(OBJPATH)ext_chk.o \
			  $(OBJPATH)ext_copy.o $(OBJPATH)ext_def.o $(OBJPATH)ext_rd.o \
			  $(OBJPATH)ext_wr.o $(OBJPATH)imp_exp.o $(OBJPATH)read.o \
			  $(OBJPATH)trustmgr.o $(OBJPATH)write.o

CRYPTOBJS	= $(OBJPATH)aes_modes.o $(OBJPATH)aescrypt.o $(OBJPATH)aeskey.o \
			  $(OBJPATH)aestab.o $(OBJPATH)bfecb.o $(OBJPATH)bfenc.o \
			  $(OBJPATH)bfskey.o $(OBJPATH)castecb.o $(OBJPATH)castenc.o \
			  $(OBJPATH)castskey.o $(OBJPATH)descbc.o $(OBJPATH)desecb.o \
			  $(OBJPATH)desecb3.o $(OBJPATH)desenc.o $(OBJPATH)desskey.o \
			  $(OBJPATH)icbc.o $(OBJPATH)iecb.o $(OBJPATH)iskey.o \
			  $(OBJPATH)rc2cbc.o $(OBJPATH)rc2ecb.o $(OBJPATH)rc2skey.o \
			  $(OBJPATH)rc4enc.o $(OBJPATH)rc4skey.o $(OBJPATH)rc5ecb.o \
			  $(OBJPATH)rc5enc.o $(OBJPATH)rc5skey.o $(OBJPATH)skipjack.o

CTXOBJS		= $(OBJPATH)kg_dlp.o $(OBJPATH)kg_prime.o $(OBJPATH)kg_rsa.o \
			  $(OBJPATH)keyload.o $(OBJPATH)key_rd.o $(OBJPATH)key_wr.o \
			  $(OBJPATH)ctx_3des.o $(OBJPATH)ctx_aes.o $(OBJPATH)ctx_bf.o \
			  $(OBJPATH)ctx_cast.o $(OBJPATH)ctx_des.o $(OBJPATH)ctx_dh.o \
			  $(OBJPATH)ctx_dsa.o $(OBJPATH)ctx_elg.o $(OBJPATH)ctx_hmd5.o \
			  $(OBJPATH)ctx_hrmd.o $(OBJPATH)ctx_hsha.o $(OBJPATH)ctx_idea.o \
			  $(OBJPATH)ctx_md2.o $(OBJPATH)ctx_md4.o $(OBJPATH)ctx_md5.o \
			  $(OBJPATH)ctx_misc.o $(OBJPATH)ctx_rc2.o $(OBJPATH)ctx_rc4.o \
			  $(OBJPATH)ctx_rc5.o $(OBJPATH)ctx_ripe.o $(OBJPATH)ctx_rsa.o \
			  $(OBJPATH)ctx_sha.o $(OBJPATH)ctx_sha2.o $(OBJPATH)ctx_skip.o

DEVOBJS		= $(OBJPATH)fortezza.o $(OBJPATH)pkcs11.o $(OBJPATH)system.o

ENVOBJS		= $(OBJPATH)cms_denv.o $(OBJPATH)cms_env.o $(OBJPATH)decode.o \
			  $(OBJPATH)encode.o $(OBJPATH)pgp_denv.o $(OBJPATH)pgp_env.o \
			  $(OBJPATH)res_actn.o $(OBJPATH)res_denv.o $(OBJPATH)res_env.o

HASHOBJS	= $(OBJPATH)md2dgst.o $(OBJPATH)md4dgst.o $(OBJPATH)md5dgst.o \
			  $(OBJPATH)rmddgst.o $(OBJPATH)sha1dgst.o $(OBJPATH)sha2.o

IOOBJS		= $(OBJPATH)cmp_tcp.o $(OBJPATH)dns.o $(OBJPATH)file.o \
			  $(OBJPATH)http_rd.o $(OBJPATH)http_wr.o $(OBJPATH)memory.o \
			  $(OBJPATH)net.o $(OBJPATH)stream.o $(OBJPATH)tcp.o

KEYSETOBJS	= $(OBJPATH)dbms.o $(OBJPATH)ca_add.o $(OBJPATH)ca_issue.o \
			  $(OBJPATH)ca_misc.o $(OBJPATH)ca_rev.o $(OBJPATH)dbx_misc.o \
			  $(OBJPATH)dbx_rd.o $(OBJPATH)dbx_wr.o $(OBJPATH)http.o \
			  $(OBJPATH)ldap.o $(OBJPATH)odbc.o $(OBJPATH)pgp.o \
			  $(OBJPATH)pkcs12.o $(OBJPATH)pkcs15.o $(OBJPATH)pkcs15_add.o \
			  $(OBJPATH)pkcs15_att.o $(OBJPATH)pkcs15_rd.o \
			  $(OBJPATH)pkcs15_wr.o

KRNLOBJS	= $(OBJPATH)attr_acl.o $(OBJPATH)certm_acl.o $(OBJPATH)init.o \
			  $(OBJPATH)int_msg.o $(OBJPATH)key_acl.o $(OBJPATH)mech_acl.o \
			  $(OBJPATH)msg_acl.o $(OBJPATH)obj_acc.o $(OBJPATH)objects.o \
			  $(OBJPATH)sec_mem.o $(OBJPATH)semaphore.o $(OBJPATH)sendmsg.o

LIBOBJS		= $(OBJPATH)cryptapi.o $(OBJPATH)cryptcfg.o $(OBJPATH)cryptcrt.o \
			  $(OBJPATH)cryptctx.o $(OBJPATH)cryptdev.o $(OBJPATH)cryptenv.o \
			  $(OBJPATH)cryptkey.o $(OBJPATH)cryptlib.o $(OBJPATH)cryptses.o \
			  $(OBJPATH)cryptusr.o

MECHOBJS	= $(OBJPATH)keyex.o $(OBJPATH)keyex_int.o $(OBJPATH)keyex_rw.o \
			  $(OBJPATH)mech_drv.o $(OBJPATH)mech_enc.o $(OBJPATH)mech_sig.o \
			  $(OBJPATH)mech_wrp.o $(OBJPATH)obj_qry.o $(OBJPATH)sign.o \
			  $(OBJPATH)sign_cms.o $(OBJPATH)sign_int.o $(OBJPATH)sign_pgp.o \
			  $(OBJPATH)sign_rw.o $(OBJPATH)sign_x509.o

MISCOBJS	= $(OBJPATH)asn1_chk.o $(OBJPATH)asn1_rd.o $(OBJPATH)asn1_wr.o \
			  $(OBJPATH)asn1_ext.o $(OBJPATH)base64.o $(OBJPATH)int_api.o \
			  $(OBJPATH)int_attr.o $(OBJPATH)int_env.o $(OBJPATH)java_jni.o \
			  $(OBJPATH)misc_rw.o $(OBJPATH)os_spec.o $(OBJPATH)pgp_misc.o \
			  $(OBJPATH)random.o $(OBJPATH)unix.o

SESSOBJS	= $(OBJPATH)certstore.o $(OBJPATH)cmp.o $(OBJPATH)cmp_rd.o \
			  $(OBJPATH)cmp_wr.o $(OBJPATH)ocsp.o $(OBJPATH)pnppki.o \
			  $(OBJPATH)rtcs.o $(OBJPATH)scep.o $(OBJPATH)scorebrd.o \
			  $(OBJPATH)sess_attr.o $(OBJPATH)sess_rw.o \
			  $(OBJPATH)session.o $(OBJPATH)ssh.o $(OBJPATH)ssh1.o \
			  $(OBJPATH)ssh2.o $(OBJPATH)ssh2_chn.o $(OBJPATH)ssh2_cli.o \
			  $(OBJPATH)ssh2_cry.o $(OBJPATH)ssh2_msg.o $(OBJPATH)ssh2_rw.o \
			  $(OBJPATH)ssh2_svr.o $(OBJPATH)ssl.o $(OBJPATH)ssl_cli.o \
			  $(OBJPATH)ssl_cry.o $(OBJPATH)ssl_rw.o $(OBJPATH)ssl_svr.o \
			  $(OBJPATH)tsp.o

ZLIBOBJS	= $(OBJPATH)adler32.o $(OBJPATH)deflate.o $(OBJPATH)inffast.o \
			  $(OBJPATH)inflate.o $(OBJPATH)inftrees.o $(OBJPATH)trees.o \
			  $(OBJPATH)zutil.o

OBJS		= $(BNOBJS) $(CERTOBJS) $(CRYPTOBJS) $(CTXOBJS) $(DEVOBJS) \
			  $(ENVOBJS) $(HASHOBJS) $(IOOBJS) $(KEYSETOBJS) $(KRNLOBJS) \
			  $(LIBOBJS) $(MECHOBJS) $(MISCOBJS) $(SESSOBJS) $(ZLIBOBJS) \
			  $(OSOBJS)

# Object files for the self-test code

TESTOBJS	= certs.o devices.o envelope.o highlvl.o keydbx.o keyfile.o \
			  loadkey.o lowlvl.o scert.o sreqresp.o ssh.o ssl.o stress.o \
			  testlib.o utils.o

# Various functions all make use of certain headers so we define the
# dependencies once here

IO_DEP = io/stream.h misc/misc_rw.h

ASN1_DEP = $(IO_DEP) misc/asn1.h misc/asn1_ext.h

CRYPT_DEP	= cryptlib.h crypt.h cryptkrn.h misc/config.h misc/consts.h \
			  misc/int_api.h misc/os_spec.h

KERNEL_DEP	= kernel/acl.h kernel/kernel.h kernel/thread.h

ZLIB_DEP = zlib/zconf.h zlib/zlib.h zlib/zutil.h

#****************************************************************************
#*																			*
#*							Default and High-level Targets					*
#*																			*
#****************************************************************************

# Find the system type and use a conditional make depending on that.
#
# Slowaris doesn't ship with a compiler by default, so Sun had to provide
# something that pretends to be one for things that look for a cc.  This
# makes it really hard to figure out what's really going on.  The default cc,
# /usr/ucb/cc, is a script that looks for a real compiler elsewhere.  If the
# Sun compiler is installed, this will be via a link /usr/ccs/bin/ucbcc,
# which in turn points to /opt/SUNWspro.  If it's not installed, or installed
# incorrectly, it will bail out with a "package not installed" error.  We
# check for this bogus compiler and if we get the error message fall back to
# gcc, which is how most people just fix this mess.
#
# The MVS USS c89 compiler has a strict ordering of options.  That ordering
# can be relaxed with the _C89_CCMODE environment variable to accept options
# and file names in any order, so we check to make sure that this is set.
#
# The Cray uname reports the machine serial number instead of the machine
# type by default, so we have to explicitly check for Cray systems and
# modify the machine-detection mechanism to handle this.
#
# The '-' to disable error-checking in several cases below is necessary for
# the braindamaged QNX make, which bails out as soon as one of the tests
# fails, whether this would affect the make or not.
#
# We have to special-case the situation where the OS name is an alias for
# uname rather than being predefined (this occurs when cross-compiling),
# because the resulting expansion would contain two levels of `` escapes.  To
# handle this, we leave a predefined OS name in place, but replace a call to
# uname with instructions to the osversion.sh script to figure it out for
# itself.  In addition since $(CROSSCOMPILE) is usually a null value, we add
# an extra character to the comparison string to avoid syntax errors.

default:
	@make directories
	@make toolscripts
	@- if [ $(OSNAME) = 'OS/390' -a "$(_C89_CCMODE)" != "1" ] ; then \
		echo "The c89 environment variable _C89_CCMODE must be set to 1." >&2 ; \
		exit 1 ; \
	fi
	@case $(OSNAME) in \
		'BeOS') \
			make CFLAGS="$(CFLAGS) `./tools/ccopts.sh $(CC)` \
				-DOSVERSION=`./tools/osversion.sh BeOS` \
				-D_STATIC_LINKING" BeOS ;; \
		'HP-UX') \
			if gcc -v > /dev/null 2>&1 ; then \
				make CC=gcc LD=gcc CFLAGS="$(CFLAGS) `./tools/ccopts.sh gcc` \
					-DOSVERSION=`./tools/osversion.sh HP-UX`" HP-UX ; \
			else \
				make CFLAGS="$(CFLAGS) `./tools/ccopts.sh $(CC)` \
					-DOSVERSION=`./tools/osversion.sh HP-UX`" HP-UX ; \
			fi ;; \
		'SunOS') \
			if [ `/usr/ucb/cc | grep -c installed` = '1' ] ; then \
				make CC=gcc LD=gcc CFLAGS="$(CFLAGS) `./tools/ccopts.sh gcc` \
					-DOSVERSION=`./tools/osversion.sh SunOS`" SunOS ; \
			else \
				make CFLAGS="$(CFLAGS) `./tools/ccopts.sh $(CC)` \
					-DOSVERSION=`./tools/osversion.sh SunOS`" SunOS ; \
			fi ;; \
		*) \
			if [ `uname -m | cut -c 1-4` = 'CRAY' ] ; then \
				make CFLAGS="$(CFLAGS) `./tools/ccopts.sh $(CC)` \
					-DOSVERSION=`./tools/osversion.sh CRAY`" OSNAME="CRAY" CRAY ; \
			elif [ '$(CROSSCOMPILE)x' = '1x' ] ; then \
				make CFLAGS="$(CFLAGS) `./tools/ccopts.sh $(CC)` \
					-DOSVERSION=`./tools/osversion.sh $(OSNAME)`" $(OSNAME) ; \
			else \
				make CFLAGS="$(CFLAGS) `./tools/ccopts.sh $(CC)` \
					-DOSVERSION=`./tools/osversion.sh autodetect`" $(OSNAME) ; \
			fi ;; \
	esac

shared:
	@make directories
	@make toolscripts
	@- if [ $(OSNAME) = 'OS/390' -a "$(_C89_CCMODE)" != "1" ] ; then \
		echo "The c89 environment variable _C89_CCMODE must be set to 1." >&2 ; \
		exit 1; \
	fi
	@case $(OSNAME) in \
		'Darwin') \
			make TARGET=$(DYLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
				CFLAGS="$(CFLAGS) -fno-common `./tools/ccopts.sh $(CC) Darwin` \
				-DOSVERSION=`./tools/osversion.sh Darwin`" Darwin ;; \
		'HP-UX') \
			if gcc -v > /dev/null 2>&1 ; then \
				make TARGET=$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
					CC=gcc LD=gcc CFLAGS="$(CFLAGS) `./tools/ccopts.sh gcc HP-UX` \
					-DOSVERSION=`./tools/osversion.sh HP-UX`" HP-UX ; \
			else \
				make TARGET=$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
					CFLAGS="$(CFLAGS) `./tools/ccopts.sh $(CC) HP-UX` \
					-DOSVERSION=`./tools/osversion.sh HP-UX`" HP-UX ; \
			fi ;; \
		'SunOS') \
			if [ `/usr/ucb/cc | grep -c installed` = '1' ] ; then \
				make TARGET=$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
					CC=gcc LD=gcc CFLAGS="$(CFLAGS) `./tools/ccopts.sh gcc SunOS` \
					-DOSVERSION=`./tools/osversion.sh SunOS`" SunOS ; \
			else \
				make TARGET=$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
					CFLAGS="$(CFLAGS) `./tools/ccopts.sh $(CC) SunOS` \
					-DOSVERSION=`./tools/osversion.sh SunOS`" SunOS ; \
			fi ;; \
		*) \
			if [ '$(CROSSCOMPILE)x' = '1x' ] ; then \
				make TARGET=$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
					CFLAGS="$(CFLAGS) `./tools/ccopts.sh $(CC) $(OSNAME)` \
					-DOSVERSION=`./tools/osversion.sh $(OSNAME)`" $(OSNAME) ; \
			else \
				make TARGET=$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
					CFLAGS="$(CFLAGS) `./tools/ccopts.sh $(CC) autodetect` \
					-DOSVERSION=`./tools/osversion.sh autodetect`" $(OSNAME) ; \
			fi ;; \
	esac

directories:
	@- if [ ! -d $(STATIC_OBJ_PATH) ] ; then mkdir $(STATIC_OBJ_DIR) ; fi
	@- if [ ! -d $(SHARED_OBJ_PATH) ] ; then mkdir $(SHARED_OBJ_DIR) ; fi

toolscripts:
	@- if [ ! -x ./tools/buildasm.sh ] ; then chmod +x ./tools/buildasm.sh ; fi
	@- if [ ! -x ./tools/buildlib.sh ] ; then chmod +x ./tools/buildlib.sh ; fi
	@- if [ ! -x ./tools/buildsharedlib.sh ] ; then chmod +x ./tools/buildsharedlib.sh ; fi
	@- if [ ! -x ./tools/ccopts.sh ] ; then chmod +x ./tools/ccopts.sh ; fi
	@- if [ ! -x ./tools/getlibs.sh ] ; then chmod +x ./tools/getlibs.sh ; fi
	@- if [ ! -x ./tools/mkhdr.sh ] ; then chmod +x ./tools/mkhdr.sh ; fi
	@- if [ ! -x ./tools/osversion.sh ] ; then chmod +x ./tools/osversion.sh ; fi

# Frohe Ostern.

babies:
	@echo "Good grief, what do you think I am?  Unix is capable, but not that capable."

cookies:
	@echo "Mix 250g flour, 150g sugar, 125g butter, an egg, a few drops of vanilla"
	@echo "essence, and 1 tsp baking powder into a dough, cut cookies from rolls of"
	@echo "dough, bake for about 15 minutes at 180C until they turn very light brown"
	@echo "at the edges."

love:
	@echo "Nicht wahr?"

#****************************************************************************
#*																			*
#*								C Module Targets							*
#*																			*
#****************************************************************************

# Main directory

$(OBJPATH)cryptapi.o:	$(CRYPT_DEP) crypt/md2.h crypt/md4.h crypt/md5.h \
						crypt/sha.h cryptapi.c
						$(CC) $(CFLAGS) cryptapi.c -o $(OBJPATH)cryptapi.o

$(OBJPATH)cryptcfg.o:	$(CRYPT_DEP) cryptcfg.c
						$(CC) $(CFLAGS) cryptcfg.c -o $(OBJPATH)cryptcfg.o

$(OBJPATH)cryptcrt.o:	$(CRYPT_DEP) cert/cert.h cryptcrt.c
						$(CC) $(CFLAGS) cryptcrt.c -o $(OBJPATH)cryptcrt.o

$(OBJPATH)cryptctx.o:	$(CRYPT_DEP) context/context.h cryptctx.c
						$(CC) $(CFLAGS) cryptctx.c -o $(OBJPATH)cryptctx.o

$(OBJPATH)cryptdev.o:	$(CRYPT_DEP) device/device.h cryptdev.c
						$(CC) $(CFLAGS) cryptdev.c -o $(OBJPATH)cryptdev.o

$(OBJPATH)cryptenv.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						cryptenv.c
						$(CC) $(CFLAGS) cryptenv.c -o $(OBJPATH)cryptenv.o

$(OBJPATH)cryptkey.o:	$(CRYPT_DEP) keyset/keyset.h cryptkey.c
						$(CC) $(CFLAGS) cryptkey.c -o $(OBJPATH)cryptkey.o

$(OBJPATH)cryptlib.o:	$(CRYPT_DEP) cryptlib.c
						$(CC) $(CFLAGS) cryptlib.c -o $(OBJPATH)cryptlib.o

$(OBJPATH)cryptses.o:	$(CRYPT_DEP) cryptses.c
						$(CC) $(CFLAGS) cryptses.c -o $(OBJPATH)cryptses.o

$(OBJPATH)cryptusr.o:	$(CRYPT_DEP) cryptusr.c
						$(CC) $(CFLAGS) cryptusr.c -o $(OBJPATH)cryptusr.o

# Additional modules whose use needs to be explicitly enabled by the user.

$(OBJPATH)java_jni.o:	$(CRYPT_DEP) bindings/java_jni.c
						$(CC) $(CFLAGS) bindings/java_jni.c -o $(OBJPATH)java_jni.o

# bn subdirectory

$(OBJPATH)bn_add.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_add.c
						$(CC) $(CFLAGS) bn/bn_add.c -o $(OBJPATH)bn_add.o

$(OBJPATH)bn_asm.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_asm.c
						$(CC) $(CFLAGS) bn/bn_asm.c -o $(OBJPATH)bn_asm.o

$(OBJPATH)bn_ctx.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_ctx.c
						$(CC) $(CFLAGS) bn/bn_ctx.c -o $(OBJPATH)bn_ctx.o

$(OBJPATH)bn_div.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_div.c
						$(CC) $(CFLAGS) bn/bn_div.c -o $(OBJPATH)bn_div.o

$(OBJPATH)bn_exp.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_exp.c
						$(CC) $(CFLAGS) bn/bn_exp.c -o $(OBJPATH)bn_exp.o

$(OBJPATH)bn_exp2.o:	crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_exp2.c
						$(CC) $(CFLAGS) bn/bn_exp2.c -o $(OBJPATH)bn_exp2.o

$(OBJPATH)bn_gcd.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_gcd.c
						$(CC) $(CFLAGS) bn/bn_gcd.c -o $(OBJPATH)bn_gcd.o

$(OBJPATH)bn_lib.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_lib.c
						$(CC) $(CFLAGS) bn/bn_lib.c -o $(OBJPATH)bn_lib.o

$(OBJPATH)bn_mod.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_mod.c
						$(CC) $(CFLAGS) bn/bn_mod.c -o $(OBJPATH)bn_mod.o

$(OBJPATH)bn_mont.o:	crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_mont.c
						$(CC) $(CFLAGS) bn/bn_mont.c -o $(OBJPATH)bn_mont.o

$(OBJPATH)bn_mul.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_mul.c
						$(CC) $(CFLAGS) bn/bn_mul.c -o $(OBJPATH)bn_mul.o

$(OBJPATH)bn_recp.o:	crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_recp.c
						$(CC) $(CFLAGS) bn/bn_recp.c -o $(OBJPATH)bn_recp.o

$(OBJPATH)bn_shift.o:	crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_shift.c
						$(CC) $(CFLAGS) bn/bn_shift.c -o $(OBJPATH)bn_shift.o

$(OBJPATH)bn_sqr.o:		crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_sqr.c
						$(CC) $(CFLAGS) bn/bn_sqr.c -o $(OBJPATH)bn_sqr.o

$(OBJPATH)bn_word.o:	crypt/osconfig.h bn/bn.h bn/bn_lcl.h bn/bn_word.c
						$(CC) $(CFLAGS) bn/bn_word.c -o $(OBJPATH)bn_word.o

# cert subdirectory

$(OBJPATH)certrev.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certrev.c
						$(CC) $(CFLAGS) cert/certrev.c -o $(OBJPATH)certrev.o

$(OBJPATH)certschk.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certschk.c
						$(CC) $(CFLAGS) cert/certschk.c -o $(OBJPATH)certschk.o

$(OBJPATH)certsign.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certsign.c
						$(CC) $(CFLAGS) cert/certsign.c -o $(OBJPATH)certsign.o

$(OBJPATH)certval.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/certval.c
						$(CC) $(CFLAGS) cert/certval.c -o $(OBJPATH)certval.o

$(OBJPATH)chain.o:		$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/chain.c
						$(CC) $(CFLAGS) cert/chain.c -o $(OBJPATH)chain.o

$(OBJPATH)chk_cert.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/chk_cert.c
						$(CC) $(CFLAGS) cert/chk_cert.c -o $(OBJPATH)chk_cert.o

$(OBJPATH)chk_chn.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/chk_chn.c
						$(CC) $(CFLAGS) cert/chk_chn.c -o $(OBJPATH)chk_chn.o

$(OBJPATH)chk_use.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/chk_use.c
						$(CC) $(CFLAGS) cert/chk_use.c -o $(OBJPATH)chk_use.o

$(OBJPATH)comp_get.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/comp_get.c
						$(CC) $(CFLAGS) cert/comp_get.c -o $(OBJPATH)comp_get.o

$(OBJPATH)comp_set.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/comp_set.c
						$(CC) $(CFLAGS) cert/comp_set.c -o $(OBJPATH)comp_set.o

$(OBJPATH)dn.o:			$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/dn.c
						$(CC) $(CFLAGS) cert/dn.c -o $(OBJPATH)dn.o

$(OBJPATH)dnstring.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/dnstring.c
						$(CC) $(CFLAGS) cert/dnstring.c -o $(OBJPATH)dnstring.o

$(OBJPATH)ext.o:		$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/ext.c
						$(CC) $(CFLAGS) cert/ext.c -o $(OBJPATH)ext.o

$(OBJPATH)ext_add.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/ext_add.c
						$(CC) $(CFLAGS) cert/ext_add.c -o $(OBJPATH)ext_add.o

$(OBJPATH)ext_chk.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/ext_chk.c
						$(CC) $(CFLAGS) cert/ext_chk.c -o $(OBJPATH)ext_chk.o

$(OBJPATH)ext_copy.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/ext_copy.c
						$(CC) $(CFLAGS) cert/ext_copy.c -o $(OBJPATH)ext_copy.o

$(OBJPATH)ext_def.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/ext_def.c
						$(CC) $(CFLAGS) cert/ext_def.c -o $(OBJPATH)ext_def.o

$(OBJPATH)ext_rd.o:		$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/ext_rd.c
						$(CC) $(CFLAGS) cert/ext_rd.c -o $(OBJPATH)ext_rd.o

$(OBJPATH)ext_wr.o:		$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/ext_wr.c
						$(CC) $(CFLAGS) cert/ext_wr.c -o $(OBJPATH)ext_wr.o

$(OBJPATH)imp_exp.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/imp_exp.c
						$(CC) $(CFLAGS) cert/imp_exp.c -o $(OBJPATH)imp_exp.o

$(OBJPATH)read.o:		$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/read.c
						$(CC) $(CFLAGS) cert/read.c -o $(OBJPATH)read.o

$(OBJPATH)trustmgr.o:	$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/trustmgr.c
						$(CC) $(CFLAGS) cert/trustmgr.c -o $(OBJPATH)trustmgr.o

$(OBJPATH)write.o:		$(CRYPT_DEP) $(ASN1_DEP) cert/cert.h cert/write.c
						$(CC) $(CFLAGS) cert/write.c -o $(OBJPATH)write.o

# context subdirectory

$(OBJPATH)kg_dlp.o:		$(CRYPT_DEP) context/context.h bn/bn_prime.h context/kg_dlp.c
						$(CC) $(CFLAGS) context/kg_dlp.c -o $(OBJPATH)kg_dlp.o

$(OBJPATH)kg_prime.o:	$(CRYPT_DEP) context/context.h bn/bn_prime.h context/kg_prime.c
						$(CC) $(CFLAGS) context/kg_prime.c -o $(OBJPATH)kg_prime.o

$(OBJPATH)kg_rsa.o:		$(CRYPT_DEP) context/context.h bn/bn_prime.h context/kg_rsa.c
						$(CC) $(CFLAGS) context/kg_rsa.c -o $(OBJPATH)kg_rsa.o

$(OBJPATH)keyload.o:	$(CRYPT_DEP) context/context.h context/keyload.c
						$(CC) $(CFLAGS) context/keyload.c -o $(OBJPATH)keyload.o

$(OBJPATH)key_rd.o:		$(CRYPT_DEP) $(ASN1_DEP) context/key_rd.c
						$(CC) $(CFLAGS) context/key_rd.c -o $(OBJPATH)key_rd.o

$(OBJPATH)key_wr.o:		$(CRYPT_DEP) $(ASN1_DEP) context/key_wr.c
						$(CC) $(CFLAGS) context/key_wr.c -o $(OBJPATH)key_wr.o

$(OBJPATH)ctx_3des.o:	$(CRYPT_DEP) context/context.h crypt/des.h context/ctx_3des.c
						$(CC) $(CFLAGS) context/ctx_3des.c -o $(OBJPATH)ctx_3des.o

$(OBJPATH)ctx_aes.o:	$(CRYPT_DEP) context/context.h crypt/aes.h crypt/aesopt.h \
						context/ctx_aes.c
						$(CC) $(CFLAGS) context/ctx_aes.c -o $(OBJPATH)ctx_aes.o

$(OBJPATH)ctx_bf.o:		$(CRYPT_DEP) context/context.h crypt/blowfish.h context/ctx_bf.c
						$(CC) $(CFLAGS) context/ctx_bf.c -o $(OBJPATH)ctx_bf.o

$(OBJPATH)ctx_cast.o:	$(CRYPT_DEP) context/context.h crypt/cast.h context/ctx_cast.c
						$(CC) $(CFLAGS) context/ctx_cast.c -o $(OBJPATH)ctx_cast.o

$(OBJPATH)ctx_des.o:	$(CRYPT_DEP) context/context.h crypt/testdes.h crypt/des.h \
						context/ctx_des.c
						$(CC) $(CFLAGS) context/ctx_des.c -o $(OBJPATH)ctx_des.o

$(OBJPATH)ctx_dh.o:		$(CRYPT_DEP) context/context.h bn/bn.h context/ctx_dh.c
						$(CC) $(CFLAGS) context/ctx_dh.c -o $(OBJPATH)ctx_dh.o

$(OBJPATH)ctx_dsa.o:	$(CRYPT_DEP) context/context.h bn/bn.h context/ctx_dsa.c
						$(CC) $(CFLAGS) context/ctx_dsa.c -o $(OBJPATH)ctx_dsa.o

$(OBJPATH)ctx_elg.o:	$(CRYPT_DEP) context/context.h bn/bn.h context/ctx_elg.c
						$(CC) $(CFLAGS) context/ctx_elg.c -o $(OBJPATH)ctx_elg.o

$(OBJPATH)ctx_hmd5.o:	$(CRYPT_DEP) context/context.h crypt/md5.h context/ctx_hmd5.c
						$(CC) $(CFLAGS) context/ctx_hmd5.c -o $(OBJPATH)ctx_hmd5.o

$(OBJPATH)ctx_hrmd.o:	$(CRYPT_DEP) context/context.h crypt/ripemd.h context/ctx_hrmd.c
						$(CC) $(CFLAGS) context/ctx_hrmd.c -o $(OBJPATH)ctx_hrmd.o

$(OBJPATH)ctx_hsha.o:	$(CRYPT_DEP) context/context.h crypt/sha.h context/ctx_hsha.c
						$(CC) $(CFLAGS) context/ctx_hsha.c -o $(OBJPATH)ctx_hsha.o

$(OBJPATH)ctx_idea.o:	$(CRYPT_DEP) context/context.h crypt/idea.h context/ctx_idea.c
						$(CC) $(CFLAGS) context/ctx_idea.c -o $(OBJPATH)ctx_idea.o

$(OBJPATH)ctx_md2.o:	$(CRYPT_DEP) context/context.h crypt/md2.h context/ctx_md2.c
						$(CC) $(CFLAGS) context/ctx_md2.c -o $(OBJPATH)ctx_md2.o

$(OBJPATH)ctx_md4.o:	$(CRYPT_DEP) context/context.h crypt/md4.h context/ctx_md4.c
						$(CC) $(CFLAGS) context/ctx_md4.c -o $(OBJPATH)ctx_md4.o

$(OBJPATH)ctx_md5.o:	$(CRYPT_DEP) context/context.h crypt/md5.h context/ctx_md5.c
						$(CC) $(CFLAGS) context/ctx_md5.c -o $(OBJPATH)ctx_md5.o

$(OBJPATH)ctx_misc.o:	$(CRYPT_DEP) context/context.h context/ctx_misc.c
						$(CC) $(CFLAGS) context/ctx_misc.c -o $(OBJPATH)ctx_misc.o

$(OBJPATH)ctx_rc2.o:	$(CRYPT_DEP) context/context.h crypt/rc2.h context/ctx_rc2.c
						$(CC) $(CFLAGS) context/ctx_rc2.c -o $(OBJPATH)ctx_rc2.o

$(OBJPATH)ctx_rc4.o:	$(CRYPT_DEP) context/context.h crypt/rc4.h context/ctx_rc4.c
						$(CC) $(CFLAGS) context/ctx_rc4.c -o $(OBJPATH)ctx_rc4.o

$(OBJPATH)ctx_rc5.o:	$(CRYPT_DEP) context/context.h crypt/rc5.h context/ctx_rc5.c
						$(CC) $(CFLAGS) context/ctx_rc5.c -o $(OBJPATH)ctx_rc5.o

$(OBJPATH)ctx_ripe.o:	$(CRYPT_DEP) context/context.h crypt/ripemd.h context/ctx_ripe.c
						$(CC) $(CFLAGS) context/ctx_ripe.c -o $(OBJPATH)ctx_ripe.o

$(OBJPATH)ctx_rsa.o:	$(CRYPT_DEP) context/context.h bn/bn.h context/ctx_rsa.c
						$(CC) $(CFLAGS) context/ctx_rsa.c -o $(OBJPATH)ctx_rsa.o

$(OBJPATH)ctx_sha.o:	$(CRYPT_DEP) context/context.h crypt/sha.h context/ctx_sha.c
						$(CC) $(CFLAGS) context/ctx_sha.c -o $(OBJPATH)ctx_sha.o

$(OBJPATH)ctx_sha2.o:	$(CRYPT_DEP) context/context.h crypt/sha2.h context/ctx_sha2.c
						$(CC) $(CFLAGS) context/ctx_sha2.c -o $(OBJPATH)ctx_sha2.o

$(OBJPATH)ctx_skip.o:	$(CRYPT_DEP) context/context.h context/ctx_skip.c
						$(CC) $(CFLAGS) context/ctx_skip.c -o $(OBJPATH)ctx_skip.o

# crypt subdirectory - crypt algos

$(OBJPATH)aes_modes.o:	$(CRYPT_DEP) crypt/aes.h crypt/aesopt.h crypt/aes_modes.c
						$(CC) $(CFLAGS) crypt/aes_modes.c -o $(OBJPATH)aes_modes.o

$(OBJPATH)aescrypt.o:	$(CRYPT_DEP) crypt/aes.h crypt/aesopt.h crypt/aescrypt.c
						$(CC) $(CFLAGS) crypt/aescrypt.c -o $(OBJPATH)aescrypt.o

$(OBJPATH)aeskey.o:		$(CRYPT_DEP) crypt/aes.h crypt/aesopt.h crypt/aeskey.c
						$(CC) $(CFLAGS) crypt/aeskey.c -o $(OBJPATH)aeskey.o

$(OBJPATH)aestab.o:		$(CRYPT_DEP) crypt/aes.h crypt/aesopt.h crypt/aestab.c
						$(CC) $(CFLAGS) crypt/aestab.c -o $(OBJPATH)aestab.o

$(OBJPATH)bfecb.o:		crypt/osconfig.h crypt/blowfish.h crypt/bflocl.h crypt/bfecb.c
						$(CC) $(CFLAGS) crypt/bfecb.c -o $(OBJPATH)bfecb.o

$(OBJPATH)bfenc.o:		crypt/osconfig.h crypt/blowfish.h crypt/bflocl.h crypt/bfenc.c
						$(CC) $(CFLAGS) crypt/bfenc.c -o $(OBJPATH)bfenc.o

$(OBJPATH)bfskey.o:		crypt/osconfig.h crypt/blowfish.h crypt/bflocl.h crypt/bfpi.h \
						crypt/bfskey.c
						$(CC) $(CFLAGS) crypt/bfskey.c -o $(OBJPATH)bfskey.o

$(OBJPATH)castecb.o:	crypt/osconfig.h crypt/cast.h crypt/castlcl.h crypt/castecb.c
						$(CC) $(CFLAGS) crypt/castecb.c -o $(OBJPATH)castecb.o

$(OBJPATH)castenc.o:	crypt/osconfig.h crypt/cast.h crypt/castlcl.h crypt/castenc.c
						$(CC) $(CFLAGS) crypt/castenc.c -o $(OBJPATH)castenc.o

$(OBJPATH)castskey.o:	crypt/osconfig.h crypt/cast.h crypt/castlcl.h crypt/castsbox.h \
						crypt/castskey.c
						$(CC) $(CFLAGS) crypt/castskey.c -o $(OBJPATH)castskey.o

$(OBJPATH)descbc.o:		crypt/osconfig.h crypt/des.h crypt/deslocl.h crypt/descbc.c
						$(CC) $(CFLAGS) crypt/descbc.c -o $(OBJPATH)descbc.o

$(OBJPATH)desecb.o:		crypt/osconfig.h crypt/des.h crypt/deslocl.h crypt/desecb.c
						$(CC) $(CFLAGS) crypt/desecb.c -o $(OBJPATH)desecb.o

$(OBJPATH)desecb3.o:	crypt/osconfig.h crypt/des.h crypt/deslocl.h crypt/desecb3.c
						$(CC) $(CFLAGS) crypt/desecb3.c -o $(OBJPATH)desecb3.o

$(OBJPATH)desenc.o:		crypt/osconfig.h crypt/des.h crypt/deslocl.h crypt/desenc.c
						$(CC) $(CFLAGS) crypt/desenc.c -o $(OBJPATH)desenc.o

$(OBJPATH)desskey.o:	crypt/osconfig.h crypt/des.h crypt/deslocl.h crypt/desskey.c
						$(CC) $(CFLAGS) crypt/desskey.c -o $(OBJPATH)desskey.o

$(OBJPATH)icbc.o:		$(CRYPT_DEP) crypt/idea.h crypt/idealocl.h crypt/icbc.c
						$(CC) $(CFLAGS) crypt/icbc.c -o $(OBJPATH)icbc.o

$(OBJPATH)iecb.o:		$(CRYPT_DEP) crypt/idea.h crypt/idealocl.h crypt/iecb.c
						$(CC) $(CFLAGS) crypt/iecb.c -o $(OBJPATH)iecb.o

$(OBJPATH)iskey.o:		$(CRYPT_DEP) crypt/idea.h crypt/idealocl.h crypt/iskey.c
						$(CC) $(CFLAGS) crypt/iskey.c -o $(OBJPATH)iskey.o

$(OBJPATH)rc2cbc.o:		crypt/osconfig.h crypt/rc2.h crypt/rc2locl.h crypt/rc2cbc.c
						$(CC) $(CFLAGS) crypt/rc2cbc.c -o $(OBJPATH)rc2cbc.o

$(OBJPATH)rc2ecb.o:		crypt/osconfig.h crypt/rc2.h crypt/rc2locl.h crypt/rc2ecb.c
						$(CC) $(CFLAGS) crypt/rc2ecb.c -o $(OBJPATH)rc2ecb.o

$(OBJPATH)rc2skey.o:	crypt/osconfig.h crypt/rc2.h crypt/rc2locl.h crypt/rc2skey.c
						$(CC) $(CFLAGS) crypt/rc2skey.c -o $(OBJPATH)rc2skey.o

$(OBJPATH)rc4enc.o:		crypt/osconfig.h crypt/rc4.h crypt/rc4locl.h crypt/rc4enc.c
						$(CC) $(CFLAGS) crypt/rc4enc.c -o $(OBJPATH)rc4enc.o

$(OBJPATH)rc4skey.o:	crypt/osconfig.h crypt/rc4.h crypt/rc4locl.h crypt/rc4skey.c
						$(CC) $(CFLAGS) crypt/rc4skey.c -o $(OBJPATH)rc4skey.o

$(OBJPATH)rc5ecb.o:		crypt/osconfig.h crypt/rc5.h crypt/rc5locl.h crypt/rc5ecb.c
						$(CC) $(CFLAGS) crypt/rc5ecb.c -o $(OBJPATH)rc5ecb.o

$(OBJPATH)rc5enc.o:		crypt/osconfig.h crypt/rc5.h crypt/rc5locl.h crypt/rc5enc.c
						$(CC) $(CFLAGS) crypt/rc5enc.c -o $(OBJPATH)rc5enc.o

$(OBJPATH)rc5skey.o:	crypt/osconfig.h crypt/rc5.h crypt/rc5locl.h crypt/rc5skey.c
						$(CC) $(CFLAGS) crypt/rc5skey.c -o $(OBJPATH)rc5skey.o

$(OBJPATH)skipjack.o:	crypt/skipjack.c
						$(CC) $(CFLAGS) crypt/skipjack.c -o $(OBJPATH)skipjack.o

# crypt subdirectory - hash algos

$(OBJPATH)md2dgst.o:	crypt/osconfig.h crypt/md2.h crypt/md2dgst.c
						$(CC) $(CFLAGS) crypt/md2dgst.c -o $(OBJPATH)md2dgst.o

$(OBJPATH)md4dgst.o:	crypt/osconfig.h crypt/md4.h crypt/md4locl.h \
						crypt/md4dgst.c
						$(CC) $(CFLAGS) crypt/md4dgst.c -o $(OBJPATH)md4dgst.o

$(OBJPATH)md5dgst.o:	crypt/osconfig.h crypt/md5.h crypt/md5locl.h \
						crypt/md5dgst.c
						$(CC) $(CFLAGS) crypt/md5dgst.c -o $(OBJPATH)md5dgst.o

$(OBJPATH)rmddgst.o:	crypt/osconfig.h crypt/ripemd.h crypt/rmdlocl.h \
						crypt/rmddgst.c
						$(CC) $(CFLAGS) crypt/rmddgst.c -o $(OBJPATH)rmddgst.o

$(OBJPATH)sha1dgst.o:	crypt/osconfig.h crypt/sha.h crypt/sha1locl.h \
						crypt/sha1dgst.c
						$(CC) $(CFLAGS) crypt/sha1dgst.c -o $(OBJPATH)sha1dgst.o

$(OBJPATH)sha2.o:		crypt/osconfig.h crypt/sha.h crypt/sha1locl.h crypt/sha2.c
						$(CC) $(CFLAGS) crypt/sha2.c -o $(OBJPATH)sha2.o

# device subdirectory

$(OBJPATH)fortezza.o:	$(CRYPT_DEP) device/device.h device/fortezza.c
						$(CC) $(CFLAGS) device/fortezza.c -o $(OBJPATH)fortezza.o

$(OBJPATH)pkcs11.o:		$(CRYPT_DEP) device/device.h device/pkcs11.c
						$(CC) $(CFLAGS) device/pkcs11.c -o $(OBJPATH)pkcs11.o

$(OBJPATH)system.o:		$(CRYPT_DEP) device/device.h device/capabil.h device/system.c
						$(CC) $(CFLAGS) device/system.c -o $(OBJPATH)system.o

# envelope subdirectory

$(OBJPATH)cms_denv.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/cms_denv.c
						$(CC) $(CFLAGS) envelope/cms_denv.c -o $(OBJPATH)cms_denv.o

$(OBJPATH)cms_env.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/cms_env.c
						$(CC) $(CFLAGS) envelope/cms_env.c -o $(OBJPATH)cms_env.o

$(OBJPATH)decode.o:		$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/decode.c
						$(CC) $(CFLAGS) envelope/decode.c -o $(OBJPATH)decode.o

$(OBJPATH)encode.o:		$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/encode.c
						$(CC) $(CFLAGS) envelope/encode.c -o $(OBJPATH)encode.o

$(OBJPATH)pgp_denv.o:	$(CRYPT_DEP) $(IO_DEP) misc/pgp.h envelope/pgp_denv.c
						$(CC) $(CFLAGS) envelope/pgp_denv.c -o $(OBJPATH)pgp_denv.o

$(OBJPATH)pgp_env.o:	$(CRYPT_DEP) $(IO_DEP) misc/pgp.h envelope/pgp_env.c
						$(CC) $(CFLAGS) envelope/pgp_env.c -o $(OBJPATH)pgp_env.o

$(OBJPATH)res_actn.o:	$(CRYPT_DEP) envelope/envelope.h envelope/res_actn.c
						$(CC) $(CFLAGS) envelope/res_actn.c -o $(OBJPATH)res_actn.o

$(OBJPATH)res_denv.o:	$(CRYPT_DEP) envelope/envelope.h envelope/res_denv.c
						$(CC) $(CFLAGS) envelope/res_denv.c -o $(OBJPATH)res_denv.o

$(OBJPATH)res_env.o:	$(CRYPT_DEP) envelope/envelope.h envelope/res_env.c
						$(CC) $(CFLAGS) envelope/res_env.c -o $(OBJPATH)res_env.o

# io subdirectory

$(OBJPATH)cmp_tcp.o:	$(CRYPT_DEP) io/cmp_tcp.c
						$(CC) $(CFLAGS) io/cmp_tcp.c -o $(OBJPATH)cmp_tcp.o

$(OBJPATH)dns.o:		$(CRYPT_DEP) io/tcp.h io/dns.c
						$(CC) $(CFLAGS) io/dns.c -o $(OBJPATH)dns.o

$(OBJPATH)file.o:		$(CRYPT_DEP) $(ASN1_DEP) io/file.h io/file.c
						$(CC) $(CFLAGS) io/file.c -o $(OBJPATH)file.o

$(OBJPATH)http_rd.o:	$(CRYPT_DEP) io/http_rd.c
						$(CC) $(CFLAGS) io/http_rd.c -o $(OBJPATH)http_rd.o

$(OBJPATH)http_wr.o:	$(CRYPT_DEP) io/http_wr.c
						$(CC) $(CFLAGS) io/http_wr.c -o $(OBJPATH)http_wr.o

$(OBJPATH)memory.o:		$(CRYPT_DEP) $(ASN1_DEP) io/memory.c
						$(CC) $(CFLAGS) io/memory.c -o $(OBJPATH)memory.o

$(OBJPATH)net.o:		$(CRYPT_DEP) $(ASN1_DEP) io/tcp.h io/net.c
						$(CC) $(CFLAGS) io/net.c -o $(OBJPATH)net.o

$(OBJPATH)stream.o:		$(CRYPT_DEP) $(ASN1_DEP) io/stream.c
						$(CC) $(CFLAGS) io/stream.c -o $(OBJPATH)stream.o

$(OBJPATH)tcp.o:		$(CRYPT_DEP) io/tcp.h io/tcp.c
						$(CC) $(CFLAGS) io/tcp.c -o $(OBJPATH)tcp.o

# kernel subdirectory

$(OBJPATH)attr_acl.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/attr_acl.c
						$(CC) $(CFLAGS) kernel/attr_acl.c -o $(OBJPATH)attr_acl.o

$(OBJPATH)certm_acl.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/certm_acl.c
						$(CC) $(CFLAGS) kernel/certm_acl.c -o $(OBJPATH)certm_acl.o

$(OBJPATH)init.o:		$(CRYPT_DEP) $(KERNEL_DEP) kernel/init.c
						$(CC) $(CFLAGS) kernel/init.c -o $(OBJPATH)init.o

$(OBJPATH)int_msg.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/int_msg.c
						$(CC) $(CFLAGS) kernel/int_msg.c -o $(OBJPATH)int_msg.o

$(OBJPATH)key_acl.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/key_acl.c
						$(CC) $(CFLAGS) kernel/key_acl.c -o $(OBJPATH)key_acl.o

$(OBJPATH)mech_acl.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/mech_acl.c
						$(CC) $(CFLAGS) kernel/mech_acl.c -o $(OBJPATH)mech_acl.o

$(OBJPATH)msg_acl.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/msg_acl.c
						$(CC) $(CFLAGS) kernel/msg_acl.c -o $(OBJPATH)msg_acl.o

$(OBJPATH)obj_acc.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/obj_acc.c
						$(CC) $(CFLAGS) kernel/obj_acc.c -o $(OBJPATH)obj_acc.o

$(OBJPATH)objects.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/objects.c
						$(CC) $(CFLAGS) kernel/objects.c -o $(OBJPATH)objects.o

$(OBJPATH)sec_mem.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/sec_mem.c
						$(CC) $(CFLAGS) kernel/sec_mem.c -o $(OBJPATH)sec_mem.o

$(OBJPATH)semaphore.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/semaphore.c
						$(CC) $(CFLAGS) kernel/semaphore.c -o $(OBJPATH)semaphore.o

$(OBJPATH)sendmsg.o:	$(CRYPT_DEP) $(KERNEL_DEP) kernel/sendmsg.c
						$(CC) $(CFLAGS) kernel/sendmsg.c -o $(OBJPATH)sendmsg.o

# keyset subdirectory

$(OBJPATH)dbms.o:		$(CRYPT_DEP) keyset/keyset.h keyset/dbms.c
						$(CC) $(CFLAGS) keyset/dbms.c -o $(OBJPATH)dbms.o

$(OBJPATH)ca_add.o:		$(CRYPT_DEP) keyset/keyset.h keyset/ca_add.c
						$(CC) $(CFLAGS) keyset/ca_add.c -o $(OBJPATH)ca_add.o

$(OBJPATH)ca_issue.o:	$(CRYPT_DEP) keyset/keyset.h keyset/ca_issue.c
						$(CC) $(CFLAGS) keyset/ca_issue.c -o $(OBJPATH)ca_issue.o

$(OBJPATH)ca_misc.o:	$(CRYPT_DEP) keyset/keyset.h keyset/ca_misc.c
						$(CC) $(CFLAGS) keyset/ca_misc.c -o $(OBJPATH)ca_misc.o

$(OBJPATH)ca_rev.o:		$(CRYPT_DEP) keyset/keyset.h keyset/ca_rev.c
						$(CC) $(CFLAGS) keyset/ca_rev.c -o $(OBJPATH)ca_rev.o

$(OBJPATH)dbx_misc.o:	$(CRYPT_DEP) keyset/keyset.h keyset/dbx_misc.c
						$(CC) $(CFLAGS) keyset/dbx_misc.c -o $(OBJPATH)dbx_misc.o

$(OBJPATH)dbx_rd.o:		$(CRYPT_DEP) keyset/keyset.h keyset/dbx_rd.c
						$(CC) $(CFLAGS) keyset/dbx_rd.c -o $(OBJPATH)dbx_rd.o

$(OBJPATH)dbx_wr.o:		$(CRYPT_DEP) keyset/keyset.h keyset/dbx_wr.c
						$(CC) $(CFLAGS) keyset/dbx_wr.c -o $(OBJPATH)dbx_wr.o

$(OBJPATH)http.o:		$(CRYPT_DEP) keyset/keyset.h keyset/http.c
						$(CC) $(CFLAGS) keyset/http.c -o $(OBJPATH)http.o

$(OBJPATH)ldap.o:		$(CRYPT_DEP) keyset/keyset.h keyset/ldap.c
						$(CC) $(CFLAGS) keyset/ldap.c -o $(OBJPATH)ldap.o

$(OBJPATH)odbc.o:		$(CRYPT_DEP) keyset/keyset.h keyset/odbc.c
						$(CC) $(CFLAGS) keyset/odbc.c -o $(OBJPATH)odbc.o

$(OBJPATH)pgp.o:		$(CRYPT_DEP) misc/pgp.h keyset/pgp.c
						$(CC) $(CFLAGS) keyset/pgp.c -o $(OBJPATH)pgp.o

$(OBJPATH)pkcs12.o:		$(CRYPT_DEP) keyset/keyset.h keyset/pkcs12.c
						$(CC) $(CFLAGS) keyset/pkcs12.c -o $(OBJPATH)pkcs12.o

$(OBJPATH)pkcs15.o:		$(CRYPT_DEP) keyset/keyset.h keyset/pkcs15.h keyset/pkcs15.c
						$(CC) $(CFLAGS) keyset/pkcs15.c -o $(OBJPATH)pkcs15.o

$(OBJPATH)pkcs15_add.o:	$(CRYPT_DEP) keyset/keyset.h keyset/pkcs15.h keyset/pkcs15_add.c
						$(CC) $(CFLAGS) keyset/pkcs15_add.c -o $(OBJPATH)pkcs15_add.o

$(OBJPATH)pkcs15_att.o:	$(CRYPT_DEP) keyset/keyset.h keyset/pkcs15.h keyset/pkcs15_att.c
						$(CC) $(CFLAGS) keyset/pkcs15_att.c -o $(OBJPATH)pkcs15_att.o

$(OBJPATH)pkcs15_rd.o:	$(CRYPT_DEP) keyset/keyset.h keyset/pkcs15.h keyset/pkcs15_rd.c
						$(CC) $(CFLAGS) keyset/pkcs15_rd.c -o $(OBJPATH)pkcs15_rd.o

$(OBJPATH)pkcs15_wr.o:	$(CRYPT_DEP) keyset/keyset.h keyset/pkcs15.h keyset/pkcs15_wr.c
						$(CC) $(CFLAGS) keyset/pkcs15_wr.c -o $(OBJPATH)pkcs15_wr.o

# mechanism subdirectory

$(OBJPATH)keyex.o:		$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/keyex.c
						$(CC) $(CFLAGS) mechs/keyex.c -o $(OBJPATH)keyex.o

$(OBJPATH)keyex_int.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/keyex_int.c
						$(CC) $(CFLAGS) mechs/keyex_int.c -o $(OBJPATH)keyex_int.o

$(OBJPATH)keyex_rw.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/keyex_rw.c
						$(CC) $(CFLAGS) mechs/keyex_rw.c -o $(OBJPATH)keyex_rw.o

$(OBJPATH)mech_drv.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/mech_drv.c
						$(CC) $(CFLAGS) mechs/mech_drv.c -o $(OBJPATH)mech_drv.o

$(OBJPATH)mech_enc.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/mech_enc.c
						$(CC) $(CFLAGS) mechs/mech_enc.c -o $(OBJPATH)mech_enc.o

$(OBJPATH)mech_sig.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/mech_sig.c
						$(CC) $(CFLAGS) mechs/mech_sig.c -o $(OBJPATH)mech_sig.o

$(OBJPATH)mech_wrp.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/mech_wrp.c
						$(CC) $(CFLAGS) mechs/mech_wrp.c -o $(OBJPATH)mech_wrp.o

$(OBJPATH)obj_qry.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/obj_qry.c
						$(CC) $(CFLAGS) mechs/obj_qry.c -o $(OBJPATH)obj_qry.o

$(OBJPATH)sign.o:		$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/sign.c
						$(CC) $(CFLAGS) mechs/sign.c -o $(OBJPATH)sign.o

$(OBJPATH)sign_cms.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/sign_cms.c
						$(CC) $(CFLAGS) mechs/sign_cms.c -o $(OBJPATH)sign_cms.o

$(OBJPATH)sign_int.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/sign_int.c
						$(CC) $(CFLAGS) mechs/sign_int.c -o $(OBJPATH)sign_int.o

$(OBJPATH)sign_pgp.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/sign_pgp.c
						$(CC) $(CFLAGS) mechs/sign_pgp.c -o $(OBJPATH)sign_pgp.o

$(OBJPATH)sign_rw.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/sign_rw.c
						$(CC) $(CFLAGS) mechs/sign_rw.c -o $(OBJPATH)sign_rw.o

$(OBJPATH)sign_x509.o:	$(CRYPT_DEP) $(ASN1_DEP) mechs/mech.h mechs/sign_x509.c
						$(CC) $(CFLAGS) mechs/sign_x509.c -o $(OBJPATH)sign_x509.o

# misc subdirectory

$(OBJPATH)asn1_chk.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/asn1_chk.c
						$(CC) $(CFLAGS) misc/asn1_chk.c -o $(OBJPATH)asn1_chk.o

$(OBJPATH)asn1_ext.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/asn1_ext.c
						$(CC) $(CFLAGS) misc/asn1_ext.c -o $(OBJPATH)asn1_ext.o

$(OBJPATH)asn1_rd.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/asn1_rd.c
						$(CC) $(CFLAGS) misc/asn1_rd.c -o $(OBJPATH)asn1_rd.o

$(OBJPATH)asn1_wr.o:	$(CRYPT_DEP) $(ASN1_DEP) misc/asn1_wr.c
						$(CC) $(CFLAGS) misc/asn1_wr.c -o $(OBJPATH)asn1_wr.o

$(OBJPATH)base64.o:		$(CRYPT_DEP) misc/base64.c
						$(CC) $(CFLAGS) misc/base64.c -o $(OBJPATH)base64.o

$(OBJPATH)int_api.o:	$(CRYPT_DEP) misc/int_api.c
						$(CC) $(CFLAGS) misc/int_api.c -o $(OBJPATH)int_api.o

$(OBJPATH)int_attr.o:	$(CRYPT_DEP) misc/int_attr.c
						$(CC) $(CFLAGS) misc/int_attr.c -o $(OBJPATH)int_attr.o

$(OBJPATH)int_env.o:	$(CRYPT_DEP) misc/int_env.c
						$(CC) $(CFLAGS) misc/int_env.c -o $(OBJPATH)int_env.o

$(OBJPATH)misc_rw.o:	$(CRYPT_DEP) $(IO_DEP) misc/misc_rw.c
						$(CC) $(CFLAGS) misc/misc_rw.c -o $(OBJPATH)misc_rw.o

$(OBJPATH)os_spec.o: 	$(CRYPT_DEP) misc/os_spec.c
						$(CC) $(CFLAGS) misc/os_spec.c -o $(OBJPATH)os_spec.o

$(OBJPATH)pgp_misc.o:	$(CRYPT_DEP) $(IO_DEP) misc/pgp.h misc/pgp_misc.c
						$(CC) $(CFLAGS) misc/pgp_misc.c -o $(OBJPATH)pgp_misc.o

$(OBJPATH)random.o:		$(CRYPT_DEP) random/random.c
						$(CC) $(CFLAGS) random/random.c -o $(OBJPATH)random.o

$(OBJPATH)unix.o:		$(CRYPT_DEP) random/unix.c
						$(CC) $(CFLAGS) random/unix.c -o $(OBJPATH)unix.o

# session subdirectory

$(OBJPATH)certstore.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/certstore.c
						$(CC) $(CFLAGS) session/certstore.c -o $(OBJPATH)certstore.o

$(OBJPATH)cmp.o:		$(CRYPT_DEP) $(ASN1_DEP) session/cmp.h session/session.h \
						session/cmp.c
						$(CC) $(CFLAGS) session/cmp.c -o $(OBJPATH)cmp.o

$(OBJPATH)cmp_rd.o:		$(CRYPT_DEP) $(ASN1_DEP) session/cmp.h session/session.h \
						session/cmp_rd.c
						$(CC) $(CFLAGS) session/cmp_rd.c -o $(OBJPATH)cmp_rd.o

$(OBJPATH)cmp_wr.o:		$(CRYPT_DEP) $(ASN1_DEP) session/cmp.h session/session.h \
						session/cmp_wr.c
						$(CC) $(CFLAGS) session/cmp_wr.c -o $(OBJPATH)cmp_wr.o

$(OBJPATH)ocsp.o:		$(CRYPT_DEP) $(ASN1_DEP) session/session.h session/ocsp.c
						$(CC) $(CFLAGS) session/ocsp.c -o $(OBJPATH)ocsp.o

$(OBJPATH)pnppki.o:		$(CRYPT_DEP) $(ASN1_DEP) session/cmp.h session/session.h \
						session/pnppki.c
						$(CC) $(CFLAGS) session/pnppki.c -o $(OBJPATH)pnppki.o

$(OBJPATH)rtcs.o:		$(CRYPT_DEP) $(ASN1_DEP) session/session.h session/rtcs.c
						$(CC) $(CFLAGS) session/rtcs.c -o $(OBJPATH)rtcs.o

$(OBJPATH)scep.o:		$(CRYPT_DEP) $(ASN1_DEP) session/session.h session/scep.c
						$(CC) $(CFLAGS) session/scep.c -o $(OBJPATH)scep.o

$(OBJPATH)scorebrd.o:	$(CRYPT_DEP) $(ASN1_DEP) session/session.h session/scorebrd.c
						$(CC) $(CFLAGS) session/scorebrd.c -o $(OBJPATH)scorebrd.o

$(OBJPATH)sess_attr.o:	$(CRYPT_DEP) session/session.h session/sess_attr.c
						$(CC) $(CFLAGS) session/sess_attr.c -o $(OBJPATH)sess_attr.o

$(OBJPATH)sess_rw.o:	$(CRYPT_DEP) $(ASN1_DEP) session/session.h session/sess_rw.c
						$(CC) $(CFLAGS) session/sess_rw.c -o $(OBJPATH)sess_rw.o

$(OBJPATH)session.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/session.c
						$(CC) $(CFLAGS) session/session.c -o $(OBJPATH)session.o

$(OBJPATH)ssh.o:		$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssh.h \
						session/ssh.c
						$(CC) $(CFLAGS) session/ssh.c -o $(OBJPATH)ssh.o

$(OBJPATH)ssh1.o:		$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssh.h \
						session/ssh1.c
						$(CC) $(CFLAGS) session/ssh1.c -o $(OBJPATH)ssh1.o

$(OBJPATH)ssh2.o:		$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssh.h \
						session/ssh2.c
						$(CC) $(CFLAGS) session/ssh2.c -o $(OBJPATH)ssh2.o

$(OBJPATH)ssh2_chn.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssh.h \
						session/ssh2_chn.c
						$(CC) $(CFLAGS) session/ssh2_chn.c -o $(OBJPATH)ssh2_chn.o

$(OBJPATH)ssh2_cli.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssh.h \
						session/ssh2_cli.c
						$(CC) $(CFLAGS) session/ssh2_cli.c -o $(OBJPATH)ssh2_cli.o

$(OBJPATH)ssh2_cry.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssh.h \
						session/ssh2_cry.c
						$(CC) $(CFLAGS) session/ssh2_cry.c -o $(OBJPATH)ssh2_cry.o

$(OBJPATH)ssh2_msg.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssh.h \
						session/ssh2_msg.c
						$(CC) $(CFLAGS) session/ssh2_msg.c -o $(OBJPATH)ssh2_msg.o

$(OBJPATH)ssh2_rw.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssh.h \
						session/ssh2_rw.c
						$(CC) $(CFLAGS) session/ssh2_rw.c -o $(OBJPATH)ssh2_rw.o

$(OBJPATH)ssh2_svr.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssh.h \
						session/ssh2_svr.c
						$(CC) $(CFLAGS) session/ssh2_svr.c -o $(OBJPATH)ssh2_svr.o

$(OBJPATH)ssl.o:		$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssl.h \
						session/ssl.c
						$(CC) $(CFLAGS) session/ssl.c -o $(OBJPATH)ssl.o

$(OBJPATH)ssl_cli.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssl.h \
						session/ssl_cli.c
						$(CC) $(CFLAGS) session/ssl_cli.c -o $(OBJPATH)ssl_cli.o

$(OBJPATH)ssl_cry.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssl.h \
						session/ssl_cry.c
						$(CC) $(CFLAGS) session/ssl_cry.c -o $(OBJPATH)ssl_cry.o

$(OBJPATH)ssl_rw.o:		$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssl.h \
						session/ssl_rw.c
						$(CC) $(CFLAGS) session/ssl_rw.c -o $(OBJPATH)ssl_rw.o

$(OBJPATH)ssl_svr.o:	$(CRYPT_DEP) $(IO_DEP) session/session.h session/ssl.h \
						session/ssl_svr.c
						$(CC) $(CFLAGS) session/ssl_svr.c -o $(OBJPATH)ssl_svr.o

$(OBJPATH)tsp.o:		$(CRYPT_DEP) $(ASN1_DEP) session/session.h session/tsp.c
						$(CC) $(CFLAGS) session/tsp.c -o $(OBJPATH)tsp.o

# zlib subdirectory

$(OBJPATH)adler32.o:	$(ZLIB_DEP) zlib/adler32.c
						$(CC) $(CFLAGS) zlib/adler32.c -o $(OBJPATH)adler32.o

$(OBJPATH)deflate.o:	$(ZLIB_DEP) zlib/deflate.c
						$(CC) $(CFLAGS) zlib/deflate.c -o $(OBJPATH)deflate.o

$(OBJPATH)inffast.o:	$(ZLIB_DEP) zlib/inffast.h zlib/inffixed.h \
						zlib/inftrees.h zlib/inffast.c
						$(CC) $(CFLAGS) zlib/inffast.c -o $(OBJPATH)inffast.o

$(OBJPATH)inflate.o:	$(ZLIB_DEP) zlib/inflate.c
						$(CC) $(CFLAGS) zlib/inflate.c -o $(OBJPATH)inflate.o

$(OBJPATH)inftrees.o:	$(ZLIB_DEP) zlib/inftrees.h zlib/inftrees.c
						$(CC) $(CFLAGS) zlib/inftrees.c -o $(OBJPATH)inftrees.o

$(OBJPATH)trees.o:		$(ZLIB_DEP) zlib/trees.h zlib/trees.c
						$(CC) $(CFLAGS) zlib/trees.c -o $(OBJPATH)trees.o

$(OBJPATH)zutil.o:		$(ZLIB_DEP) zlib/zutil.c
						$(CC) $(CFLAGS) zlib/zutil.c -o $(OBJPATH)zutil.o

#****************************************************************************
#*																			*
#*								Test Code Targets							*
#*																			*
#****************************************************************************

# The test code

utils.o:				cryptlib.h crypt.h test/test.h test/utils.c
						$(CC) $(CFLAGS) test/utils.c

certs.o:				cryptlib.h crypt.h test/test.h test/certs.c
						$(CC) $(CFLAGS) test/certs.c

devices.o:				cryptlib.h crypt.h test/test.h test/devices.c
						$(CC) $(CFLAGS) test/devices.c

envelope.o:				cryptlib.h crypt.h test/test.h test/envelope.c
						$(CC) $(CFLAGS) test/envelope.c

highlvl.o:				cryptlib.h crypt.h test/test.h test/highlvl.c
						$(CC) $(CFLAGS) test/highlvl.c

keydbx.o:				cryptlib.h crypt.h test/test.h test/keydbx.c
						$(CC) $(CFLAGS) test/keydbx.c

keyfile.o:				cryptlib.h crypt.h test/test.h test/keyfile.c
						$(CC) $(CFLAGS) test/keyfile.c

loadkey.o:				cryptlib.h crypt.h test/test.h test/loadkey.c
						$(CC) $(CFLAGS) test/loadkey.c

lowlvl.o:				cryptlib.h crypt.h test/test.h test/lowlvl.c
						$(CC) $(CFLAGS) test/lowlvl.c

scert.o:				cryptlib.h crypt.h test/test.h test/scert.c
						$(CC) $(CFLAGS) test/scert.c

sreqresp.o:				cryptlib.h crypt.h test/test.h test/sreqresp.c
						$(CC) $(CFLAGS) test/sreqresp.c

ssh.o:					cryptlib.h crypt.h test/test.h test/ssh.c
						$(CC) $(CFLAGS) test/ssh.c

ssl.o:					cryptlib.h crypt.h test/test.h test/ssl.c
						$(CC) $(CFLAGS) test/ssl.c

stress.o:				cryptlib.h crypt.h test/test.h test/stress.c
						$(CC) $(CFLAGS) test/stress.c

testlib.o:				cryptlib.h crypt.h test/test.h test/testlib.c
						$(CC) $(CFLAGS) test/testlib.c

#****************************************************************************
#*																			*
#*									Link Targets							*
#*																			*
#****************************************************************************

# Create the static and shared libraries.  The main test program is also
# listed as a dependency since we need to use OS-specific compiler options
# for it that a simple 'make testlib' won't give us (the test program checks
# whether the compiler options were set correctly when building the library,
# so it needs to include a few library-specific files that wouldn't be used
# in a normal program).
#
# When cross-compiling, we have to use the hosted tools and libraries rather
# than the system tools and libraries for the build, so we special-case this
# step based on the $(OSNAME) setting supplied to the build script.

$(LIBNAME):		$(OBJS) $(EXTRAOBJS) $(TESTOBJS)
				@./tools/buildlib.sh $(OSNAME) $(LIBNAME) $(OBJS) $(EXTRAOBJS)


$(SLIBNAME):	$(OBJS) $(EXTRAOBJS) $(TESTOBJS)
				@./tools/buildsharedlib.sh $(OSNAME) $(SLIBNAME) $(LD) $(OBJS) \
					$(EXTRAOBJS)

$(DYLIBNAME):	$(OBJS) $(EXTRAOBJS) $(TESTOBJS)
				@$(LD) -dynamiclib -compatibility_version $(MAJ).$(MIN) \
					-current_version $(MAJ).$(MIN).$(PLV) \
					-o $(DYLIBNAME) $(OBJS) $(EXTRAOBJS)

# If installing cryptlib as a systemwide lib, run ldconfig (which normally
# reads /etc/ld.so.conf, sets up the appropriate symbolic links in the
# shared lib directory, and writes a cache file /etc/ld.so.cache for use by
# other programs). The loader the consults /etc/ld.so.cache to find the
# libraries it needs.  This is why ldconfig has to be run when a new lib is
# added or removed.
#
#	ldconfig -n <cryptlib .so directory path>
#
# A temporary workaround for testing is to set LD_LIBRARY_PATH to the
# directory containing the cryptlib shared lib.  This (colon-separated) list
# of directories is searched before the standard library directories.  This
# may have system-specific variations, e.g. under PHUX it's called
# SHLIB_PATH and under Aches it's LIBPATH.  BeOS uses LIBRARY_PATH, and
# needs to have it pointed to . to find the shared lib, otherwise it fails
# with a "Missing library" error without indicating which library is missing.
#
# To run stestlib with a one-off lib path change, use either the universal:
#
#	env LD_LIBRARY_PATH=. ./testlib
#
# or the shell-specific (cdh):
#
#	setenv LD_LIBRARY_PATH .:$LD_LIBRARY_PATH
#	./testlib
#
# or (sh):
#
#	LD_LIBRARY_PATH=. ; export LD_LIBRARY_PATH
#	./testlib
#
# Finally, ldd <filename> will print out shared lib dependencies.
#
# We don't give the library as a dependency since the user has to make this
# explicitly rather than implicitly via testlib in order to go via the
# auto-config mechanism.  Since OS X uses special dylibs instead of normal
# shared libs, we detect this and build the appropriate lib type.
#
# To test the code with extended malloc diagnostics on systems with
# phkmalloc, use:
#
#	env MALLOC_OPTIONS="AJVX" ./testlib

testlib:		$(TESTOBJS)
				@rm -f $(LINKFILE)
				@echo $(TESTOBJS) > $(LINKFILE)
				@$(LD) -o testlib $(LDFLAGS) `cat $(LINKFILE)` -L. -l$(PROJ) \
					`./tools/getlibs.sh autodetect`
				@rm -f $(LINKFILE)

stestlib:		$(TESTOBJS)
				@rm -f $(LINKFILE)
				@echo $(TESTOBJS) > $(LINKFILE)
				@if [ $(OSNAME) = 'AIX' ] ; then \
					$(LD) -o testlib $(LDFLAGS) `cat $(LINKFILE)` -L. $(SLIBNAME).a \
						`./tools/getlibs.sh AIX` ; \
				elif [ $(OSNAME) = 'Darwin' ] ; then \
					$(LD) -o testlib $(LDFLAGS) `cat $(LINKFILE)` -L. $(DYLIBNAME) \
						`./tools/getlibs.sh Darwin` ; \
				elif [ $(OSNAME) = 'HP-UX' ] ; then \
					$(LD) -o testlib $(LDFLAGS) `cat $(LINKFILE)` -L. lib$(PROJ).sl \
						`./tools/getlibs.sh HP-UX` ; \
				else \
					$(LD) -o testlib $(LDFLAGS) `cat $(LINKFILE)` -L. $(SLIBNAME) \
						`./tools/getlibs.sh autodetect` ; \
				fi
				@rm -f $(LINKFILE)

#****************************************************************************
#*																			*
#*								Unix OS Targets								*
#*																			*
#****************************************************************************

# Aches: A vaguely Unix-compatible OS designed by IBM.  The maxmem option
#		 is to give the optimizer more headroom, it's not really needed
#		 but avoids millions of informational messages telling you to
#		 increase it from the default 2048.  The roconst puts const data
#		 into read-only memory (this may happen anyway on some versions of
#		 the compiler).

AIX:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	make $(DEFINES) CFLAGS="$(CFLAGS) -O2 -qmaxmem=-1 -qroconst -D_REENTRANT"

# Apollo: Yeah, this makefile has been around for awhile.  Why do you ask?

Apollo:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O4"

# AUX: su root; rm -rf /; echo "Now install MkLinux"

A/UX:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O4"

# Millions of Intel BSD's (many are really BSE's, with incredibly archaic
#			development tools and libs, although it's slowly getting better):
#			cc is gcc except when it isn't.  Most are still using a.out,
#			although some are slowly going to ELF, which we can autodetect by
#			checking whether the compiler defines __ELF__.  If the compiler
#			check doesn't work then [ `uname -r | cut -f 1 -d '.'` -ge 4 ]
#			(for FreeBSD) and -ge 2 (for OpenBSD) should usually work.
#
#			NetBSD for many years (up until around 1999-2000) used an
#			incredibly old version of as that didn't handle 486 opcodes (!!),
#			so the asm code was disabled by default.  In addition it used an
#			equally archaic version of gcc, requiring manual fiddling with
#			the compiler type and options.  If you're still using one of
#			these ancient versions, you'll have to change the entry below to
#			handle it.  In addition the rule is currently hardwired to assume
#			x86 due to lack of access to a non-x86 box, if you're building on
#			a different architecture you'll have to change the entry slightly
#			to detect x86 vs. whatever you're currently using, see the Linux
#			entry for an example.

BSD386:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3"
iBSD:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3"
BSD/OS:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3"
FreeBSD:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3 -pthread"
NetBSD:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3 -pthread"
OpenBSD:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3"

# Convex:

Convex:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O4"

# Cray Unicos: The Cray compiler complains about char * vs. unsigned char
#			   passed to functions, there's no way to disable this directly
#			   so the best that we can do is disable warnings:
#				cc-256 Function call argument or assignment has incompatible type
#				cc-265 Function call argument has incompatible type

CRAY:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -h nomessage=256:265 -O2"

# Cygwin: cc is gcc.

CYGWIN_NT-5.0:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3 -D__CYGWIN__ -I/usr/local/include"

CYGWIN_NT-5.1:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
		-fomit-frame-pointer -O3 -D__CYGWIN__ -I/usr/local/include"

# DGUX: cc is a modified gcc.

dgux:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -ansi -fomit-frame-pointer -O3"

# PHUX: A SYSVR2 layer with a SYSVR3 glaze on top of an adapted BSD 4.2
#		kernel.  Use cc, the exact incantation varies somewhat depending on
#		which version of PHUX you're running.  For 9.x you need to use
#		'-Aa -D_HPUX_SOURCE' to get the compiler into ANSI mode, in 10.x this
#		changed to just '-Ae', and after 10.30 -Ae was the default mode.
#		With PA-RISC 2 you should probably also define +DD64 to compile in
#		64-bit mode under PHUX 11.x, under even newer versions this becomes
#		+DA2.0w (note that building 64-bit versions of anything will probably
#		cause various build problems arising from the compiler and linker
#		because although the CPU may be 64 bit the software development tools
#		really, really want to give you 32-bit versions of everything and it
#		takes quite some cajoling to actually get them to spit out a 64-bit
#		result).  In addition the PHUX compilers don't recognise -On like the
#		rest of the universe but use +On instead so we adjust things based
#		on the compiler we're using.  In addition we only build the asm code
#		under 11 since it doesn't like 10.x and earlier systems.
#
#		Newer compilers can use +Oall to apply all optimisations (even the
#		dodgy ones).  Typically going from +O2 -> +O3 -> +O4 gives a ~10-15%
#		improvement at each step.  Finally, when making the shared lib you
#		can only use +O2, not +O3, because it gives the compiler the speed
#		wobbles.  In theory we could also use +ESlit to force const data
#		into a read-only segment, but this is defeated by a compiler bug
#		that doesn't initialise non-explicitly-initialised struct elements
#		to zero any more when this option is enabled (this is a double-bug
#		that violates two C rules because if there are insufficient
#		initialisers the remaining elements should be set to zero, and for
#		static objects they should be set to zero even if there are no
#		initialisers).
#
#		Note that the PHUX compilers (especially the earlier ones) are
#		horribly broken and will produce all sorts of of bogus warnings of
#		non-problems, eg:
#
#			/usr/ccs/bin/ld: (Warning) Quadrant change in relocatable
#							 expression in subspace $CODE$
#
#		(translation: Klingons off the starboard bow!).  The code contains
#		workarounds for non-errors (for example applying a cast to anything
#		magically turns it into an rvalue), but it's not worth fixing the
#		warnings for an OS as broken as this.  In addition most of the HP
#		compilers are incapable of handling whitespace before a preprocessor
#		directive, so you need to either (a) get a non-broken compiler or
#		(b) run each file through sed to strip the whitespace, something like:
#
#		#! /bin/csh -f
#		foreach file (*.h *.c)
#		  sed -e 's/  #/#/g' -e 's/	#/#/g' -e 's/	  #/#/g' $file > tmp
#		  mv tmp $file
#		end
#
#		Again, it isn't worth changing every single source file just to
#		accomodate this piece of compiler braindamage.
#
#		The asm bignum asm code is for PA-RISC 2.0, so we have to make sure
#		that we're building a PA-RISC 2.0 version if we use the asm code.
#		This can be detected with "getconf CPU_VERSION", if the result is >=
#		532 (equal to the symbolic define CPU_PA_RISC2_0) it's PA-RISC 2.0.
#		We need to explicitly check the architecture rather than the OS
#		since although PHUX 10.20 first supported PA-RISC 2.0, it wasn't
#		until PHUX 11.00 that the 64-bit capabilities were first supported
#		(previously it was treated as PA-RISC 1.x, 32-bit, or a 1.x/2.0
#		hybrid).  Because of the not-quite PA-RISC 2.0 support in PHUX 10.x,
#		we'd need to check the kernel with "file /stand/vmunix" for that,
#		which will report "ELF-64 executable object file - PA-RISC 2.0
#		(LP64)" for PA-RISC 2.0.
#
#		Even then, this may not necessarily work, depending on the phase of
#		the moon and a few other variables.  If testlib dumps core right at
#		the start (in the internal self-test), disable the use of the asm
#		code and rebuild.
#
#		In addition pa_risc2.s is written using the HP as syntax rather than
#		gas syntax, so we can only build it if we're using the PHUX native
#		development tools.
#
#		Finally, the default PHUX system ships with a non-C compiler (C++)
#		with most of the above bugs, but that can't process standard C code
#		either.  To detect this we feed it a C-compiler option and check for
#		a non-C-compiler error message, in this case +O3 which yields "The
#		+O3 option is available only with the C/ANSI C product; ignored".
#
#		The PHUX compiler bugs comment is really starting to give the SCO
#		one a run for its money.

HP-UX:
	@if [ `$(CC) +O3 ./tools/endian.c -o /dev/null 2>&1 | grep -c "ANSI C product"` = '1' ] ; then \
		echo "Warning: This system appears to be running the HP bundled C++ compiler as" ; \
		echo "         its cc.  You need to install a proper C compiler to build cryptlib." ; \
		echo "" ; \
		fi
	@rm -f a.out
	@if [ `uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'` -eq 11 ] ; then \
		if [ $(CC) = "gcc" ] ; then \
			if [ `getconf CPU_VERSION` -ge 532 ] ; then \
				make $(DEFINES) CFLAGS="$(CFLAGS) -O3 -mpa-risc-2-0 -D_REENTRANT" ; \
  			else \
				make $(DEFINES) CFLAGS="$(CFLAGS) -O3 -D_REENTRANT" ; \
  			fi ; \
		else \
			if [ `getconf CPU_VERSION` -ge 532 ] ; then \
				./tools/buildasm.sh $(AS) $(OBJPATH) ; \
				make $(DEFINES) CFLAGS="$(CFLAGS) +O3 +ESlit +DA2.0 +DS2.0 -Ae -D_REENTRANT" ; \
			else \
				make $(DEFINES) CFLAGS="$(CFLAGS) +O3 -D_REENTRANT" ; \
			fi ; \
		fi ; \
	elif [ `uname -r | sed 's/^[A-Z].//' | cut -f 1 -d '.'` -eq 10 ] ; then \
		if [ $(CC) = "gcc" ] ; then \
			make $(DEFINES) CFLAGS="$(CFLAGS) -O3" ; \
		else \
			make $(DEFINES) CFLAGS="$(CFLAGS) -Ae +O3" ; \
		fi ; \
	else \
		make $(DEFINES) CFLAGS="$(CFLAGS) -Aa -D_HPUX_SOURCE +O3" ; \
	fi

# Irix: Use cc.

IRIX:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O3"
IRIX64:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O3"

# ISC Unix: Use gcc.

ISC:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -mcpu=pentium"

# Linux: cc is gcc.

Linux:
	@if uname -m | grep "i[3,4,5,6]86" > /dev/null; then \
		./tools/buildasm.sh $(AS) $(OBJPATH) ; \
		make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
			-fomit-frame-pointer -O3 -D_REENTRANT" ; \
	else \
		make $(DEFINES) CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -D_REENTRANT" ; \
	fi

# Mac OS X: BSD variant.

Darwin:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -DUSE_ODBC -fomit-frame-pointer -O3" \
		LDFLAGS="-object -s"

# NCR MP-RAS: Use the NCR cc.  The "-DNCR_UST" is needed to enable threading
#			  (User-Space Threads).

UNIX_SV:
	@make $(DEFINES) ARMETHOD=rcs CFLAGS="$(CFLAGS) -D_MPRAS -DNCR_UST \
		-O2 -Xa -Hnocopyr -K xpg42 -K catchnull '-Hpragma=Offwarn(39)' \
		'-Hpragma=Offwarn(73)'"

# NeXT 3.0:

NeXT:
	@make $(DEFINES) LDFLAGS="-object -s"

# OSF 1: Use gcc and the asm version of the bn routines.  If you're using
#		 the OSF1 cc you need to use "-std1" to force ANSI compliance and
#		 change the optimization CFLAGS.

OSF1:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -D_REENTRANT"

# QNX: Older versions of QNX use braindamaged old DOS-style Watcom tools
#	   that can't handle Unix-style code (or behaviour).  To get around this
#	   we rewrite the asm command-line to make it more DOS-like, however the
#	   assembler can't handle either ELF or a.out formats either so we leave
#	   it as a user-specified option.

QNX:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O4"

QNX-asm:
	@- if grep "s -o" makefile > /dev/null ; then \
		sed s/"s -o "/"s -fo="/g makefile > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM -O4"

# SCO: Unlike the entire rest of the world, SCO doesn't use -On, although it
#	   does recognise -O3 to mean "turn off pass 3 optimization".  The SCO cc
#	   is in fact a mutant version of Microsoft C 6.0, so we use the usual
#	   MSC optimization options except for the unsafe ones.  -Olx is
#	   equivalent to -Oegilt.  Unless SCO rewrote half the compiler when
#	   no-one was looking, you won't be getting much optimization for your
#	   -O.
#
#	   Actually it turns out that the only thing you get with -Olx is
#	   compiler bugs, so we only use -O, and even with that you get internal
#	   compiler faults that it traps and forces a compiler restart on,
#	   presumably with optimisations disabled.
#
#	   SCO is basically too braindamaged to support any of the asm builds.
#	   as won't take input from stdin and dumps core on the crypto .S files,
#	   and cc/as barf on bni80386.s.  Even compiling the straight C code
#	   gives a whole slew of internal compiler errors/failed assertions.  If
#	   you have a setup that works (i.e.with GNU tools installed) then you
#	   can call buildasm.sh to use the asm routines.
#
#	   For another taste of the wonderful SCO compiler, take the trivial lex
#	   example from the dragon book, lex it, and compile it.  Either the
#	   compiler will core dump from a SIGSEGV or the resulting program will
#	   from a SIGILL, depending on what level of optimization you use (a
#	   compiler that'll produce illegal code as output is pretty impressive).
#
#	   In addition the SCO cc ignores the path for output files and dumps the
#	   whole mess in the same directory as the source files.  This means you
#	   need to set STATIC_OBJ_PATH = . in order for the library to be built,
#	   however the following rule does this for you by forwarding down the
#	   $(TARGET) define rather than $(DEFINES), which also includes the
#	   output path.
#
#	   If you're building the shared version after building the static one
#	   you need to manually remove all the object files before trying to
#	   build it.
#
#	   The SCO/UnixWare sockets libraries are extraordinarily buggy, make
#	   sure that you've got the latest patches installed if you plan to use
#	   cryptlib's secure session interface.  Note that some bugs reappear in
#	   later patches, so you should make sure that you really do have the
#	   very latest patch installed ("SCO - Where Quality is Job #9" -
#	   unofficial company motto following a SCO employee survey).
#
#	   In terms of straight compiling of code, UnixWare (SCO 7.x) is only
#	   marginally better.  as now finally accepts input from stdin if '-' is
#	   specified as a command-line arg, but it doesn't recognise 486
#	   instructions yet (they've only been with us for over a decade for
#	   crying out loud), even using the BSDI-format kludge doesn't quite
#	   work since as just terminates with an internal error.
#
#	   The compiler breaks when processing the aestab.c file, if you want to
#	   use the SCO cc to build cryptlib you'll have to do without AES (or
#	   use gcc, see below).
#
#	   UnixWare also finally supports threads, but it may not be possible to
#	   build cryptlib with threading support under older versions because of
#	   a compiler bug in which the preprocessor sprays random spaces around
#	   any code in which token-pasting is used.  Although having foo##->mutex
#	   turn into "certInfo -> mutex" is OK, foo##.mutex turns into
#	   "certInfo. mutex" which the compiler chokes on (the appearances of
#	   spaces in different places doesn't seem to follow any pattern, the
#	   quoted strings above are exactly as output by the preprocessor).
#
#	   To avoid this mess, you can build the code using the SCO-modified gcc
#	   which has been hacked to work with cc-produced libraries (the code
#	   below tries this by default, falling back to the SCO compiler only if
#	   it can't find gcc).
#
#	   Cool, the SCO comment is now longer than the comments for all the
#	   other Unix variants put together.

SCO:
	@if gcc -v > /dev/null 2>&1 ; then \
		./tools/buildasm.sh $(AS) $(OBJPATH) ; \
		make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
			-fomit-frame-pointer -O3 -D_REENTRANT"; \
	else \
		echo "Please read the entry for SCO in the makefile before continuing." ; \
		make $(TARGET) CFLAGS="$(CFLAGS) -O" ; \
	fi
UnixWare:
	@if gcc -v > /dev/null 2>&1 ; then \
		./tools/buildasm.sh $(AS) $(OBJPATH) ; \
		make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(CFLAGS) -DUSE_ASM \
			-fomit-frame-pointer -O3 -D_REENTRANT"; \
	else \
		echo "Please read the entry for UnixWare in the makefile before continuing." ; \
		make $(DEFINES) CFLAGS="$(CFLAGS) -O -Xa -Khost -Kthread" ; \
	fi

itgoaway:
	@echo "You poor bastard."

# Sun/Slowaris: An OS named after the 1972 Andrei Tarkovsky film about a space
#				station that drives people who work there mad.  Use gcc, but
#				fall back to the SUNSwspro compiler if necessary (in the c
#				checks below, the '-' is necessary because one of the checks
#				returns a nonzero status somewhere that causes make to bail
#				out, and the error suppression is necessary to avoid dozens of
#				bogus warnings about signed vs.unsigned chars).

SunOS:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@- if [ `uname -r | tr -d '[A-Z].' | cut -c 1` = '4' ] ; then \
		make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3" ; \
	else \
		if [ `/usr/ucb/cc | grep -c installed` = '1' ] ; then \
			make $(DEFINES) CC=$(CC) CFLAGS="$(CFLAGS) -fomit-frame-pointer \
				-O3 -D_REENTRANT" ; \
		else \
			make $(DEFINES) CFLAGS="$(CFLAGS) -erroff=E_ARG_INCOMPATIBLE_WITH_ARG \
				-xO3 -D_REENTRANT" ; \
		fi ; \
	fi

# SVR4: Better results can be obtained by upgrading your OS to 4.4 BSD.
#		A few SVR4 unames don't report the OS name properly (Olivetti Unix)
#		so it's necessary to specify the SVR4 target on the command line.

SVR4:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -O3"

# Ultrix: Use vcc or gcc.

ULTRIX:
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3"

# Amdahl UTS 4:

UTS4:
	@make $(DEFINES) CFLAGS="$(CFLAGS) -Xc -O4"

#****************************************************************************
#*																			*
#*								Other OS Targets							*
#*																			*
#****************************************************************************

# BeOS: By default we use the newer BeOS development environment, which uses
#		gcc.  Since BeOS doesn't use the default Unix environment, we use
#		XCFLAGS and insert __BEOS__ as the OS.
#
#		The older BeOS development environment can still be used with:
#
#	@make $(DEFINES) CC=mwcc AR="mwcc -xml -o" LD="mwcc -xms -f crypt.exp"

BeOS:
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/beos\.o/g makefile | sed s/unix\.c/beos\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	@if [ `uname -m` = 'BePC' ]; then \
		make asm_elf OBJPATH=$(OBJPATH) ; \
		make $(DEFINES) EXTRAOBJS="$(ASMOBJS)" CFLAGS="$(XCFLAGS) -DUSE_ASM \
			-D__BEOS__ -fomit-frame-pointer -O3 -D_REENTRANT" ; \
	else \
		make $(DEFINES) CFLAGS="$(CFLAGS) -U__UNIX__ -D__BEOS__ \
			-fomit-frame-pointer -O3 -D_REENTRANT" ; \
	fi

# EPOC: Cross-compilation requires custom code paths to build using the
#		Symbian SDK rather than the native compiler.  The following defines
#		are for Symbian OS 7.x as the SDK and ARM as the architecture.
#
# EPOC		= /usr/local/symbian/7.0
# CXX		= ${EPOC}/bin/arm-epoc-pe-g++
# CC		= ${EPOC}/bin/arm-epoc-pe-gcc
# AR		= ${EPOC}/bin/arm-epoc-pe-ar
# LD		= ${EPOC}/bin/arm-epoc-pe-ld
# CPP		= ${EPOC}/bin/arm-epoc-pe-cpp
# RANLIB	= ${EPOC}/bin/arm-epoc-pe-ranlib
# STRIP		= ${EPOC}/bin/arm-epoc-pe-strip
# INCS		= -I$(EPOC)/include/libc

EPOC:
	@make CFLAGS="$(XCFLAGS) -D__EPOC__" $(DEFINES)

# IBM MVS (a.k.a.OS/390, z/OS): File naming behaviour is controlled by the
#								DDNAME_IO define:
#
#	DDNAME_IO defined:
#		Use ddnames for all I/O.  User options will be saved in dynamically
#		allocated datasets userid.CRYPTLIB.filename.
#
#	DDNAME_IO not defined:
#		Use HFS for all I/O.  User options will be saved in directory
#		$HOME/.cryptlib.
#
#	Note: Tested on OS/390 2.10.

OS/390:
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/mvs\.o/g makefile | sed s/unix\.c/mvs\.c/g > makefile.tmp || exit 1 ; \
	fi
	@./tools/buildasm.sh $(AS) $(OBJPATH)
	@make $(DEFINES) OSOBJS="$(OBJPATH)mvsent.o" CFLAGS="$(XCFLAGS) -O2 \
		-W c,'langlvl(extended) csect rent roc ros targ(osv2r7) enum(4)' \
		-W c,'CONVLIT(ISO8859-1)' -DDDNAME_IO -D_OPEN_THREADS \
		-D_XOPEN_SOURCE_EXTENDED=1"

# Tandem NSK/OSS: Use c89.  There are two variants of the OS here, OSS
#				  (Posix-like layer over NSK) and NSK hosted on OSS (many
#				  of the Posix functions aren't available).  The following
#				  builds for the OSS target (the default), to build for
#				  NSK use "-Wsystype=guardian".  For optimisation there's
#				  only -O, which is equivalent to the Tandem-specific
#				  -Woptimize=2 setting.  We need to enable extensions with
#				  -Wextensions for the networking code or many of the
#				  networking header data types are NOP'ed out.
#
#				  The compiler is pretty picky, we turn off warnings for:
#
#					Nested comments (106)
#					Unreachable code (203, usually for failsafe defaults
#						after a case statement)
#					Unsigned char vs. char (232)
#					Char vs. unsigned char (252)
#					Int vs. static int functions (257, the STATIC_FN
#						issue)
#					Mixing enum and int (272)
#					Char vs. unsigned char (611),
#					Variable initialised but never used (770, mostly in
#						OpenSSL code)
#					Int vs. unsigned int (1506)

NONSTOP_KERNEL:
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/tandem\.o/g makefile | sed s/unix\.c/tandem\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	@make $(DEFINES) CC=c89 CFLAGS="$(CFLAGS) -O -Wextensions -Wnowarn=106,203,232,252,257,272,611,770,1506"

#****************************************************************************
#*																			*
#*							Cross-Compilation Targets						*
#*																			*
#****************************************************************************

# Generic entry for cross-compilation.  You need to provide at least the
# following:
#
#	-DCONFIG_DATA_LITTLEENDIAN/-DCONFIG_DATA_BIGENDIAN
#		Override endianness auto-detection.
#
#	-DOSVERSION=major_version
#		OS major version number.
#
#	$(OSNAME)
#		The target OS name, to select the appropriate compiler/link
#		options further down.
#
# For further options, see the cryptlib manual.
#
# Since we're cross-compiling here, we use $(XCFLAGS) and $(XDEFINES) instead
# if the usual $(CFLAGS) and $(DEFINES), which assume that the target is a
# Unix system.
#
# If you add a new entry here, you also need to update tools/osversion.sh to
# return the appropriate OS version for the system you're cross-compiling
# for.

target-X:
	@make directories
	make $(DEFINES) OSNAME=target-X CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_xxxENDIAN -DOSVERSION=major_version \
		-fomit-frame-pointer -O3 -D_REENTRANT"

# Specific cross-compilation entries.
#
# MIPS running Linux: Little-endian, 2.x kernel.  Note that we use $(CFLAGS)
# rather than $(XCFLAGS) since this is a Unix system, just not the same as
# the source one.

target-mips:
	@make directories
	make $(XDEFINES) OSNAME=Linux CFLAGS="$(CFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -DOSVERSION=2 \
		-fomit-frame-pointer -O3 -D_REENTRANT"

# Atmel ARM7 TDMI: Little-endian, no OS, maximum restrictions on resource
# usage since it's running on the bare metal.

target-atmel:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/atmel\.o/g makefile | sed s/unix\.c/atmel\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	make $(XDEFINES) OSNAME=Atmel CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -DCONFIG_NO_STDIO -DCONFIG_CONSERVE_MEMORY \
		-DCONFIG_NO_DYNALLOC -fomit-frame-pointer -O3"

# ucLinux on ARM: Little-endian.  Note that we use $(CFLAGS) rather than
# $(XCFLAGS) since this is a Unix system, just not the same as the source one.

target-uclinux:
	@make directories
	make $(XDEFINES) OSNAME=ucLinux CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -DCONFIG_CONSERVE_MEMORY -fomit-frame-pointer -O3"

# PalmOS on ARM: Little-endian.  The first target is for the Palm tools, the
# second for the PRC tools package.  The latter needs to have assorted extra
# defines that are automatically set by the Palm tools set manually.  The
# optimisation level for the Palm compiler is left at the default -O, which is
# equivalent to -O3.  -O4 and -O5 are somewhat flaky.
#
# The toolchains can require a bit of tweaking to get running due to problems
# with finding include directories.  The PRC tools using gcc expect to find
# standard ARM headers as a fallback from the PalmOS ones, using
# #include_next to pull in the next headers.  For a standard install this
# requires specifying the additional include file paths with
# "-idirafter /usr/lib/gcc-lib/arm-palmos/...".  The Palm tools under Cygwin
# are even more problematic, and may require manual instruction on where to
# find their include files for both the Palm and ANSI/ISO C standard headers.
#
# The PalmOS compiler sets an idiotic -wall by default, requiring that we
# manually turn off a pile of the more annoying warnings, although the worst
# one (used before initialised) can't be turned off.  For the warnings that
# we can turn off:
#
#	112 = unreachable code
#	187 = comparison of unsigned type for < 0
#	189 = enumerated type mixed with another type (== int)

palm-sld:		cryptlib.sld
	pslib -inDef cryptlib.sld -outObjStartup $(OBJPATH)cryptsld.o \
	-outObjStub palmcl.obj -outEntryNums palmcl.h

target-palmos:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/palmos\.o/g makefile | sed s/unix\.c/palmos\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	@make palm-sld
	make $(XDEFINES) OSNAME=PalmOS CC=pacc CFLAGS="$(XCFLAGS) \
		-I$(PALMSDK_PATH)/headers/ \
		-I$(PALMSDK_PATH)/headers/posix/ \
		-nologo -D__PALMOS_KERNEL__ -DBUILD_TYPE=BUILD_TYPE_RELEASE \
		-DCONFIG_DATA_LITTLEENDIAN -O -wd112 -wd187 -wd189"

target-palmos-prc:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/palmos\.o/g makefile | sed s/unix\.c/palmos\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	make $(XDEFINES) OSNAME=PalmOS-PRC CC=arm-palmos-gcc CFLAGS="$(XCFLAGS) \
		-idirafter /usr/lib/gcc-lib/arm-palmos/3.2.2/include/ \
		-D__PALMOS_KERNEL__ -D__PALMSOURCE__ -DBUILD_TYPE=BUILD_TYPE_RELEASE \
		-DCONFIG_DATA_LITTLEENDIAN -fomit-frame-pointer -O3"

# MinGW: Gnu Win32 SDK hosted under Cygwin or non-Windows OS.  This is
# effectively a cross-compile since although the host environment is Unix
# (or at least emulated Unix), the target is Win32.

target-mingw:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/win32\.o/g makefile | sed s/unix\.c/win32\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	@make asm_elf OBJPATH=$(OBJPATH)
	make $(XDEFINES) OSNAME=MinGW CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -DWIN32 -DUSE_ASM -fomit-frame-pointer -O3"

# Xilinx XMK: Gnu toolchain under Unix or Cygwin.  There are two possible
# compilers, gcc for MicroBlaze (Xilinx custom RISC core) or for PPC.  The
# MB gcc doesn't predefine any symbols allowing us to autoconfigure
# ourselves, so we manually define __mb__.  It may also be necessary to use
# the MicroBlaze-specific mb-ar instead of the standard ar.
#
# Note that the MB cores are highly reconfigurable and may have all sorts
# of capabilities enabled or disabled.  You'll need to edit the 'xl'
# options below based on your config.

target-xmk-mb:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/xmk\.o/g makefile | sed s/unix\.c/xmk\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	make $(XDEFINES) OSNAME=XMK CC=mb-gcc CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_BIGENDIAN -DCONFIG_CONSERVE_MEMORY -D__XMK__ \
		-D__mb__ -mno-xl-soft-mul -mxl-barrel-shift -mno-xl-soft-div \
		-fomit-frame-pointer -O2 -I../microblaze_0/include"

target-xmk-ppc:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/xmk\.o/g makefile | sed s/unix\.c/xmk\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	make $(XDEFINES) OSNAME=XMK CC=powerpc-eabi-gcc CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -D__XMK__ -fomit-frame-pointer -O3"

# VxWorks: VxWorks toolchain under Windows.

target-vxworks:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/vxworks\.o/g makefile | sed s/unix\.c/vxworks\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	make $(XDEFINES) OSNAME=VxWorks CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -D__VXWORKS__ -O3"

# Kadak AMX: Gnu toolchain under Unix or Cygwin or ARM cc for ARM CPUs.  The
# entry below is for the ARM toolchain.

target-amx:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/amx\.o/g makefile | sed s/unix\.c/amx\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	make $(XDEFINES) OSNAME=AMX CC=armcc CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -D__AMX__ -O2"

# eCOS: Gnu toolchain under Unix.  The entry below is for the ARM toolchain.

target-ecos:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/ecos\.o/g makefile | sed s/unix\.c/ecos\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	make $(XDEFINES) OSNAME=eCOS CC=armcc CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -D__ECOS__ -O2"

# uC/OS-II: Generic toolchain for various architectures, the entry below is
#			for x86..

target-ucos:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/ucos\.o/g makefile | sed s/unix\.c/ucos\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	make $(XDEFINES) OSNAME=UCOS CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -D__UCOS__ -O3"

# ChorusOS: Generic toolchain for various architectures, the entry below is
#			for x86..

target-chorus:
	@make directories
	@if grep "unix\.o" makefile > /dev/null ; then \
		sed s/unix\.o/chorus\.o/g makefile | sed s/unix\.c/chorus\.c/g > makefile.tmp || exit 1 ; \
		mv -f makefile.tmp makefile || exit 1 ; \
	fi
	make $(XDEFINES) OSNAME=CHORUS CFLAGS="$(XCFLAGS) \
		-DCONFIG_DATA_LITTLEENDIAN -D__CHORUS__ -O3"

#****************************************************************************
#*																			*
#*						Clean up after make has finished					*
#*																			*
#****************************************************************************

# The removal of the object file directories is silenced since the
# directories may not exist and we don't want unnecessary error messages
# arising from trying to remove them

clean:
	rm -f *.o core testlib stestlib endian $(LIBNAME) $(SLIBNAME)
	@rm -f $(STATIC_OBJ_PATH)*.o
	@if [ -d $(STATIC_OBJ_PATH) ] ; then rmdir $(STATIC_OBJ_DIR) ; fi
	@rm -f $(SHARED_OBJ_PATH)*.o
	@if [ -d $(SHARED_OBJ_DIR) ] ; then rmdir $(SHARED_OBJ_DIR) ; fi
	@if [ `uname -s` = 'CYGWIN_NT-5.0' ] ; then rm -f *.exe; fi
	@if [ `uname -s` = 'HP-UX' ] ; then rm -f lib$(PROJ).sl; fi
