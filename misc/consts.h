/****************************************************************************
*																			*
*				cryptlib Data Size and Crypto-related Constants 			*
*						Copyright Peter Gutmann 1992-2007					*
*																			*
****************************************************************************/

#ifndef _CONSTS_DEFINED

#define _CONSTS_DEFINED

/* The maximum length that can be safely handled using an integer.  We don't
   quite allow the maximum possible length since most data/message formats
   impose some extra overhead themselves.
   
   In addition to the maximum-possible length we also define a shorter
   length defined as a generally sensible upper bound for values that 
   shouldn't require arbitrary-length data quantities */

#ifdef SYSTEM_16BIT
  #define MAX_INTLENGTH_DELTA	8192
#else
  #define MAX_INTLENGTH_DELTA	1048576
#endif /* 16- vs. 32/64-bit systems */
#define MAX_INTLENGTH			( INT_MAX - MAX_INTLENGTH_DELTA )
#define MAX_INTLENGTH_SHORT		16384

/* The size of a cryptlib key ID, an SHA-1 hash of the SubjectPublicKeyInfo,
   and the PGP key ID */

#define KEYID_SIZE				20
#define	PGP_KEYID_SIZE			8

/* The minimum and maximum private key data size.  This is used when 
   buffering the encrypted private key from a keyset during decryption and 
   is equal to the overall size of the total number of possible PKC 
   parameters in an encryption context, plus a little extra for encoding and 
   encryption */

#define MIN_PRIVATE_KEYSIZE		18	/* For DLP keys */
#define MAX_PRIVATE_KEYSIZE		( ( CRYPT_MAX_PKCSIZE * 8 ) + 256 )

/* The minimum and maximum working conventional key size in bits.  In order 
   to avoid problems with space inside PKC-encrypted blocks when MIN_PKCSIZE 
   is less than 1024 bits, we limit the total keysize to 256 bits, which is 
   adequate for all purposes - the limiting factor is AES-256.  
   Unfortunately when loading a default-length key into a context we can't 
   tell what the user is going to do with the generated key (for example 
   whether they'll export it using a very short public key) so we have to 
   take the approach of using a practical working key length that will work 
   even with a short public key.  This means that for Blowfish, RC2, RC4, 
   and RC5 the working keylength is shorter than strictly necessary 
   (actually for RC2 we have to limit the keysize to 128 bits for CMS/SMIME 
   compatibility) */

#define MIN_KEYSIZE				bitsToBytes( 56 )
#define MAX_WORKING_KEYSIZE		bitsToBytes( 256 )

/* The minimum public key size (c.f. CRYPT_MAX_PKCSIZE).  This is a bit less 
   than the actual size because keygen specifics can lead to keys that are 
   slightly shorter than the nominal size.  In addition we have to have a 
   special value for ECC keys, for which key sizes work differently that
   conventional PKCs */

#define MIN_PKCSIZE				( bitsToBytes( 1024 ) - 4 )
#define MIN_PKCSIZE_ECC			( bitsToBytes( 192 ) - 4 )

/* The size of the largest public-key wrapped value, corresponding to an
   ASN.1-encoded Elgamal-encrypted key */

#define MAX_PKCENCRYPTED_SIZE	( 16 + ( CRYPT_MAX_PKCSIZE * 2 ) )

/* The maximum public-key object size.  This is used to allocate temporary
   buffers when working with signatures and PKC-encrypted keys.  The size
   estimate is somewhat crude and involves a fair safety margin, it usually
   contains a single PKC object (signature or encrypted key) along with
   algorithm and key ID information */

#define MAX_PKC_OBJECTSIZE		( CRYPT_MAX_PKCSIZE * 2 )

/* The minimum size of an encoded signature or exported key object.  This is
   used by the pointer-check macros (for the OSes that support this) to
   check that the pointers to objects that are passed to functions point to
   the minimal amount of valid memory required for an object, and also to
   zero the buffer for the object to ensure that the caller gets invalid
   data if the function fails */

#define MIN_CRYPT_OBJECTSIZE	64

/* The minimum size of a certificate.  This is used by the pointer-check
   macros (for the OSes that support this) to check that the pointers being
   passed to these functions point to the minimal amount of valid memory
   required for an object */

#define MIN_CERTSIZE			256

/* The maximum size of an object attribute.  In theory this can be any size,
   but in practice we limit it to the following maximum to stop people
   creating things like certs containing MPEGs of themselves playing with
   their cat */

#define MAX_ATTRIBUTE_SIZE		1024

/* Some objects contain internal buffers used to process data whose size can
   be specified by the user, the following is the minimum size allowed for
   these buffers */

#define MIN_BUFFER_SIZE			8192

/* The minimum allowed length for object names (keysets, devices, users,
   etc).  In theory this could be a single character, but by default we
   make it 2 chars to make things more resistant to off-by-one errors in
   lengths, particularly since it applies to external objects outside
   cryptlib's control */

#ifdef UNICODE_CHARS
  #define MIN_NAME_LENGTH		( 2 * sizeof( wchar_t ) )
#else
  #define MIN_NAME_LENGTH		2
#endif /* Unicode vs. ASCII environments */

/* The minimum time value that's regarded as being a valid time (we have to 
   allow dates slightly before the current time because of things like 
   backdated cert revocations, as a rule of thumb we allow a date up to five 
   years in the past), an approximation of the current time (with the 
   constraint that it's not after the current date), and a somewhat more
   relaxed minimum time value used when reading stored data, which can
   contain keys that have been hanging around for years */

#define MIN_TIME_VALUE			( ( 2003 - 1970 ) * 365 * 86400L )
#define MIN_STORED_TIME_VALUE	( ( 1995 - 1970 ) * 365 * 86400L )
#define CURRENT_TIME_VALUE		( MIN_TIME_VALUE + ( 86400L * 365 * 5 ) )

/* The minimum and maximum network port numbers.  Note that we allow ports 
   down to 21 (= FTP) rather than the more obvious 22 (= SSH) provided by 
   cryptlib sessions because the URL-handling code is also used for general-
   purpose URI parsing for which the lowest-numbered one that we'd normally 
   run into is FTP.  We set the upper bound at the end of the non-ephemeral 
   port range, 49152-65535 is for ephemeral ports that are only valid for 
   the duration of a TCP session */

#define MIN_PORT_NUMBER		21
#define MAX_PORT_NUMBER		49151L

/* Some object types interact with exteral services that can return detailed
   error messages when problems occur, the following is the maximum length
   error string that we store.  Anything beyond this size is truncated */

#define MAX_ERRMSG_SIZE			512

/* The maximum number of iterations that we allow for an iterated key setup
   such as a hashed password.  This is used to prevent DoS attacks from data
   containing excessive iteration counts */

#define MAX_KEYSETUP_ITERATIONS	20000

/* All non-constant loops contain a guard to prevent excessive looping.  
   This is a generalisation of the programming practice that when looping on 
   externally-supplied data, we should perform a sanity check on loop 
   iterations to prevent DoS attacks due to malformed data.  The exception
   to the guard-condition requirement is pointer-chasing loops, for which 
   (if the pointers become corrupted so the loop doesn't terminate as it
   should) we'd segfault long before the guard would ever be reached.
   
   Apart from the data safety checking, this checking catches two things:

	1. Running off the end of a lookup table.
	
	2. A loop that uses a function as its terminating condition and doesn't
	   exit at the expected point:

		do {
			term = foo();
		   }
		while( !term );
	
		for( ptr = listHead; ptr != NULL; ptr = getNextValue( ptr ) );
   
   The following bounds on loop iterations apply:

	FAILSAFE_SMALL: Expect 1 but can have a few more.
	FAILSAFE_MED: Expect 10-20 but can have a few more.
	FAILSAFE_LARGE: Expect many, but not too many.

  In addition to these values there's a special value FAILSAFE_MAX which
  is equivalent to the ASN.1 (1...MAX) construct in setting an upper bound 
  on loop iterations without necessarily setting any specific limit:

	FAILSAFE_MAX: A value that's unlikely to be reached during normal 
				  operation, but that also won't result in an excessive 
				  stall if it's exceeded */

#define FAILSAFE_ITERATIONS_SMALL	10
#define FAILSAFE_ITERATIONS_MED		50
#define FAILSAFE_ITERATIONS_LARGE	1000
#ifdef SYSTEM_16BIT
  #define FAILSAFE_ITERATIONS_MAX	10000
#else
  #define FAILSAFE_ITERATIONS_MAX	100000
#endif /* 16-bit vs 32/64-bit systems */

/* Pseudo-constants used for array bounds-checking.  These provide a more
   precise limit than the FAILSAFE_ITERATIONS_xxx values above */

#define FAILSAFE_ARRAYSIZE( array, elementType ) \
		( sizeof( array ) / sizeof( elementType ) )

/* The minimum and maximum size of various Internet-related values, used for
   range checking */

#define MIN_DNS_SIZE			4			/* x.com */
#define MAX_DNS_SIZE			255			/* Max hostname size */
#define MIN_RFC822_SIZE			7			/* x@yy.zz */
#define MAX_RFC822_SIZE			255
#define MIN_URL_SIZE			12			/* http://x.com */
#define MAX_URL_SIZE			MAX_DNS_SIZE

/* The HMAC input and output padding values.  These are defined here rather
   than in context.h because they're needed by some routines that perform
   HMAC operations using raw SHA-1 contexts, since some devices provide SHA-1
   but not HMAC-SHA1 so we have to build it ourselves where it's needed for
   things like key hashing */

#define HMAC_IPAD				0x36
#define HMAC_OPAD				0x5C

/* Generic error return code/invalid value code */

#define CRYPT_ERROR				-1

/* Sometimes compilers get confused about whether a variable has been 
   initialised or not and report a used-before-initialised error when there
   isn't one.  This happens most frequently when the variable is initialised
   as part of a conditional expression where the developer knows the control
   flow will result in an initialisation but the compiler doesn't.  To get
   around this we perform a dummy initialisation of the variable with a 
   symbolic value to get rid of the false positive */

#define DUMMY_INIT				0
#define DUMMY_INIT_PTR			NULL

/* A special return code to indicate that everything went OK but there's
   some special action to perform.  This is generally used when a lower-level
   routine wants to return a CRYPT_OK with some condition attached, typically
   that the calling routine not update state information since it's already
   been done by the returning routine or because the returning routine has
   more work to do on a later call */

#define OK_SPECIAL				-4321

/* When parameters get passed in messages, their mapping to parameters passed
   to the calling function gets lost.  The following error codes are used to
   denote errors in message parameters that are mapped to function parameter
   error codes by the caller.  For a message call:

	krnlSendMessage( object, {args}, MESSAGE_TYPE, value );

   we have the following possible error codes */

#define CRYPT_ARGERROR_OBJECT	-1000		/* Error in object being sent msg.*/
#define CRYPT_ARGERROR_VALUE	-1001		/* Error in message value */
#define CRYPT_ARGERROR_STR1		-1002		/* Error in first string arg */
#define CRYPT_ARGERROR_STR2		-1003		/* Error in second string arg */
#define CRYPT_ARGERROR_NUM1		-1004		/* Error in first numeric arg */
#define CRYPT_ARGERROR_NUM2		-1005		/* Error in second numeric arg */

#define cryptArgError( status )	\
		( ( status ) >= CRYPT_ARGERROR_NUM2 && ( status ) <= CRYPT_ARGERROR_OBJECT )
#define cryptStandardError( status ) \
		( ( status ) >= CRYPT_ENVELOPE_RESOURCE && ( status ) <= CRYPT_OK )

/* The data formats for reading/writing public keys */

typedef enum {
	KEYFORMAT_NONE,		/* No key format */
	KEYFORMAT_CERT,		/* X.509 SubjectPublicKeyInfo */
/*	KEYFORMAT_PUBLIC,	// PKCS #15 public key - currently unused */
	KEYFORMAT_SSH,		/* SSHv2 public key */
	KEYFORMAT_SSH1,		/* SSHv1 public key */
	KEYFORMAT_SSL,		/* SSL public key */
	KEYFORMAT_PGP,		/* PGP public key */
	KEYFORMAT_PRIVATE,	/* Private key */
	KEYFORMAT_PRIVATE_OLD,	/* Older format for backwards-compatibility */
	KEYFORMAT_LAST		/* Last possible key format type */
	} KEYFORMAT_TYPE;

/* The different types of actions that can be signalled to the management
   function for each object class.  This instructs the management function
   to initialise or shut down any object-class-specific information that it
   may maintain */

typedef enum {
	MANAGEMENT_ACTION_NONE,				/* No management action */
	MANAGEMENT_ACTION_PRE_INIT,			/* Pre-initialisation */
	MANAGEMENT_ACTION_INIT,				/* Initialisation */
	MANAGEMENT_ACTION_PRE_SHUTDOWN,		/* Pre-shutdown */
	MANAGEMENT_ACTION_SHUTDOWN,			/* Shutdown */
	MANAGEMENT_ACTION_LAST				/* Last possible management action */
	} MANAGEMENT_ACTION_TYPE;

#endif /* _CONSTS_DEFINED */
