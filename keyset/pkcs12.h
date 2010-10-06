/****************************************************************************
*																			*
*						PKCS #12 Definitions Header File					*
*						Copyright Peter Gutmann 1997-2009					*
*																			*
****************************************************************************/

#ifndef _PKCS12_DEFINED

#define _PKCS12_DEFINED


#if defined( USE_PKCS12 ) && defined( _MSC_VER )
  #pragma message( "  Building with PKCS #12 enabled." )
#endif /* USE_PKCS12 with VC++ */

/****************************************************************************
*																			*
*								PKCS #12 Constants							*
*																			*
****************************************************************************/

/* A PKCS #12 file can in theory contain multiple key and certificate 
   objects, however nothing seems to use this capability.  There are half 
   a dozen different interpretations as to how it's supposed to work, both 
   in terms of how to interpret the format and what to do with things like 
   MACing, which can only use a single key even if there are multiple 
   different encryption keys used for the data, and because the complete 
   abscence of key indexing information means that there's no easy way to 
   sort out which key is used for what.  The code is written to handle 
   multiple personalities like PKCS #15 and PGP, but is restricted to 
   using only a single personality */

#define MAX_PKCS12_OBJECTS		1

/* The minimum number of keying iterations to use when deriving a key wrap
   key from a password */

#define MIN_KEYING_ITERATIONS	1000

/* The minimum size of an object in a keyset, used for sanity-checking when
   reading a keyset */

#define MIN_OBJECT_SIZE			64

/* Parameters for PKCS #12's homebrew password-derivation mechanism.  The ID
   values function as diversifiers when generating the same keying material
   from a given password and in effect function as an extension of the salt */

#define KEYWRAP_ID_WRAPKEY		1
#define KEYWRAP_ID_IV			2
#define KEYWRAP_ID_MACKEY		4
#define KEYWRAP_SALTSIZE		8

/****************************************************************************
*																			*
*							PKCS #12 Types and Structures					*
*																			*
****************************************************************************/

/* The following structure contains the information for a private key or
   certificate object */

typedef struct {
	/* The overall object data and the location of the payload within it, 
	   usually in the form of encrypted data */
	BUFFER_OPT_FIXED( dataLen ) \
	const void *data;				/* Object data */
	int dataSize;
	int payloadOffset, payloadSize;	/* Payload within object data */

	/* Encryption information needed to process the payload */
	CRYPT_ALGO_TYPE cryptAlgo;		/* Encryption algorithm */
	int keySize;					/* Key size in bytes */
	BUFFER( CRYPT_MAX_HASHSIZE, saltSize ) \
	BYTE salt[ CRYPT_MAX_HASHSIZE + 8 ];
	int saltSize;					/* Password-derivation salt */
	int iterations;					/* Password-derivation iterations */
	} PKCS12_OBJECT_INFO;

/* The following structure contains the information for one personality, 
   which covers one or more of a private key and a certificate */

typedef struct {
	/* General information */
	int index;						/* Unique value for this personality */
	BUFFER( CRYPT_MAX_TEXTSIZE, labelLength ) \
	char label[ CRYPT_MAX_TEXTSIZE + 8 ];/* PKCS #12 object label */
	int labelLength;
	BUFFER( CRYPT_MAX_HASHSIZE, idLength ) \
	BYTE id[ CRYPT_MAX_HASHSIZE + 8 ];/* PKCS #12 object ID */
	int idLength;

	/* Key and certificate object information */
	PKCS12_OBJECT_INFO keyInfo, certInfo;

	/* Alongside the per-object security information, PKCS #12 files also 
	   have a MAC for the keyset as a whole.  This is supposedly optional 
	   but many apps will reject the keyset (or even crash) if it's not 
	   present.

	   Since the same key is used for both the whole-keyset MAC and the 
	   individual objects, we can really only have a single personality per 
	   keyset.  For now we deal with this by storing the MAC security 
	   information alongside the other object information */
	CRYPT_CONTEXT iMacContext;		/* MAC context */
	BUFFER( CRYPT_MAX_HASHSIZE, macSaltSize ) \
	BYTE macSalt[ CRYPT_MAX_HASHSIZE + 8 ];
	int macSaltSize;				/* Salt for MAC key */
	int macIterations;				/* Number of iters.to derive MAC key */
	BOOLEAN macInitialised;			/* Whether MAC context has been set up */
	} PKCS12_INFO;

/****************************************************************************
*																			*
*								PKCS #12 Functions							*
*																			*
****************************************************************************/

/* Prototypes for functions in pkcs12.c */

STDC_NONNULL_ARG( ( 1 ) ) \
void pkcs12freeObjectEntry( INOUT PKCS12_OBJECT_INFO *pkcs12objectInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void pkcs12freeEntry( INOUT PKCS12_INFO *pkcs12info );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int createPkcs12KeyWrapContext( INOUT PKCS12_OBJECT_INFO *pkcs12objectInfo,
								IN_HANDLE const CRYPT_USER cryptOwner,
								IN_BUFFER( passwordLength ) const char *password, 
								IN_LENGTH_NAME const int passwordLength,
								OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
								const BOOLEAN initParams );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int createPkcs12MacContext( INOUT PKCS12_INFO *pkcs12info,
							IN_HANDLE const CRYPT_USER cryptOwner,
							IN_BUFFER( passwordLength ) const char *password, 
							IN_LENGTH_NAME const int passwordLength,
							OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
							const BOOLEAN initParams );

/* Prototypes for functions in pkcs12_rd.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int readPkcs12Keyset( INOUT STREAM *stream, 
					  OUT_ARRAY( maxNoPkcs12objects ) PKCS12_INFO *pkcs12info, 
					  IN_LENGTH_SHORT const int maxNoPkcs12objects, 
					  IN_LENGTH const long endPos,
					  INOUT ERROR_INFO *errorInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initPKCS12get( INOUT KEYSET_INFO *keysetInfoPtr );

/* Prototypes for functions in pkcs12_wr.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initPKCS12set( INOUT KEYSET_INFO *keysetInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int pkcs12Flush( INOUT STREAM *stream, 
				 IN_ARRAY( noPkcs12objects ) const PKCS12_INFO *pkcs12info, 
				 IN_LENGTH_SHORT const int noPkcs12objects );

#endif /* _PKCS12_DEFINED */
