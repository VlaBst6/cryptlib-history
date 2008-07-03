/****************************************************************************
*																			*
*						cryptlib Internal API Header File 					*
*						Copyright Peter Gutmann 1992-2007					*
*																			*
****************************************************************************/

#ifndef _INTAPI_DEFINED

#define _INTAPI_DEFINED

/* Internal forms of various external functions.  These work with internal
   resources that are marked as being inaccessible to the corresponding
   external functions, and don't perform all the checking that their
   external equivalents perform, since the parameters have already been
   checked by cryptlib */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int iCryptCreateSignature( OUT_BUFFER_OPT( signatureMaxLength, *signatureLength ) \
							void *signature, 
						   IN_LENGTH const int signatureMaxLength,
						   OUT_LENGTH_Z int *signatureLength,
						   IN_ENUM( CRYPT_FORMAT ) \
							const CRYPT_FORMAT_TYPE formatType,
						   IN_HANDLE const CRYPT_CONTEXT iSignContext,
						   IN_HANDLE const CRYPT_CONTEXT iHashContext,
						   IN_HANDLE_OPT const CRYPT_CERTIFICATE iExtraData,
						   IN_HANDLE_OPT const CRYPT_SESSION iTspSession );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int iCryptCheckSignature( IN_BUFFER( signatureLength ) const void *signature, 
						  IN_LENGTH_SHORT const int signatureLength,
						  IN_ENUM( CRYPT_FORMAT ) \
							const CRYPT_FORMAT_TYPE formatType,
						  IN_HANDLE const CRYPT_HANDLE iSigCheckKey,
						  IN_HANDLE const CRYPT_CONTEXT iHashContext,
						  IN_HANDLE const CRYPT_CONTEXT iHash2Context,
						  OUT_OPT_HANDLE_OPT CRYPT_HANDLE *extraData );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int iCryptImportKey( IN_BUFFER( encryptedKeyLength ) const void *encryptedKey, 
					 IN_LENGTH_SHORT const int encryptedKeyLength,
					 IN_ENUM( CRYPT_FORMAT ) \
						const CRYPT_FORMAT_TYPE formatType,
					 IN_HANDLE const CRYPT_CONTEXT iImportKey,
					 IN_HANDLE_OPT const CRYPT_CONTEXT iSessionKeyContext,
					 OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iReturnedContext );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
int iCryptExportKey( OUT_BUFFER_OPT( encryptedKeyMaxLength, *encryptedKeyLength ) \
						void *encryptedKey, 
					 IN_LENGTH_Z const int encryptedKeyMaxLength,
					 OUT_LENGTH_Z int *encryptedKeyLength,
					 IN_ENUM( CRYPT_FORMAT ) \
						const CRYPT_FORMAT_TYPE formatType,
					 IN_HANDLE_OPT const CRYPT_CONTEXT iSessionKeyContext,
					 IN_HANDLE const CRYPT_CONTEXT iExportKey );

/* Copy a string attribute to external storage, with various range checks
   to follow the cryptlib external API semantics.  There are two variants
   of this function depending on whether the result parameters are passed
   in as discrete values or packed into a MESSAGE_DATA struct */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int attributeCopy( INOUT MESSAGE_DATA *msgData, 
				   IN_BUFFER( attributeLength ) const void *attribute, 
				   IN_LENGTH_SHORT_Z const int attributeLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 4 ) ) \
int attributeCopyParams( OUT_BUFFER_OPT( destMaxLength, *destLength ) void *dest, 
						 IN_LENGTH_SHORT_Z const int destMaxLength, 
						 OUT_LENGTH_SHORT_Z int *destLength, 
						 IN_BUFFER( sourceLength ) const void *source, 
						 IN_LENGTH_SHORT_Z const int sourceLength );

/* Check whether a password is valid or not.  Currently this just checks that
   it contains at least one character, but stronger checking can be
   substituted if required */

#ifdef UNICODE_CHARS
  #define isBadPassword( password ) \
		  ( !isReadPtr( password, sizeof( wchar_t ) ) || \
		    ( wcslen( password ) < 1 ) )
#else
  #define isBadPassword( password ) \
		  ( !isReadPtr( password, 1 ) || \
		    ( strlen( password ) < 1 ) )
#endif /* Unicode vs. ASCII environments */

/* Check whether a given algorithm is available for use.  This is performed
   frequently enough that we have a special krnlSendMessage() wrapper
   function for it rather than having to explicitly query the system
   object */

CHECK_RETVAL_BOOL \
BOOLEAN algoAvailable( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo );

/* For a given algorithm pair, check whether the first is stronger than the
   second */

CHECK_RETVAL_BOOL \
BOOLEAN isStrongerHash( IN_ALGO const CRYPT_ALGO_TYPE algorithm1,
						IN_ALGO const CRYPT_ALGO_TYPE algorithm2 );

/* Check that a string has at least a minimal amount of entropy.  This is
   used as a sanity-check on (supposedly) random keys before we load them */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkEntropy( IN_BUFFER( dataLength ) const BYTE *data, 
					  IN_LENGTH_SHORT_MIN( MIN_KEYSIZE ) const int dataLength );

/* Map one value to another, used to map values from one representation 
   (e.g. PGP algorithms or HMAC algorithms) to another (cryptlib algorithms
   or the underlying hash used for the HMAC algorithm) */

typedef struct {
	int source, destination;
	} MAP_TABLE;

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int mapValue( IN_INT_SHORT_Z const int srcValue,
			  OUT_INT_SHORT_Z int *destValue,
			  IN_ARRAY( mapTblSize ) const MAP_TABLE *mapTbl,
			  IN_LENGTH_SHORT const int mapTblSize );

/* Read a line of text from a stream.  The caller passes in a character-read
   function callback that returns the next character from a supplied input
   stream, and readTextLine() uses it to fetch the next line of input up to
   an EOL.  The localError flag is set when the returned error code was
   generated by readTextLine() itself, rather than being passed up from the
   character-read function.  This allows the caller to report the errors
   differently, for example a data-formatting error vs. a network I/O error.
   
   It would be nice if we could declare READCHARFUNCTION as taking a 
   STREAM * but this header gets included long before the stream header does
   so the STREAM structure isn't visible at this point */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
typedef int ( *READCHARFUNCTION )( INOUT void *streamPtr );

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readTextLine( READCHARFUNCTION readCharFunction, 
				  INOUT void *streamPtr,
				  OUT_BUFFER( lineBufferMaxLen, lineBufferSize ) char *lineBuffer, 
				  IN_LENGTH_SHORT_MIN( 10 ) const int lineBufferMaxLen, 
				  OUT_LENGTH_SHORT_Z int *lineBufferSize, 
				  OUT_OPT_BOOL BOOLEAN *localError );

/* Get OS-specific values */

#if defined( __WIN32__ ) || defined( __WINCE__ )
typedef enum { 
	SYSVAR_NONE,			/* No system variable */
	SYSVAR_OSVERSION,		/* OS version number */
	SYSVAR_ISWIN95,			/* Whether code base is Win95 or WinNT */
	SYSVAR_HWCAP,			/* Hardware crypto capabilities */
	SYSVAR_PAGESIZE,		/* System page size */
	SYSVAR_LAST				/* Last valid system variable type */
	} SYSVAR_TYPE;
#elif defined( __UNIX__ )
typedef enum { 
	SYSVAR_NONE,			/* No system variable */
	SYSVAR_HWCAP,			/* Hardware crypto capabilities */
	SYSVAR_PAGESIZE,		/* System page size */
	SYSVAR_LAST				/* Last valid system variable type */
	} SYSVAR_TYPE;
#else
typedef enum { SYSVAR_NONE, SYSVAR_LAST } SYSVAR_TYPE;
#endif /* OS-specific system variable types */

CHECK_RETVAL \
int initSysVars( void );
CHECK_RETVAL \
int getSysVar( const SYSVAR_TYPE type );

/* Flags for SYSVAR_HWCAP capabilities */

#define HWCAP_FLAG_NONE		0x00	/* No special HW capabilities */
#define HWCAP_FLAG_RDTSC	0x01	/* x86 RDTSC instruction support */
#define HWCAP_FLAG_XSTORE	0x02	/* VIA XSTORE instruction support */
#define HWCAP_FLAG_XCRYPT	0x04	/* VIA XCRYPT instruction support */
#define HWCAP_FLAG_XSHA		0x08	/* VIA XSHA instruction support */
#define HWCAP_FLAG_MONTMUL	0x10	/* VIA bignum instruction support */
#define HWCAP_FLAG_TRNG		0x20	/* Amd Geode LX TRNG MSR support */

/* Windows NT/2000/XP/Vista support ACL-based access control mechanisms for 
   system objects, so when we create objects such as files and threads we 
   give them an ACL that allows only the creator access.  The following 
   functions return the security info needed when creating objects */

#ifdef __WINDOWS__
  #ifdef __WIN32__
	CHECK_RETVAL_PTR \
	void *initACLInfo( const int access );
	STDC_NONNULL_ARG( ( 1 ) ) \
	void *getACLInfo( void *securityInfoPtr );
	STDC_NONNULL_ARG( ( 1 ) ) \
	void freeACLInfo( void *securityInfoPtr );
  #else
	#define initACLInfo( x )	NULL
	#define getACLInfo( x )		NULL
	#define freeACLInfo( x )
  #endif /* __WIN32__ */
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*								String Functions							*
*																			*
****************************************************************************/

/* Compare two strings in a case-insensitive manner for those systems that
   don't have this function */

#if defined( __UNIX__ ) && !( defined( __CYGWIN__ ) )
  #if defined( __TANDEM_NSK__ ) || defined( __TANDEM_OSS__ )
	#include <strings.h>
  #endif /* Tandem */
  #define strnicmp	strncasecmp
  #define stricmp	strcasecmp
#elif defined( __WINCE__ )
  #define strnicmp	_strnicmp
  #define stricmp	_stricmp
#elif defined( _MSC_VER ) && ( _MSC_VER >= 1300 )
  /* VC++ 8 and up warn about these being deprecated Posix functions and
     require the ANSI/ISO conformant _strXcmp */
  #define strnicmp	_strnicmp
  #define stricmp	_stricmp
#elif defined __PALMOS__
  /* PalmOS has strcasecmp()/strncasecmp() but these aren't i18n-aware so we
     have to use a system function instead */
  #include <StringMgr.h>

  #define strnicmp	StrNCaselessCompare
  #define stricmp	StrCaselessCompare
#elif defined( __xxxOS___ )
  int strnicmp( const char *src, const char *dest, const int length );
  int stricmp( const char *src, const char *dest );
#endif /* OS-specific case-insensitive string compares */

/* Sanitise a string before passing it back to the user.  This is used to
   clear potential problem characters (for example control characters)
   from strings passed back from untrusted sources.  The function returns a 
   pointer to the string to allow it to be used in the form 
   printf( "..%s..", sanitiseString( string, strLen ) ).  In addition it
   formats the data to fit a fixed-length buffer.  If the string is longer 
   than the indicated buffer size it appends a '[...]' at the end of the 
   buffer to indicate that further data was truncated */
					
STDC_NONNULL_ARG( ( 1 ) ) \
char *sanitiseString( INOUT_BUFFER_FIXED( strMaxLen ) BYTE *string, 
					  IN_LENGTH_SHORT const int strMaxLen, 
					  IN_LENGTH_SHORT const int strLen );

/* Perform various string-processing operations */

CHECK_RETVAL_STRINGOP( strLen ) STDC_NONNULL_ARG( ( 1 ) ) \
int strFindCh( IN_BUFFER( strLen ) const char *str, 
			   IN_LENGTH_SHORT const int strLen, 
			   IN_CHAR const int findCh );
CHECK_RETVAL_STRINGOP( strLen ) STDC_NONNULL_ARG( ( 1, 3 ) ) \
int strFindStr( IN_BUFFER( strLen ) const char *str, 
				IN_LENGTH_SHORT const int strLen, 
				IN_BUFFER( findStrLen ) const char *findStr, 
				IN_LENGTH_SHORT const int findStrLen );
CHECK_RETVAL_STRINGOP( strLen ) STDC_NONNULL_ARG( ( 1 ) ) \
int strSkipWhitespace( IN_BUFFER( strLen ) const char *str, 
					   IN_LENGTH_SHORT const int strLen );
CHECK_RETVAL_STRINGOP( strLen ) STDC_NONNULL_ARG( ( 1 ) ) \
int strSkipNonWhitespace( IN_BUFFER( strLen ) const char *str, 
						  IN_LENGTH_SHORT const int strLen );
CHECK_RETVAL_STRINGOP( strLen ) STDC_NONNULL_ARG( ( 1, 2 ) ) \
int strStripWhitespace( OUT_PTR char **newStringPtr, 
						IN_BUFFER( strLen ) const char *string, 
						IN_LENGTH_SHORT const int strLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int strExtract( OUT_PTR char **newStringPtr, 
				IN_BUFFER( srcLen ) const char *string, 
				IN_LENGTH_SHORT const int startOffset,
				IN_LENGTH_SHORT const int strLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int strGetNumeric( IN_BUFFER( strLen ) const char *str, 
				   IN_LENGTH_SHORT const int strLen, 
				   OUT_INT_Z int *numericValue, 
				   IN_RANGE( 0, 100 ) const int minValue, 
				   IN_RANGE( minValue, MAX_INTLENGTH ) const int maxValue );

/****************************************************************************
*																			*
*							Error-handling Functions						*
*																			*
****************************************************************************/

/* Handle internal errors.  These follow a fixed pattern of "throw an 
   exception, return an internal-error code" (with a few exceptions for
   functions that return a pointer or void).  There's also a 
   retExt_IntError() define in int_api.h for handling extended error 
   returns */

#define INTERNAL_ERROR	0	/* Symbolic define for assertion failure */
#define retIntError() \
		{ \
		assert( INTERNAL_ERROR ); \
		return( CRYPT_ERROR_INTERNAL ); \
		}
#define retIntError_Null() \
		{ \
		assert( INTERNAL_ERROR ); \
		return( NULL ); \
		}
#define retIntError_Boolean() \
		{ \
		assert( INTERNAL_ERROR ); \
		return( FALSE ); \
		}
#define retIntError_Void() \
		{ \
		assert( INTERNAL_ERROR ); \
		return; \
		}
#define retIntError_Ext( value ) \
		{ \
		assert( INTERNAL_ERROR ); \
		return( value ); \
		}
#define retIntError_Stream( stream ) \
		{ \
		assert( INTERNAL_ERROR ); \
		return( sSetError( stream, CRYPT_ERROR_INTERNAL ) ); \
		}

/* Symobolic defines to handle design-by-contract predicates */

#define REQUIRES( x )	if( !( x ) ) retIntError()
#define REQUIRES_N( x )	if( !( x ) ) retIntError_Null()
#define REQUIRES_B( x )	if( !( x ) ) retIntError_Boolean()
#define REQUIRES_V( x )	if( !( x ) ) retIntError_Void()
#define REQUIRES_EXT( x, y )	if( !( x ) ) retIntError_Ext( y )
#define REQUIRES_S( x )	if( !( x ) ) retIntError_Stream( stream )

#define ENSURES( x )	if( !( x ) ) retIntError()
#define ENSURES_N( x )	if( !( x ) ) retIntError_Null()
#define ENSURES_B( x )	if( !( x ) ) retIntError_Boolean()
#define ENSURES_V( x )	if( !( x ) ) retIntError_Void()
#define ENSURES_EXT( x, y )	if( !( x ) ) retIntError_Ext( y )
#define ENSURES_S( x )	if( !( x ) ) retIntError_Stream( stream )

/* A struct to store extended error information.  This provides error info
   above and beyond that provided by cryptlib error codes */

typedef struct {
	int errorCode;					/* Low-level error code */
	BUFFER( MAX_ERRMSG_SIZE, errorStringLength ) \
	char errorString[ MAX_ERRMSG_SIZE + 8 ];
	int errorStringLength;			/* Error message */
	} ERROR_INFO;

/* Prototypes for various extended error-handling functions.  retExt() 
   returns after setting extended error information for the object.  
   
   In addition to the standard retExt() we also have several extended-form 
   versions of the function that take additional error info parameters:

	retExtArgFn() is identical to ertExtFn() but passes through 
		CRYPT_ARGERROR_xxx values, which are normally only present as leaked
		status codes from lower-level calls (and even then they should only
		ever occur in 'can't-occur' error situations).

	retExtObj() takes a handle to an object that may provide additional 
		error information, used when (for example) an operation references 
		a keyset, where the keyset also contains extended error information.

	retExtErr() takes a pointer to existing error info, used when (for
		example) a lower-level function has provided very low-level error 
		information but the higher-level function that calls it needs to 
		provide its own more general error information on top of it.  In
		theory we could implement simply by mapping it to retExtStr(), but
		because of the way it's implemented as a (pseudo-)vararg macro this
		isn't possible.

	retExtStr() takes an additional error string pointer and is used in the
		same way as retExtErr() */

STDC_NONNULL_ARG( ( 1 ) ) \
void clearErrorString( INOUT ERROR_INFO *errorInfoPtr );
STDC_NONNULL_ARG( ( 1, 2 ) ) \
void setErrorString( INOUT ERROR_INFO *errorInfoPtr, 
					 IN_BUFFER( stringLength ) const char *string, 
					 IN_LENGTH_ERRORMESSAGE  const int stringLength );
STDC_NONNULL_ARG( ( 1, 2 ) ) \
void copyErrorInfo( INOUT ERROR_INFO *destErrorInfoPtr, 
					const ERROR_INFO *srcErrorInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) STDC_PRINTF_FN( 3, 4 ) \
int retExtFn( IN_ERROR const int status, 
			  INOUT ERROR_INFO *errorInfoPtr, 
			  FORMAT_STRING const char *format, ... );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) STDC_PRINTF_FN( 3, 4 ) \
int retExtArgFn( IN_ERROR const int status, 
				 INOUT ERROR_INFO *errorInfoPtr, 
				 FORMAT_STRING const char *format, ... );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 4 ) ) STDC_PRINTF_FN( 4, 5 ) \
int retExtObjFn( IN_ERROR const int status, 
				 INOUT ERROR_INFO *errorInfoPtr, 
				 IN_HANDLE const CRYPT_HANDLE extErrorObject, 
				 FORMAT_STRING const char *format, ... );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 5 ) ) STDC_PRINTF_FN( 5, 6 ) \
int retExtStrFn( IN_ERROR const int status, 
				 INOUT ERROR_INFO *errorInfoPtr, 
				 IN_BUFFER( extErrorStringLength ) const char *extErrorString, 
				 IN_LENGTH_ERRORMESSAGE const int extErrorStringLength,
				 FORMAT_STRING const char *format, ... );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 4 ) ) STDC_PRINTF_FN( 4, 5 ) \
int retExtErrFn( IN_ERROR const int status, 
				 INOUT ERROR_INFO *errorInfoPtr, 
				 const ERROR_INFO *existingErrorInfoPtr, 
				 FORMAT_STRING const char *format, ... );

#ifdef USE_ERRMSGS
  #define retExt( status, extStatus )		return retExtFn extStatus
  #define retExtArg( status, extStatus )	return retExtArgFn extStatus
  #define retExtObj( status, extStatus )	return retExtObjFn extStatus
  #define retExtErr( status, extStatus )	return retExtErrFn extStatus 
  #define retExtStr( status, extStatus )	return retExtStrFn extStatus 
  #define retExt_IntError( status, extStatus ) \
		{ \
		assert( INTERNAL_ERROR ); \
		return retExtFn extStatus; \
		}
#else
  /* We're not using extended error information, just return the basic 
     status code */
  #define retExt( status, extStatus )		return status
  #define retExtArg( status, extStatus )	return status
  #define retExtObj( status, extStatus )	return status
  #define retExtErr( status, extStatus )	return status
  #define retExtStr( status, extStatus )	return status
  #define retExt_IntError( status, extStatus ) \
		{ \
		assert( INTERNAL_ERROR ); \
		return( status ); \
		}
#endif /* USE_ERRMSGS */

/* Since this function works for all object types, we have to extract the
   error info pointer from the object-specific data.  The following defines
   do this for each object type */

#define ENVELOPE_ERRINFO	&envelopeInfoPtr->errorInfo
#define KEYSET_ERRINFO		&keysetInfoPtr->errorInfo
#define SESSION_ERRINFO		&sessionInfoPtr->errorInfo
#define STREAM_ERRINFO		stream->errorInfo
#define NETSTREAM_ERRINFO	&netStream->errorInfo

/****************************************************************************
*																			*
*							Data Encode/Decode Functions					*
*																			*
****************************************************************************/

/* Special-case certificate functions.  The indirect-import function works
   somewhat like the import cert messages, but reads certs by sending
   get_next_cert messages to the message source and provides extended control
   over the format of the imported object.  The public-key read function
   converts an X.509 SubjectPublicKeyInfo record into a context.  The first
   parameter for this function is actually a STREAM *, but we can't use this
   here since STREAM * hasn't been defined yet.

   Neither of these are strictly speaking certificate functions, but the
   best (meaning least inappropriate) place to put them is with the cert-
   management code */

CHECK_RETVAL \
int iCryptImportCertIndirect( OUT CRYPT_CERTIFICATE *iCertificate,
							  const CRYPT_HANDLE iCertSource,
							  const CRYPT_KEYID_TYPE keyIDtype,
							  IN_BUFFER( keyIDlength ) const void *keyID, 
							  const int keyIDlength,
							  const int options ) \
							  STDC_NONNULL_ARG( ( 1, 4 ) );
CHECK_RETVAL \
int iCryptReadSubjectPublicKey( INOUT void *streamPtr, 
								OUT CRYPT_CONTEXT *iCryptContext,
								const BOOLEAN deferredLoad ) \
								STDC_NONNULL_ARG( ( 1, 2 ) );

/* Get information on encoded object data.  The first parameter for this
   function is actually a STREAM *, but we can't use this here since
   STREAM * hasn't been defined yet */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int queryAsn1Object( INOUT void *streamPtr, OUT QUERY_INFO *queryInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int queryPgpObject( INOUT void *streamPtr, OUT QUERY_INFO *queryInfo );

/* Export/import data to/from a stream without the overhead of going via a
   dynbuf.  The first parameter for these functions is actually a STREAM *,
   but we can't use this here since STREAM * hasn't been defined yet */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int exportAttributeToStream( INOUT void *streamPtr, 
							 IN_HANDLE const CRYPT_HANDLE cryptHandle,
							 IN_ATTRIBUTE \
								const CRYPT_ATTRIBUTE_TYPE attributeType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int exportVarsizeAttributeToStream( INOUT void *streamPtr,
									IN_HANDLE const CRYPT_HANDLE cryptHandle,
									IN_LENGTH_FIXED( CRYPT_IATTRIBUTE_RANDOM_NONCE ) \
									const CRYPT_ATTRIBUTE_TYPE attributeType,
									IN_RANGE( 8, 1024 ) \
										const int attributeDataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int exportCertToStream( INOUT void *streamPtr,
						IN_HANDLE const CRYPT_CERTIFICATE cryptCertificate,
						IN_ENUM( CRYPT_CERTFORMAT ) \
							const CRYPT_CERTFORMAT_TYPE certFormatType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int importCertFromStream( INOUT void *streamPtr,
						  OUT_HANDLE_OPT CRYPT_CERTIFICATE *cryptCertificate,
						  IN_ENUM( CRYPT_CERTTYPE ) \
							const CRYPT_CERTTYPE_TYPE certType, 
						  IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
							const int certDataLength );

/* base64/SMIME-en/decode routines */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int base64checkHeader( IN_BUFFER( dataLength ) const char *data, 
					   IN_LENGTH const int dataLength,
					   OUT_ENUM_OPT( CRYPT_CERTFORMAT ) \
					   CRYPT_CERTFORMAT_TYPE *format,
					   OUT_LENGTH_Z int *startPos );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int base64encodeLen( IN_LENGTH const int dataLength,
					 OUT_LENGTH_Z int *encodedLength,
					 IN_ENUM_OPT( CRYPT_CERTTYPE ) \
						const CRYPT_CERTTYPE_TYPE certType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int base64encode( OUT_BUFFER( destMaxLen, *destLen ) char *dest, 
				  IN_LENGTH_MIN( 10 ) const int destMaxLen, 
				  OUT_LENGTH_Z int *destLen,
				  IN_BUFFER( srcLen ) const void *src, 
				  IN_LENGTH_MIN( 10 ) const int srcLen, 
				  IN_ENUM_OPT( CRYPT_CERTTYPE ) \
					const CRYPT_CERTTYPE_TYPE certType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int base64decodeLen( IN_BUFFER( dataLength ) const char *data, 
					 IN_LENGTH_MIN( 10 ) const int dataLength,
					 OUT_LENGTH_Z int *decodedLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int base64decode( OUT_BUFFER( destMaxLen, *destLen ) void *dest, 
				  IN_LENGTH_MIN( 10 ) const int destMaxLen, 
				  OUT_LENGTH_Z int *destLen,
				  IN_BUFFER( srcLen ) const char *src, 
				  IN_LENGTH_MIN( 10 ) const int srcLen, 
				  IN_ENUM_OPT( CRYPT_CERTFORMAT ) \
					const CRYPT_CERTFORMAT_TYPE format );

/* User data en/decode routines */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN isPKIUserValue( IN_BUFFER( encValLength ) const char *encVal, 
						IN_LENGTH_SHORT_MIN( 10 ) const int encValLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int encodePKIUserValue( OUT_BUFFER( encValMaxLen, *encValLen ) char *encVal, 
						IN_LENGTH_SHORT_MIN( 10 ) const int encValMaxLen, 
						OUT_LENGTH_SHORT_Z int *encValLen,
						IN_BUFFER( valueLen ) const BYTE *value, 
						IN_LENGTH_SHORT_MIN( 8 ) const int valueLen, 
						IN_RANGE( 3, 4 ) const int noCodeGroups );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int decodePKIUserValue( OUT_BUFFER( valueMaxLen, *valueLen ) BYTE *value, 
						IN_LENGTH_SHORT_MIN( 10 ) const int valueMaxLen, 
						OUT_LENGTH_SHORT_Z int *valueLen,
						IN_BUFFER( encValLength ) const char *encVal, 
						IN_LENGTH_SHORT const int encValLength );

/****************************************************************************
*																			*
*							List Manipulation Functions						*
*																			*
****************************************************************************/

/* Insert a new element into singly-linked and doubly-lined lists.  This is
   the sort of thing we'd really need templates for */

#define insertSingleListElement( listHead, insertPoint, newElement ) \
		{ \
		if( *( listHead ) == NULL ) \
			{ \
			/* It's an empty list, make this the new list */ \
			*( listHead ) = ( newElement ); \
			} \
		else \
			{ \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				( newElement )->next = *( listHead ); \
				*( listHead ) = ( newElement ); \
				} \
			else \
				{ \
				/* Insert the element in the middle or the end of the list */ \
				( newElement )->next = ( insertPoint )->next; \
				( insertPoint )->next = ( newElement ); \
				} \
			} \
		}

#define insertDoubleListElements( listHead, insertPoint, newStartElement, newEndElement ) \
		{ \
		if( *( listHead ) == NULL ) \
			{ \
			/* If it's an empty list, make this the new list */ \
			*( listHead ) = ( newStartElement ); \
			} \
		else \
			{ \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				( newEndElement )->next = *( listHead ); \
				( *( listHead ) )->prev = ( newEndElement ); \
				*( listHead ) = ( newStartElement ); \
				} \
			else \
				{ \
				/* Insert the element in the middle or the end of the list */ \
				( newEndElement )->next = ( insertPoint )->next; \
				\
				/* Update the links for the next and previous elements */ \
				if( ( insertPoint )->next != NULL ) \
					( insertPoint )->next->prev = ( newEndElement ); \
				( insertPoint )->next = ( newStartElement ); \
				( newStartElement )->prev = ( insertPoint ); \
				} \
			} \
		}

#define insertDoubleListElement( listHead, insertPoint, newElement ) \
		insertDoubleListElements( listHead, insertPoint, newElement, newElement )

#define deleteSingleListElement( listHead, listPrev, element ) \
		{ \
		if( element == *( listHead ) ) \
			{ \
			/* Special case for first item */ \
			*( listHead ) = element->next; \
			} \
		else \
			{ \
			/* Delete from middle or end of the list */ \
			listPrev->next = element->next; \
			} \
		}

#define deleteDoubleListElement( listHead, element ) \
		{ \
		if( element == *( listHead ) ) \
			{ \
			/* Special case for first item */ \
			*( listHead ) = element->next; \
			} \
		else \
			{ \
			/* Delete from the middle or the end of the list */ \
			element->prev->next = element->next; \
			} \
		if( element->next != NULL ) \
			element->next->prev = element->prev; \
		}

/****************************************************************************
*																			*
*						Attribute List Manipulation Functions				*
*																			*
****************************************************************************/

/* In order to work with attribute lists of different types, we need a
   means of accessing the type-specific previous and next pointers and the
   attribute ID information.  The following callback function is passed to
   all attribute-list manipulation functions and provides external access
   to the required internal fields */

typedef enum {
	ATTR_NONE,			/* No attribute get type */
	ATTR_CURRENT,		/* Get details for current attribute */
	ATTR_PREV,			/* Get details for previous attribute */
	ATTR_NEXT,			/* Get details for next attribute */
	ATTR_LAST			/* Last valid attribute get type */
	} ATTR_TYPE;

typedef CHECK_RETVAL_PTR \
		const void * ( *GETATTRFUNCTION )( IN_OPT const void *attributePtr,
										   OUT_OPT_ATTRIBUTE_Z \
											CRYPT_ATTRIBUTE_TYPE *groupID,
										   OUT_OPT_ATTRIBUTE_Z \
											CRYPT_ATTRIBUTE_TYPE *attributeID,
										   OUT_OPT_ATTRIBUTE_Z \
											CRYPT_ATTRIBUTE_TYPE *instanceID,
										   IN_ENUM( ATTR ) \
											const ATTR_TYPE attrGetType );

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 2 ) ) \
void *attributeFindStart( IN_OPT const void *attributePtr,
						  IN GETATTRFUNCTION getAttrFunction );
CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 2 ) ) \
void *attributeFindEnd( IN_OPT const void *attributePtr,
						IN GETATTRFUNCTION getAttrFunction );
CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 2 ) ) \
void *attributeFind( IN_OPT const void *attributePtr,
					 IN GETATTRFUNCTION getAttrFunction,
					 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attributeID,
					 IN_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						const CRYPT_ATTRIBUTE_TYPE instanceID );
CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 2 ) ) \
void *attributeFindNextInstance( IN_OPT const void *attributePtr,
								 IN GETATTRFUNCTION getAttrFunction );
CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 2 ) )\
const void *attributeMoveCursor( IN_OPT const void *currentCursor,
								 IN GETATTRFUNCTION getAttrFunction,
								 IN_ATTRIBUTE \
									const CRYPT_ATTRIBUTE_TYPE attributeMoveType,
								 IN_RANGE( CRYPT_CURSOR_LAST, \
										   CRYPT_CURSOR_FIRST ) /* Values are -ve */
									const int cursorMoveType );

/****************************************************************************
*																			*
*								Time Functions								*
*																			*
****************************************************************************/

/* In exceptional circumstances an attempt to read the time can fail,
   returning either a garbage value (unsigned time_t) or -1 (signed time_t).
   This can be problematic because many crypto protocols and operations use
   the time at some point.  In order to protect against this, we provide a
   safe time-read function that returns either a sane time value or zero,
   and for situations where the absolute time isn't critical an approximate
   current-time function that returns either a sane time value or an
   approximate value hardcoded in at compile time.  Finally, we provide a
   reliable time function used for operations such as signing certs and
   timestamping that tries to get the time from a hardware time source if
   one is available */

#include <time.h>

time_t getTime( void );
time_t getApproxTime( void );
time_t getReliableTime( IN_HANDLE const CRYPT_HANDLE cryptHandle );

/* Monotonic timer interface that protect against the system clock being 
   changed during a timing operation.  Even without deliberate fiddling
   with the system clock, a timeout during a DST switch can cause something
   like a 5s wait to turn into a 1hr 5s wait, so we have to abstract the
   standard time API into a monotonic time API.  Since these functions are
   purely peripheral to other operations (for example handling timeouts for
   network I/O), they never fail but simply return good-enough results if
   there's a problem (although they assert in debug mode).  This is because 
   we don't want to abort a network session just because we've detected 
   some trivial clock irregularity */

typedef struct {
	time_t endTime;
	int origTimeout, timeRemaining;
	} MONOTIMER_INFO;

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setMonoTimer( INOUT MONOTIMER_INFO *timerInfo, 
				  IN_INT const int duration );
STDC_NONNULL_ARG( ( 1 ) ) \
void extendMonoTimer( INOUT MONOTIMER_INFO *timerInfo, 
					  IN_INT const int duration );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkMonoTimerExpired( INOUT MONOTIMER_INFO *timerInfo );
CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkMonoTimerExpiryImminent( INOUT MONOTIMER_INFO *timerInfo,
									  IN_INT const int timeLeft );

/* Hardware timer read routine used for performance evaluation */

CHECK_RETVAL \
long getTickCount( long startTime );

/****************************************************************************
*																			*
*							Checksum/Hash Functions							*
*																			*
****************************************************************************/

/* Hash state information.  We can call the hash function with HASH_START,
   HASH_CONTINUE, or HASH_END as required to process the input in parts */

typedef enum {
	HASH_STATE_NONE,				/* No hash state */
	HASH_STATE_START,				/* Begin hashing */
	HASH_STATE_CONTINUE,			/* Continue existing hashing */
	HASH_STATE_END,					/* Complete existing hashing */
	HASH_STATE_LAST					/* Last valid hash option */
	} HASH_STATE;

/* The hash functions are used quite a bit so we provide an internal API for
   them to avoid the overhead of having to set up an encryption context
   every time they're needed.  These take a block of input data and hash it,
   leaving the result in the output buffer.
   
   In addition to the hash-step operation, we provide a one-step atomic hash
   function that processes a single data quantity and returns its hash */

#if defined( USE_SHA2_512 )
  /* SHA2-512: ( 2 + 8 + 16 + 1 ) * sizeof( long long ) */
  typedef BYTE HASHINFO[ ( 27 * 8 ) + 8 ];
#elif defined( SYSTEM_64BIT )
  /* RIPEMD160: 24 * sizeof( long long ) + 64 */
  typedef BYTE HASHINFO[ ( 24 * 8 ) + 64 + 8 ];
#else
  /* SHA-256: ( 2 + 8 + 16 + 1 ) * sizeof( long ) */
  typedef BYTE HASHINFO[ ( 27 * 4 ) + 8 ];
#endif /* SYSTEM_64BIT */

typedef void ( *HASHFUNCTION )( INOUT_OPT HASHINFO hashInfo, 
								OUT_BUFFER_OPT_FIXED( outBufMaxLength ) \
								BYTE *outBuffer, 
								IN_LENGTH_HASH const int outBufMaxLength,
								IN_BUFFER_OPT( inLength ) const void *inBuffer, 
								IN_LENGTH_Z const int inLength,
								IN_ENUM( HASH_STATE ) \
									const HASH_STATE hashState );
typedef STDC_NONNULL_ARG( ( 1, 3 ) ) \
		void ( *HASHFUNCTION_ATOMIC )( OUT_BUFFER_FIXED( outBufMaxLength ) \
									   BYTE *outBuffer, 
									   IN_LENGTH_HASH const int outBufMaxLength,
									   IN_BUFFER( inLength ) const void *inBuffer, 
									   IN_LENGTH const int inLength );

STDC_NONNULL_ARG( ( 2 ) ) \
void getHashParameters( IN_ALGO const CRYPT_ALGO_TYPE hashAlgorithm,
						OUT_PTR HASHFUNCTION *hashFunction, 
						OUT_OPT_LENGTH_SHORT_Z int *hashOutputSize );
STDC_NONNULL_ARG( ( 2 ) ) \
void getHashAtomicParameters( IN_ALGO const CRYPT_ALGO_TYPE hashAlgorithm,
							  OUT_PTR HASHFUNCTION_ATOMIC *hashFunctionAtomic, 
							  OUT_OPT_LENGTH_SHORT_Z int *hashOutputSize );

/* Sometimes all we need is a quick-reject check, usually performed to
   lighten the load before we do a full hash check.  The following
   function returns an integer checksum that can be used to weed out
   non-matches.  If the checksum matches, we use the more heavyweight
   full hash of the data */

#define HASH_DATA_SIZE	16

RETVAL_RANGE( MAX_ERROR, 0xFFFF ) STDC_NONNULL_ARG( ( 1 ) ) \
int checksumData( IN_BUFFER( dataLength ) const void *data, 
				  IN_LENGTH const int dataLength );
STDC_NONNULL_ARG( ( 1, 3 ) ) \
void hashData( OUT_BUFFER_FIXED( hashMaxLength ) BYTE *hash, 
			   IN_LENGTH_HASH const int hashMaxLength, 
			   IN_BUFFER( dataLength ) const void *data, 
			   IN_LENGTH const int dataLength );

/****************************************************************************
*																			*
*						Dynamic Memory Management Functions					*
*																			*
****************************************************************************/

/* Dynamic buffer management functions.  When reading variable-length
   object data we can usually fit the data into a small fixed-length buffer, 
   but occasionally we have to cope with larger data amounts that require a 
   dynamically-allocated buffer.  The following routines manage this 
   process, dynamically allocating and freeing a larger buffer if required */

#define DYNBUF_SIZE		1024

typedef struct {
	BUFFER_FIXED( length ) \
	void *data;						/* Pointer to data */
	int length;
	BUFFER( DYNBUF_SIZE, length ) \
	BYTE dataBuffer[ DYNBUF_SIZE + 8 ];	/* Data buf.if size <= DYNBUF_SIZE */
	} DYNBUF;

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int dynCreate( OUT DYNBUF *dynBuf, 
			   IN_HANDLE const CRYPT_HANDLE cryptHandle,
			   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attributeType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int dynCreateCert( OUT DYNBUF *dynBuf, 
				   IN_HANDLE const CRYPT_HANDLE cryptHandle,
				   IN_ENUM( CRYPT_CERTFORMAT ) \
					const CRYPT_CERTFORMAT_TYPE formatType );
STDC_NONNULL_ARG( ( 1 ) ) \
void dynDestroy( INOUT DYNBUF *dynBuf );

#define dynLength( dynBuf )		( dynBuf ).length
#define dynData( dynBuf )		( dynBuf ).data

/* When allocating many little blocks of memory, especially in resource-
   constrained systems, it's better if we pre-allocate a small memory pool
   ourselves and grab chunks of it as required, falling back to dynamically
   allocating memory later on if we exhaust the pool.  To use a custom
   memory pool, the caller declares a state variable of type MEMPOOL_STATE,
   calls initMemPool() to initialise the pool, and then calls getMemPool()
   and freeMemPool() to allocate and free memory blocks.  The state pointer
   is declared as a void * because to the caller it's an opaque memory block
   while to the memPool routines it's structured storage */

typedef BYTE MEMPOOL_STATE[ 32 ];

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void initMemPool( OUT void *statePtr, 
				  IN_BUFFER( memPoolSize ) void *memPool, 
				  IN_LENGTH_SHORT_MIN( 64 ) const int memPoolSize );
CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
void *getMemPool( INOUT void *statePtr, IN_LENGTH_SHORT const int size );
STDC_NONNULL_ARG( ( 1, 2 ) ) \
void freeMemPool( INOUT void *statePtr, IN void *memblock );

/* Almost all objects require object-subtype-specific amounts of memory to
   store object information.  In addition some objects such as certificates
   contain arbitrary numbers of arbitrary-sized bits and pieces, most of
   which are quite small.  To avoid having to allocate worst-case sized
   blocks of memory for objects (a problem in embedded environments) or large
   numbers of tiny little blocks of memory for certificate attributes, we use
   variable-length structures in which the payload is stored after the
   structure, with a pointer inside the structure pointing into the payload
   storage (a convenient side-effect of this is that it provides good 
   spatial coherence when processing long lists of attributes).  To make 
   this easier to handle, we use macros to set up and tear down the 
   necessary variables.
   
   The use of 'storage[ 1 ]' means that the only element that's guaranteed 
   to be valid is 'storage[ 0 ]' under strict C99 definitions, however 
   declaring it as an unsized array leads to warnings from many compilers of 
   use of zero-sized arrays, so we leave it as 'storage[ 1 ]' */

#define DECLARE_VARSTRUCT_VARS \
		int storageSize; \
		BUFFER_FIXED( storageSize ) \
		BYTE storage[ 1 ]

#define initVarStruct( structure, structureType, size ) \
		memset( structure, 0, sizeof( structureType ) ); \
		structure->value = structure->storage; \
		structure->storageSize = size

#define copyVarStruct( destStructure, srcStructure, structureType ) \
		memcpy( destStructure, srcStructure, \
				sizeof( structureType ) + srcStructure->storageSize ); \
		destStructure->value = destStructure->storage;

#define endVarStruct( structure, structureType ) \
		zeroise( structure, sizeof( structureType ) + structure->storageSize )

#define sizeofVarStruct( structure, structureType ) \
		( sizeof( structureType ) + structure->storageSize )

/****************************************************************************
*																			*
*							Envelope Management Functions					*
*																			*
****************************************************************************/

/* General-purpose enveloping functions, used by various high-level
   protocols */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int envelopeWrap( IN_BUFFER( inDataLength ) const void *inData, 
				  IN_LENGTH_MIN( 16 ) const int inDataLength, 
				  OUT_BUFFER( outDataMaxLength, *outDataLength ) void *outData, 
				  IN_LENGTH_MIN( 16 ) const int outDataMaxLength, 
				  OUT_LENGTH_Z int *outDataLength, 
				  IN_ENUM( CRYPT_FORMAT ) const CRYPT_FORMAT_TYPE formatType,
				  IN_ENUM_OPT( CRYPT_CONTENT ) const CRYPT_CONTENT_TYPE contentType,
				  IN_HANDLE_OPT const CRYPT_HANDLE iPublicKey );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int envelopeUnwrap( IN_BUFFER( inDataLength ) const void *inData, 
					IN_LENGTH_MIN( 16 ) const int inDataLength,
					OUT_BUFFER( outDataMaxLength, *outDataLength ) void *outData, 
					IN_LENGTH_MIN( 16 ) const int outDataMaxLength,
					OUT_LENGTH_Z int *outDataLength, 
					IN_HANDLE_OPT const CRYPT_CONTEXT iPrivKey );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int envelopeSign( IN_BUFFER( inDataLength ) const void *inData, 
				  IN_LENGTH_MIN( 16 ) const int inDataLength,
				  OUT_BUFFER( outDataMaxLength, *outDataLength ) void *outData, 
				  IN_LENGTH_MIN( 16 ) const int outDataMaxLength,
				  OUT_LENGTH_Z int *outDataLength, 
				  IN_ENUM_OPT( CRYPT_CONTENT ) const CRYPT_CONTENT_TYPE contentType,
				  IN_HANDLE const CRYPT_CONTEXT iSigKey,
				  IN_HANDLE_OPT const CRYPT_CERTIFICATE iCmsAttributes );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5, 7 ) ) \
int envelopeSigCheck( IN_BUFFER( inDataLength ) const void *inData, 
					  IN_LENGTH_MIN( 16 ) const int inDataLength,
					  OUT_BUFFER( outDataMaxLength, *outDataLength ) void *outData, 
					  IN_LENGTH_MIN( 16 ) const int outDataMaxLength,
					  OUT_LENGTH_Z int *outDataLength, 
					  IN_HANDLE_OPT const CRYPT_CONTEXT iSigCheckKey,
					  OUT_RANGE( MAX_ERROR, CRYPT_OK ) int *sigResult, 
					  OUT_OPT_HANDLE_OPT CRYPT_CERTIFICATE *iSigningCert,
					  OUT_OPT_HANDLE_OPT CRYPT_CERTIFICATE *iCmsAttributes );

/****************************************************************************
*																			*
*							Miscellaneous Functions							*
*																			*
****************************************************************************/

/* Miscellaneous functions that need to be prototyped here (or at least in 
   some globally-visible header) in order for them to be visible in the 
   external modules that reference them */ 

/* Prototypes for functions in mechs/sign_x509.c, used by certificates and
   sessions.  In the standard PKIX tradition there are a whole range of 
   b0rken PKI protocols that couldn't quite manage a cut & paste of two 
   lines of text, adding all sorts of unnecessary extra tagging and wrappers 
   to the signature.  The encoding of these odds and handled via the 
   X509SIG_FORMATINFO.  The basic form allows a user-supplied tag and an 
   indication of whether it's explicitly or implicitly tagged.  If the 
   explicitTag flag is clear the tag is encoded as [n] { ... }.  If it's 
   set, it's encoded as [n] { SEQUENCE { ... }}.  In addition the 
   extraLength field allows the optional insertion of extra data by the 
   caller, with the wrapper length being written to include the 
   extraLength, whose payload can then be appended by the caller */

typedef struct {
	int tag;				/* Tag for signature */
	BOOLEAN isExplicit;		/* Whether tag is expicit */
	int extraLength;		/* Optional length for further data */
	} X509SIG_FORMATINFO;

#define setX509FormatInfo( formatInfo, formatTag, formatIsExplicit ) \
		memset( formatInfo, 0, sizeof( X509SIG_FORMATINFO ) ); \
		( formatInfo )->tag = ( formatTag ); \
		( formatInfo )->isExplicit = ( formatIsExplicit )

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 4 ) ) \
int createX509signature( OUT_BUFFER_OPT( sigMaxLength, *signedObjectLength ) \
							void *signedObject, 
						 IN_LENGTH_Z const int sigMaxLength, 
						 OUT_LENGTH_Z int *signedObjectLength,
						 IN_BUFFER( objectLength ) const void *object, 
						 IN_LENGTH const int objectLength,
						 IN_HANDLE const CRYPT_CONTEXT iSignContext,
						 IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						 IN_OPT const X509SIG_FORMATINFO *formatInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkX509signature( IN_BUFFER( signedObjectLength ) const void *signedObject, 
						IN_LENGTH const int signedObjectLength,
						IN_HANDLE const CRYPT_CONTEXT iSigCheckContext,
						IN_OPT const X509SIG_FORMATINFO *formatInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int createRawSignature( OUT_BUFFER( sigMaxLength, *signatureLength ) \
							void *signature, 
						IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
							const int sigMaxLength, 
						OUT_LENGTH_SHORT_Z int *signatureLength, 
						IN_HANDLE const CRYPT_CONTEXT iSignContext,
						IN_HANDLE const CRYPT_CONTEXT iHashContext );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkRawSignature( IN_BUFFER( signatureLength ) const void *signature, 
					   IN_LENGTH_SHORT const int signatureLength,
					   IN_HANDLE const CRYPT_CONTEXT iSigCheckContext,
					   IN_HANDLE const CRYPT_CONTEXT iHashContext );

/* Prototypes for functions in context/key_wr.c, used by devices */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 7 ) ) \
int writeFlatPublicKey( OUT_BUFFER_OPT( bufMaxSize, *bufSize ) void *buffer, 
						IN_LENGTH_SHORT_Z const int bufMaxSize, 
						OUT_LENGTH_SHORT_Z int *bufSize,
						IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo, 
						IN_BUFFER( component1Length ) const void *component1, 
						IN_LENGTH_PKC const int component1Length,
						IN_BUFFER( component2Length ) const void *component2, 
						IN_LENGTH_PKC const int component2Length,
						IN_BUFFER_OPT( component3Length ) const void *component3, 
						IN_LENGTH_PKC_Z const int component3Length,
						IN_BUFFER_OPT( component4Length ) const void *component4, 
						IN_LENGTH_PKC_Z const int component4Length );

/* Prototypes for functions in cryptcrt.c, used by devices */

#ifdef USE_CERTIFICATES

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createCertificateIndirect( INOUT MESSAGE_CREATEOBJECT_INFO *createInfo,
							   STDC_UNUSED const void *auxDataPtr, 
							   STDC_UNUSED const int auxValue );
#else
  #define createCertificateIndirect( createInfo, auxDataPtr, auxValue ) \
		  CRYPT_ERROR_NOTAVAIL
#endif /* USE_CERTIFICATES */

/* Prototypes for functions in context/ctx_misc.c, used in the ASN.1/misc 
   read/write routines */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int extractBignum( INOUT void *bignumPtr, 
				   IN_BUFFER( length ) const void *buffer, 
				   IN_LENGTH_SHORT const int length,
				   IN_LENGTH_PKC const int minLength, 
				   IN_LENGTH_PKC const int maxLength, 
				   INOUT_OPT const void *maxRangePtr,
				   const BOOLEAN checkShortKey );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int getBignumData( const void *bignumPtr,
				   OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
				   IN_LENGTH_SHORT_MIN( 16 ) const int dataMaxLength, 
				   OUT_LENGTH_SHORT_Z int *dataLength );

#endif /* _INTAPI_DEFINED */
