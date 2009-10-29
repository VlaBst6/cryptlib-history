/****************************************************************************
*																			*
*				cryptlib SSL v3/TLS Key Management Routines					*
*					 Copyright Peter Gutmann 1998-2008						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssl.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/ssl.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSL

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Initialise and destroy the crypto information in the handshake state
   information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initHandshakeCryptInfo( INOUT SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* Clear the handshake information contexts */
	handshakeInfo->clientMD5context = \
		handshakeInfo->serverMD5context = \
			handshakeInfo->clientSHA1context = \
				handshakeInfo->serverSHA1context = \
					handshakeInfo->dhContext = CRYPT_ERROR;

	/* Create the MAC/dual-hash contexts for incoming and outgoing data.
	   SSL uses a pre-HMAC variant for which we can't use real HMAC but have
	   to construct it ourselves from MD5 and SHA-1, TLS uses a straight dual
	   hash and MACs that once a MAC key becomes available at the end of the
	   handshake */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_MD5 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->clientMD5context = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_MD5 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->serverMD5context = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA1 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->clientSHA1context = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA1 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->serverSHA1context = createInfo.cryptHandle;
		return( CRYPT_OK );
		}

	/* One or more of the contexts couldn't be created, destroy all of the
	   contexts that have been created so far */
	destroyHandshakeCryptInfo( handshakeInfo );
	return( status );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void destroyHandshakeCryptInfo( INOUT SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* Destroy any active contexts.  We need to do this here (even though
	   it's also done in the general session code) to provide a clean exit in
	   case the session activation fails, so that a second activation attempt
	   doesn't overwrite still-active contexts */
	if( handshakeInfo->clientMD5context != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->clientMD5context,
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->clientMD5context = CRYPT_ERROR;
		}
	if( handshakeInfo->serverMD5context != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->serverMD5context,
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->serverMD5context = CRYPT_ERROR;
		}
	if( handshakeInfo->clientSHA1context != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->clientSHA1context,
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->clientSHA1context = CRYPT_ERROR;
		}
	if( handshakeInfo->serverSHA1context != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->serverSHA1context,
						  IMESSAGE_DECREFCOUNT );
		handshakeInfo->serverSHA1context = CRYPT_ERROR;
		}
	if( handshakeInfo->dhContext != CRYPT_ERROR )
		{
		krnlSendNotifier( handshakeInfo->dhContext, IMESSAGE_DECREFCOUNT );
		handshakeInfo->dhContext = CRYPT_ERROR;
		}
	}

/* Initialise and destroy the session security contexts */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initSecurityContextsSSL( INOUT SESSION_INFO *sessionInfoPtr )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->integrityAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iAuthInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->integrityAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iAuthOutContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptOutContext = createInfo.cryptHandle;

		return( CRYPT_OK );
		}

	/* One or more of the contexts couldn't be created, destroy all of the 
	   contexts that have been created so far */
	destroySecurityContextsSSL( sessionInfoPtr );
	return( status );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void destroySecurityContextsSSL( INOUT SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Destroy any active contexts */
	if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iKeyexCryptContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iKeyexCryptContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptInContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
						  IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
		}
	}

/****************************************************************************
*																			*
*								Keying Functions							*
*																			*
****************************************************************************/

/* Load a DH key into a context, with the fixed value below being used for
   the SSL server.  The prime is the value 2^1024 - 2^960 - 1 +
   2^64 * { [2^894 pi] + 129093 }, from the Oakley spec (RFC 2412) */

static const BYTE FAR_BSS dh1024SSL[] = {
	0x00, 0x80,		/* p */
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
		0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
		0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
		0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
		0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
		0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
		0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
		0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
		0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
		0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x00, 0x01,		/* g */
		0x02
	};

static const BYTE FAR_BSS dh2048SSL[] = {
	0x01, 0x01,		/* p */
		0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
		0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
		0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
		0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
		0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
		0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
		0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
		0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
		0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
		0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
		0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
		0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
		0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
		0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
		0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
		0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
		0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
		0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
		0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
		0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
		0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
		0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
		0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x00, 0x01,		/* g */
		0x02
	};

typedef struct {
	const CRYPT_ECCCURVE_TYPE curveType;
	const BYTE FAR_BSS *curveData;
	} ECCCURVE_SSL_INFO;

static const BYTE FAR_BSS ecdh192SSL[] = {
	0x03,		/* NamedCurve */
	0x00, 0x13	/* P192 */
	};
static const BYTE FAR_BSS ecdh224SSL[] = {
	0x03,		/* NamedCurve */
	0x00, 0x15	/* P224 */
	};
static const BYTE FAR_BSS ecdh256SSL[] = {
	0x03,		/* NamedCurve */
	0x00, 0x17	/* P256 */
	};
static const BYTE FAR_BSS ecdh384SSL[] = {
	0x03,		/* NamedCurve */
	0x00, 0x18	/* P384 */
	};
static const BYTE FAR_BSS ecdh521SSL[] = {
	0x03,		/* NamedCurve */
	0x00, 0x19	/* P521 */
	};
static const ECCCURVE_SSL_INFO eccCurveMapTbl[] = {
	{ CRYPT_ECCCURVE_P192, ecdh192SSL },
	{ CRYPT_ECCCURVE_P224, ecdh224SSL },
	{ CRYPT_ECCCURVE_P256, ecdh256SSL },
	{ CRYPT_ECCCURVE_P384, ecdh384SSL },
	{ CRYPT_ECCCURVE_P521, ecdh521SSL },
	{ CRYPT_ECCCURVE_NONE, NULL }, 
		{ CRYPT_ECCCURVE_NONE, NULL }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initDHcontextSSL( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
					  IN_BUFFER_OPT( keyDataLength ) const void *keyData, 
					  IN_LENGTH_SHORT_Z const int keyDataLength,
					  IN_HANDLE_OPT const CRYPT_CONTEXT iServerKeyTemplate,
					  IN_ENUM_OPT( CRYPT_ECCCURVE ) \
							const CRYPT_ECCCURVE_TYPE eccParams )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int keySize = bitsToBytes( 1024 ), status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( ( keyData == NULL && keyDataLength == 0 ) || \
			isReadPtr( keyData, keyDataLength ) );

	REQUIRES( ( keyData == NULL && keyDataLength == 0 ) || \
			  ( keyData != NULL && \
				keyDataLength > 0 && keyDataLength < MAX_INTLENGTH_SHORT ) );
	REQUIRES( iServerKeyTemplate == CRYPT_UNUSED || \
			  isHandleRangeValid( iServerKeyTemplate ) );
	REQUIRES( eccParams >= CRYPT_ECCCURVE_NONE && \
			  eccParams < CRYPT_ECCCURVE_LAST );

	/* Clear return value */
	*iCryptContext = CRYPT_ERROR;

	/* If we're loading a built-in key, match the DH key size to the server 
	   authentication key size.  If there's no server key present, we 
	   default to the 1024-bit key because we don't know how much processing
	   power the client has, and if we're using anon-DH anyway (implied by 
	   the lack of server authentication key) then 1024 vs. 2048 bits isn't 
	   a big loss */
	if( keyData == NULL && iServerKeyTemplate != CRYPT_UNUSED )
		{
		status = krnlSendMessage( iServerKeyTemplate, IMESSAGE_GETATTRIBUTE,
								  &keySize, CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Create the DH/ECDH context */
	setMessageCreateObjectInfo( &createInfo, \
								( eccParams != CRYPT_ECCCURVE_NONE ) ? \
									CRYPT_ALGO_ECDH : CRYPT_ALGO_DH );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, "TLS key agreement key", 21 );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Load the key into the context.  If we're being given externally-
	   supplied DH/ECDH key components, load them, otherwise use the built-
	   in key */
	if( keyData != NULL )
		{
		/* If we're the client we'll have been sent DH/ECDH key components 
		   by the server */
		setMessageData( &msgData, ( MESSAGE_CAST ) keyData, keyDataLength ); 
		}
	else
		{
		/* If we've been given ECC parameter information then we're using
		   ECDH */
		if( eccParams != CRYPT_ECCCURVE_NONE )
			{
			const ECCCURVE_SSL_INFO *eccCurveInfoPtr = NULL;
			int i;

			for( i = 0; 
				 eccCurveMapTbl[ i ].curveType != CRYPT_ECCCURVE_NONE && \
				 i < FAILSAFE_ARRAYSIZE( eccCurveMapTbl, ECCCURVE_SSL_INFO );
				 i++ )
				{
				if( eccCurveMapTbl[ i ].curveType == eccParams )
					{
					eccCurveInfoPtr = &eccCurveMapTbl[ i ];
					break;
					}
				}
			ENSURES( i < FAILSAFE_ARRAYSIZE( eccCurveMapTbl, \
											 ECCCURVE_SSL_INFO ) );
			ENSURES( eccCurveInfoPtr != NULL );
			setMessageData( &msgData, 
							( MESSAGE_CAST ) eccCurveInfoPtr->curveData, 3 );
			}
		else
			{
			/* We're using straight DH, use a key that corresponds 
			   approximately in size to the server authentication key.  We 
			   allow for a bit of slop to avoid having a 1025-bit server 
			   authentication key lead to the use of a 2048-bit DH  key */
			if( keySize > bitsToBytes( 1024 ) + 16 )
				{ setMessageData( &msgData, ( MESSAGE_CAST ) dh2048SSL,
								  sizeof( dh2048SSL ) ); }
			else
				{ setMessageData( &msgData, ( MESSAGE_CAST ) dh1024SSL,
								  sizeof( dh1024SSL ) ); }
			}
		}
	status = krnlSendMessage( createInfo.cryptHandle,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_KEY_SSL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( keyData == NULL )
			{
			/* If we got an error loading a known-good, fixed-format key 
			   then we report the problem as an internal error rather than 
			   (say) a bad-data error */
			retIntError();
			}
		return( status );
		}
	*iCryptContext = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/* Create the master secret from a shared secret value, typically a
   password */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int createSharedPremasterSecret( OUT_BUFFER( premasterSecretMaxLength, \
											 *premasterSecretLength ) \
									void *premasterSecret, 
								 IN_LENGTH_SHORT \
									const int premasterSecretMaxLength, 
								 OUT_LENGTH_SHORT_Z int *premasterSecretLength,
								 IN_BUFFER( sharedSecretLength ) \
									const void *sharedSecret, 
								 IN_LENGTH_SHORT const int sharedSecretLength,
								 const BOOLEAN isEncodedValue )
	{
	STREAM stream;
	BYTE zeroes[ CRYPT_MAX_TEXTSIZE + 8 ];
	int status;

	assert( isWritePtr( premasterSecret, premasterSecretMaxLength ) );
	assert( isWritePtr( premasterSecretLength, sizeof( int ) ) );
	assert( isReadPtr( sharedSecret, sharedSecretLength ) );

	REQUIRES( premasterSecretMaxLength > 0 && \
			  premasterSecretMaxLength < MAX_INTLENGTH_SHORT );
	REQUIRES( sharedSecretLength > 0 && \
			  sharedSecretLength < MAX_INTLENGTH_SHORT );

	/* Clear return value */
	*premasterSecretLength = 0;

	/* Write the PSK-derived premaster secret value:

		uint16	otherSecretLen
		byte[]	otherSecret
		uint16	pskLen
		byte[]	psk

	   Because the TLS PRF splits the input into two halves of which one half 
	   is processed by HMAC-MD5 and the other by HMAC-SHA1, it's necessary
	   to extend the PSK in some way to provide input to both halves of the
	   PRF.  In a rather dubious decision, the spec requires that the MD5
	   half be set to all zeroes, with only the SHA1 half being used.  This 
	   is done by writing otherSecret as a number of zero bytes equal in 
	   length to the password (when used with RSA or DH/ECDH otherSecret
	   contains the RSA/DH/ECDH value, for pure PSK it contains zeroes) */
	memset( zeroes, 0, CRYPT_MAX_TEXTSIZE );
	sMemOpen( &stream, premasterSecret, premasterSecretMaxLength );
	if( isEncodedValue )
		{
		BYTE decodedValue[ 64 + 8 ];
		int decodedValueLength;

		/* It's a cryptlib-style encoded password, decode it into its binary
		   value */
		status = decodePKIUserValue( decodedValue, 64, &decodedValueLength,
									 sharedSecret, sharedSecretLength );
		if( cryptStatusError( status ) )
			{
			DEBUG_DIAG(( "Couldn't decode supposedly valid PKI user "
						 "value" ));
			assert( DEBUG_WARN );
			return( status );
			}
		writeUint16( &stream, decodedValueLength );
		swrite( &stream, zeroes, decodedValueLength );
		writeUint16( &stream, decodedValueLength );
		status = swrite( &stream, decodedValue, decodedValueLength );
		zeroise( decodedValue, decodedValueLength );
		}
	else
		{
		writeUint16( &stream, sharedSecretLength );
		swrite( &stream, zeroes, sharedSecretLength );
		writeUint16( &stream, sharedSecretLength );
		status = swrite( &stream, sharedSecret, sharedSecretLength );
		}
	if( cryptStatusError( status ) )
		return( status );
	*premasterSecretLength = stell( &stream );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/* Wrap/unwrap the pre-master secret */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int wrapPremasterSecret( INOUT SESSION_INFO *sessionInfoPtr,
						 INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						 OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
						 IN_LENGTH_SHORT const int dataMaxLength, 
						 OUT_LENGTH_SHORT_Z int *dataLength )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( dataMaxLength > 0 && dataMaxLength < MAX_INTLENGTH_SHORT );

	/* Clear return values */
	memset( data, 0, min( 16, dataMaxLength ) );
	*dataLength = 0;

	/* Create the premaster secret and wrap it using the server's public
	   key.  Note that the version that we advertise at this point is the
	   version originally offered by the client in its hello message, not
	   the version eventually negotiated for the connection.  This is
	   designed to prevent rollback attacks (but see also the comment in
	   unwrapPremasterSecret() below) */
	handshakeInfo->premasterSecretSize = SSL_SECRET_SIZE;
	handshakeInfo->premasterSecret[ 0 ] = SSL_MAJOR_VERSION;
	handshakeInfo->premasterSecret[ 1 ] = \
						intToByte( handshakeInfo->clientOfferedVersion );
	setMessageData( &msgData,
					handshakeInfo->premasterSecret + VERSIONINFO_SIZE,
					handshakeInfo->premasterSecretSize - VERSIONINFO_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	setMechanismWrapInfo( &mechanismInfo, data, dataMaxLength,
						  handshakeInfo->premasterSecret,
						  handshakeInfo->premasterSecretSize, CRYPT_UNUSED,
						  sessionInfoPtr->iKeyexCryptContext );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT,
							  &mechanismInfo, MECHANISM_ENC_PKCS1_RAW );
	if( cryptStatusOK( status ) )
		*dataLength = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int unwrapPremasterSecret( INOUT SESSION_INFO *sessionInfoPtr, 
						   INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						   IN_BUFFER( dataLength ) const void *data, 
						   IN_LENGTH_SHORT const int dataLength )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( data, dataLength ) );

	REQUIRES( dataLength > 0 && dataLength < MAX_INTLENGTH_SHORT );

	/* Decrypt the encrypted premaster secret.  In theory we could
	   explicitly defend against Bleichenbacher-type attacks at this point
	   by setting the premaster secret to a pseudorandom value if we get a
	   bad data or (later) an incorrect version error and continuing as
	   normal, however the attack depends on the server returning
	   information required to pinpoint the cause of the failure and
	   cryptlib just returns a generic "failed" response for any handshake
	   failure, so this explicit defence isn't really necessary, and not
	   doing this avoids a trivial DoS attack in which a client sends us
	   junk and forces us to continue with the handshake even tbough we've
	   detected that it's junk.

	   There's a second, lower-grade level of oracle that an attacker can
	   use in the version check if they can distinguish between a decrypt 
	   failure due to bad PKCS #1 padding and a failure due to a bad version 
	   number (see "Attacking RSA-based Sessions in SSL/TLS", Vlastimil
	   Klima, Ondrej Pokorny, and Tomas Rosa, CHES'03).  If we use the 
	   Bleichenbacher defence and continue the handshake on bad padding but 
	   bail out on a bad version then the two cases can be distinguished, 
	   however since cryptlib bails out immediately in either case the two
	   shouldn't be distinguishable */
	handshakeInfo->premasterSecretSize = SSL_SECRET_SIZE;
	setMechanismWrapInfo( &mechanismInfo, ( MESSAGE_CAST ) data, dataLength,
						  handshakeInfo->premasterSecret,
						  handshakeInfo->premasterSecretSize, CRYPT_UNUSED,
						  sessionInfoPtr->privateKey );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT,
							  &mechanismInfo, MECHANISM_ENC_PKCS1_RAW );
	if( cryptStatusOK( status ) && \
		mechanismInfo.keyDataLength != handshakeInfo->premasterSecretSize )
		status = CRYPT_ERROR_BADDATA;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that it looks OK.  Note that the version that we check for
	   at this point is the version originally offered by the client in its
	   hello message, not the version eventually negotiated for the
	   connection.  This is designed to prevent rollback attacks */
	if( handshakeInfo->premasterSecret[ 0 ] != SSL_MAJOR_VERSION || \
		handshakeInfo->premasterSecret[ 1 ] != handshakeInfo->clientOfferedVersion )
		{
		/* Microsoft braindamage, even recent versions of MSIE still send 
		   the wrong version number for the premaster secret (making it look 
		   like a rollback attack), so if we're expecting 3.1 and get 3.0, 
		   it's MSIE screwing up */
		if( handshakeInfo->premasterSecret[ 0 ] == SSL_MAJOR_VERSION && \
			handshakeInfo->premasterSecret[ 1 ] == SSL_MINOR_VERSION_SSL && \
			sessionInfoPtr->version == SSL_MINOR_VERSION_SSL && \
			handshakeInfo->clientOfferedVersion == SSL_MINOR_VERSION_TLS )
			{
			setErrorString( ( ERROR_INFO * ) &sessionInfoPtr->errorInfo, 
							"Warning: Accepting invalid premaster secret "
							"version 3.0 (MSIE bug)", 66 );
			}
		else
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid premaster secret version data 0x%02X 0x%02X, "
					  "expected 0x03 0x%02X",
					  handshakeInfo->premasterSecret[ 0 ],
					  handshakeInfo->premasterSecret[ 1 ],
					  handshakeInfo->clientOfferedVersion ) );
			}
		}

	return( CRYPT_OK );
	}

/* Convert a pre-master secret to a master secret, and a master secret to
   keying material */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int premasterToMaster( const SESSION_INFO *sessionInfoPtr, 
					   const SSL_HANDSHAKE_INFO *handshakeInfo, 
					   OUT_BUFFER_FIXED( masterSecretLength ) void *masterSecret, 
					   IN_LENGTH_SHORT const int masterSecretLength )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( masterSecret, masterSecretLength ) );

	REQUIRES( masterSecretLength > 0 && \
			  masterSecretLength < MAX_INTLENGTH_SHORT );

	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		memcpy( nonceBuffer, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
		memcpy( nonceBuffer + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
				SSL_NONCE_SIZE );
		setMechanismDeriveInfo( &mechanismInfo, masterSecret,
								masterSecretLength,
								handshakeInfo->premasterSecret,
								handshakeInfo->premasterSecretSize,
								CRYPT_USE_DEFAULT, nonceBuffer,
								SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
		return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
								 &mechanismInfo, MECHANISM_DERIVE_SSL ) );
		}

	memcpy( nonceBuffer, "master secret", 13 );
	memcpy( nonceBuffer + 13, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	memcpy( nonceBuffer + 13 + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
			SSL_NONCE_SIZE );
	setMechanismDeriveInfo( &mechanismInfo, masterSecret, masterSecretLength,
							handshakeInfo->premasterSecret,
							handshakeInfo->premasterSecretSize,
							CRYPT_USE_DEFAULT, nonceBuffer,
							13 + SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
	return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							 &mechanismInfo, MECHANISM_DERIVE_TLS ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int masterToKeys( const SESSION_INFO *sessionInfoPtr, 
				  const SSL_HANDSHAKE_INFO *handshakeInfo, 
				  IN_BUFFER( masterSecretLength ) const void *masterSecret, 
				  IN_LENGTH_SHORT const int masterSecretLength,
				  OUT_BUFFER_FIXED( keyBlockLength ) void *keyBlock, 
				  IN_LENGTH_SHORT const int keyBlockLength )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( masterSecret, masterSecretLength ) );
	assert( isWritePtr( keyBlock, keyBlockLength ) );

	REQUIRES( masterSecretLength > 0 && \
			  masterSecretLength < MAX_INTLENGTH_SHORT );
	REQUIRES( keyBlockLength > 0 && \
			  keyBlockLength < MAX_INTLENGTH_SHORT );

	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		memcpy( nonceBuffer, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
		memcpy( nonceBuffer + SSL_NONCE_SIZE, handshakeInfo->clientNonce,
				SSL_NONCE_SIZE );
		setMechanismDeriveInfo( &mechanismInfo, keyBlock, keyBlockLength,
								masterSecret, masterSecretLength, CRYPT_USE_DEFAULT,
								nonceBuffer, SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
		return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
								 &mechanismInfo, MECHANISM_DERIVE_SSL ) );
		}

	memcpy( nonceBuffer, "key expansion", 13 );
	memcpy( nonceBuffer + 13, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	memcpy( nonceBuffer + 13 + SSL_NONCE_SIZE, handshakeInfo->clientNonce,
			SSL_NONCE_SIZE );
	setMechanismDeriveInfo( &mechanismInfo, keyBlock, keyBlockLength,
							masterSecret, masterSecretLength, CRYPT_USE_DEFAULT,
							nonceBuffer, 13 + SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
	return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							 &mechanismInfo, MECHANISM_DERIVE_TLS ) );
	}

/* Load the SSL/TLS cryptovariables */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int loadKeys( INOUT SESSION_INFO *sessionInfoPtr,
			  const SSL_HANDSHAKE_INFO *handshakeInfo,
			  IN_BUFFER( keyBlockLength ) const void *keyBlock, 
			  IN_LENGTH_SHORT_MIN( 16 ) const int keyBlockLength,
			  const BOOLEAN isClient )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	BYTE *keyBlockPtr = ( BYTE * ) keyBlock;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( keyBlock, keyBlockLength ) );

	REQUIRES( keyBlockLength >= ( sessionInfoPtr->authBlocksize * 2 ) + \
								( handshakeInfo->cryptKeysize * 2 ) + \
								( sessionInfoPtr->cryptBlocksize * 2 ) && \
			  keyBlockLength < MAX_INTLENGTH_SHORT );

	/* Load the keys and secrets:

		( client_write_mac || server_write_mac || \
		  client_write_key || server_write_key || \
		  client_write_iv  || server_write_iv )

	   First we load the MAC keys.  For TLS these are proper MAC keys, for
	   SSL we have to build the proto-HMAC ourselves from a straight hash
	   context so we store the raw cryptovariables rather than loading them
	   into a context */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		ENSURES( rangeCheckZ( 0, sessionInfoPtr->authBlocksize, 
							  CRYPT_MAX_HASHSIZE ) );
		memcpy( isClient ? sslInfo->macWriteSecret : sslInfo->macReadSecret,
				keyBlockPtr, sessionInfoPtr->authBlocksize );
		memcpy( isClient ? sslInfo->macReadSecret : sslInfo->macWriteSecret,
				keyBlockPtr + sessionInfoPtr->authBlocksize,
				sessionInfoPtr->authBlocksize );
		}
	else
		{
		setMessageData( &msgData, keyBlockPtr, sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( isClient ? \
										sessionInfoPtr->iAuthOutContext : \
										sessionInfoPtr->iAuthInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusError( status ) )
			return( status );
		setMessageData( &msgData, keyBlockPtr + sessionInfoPtr->authBlocksize,
						sessionInfoPtr->authBlocksize );
		status = krnlSendMessage( isClient ? \
										sessionInfoPtr->iAuthInContext: \
										sessionInfoPtr->iAuthOutContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( cryptStatusError( status ) )
			return( status );
		}
	keyBlockPtr += sessionInfoPtr->authBlocksize * 2;

	/* Then we load the encryption keys */
	setMessageData( &msgData, keyBlockPtr, handshakeInfo->cryptKeysize );
	status = krnlSendMessage( isClient ? \
									sessionInfoPtr->iCryptOutContext : \
									sessionInfoPtr->iCryptInContext,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_KEY );
	keyBlockPtr += handshakeInfo->cryptKeysize;
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, keyBlockPtr, handshakeInfo->cryptKeysize );
	status = krnlSendMessage( isClient ? \
									sessionInfoPtr->iCryptInContext : \
									sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_KEY );
	keyBlockPtr += handshakeInfo->cryptKeysize;
	if( cryptStatusError( status ) )
		return( status );

	/* Finally we load the IVs if required.  This load is actually redundant
	   for TLS 1.1 since it uses explicit IVs, but it's easier to just do it
	   anyway */
	if( isStreamCipher( sessionInfoPtr->cryptAlgo ) )
		return( CRYPT_OK );	/* No IV, we're done */
	setMessageData( &msgData, keyBlockPtr,
					sessionInfoPtr->cryptBlocksize );
	krnlSendMessage( isClient ? sessionInfoPtr->iCryptOutContext : \
								sessionInfoPtr->iCryptInContext,
					 IMESSAGE_SETATTRIBUTE_S, &msgData,
					 CRYPT_CTXINFO_IV );
	keyBlockPtr += sessionInfoPtr->cryptBlocksize;
	setMessageData( &msgData, keyBlockPtr,
					sessionInfoPtr->cryptBlocksize );
	return( krnlSendMessage( isClient ? sessionInfoPtr->iCryptInContext : \
										sessionInfoPtr->iCryptOutContext,
							 IMESSAGE_SETATTRIBUTE_S, &msgData,
							 CRYPT_CTXINFO_IV ) );
	}

/* TLS versions greater than 1.0 prepend an explicit IV to the data, the
   following function loads this from the packet data stream */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int loadExplicitIV( INOUT SESSION_INFO *sessionInfoPtr, 
					INOUT STREAM *stream, 
					OUT_INT_SHORT_Z int *ivLength )
	{
	MESSAGE_DATA msgData;
	BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( ivLength, sizeof( int ) ) );

	/* Clear return value */
	*ivLength = 0;

	/* Read and load the IV */
	status = sread( stream, iv, sessionInfoPtr->cryptBlocksize );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, iv, sessionInfoPtr->cryptBlocksize );
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_IV );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Packet IV read/load failed" ) );
		}

	/* Tell the caller how much data we've consumed */
	*ivLength = sessionInfoPtr->cryptBlocksize;

	/* The following alternate code, which decrypts and discards the first
	   block, can be used when we're using hardware cryptologic that doesn't
	   allow a reaload of the IV during decryption */
#if 0
	status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_CTX_DECRYPT, iv,
							  sessionInfoPtr->cryptBlocksize );
#endif /* 0 */

	return( CRYPT_OK );
	}
#endif /* USE_SSL */
