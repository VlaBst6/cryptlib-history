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
   info */

int initHandshakeCryptInfo( SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* Clear the handshake info contexts */
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

void destroyHandshakeCryptInfo( SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* Destroy any active contexts.  We need to do this here (even though
	   it's also done in the general session code) to provide a clean exit in
	   case the session activation fails, so that a second activation attempt
	   doesn't overwrite still-active contexts */
	if( handshakeInfo->clientMD5context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->clientMD5context,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->serverMD5context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->serverMD5context,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->clientSHA1context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->clientSHA1context,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->serverSHA1context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->serverSHA1context,
						  IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->dhContext != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->dhContext, IMESSAGE_DECREFCOUNT );
	}

/* Initialise and destroy the security contexts */

int initSecurityContextsSSL( SESSION_INFO *sessionInfoPtr )
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
		sessionInfoPtr->iCryptOutContext = createInfo.cryptHandle;
	else
		{
		/* One or more of the contexts couldn't be created, destroy all of
		   the contexts that have been created so far */
		destroySecurityContextsSSL( sessionInfoPtr );
		}
	return( status );
	}

void destroySecurityContextsSSL( SESSION_INFO *sessionInfoPtr )
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

int initDHcontextSSL( CRYPT_CONTEXT *iCryptContext, const void *keyData,
					  const int keyDataLength, 
					  const CRYPT_CONTEXT iServerKeyTemplate )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int keySize = bitsToBytes( 1024 ), status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( ( keyData == NULL && keyDataLength == 0 ) || \
			isReadPtr( keyData, keyDataLength ) );
	assert( iServerKeyTemplate == CRYPT_UNUSED || \
			isHandleRangeValid( iServerKeyTemplate ) );

	/* Clear return value */
	*iCryptContext = CRYPT_ERROR;

	/* If we're loading a built-in key, match the key size to the server 
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

	/* Create the DH context */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DH );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Load the key into the context */
	setMessageData( &msgData, "TLS DH key", 10 );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusOK( status ) )
		{
		/* If we're being given externally-supplied DH key components, load
		   them, otherwise use the built-in key */
		if( keyData != NULL )
			{ setMessageData( &msgData, ( void * ) keyData,
							  keyDataLength ); }
		else
			{
			/* Use a key that corresponds approximately in size to the 
			   server auth.key.  We allow for a bit of slop to avoid having
			   a 1025-bit server auth key lead to the use of a 2048-bit DH 
			   key */
			if( keySize > bitsToBytes( 1024 ) + 16 )
				{ setMessageData( &msgData, ( void * ) dh2048SSL,
								  sizeof( dh2048SSL ) ); }
			else
				{ setMessageData( &msgData, ( void * ) dh1024SSL,
								  sizeof( dh1024SSL ) ); }
			}
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_KEY_SSL );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCryptContext = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/* Create the master secret from a shared secret value, typically a
   password */

int createSharedPremasterSecret( void *premasterSecret, 
								 const int premasterSecretMaxLength, 
								 int *premasterSecretLength,
								 const ATTRIBUTE_LIST *attributeListPtr )
	{
	STREAM stream;
	BYTE zeroes[ CRYPT_MAX_TEXTSIZE + 8 ];
	int status;

	assert( isWritePtr( premasterSecret, premasterSecretMaxLength ) );
	assert( isWritePtr( premasterSecretLength, sizeof( int ) ) );
	assert( attributeListPtr != NULL && \
			attributeListPtr->attributeID == CRYPT_SESSINFO_PASSWORD );

	/* Write the PSK-derived premaster secret value:

		uint16	otherSecretLen
		byte[]	otherSecret
		uint16	pskLen
		byte[]	psk

	   Because the TLS PRF splits the input into two halves, one half which
	   is processed by HMAC-MD5 and the other by HMAC-SHA1, it's necessary
	   to extend the PSK in some way to provide input to both halves of the
	   PRF.  In a rather dubious decision, the spec requires that the MD5
	   half be set to all zeroes, with only the SHA1 half being used.  To
	   achieve this, we write otherSecret as a number of zero bytes equal in
	   length to the password */
	memset( zeroes, 0, CRYPT_MAX_TEXTSIZE );
	sMemOpen( &stream, premasterSecret, premasterSecretMaxLength );
	if( attributeListPtr->flags & ATTR_FLAG_ENCODEDVALUE )
		{
		BYTE decodedValue[ 64 + 8 ];
		int decodedValueLength;

		/* It's a cryptlib-style encoded password, decode it into its binary
		   value */
		status = decodePKIUserValue( decodedValue, 64, &decodedValueLength,
									 attributeListPtr->value,
									 attributeListPtr->valueLength );
		if( cryptStatusError( status ) )
			{
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
		writeUint16( &stream, attributeListPtr->valueLength );
		swrite( &stream, zeroes, attributeListPtr->valueLength );
		writeUint16( &stream, attributeListPtr->valueLength );
		status = swrite( &stream, attributeListPtr->value,
						 attributeListPtr->valueLength );
		}
	if( cryptStatusError( status ) )
		{
		assert( DEBUG_WARN );
		return( status );
		}
	*premasterSecretLength = stell( &stream );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/* Wrap/unwrap the pre-master secret */

int wrapPremasterSecret( SESSION_INFO *sessionInfoPtr,
						 SSL_HANDSHAKE_INFO *handshakeInfo,
						 void *data, const int dataMaxLength, 
						 int *dataLength )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	/* Clear return value */
	memset( data, 0, dataMaxLength );
	*dataLength = 0;

	/* Create the premaster secret and wrap it using the server's public
	   key.  Note that the version that we advertise at this point is the
	   version originally offered by the client in its hello message, not
	   the version eventually negotiated for the connection.  This is
	   designed to prevent rollback attacks (but see also the comment in
	   unwrapPremasterSecret() below) */
	handshakeInfo->premasterSecretSize = SSL_SECRET_SIZE;
	handshakeInfo->premasterSecret[ 0 ] = SSL_MAJOR_VERSION;
	handshakeInfo->premasterSecret[ 1 ] = handshakeInfo->clientOfferedVersion;
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

int unwrapPremasterSecret( SESSION_INFO *sessionInfoPtr,
						   SSL_HANDSHAKE_INFO *handshakeInfo,
						   const void *data, const int dataLength )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( data, dataLength ) );

	/* Decrypt the encrypted premaster secret.  In theory we could
	   explicitly defend against Bleichenbacher-type attacks at this point
	   by setting the premaster secret to a pseudorandom value if we get a
	   bad data or (later) an incorrect version error and continuing as
	   normal, however the attack depends on the server returning
	   information required to pinpoint the cause of the failure and
	   cryptlib just returns a generic "failed" response for any handshake
	   failure, so this explicit defence isn't really necessary.

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
	setMechanismWrapInfo( &mechanismInfo, ( void * ) data, dataLength,
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
		/* Microsoft braindamage, even the latest versions of MSIE still send
		   the wrong version number for the premaster secret (making it look
		   like a rollback attack), so if we're expecting 3.1 and get 3.0, it's
		   MSIE screwing up */
		if( handshakeInfo->premasterSecret[ 0 ] == SSL_MAJOR_VERSION && \
			handshakeInfo->premasterSecret[ 1 ] == SSL_MINOR_VERSION_SSL && \
			sessionInfoPtr->version == SSL_MINOR_VERSION_SSL && \
			handshakeInfo->clientOfferedVersion == SSL_MINOR_VERSION_TLS )
			{
			ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;

			setErrorString( errorInfo, 
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

int premasterToMaster( const SESSION_INFO *sessionInfoPtr,
					   const SSL_HANDSHAKE_INFO *handshakeInfo,
					   void *masterSecret, const int masterSecretLength )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( masterSecret, masterSecretLength ) );

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

int masterToKeys( const SESSION_INFO *sessionInfoPtr,
				  const SSL_HANDSHAKE_INFO *handshakeInfo,
				  const void *masterSecret, const int masterSecretLength,
				  void *keyBlock, const int keyBlockLength )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( masterSecret, masterSecretLength ) );
	assert( isWritePtr( keyBlock, keyBlockLength ) );

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

int loadKeys( SESSION_INFO *sessionInfoPtr,
			  const SSL_HANDSHAKE_INFO *handshakeInfo,
			  const void *keyBlock, const int keyBlockLength,
			  const BOOLEAN isClient )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	BYTE *keyBlockPtr = ( BYTE * ) keyBlock;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( keyBlock, keyBlockLength ) );

	/* Sanity-check the state */
	if( keyBlockLength < ( sessionInfoPtr->authBlocksize * 2 ) + \
						 ( handshakeInfo->cryptKeysize * 2 ) + \
						 ( sessionInfoPtr->cryptBlocksize * 2 ) )
		retIntError();

	/* Load the keys and secrets:

		( client_write_mac || server_write_mac || \
		  client_write_key || server_write_key || \
		  client_write_iv  || server_write_iv )

	   First, we load the MAC keys.  For TLS these are proper MAC keys, for
	   SSL we have to build the proto-HMAC ourselves from a straight hash
	   context so we store the raw cryptovariables rather than loading them
	   into a context */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
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
	   for TLS 1.1, which uses explicit IVs, but it's easier to just do it
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

int loadExplicitIV( SESSION_INFO *sessionInfoPtr, STREAM *stream, 
					int *ivLength )
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
		retExt( status, 
				( status, SESSION_ERRINFO, "Packet IV read/load failed" ) );

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
