/****************************************************************************
*																			*
*					cryptlib PKCS #15 Private-key Add Interface				*
*						Copyright Peter Gutmann 1996-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "pkcs15.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/pkcs15.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS15

/* The minimum number of keying iterations to use when deriving a key wrap
   key from a password */

#ifdef CONFIG_SLOW_CPU
  #define MIN_KEYING_ITERATIONS	800
#else
  #define MIN_KEYING_ITERATIONS	2500
#endif /* CONFIG_SLOW_CPU */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Replace existing private-key data with updated information */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void replacePrivkeyData( INOUT PKCS15_INFO *pkcs15infoPtr, 
								IN_BUFFER( newPrivKeyDataSize ) \
									const void *newPrivKeyData, 
								IN_LENGTH_SHORT_MIN( 16 ) \
									const int newPrivKeyDataSize,
								IN_LENGTH_SHORT const int newPrivKeyOffset )
	{
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( newPrivKeyData, newPrivKeyDataSize ) );

	REQUIRES_V( newPrivKeyDataSize >= 16 && \
				newPrivKeyDataSize < MAX_INTLENGTH_SHORT );
	REQUIRES_V( newPrivKeyOffset > 0 && \
				newPrivKeyOffset < newPrivKeyDataSize && \
				newPrivKeyOffset < MAX_INTLENGTH_SHORT );

	/* If we've allocated new storage for the data rather than directly 
	   replacing the existing entry, free the existing one and replace it
	   with the new one */
	if( newPrivKeyData != pkcs15infoPtr->privKeyData )
		{
		if( pkcs15infoPtr->privKeyData != NULL )
			{
			zeroise( pkcs15infoPtr->privKeyData, 
					 pkcs15infoPtr->privKeyDataSize );
			clFree( "replacePrivkeyData", pkcs15infoPtr->privKeyData );
			}
		pkcs15infoPtr->privKeyData = ( void * ) newPrivKeyData;
		}

	/* Update the size information */
	pkcs15infoPtr->privKeyDataSize = newPrivKeyDataSize;
	pkcs15infoPtr->privKeyOffset = newPrivKeyOffset;
	}

/* Calculate the size of and if necessary allocate storage for private-key 
   data.  This function has to be accessible externally because adding or 
   changing a certificate for a private key can change the private-key 
   attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int calculatePrivkeyStorage( const PKCS15_INFO *pkcs15infoPtr,
							 OUT_PTR void **newPrivKeyDataPtr, 
							 OUT_LENGTH_SHORT_Z int *newPrivKeyDataSize, 
							 IN_LENGTH_SHORT const int privKeySize,
							 IN_LENGTH_SHORT const int privKeyAttributeSize,
							 IN_LENGTH_SHORT const int extraDataSize )
	{
	void *newPrivKeyData;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isWritePtr( newPrivKeyDataPtr, sizeof( void * ) ) );
	assert( isWritePtr( newPrivKeyDataSize, sizeof( int ) ) ); 

	REQUIRES( privKeySize > 0 && privKeySize < MAX_INTLENGTH_SHORT );
	REQUIRES( privKeyAttributeSize > 0 && \
			  privKeyAttributeSize < MAX_INTLENGTH_SHORT );
	REQUIRES( extraDataSize >= 0 && extraDataSize < MAX_INTLENGTH_SHORT );

	/* Calculate the new private-key data size */
	*newPrivKeyDataSize = sizeofObject( privKeyAttributeSize + \
										sizeofObject( \
											sizeofObject( privKeySize ) + \
											extraDataSize ) );

	/* If the new data will fit into the existing storage, we're done */
	if( *newPrivKeyDataSize <= pkcs15infoPtr->privKeyDataSize )
		return( CRYPT_OK );

	/* Allocate storage for the new data */
	newPrivKeyData = clAlloc( "calculatePrivkeyStorage", *newPrivKeyDataSize );
	if( newPrivKeyData == NULL )
		return( CRYPT_ERROR_MEMORY );
	*newPrivKeyDataPtr = newPrivKeyData;

	return( CRYPT_OK );
	}

/* Update the private-key attributes while leaving the private key itself
   untouched.  This is necessary after updating a certificate associated 
   with a private key, which can affect the key's attributes */

STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
void updatePrivKeyAttributes( INOUT PKCS15_INFO *pkcs15infoPtr,
							  OUT_BUFFER_FIXED( newPrivKeyDataSize ) \
								void *newPrivKeyData, 
							  IN_LENGTH_SHORT_MIN( 16 ) \
								const int newPrivKeyDataSize,
							  IN_BUFFER( privKeyAttributeSize ) \
								const void *privKeyAttributes, 
							  IN_LENGTH_SHORT const int privKeyAttributeSize, 
							  IN_LENGTH_SHORT const int privKeyInfoSize, 
							  IN_TAG const int keyTypeTag )
	{
	STREAM stream;
	BYTE keyBuffer[ MAX_PRIVATE_KEYSIZE + 8 ];
	int newPrivKeyOffset = DUMMY_INIT, status;

	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isWritePtr( newPrivKeyData, newPrivKeyDataSize ) );
	assert( isReadPtr( privKeyAttributes, privKeyAttributeSize ) );

	REQUIRES_V( newPrivKeyDataSize >= 16 && \
				newPrivKeyDataSize < MAX_INTLENGTH_SHORT );
	REQUIRES_V( privKeyAttributeSize > 0 && \
				privKeyAttributeSize < MAX_INTLENGTH_SHORT );
	REQUIRES_V( privKeyInfoSize > 0 && \
				privKeyInfoSize < MAX_PRIVATE_KEYSIZE );
	REQUIRES_V( keyTypeTag == DEFAULT_TAG || keyTypeTag >= 0 );

	/* Since we may be doing an in-place update of the private-key 
	   information we copy the wrapped key data out to a temporary buffer 
	   while we make the changes */
	ENSURES_V( rangeCheck( pkcs15infoPtr->privKeyOffset, privKeyInfoSize,
						   pkcs15infoPtr->privKeyDataSize ) );
	memcpy( keyBuffer, ( BYTE * ) pkcs15infoPtr->privKeyData +
								  pkcs15infoPtr->privKeyOffset,
			privKeyInfoSize );

	/* The corresponding key is already present, we need to update the key
	   attributes since adding the certificate may have changed them.  The
	   key data itself is unchanged so we just memcpy() it across verbatim */
	sMemOpen( &stream, newPrivKeyData, newPrivKeyDataSize );
	writeConstructed( &stream, privKeyAttributeSize + \
							   sizeofObject( \
									sizeofObject( privKeyInfoSize ) ), 
					  keyTypeTag );
	swrite( &stream, privKeyAttributes, privKeyAttributeSize );
	writeConstructed( &stream, ( int ) sizeofObject( privKeyInfoSize ),
					  CTAG_OB_TYPEATTR );
	status = writeSequence( &stream, privKeyInfoSize );
	if( cryptStatusOK( status ) )
		{
		newPrivKeyOffset = stell( &stream );
		status = swrite( &stream, keyBuffer, privKeyInfoSize );
		}
	sMemDisconnect( &stream );
	zeroise( keyBuffer, MAX_PRIVATE_KEYSIZE );
	ENSURES_V( cryptStatusOK( status ) && \
			   !cryptStatusError( checkObjectEncoding( newPrivKeyData, \
													   newPrivKeyDataSize ) ) );

	/* Replace the old data with the newly-written data */
	replacePrivkeyData( pkcs15infoPtr, newPrivKeyData, newPrivKeyDataSize, 
						newPrivKeyOffset );
	}

/****************************************************************************
*																			*
*							Private-key Wrap Routines						*
*																			*
****************************************************************************/

/* Create a strong encryption context to wrap a key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int createStrongEncryptionContext( OUT_HANDLE_OPT \
											CRYPT_CONTEXT *iCryptContext,
										  IN_HANDLE const CRYPT_USER iCryptOwner )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );

	REQUIRES( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( iCryptOwner ) );

	/* Clear return value */
	*iCryptContext = CRYPT_ERROR;

	/* In the interests of luser-proofing we're rather paranoid and force
	   the use of non-weak algorithms and modes of operation.  In addition
	   since OIDs are only defined for a limited subset of algorithms we 
	   also default to a guaranteed available algorithm if no OID is defined
	   for the one requested */
	status = krnlSendMessage( iCryptOwner, IMESSAGE_GETATTRIBUTE, &cryptAlgo,
							  CRYPT_OPTION_ENCR_ALGO );
	if( cryptStatusError( status ) || isWeakCryptAlgo( cryptAlgo ) || \
		cryptStatusError( sizeofAlgoIDex( cryptAlgo, CRYPT_MODE_CBC, 0 ) ) )
		cryptAlgo = CRYPT_ALGO_3DES;

	/* Create the context */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	*iCryptContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/* Generate a session key and write the wrapped key in the form
   SET OF {	[ 0 ] (EncryptedKey) } */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int writeWrappedSessionKey( INOUT STREAM *stream,
								   IN_HANDLE \
									const CRYPT_CONTEXT iSessionKeyContext,
								   IN_HANDLE const CRYPT_USER iCryptOwner,
								   IN_BUFFER( passwordLength ) \
									const char *password,
								   IN_LENGTH_NAME const int passwordLength )
	{
	CRYPT_CONTEXT iCryptContext;
	int iterations, exportedKeySize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( password, passwordLength ) );

	REQUIRES( isHandleRangeValid( iSessionKeyContext ) );
	REQUIRES( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( iCryptOwner ) );
	REQUIRES( passwordLength >= MIN_NAME_LENGTH && \
			  passwordLength < MAX_ATTRIBUTE_SIZE );

	/* In the interests of luser-proofing we force the use of a safe minimum 
	   number of iterations */
	status = krnlSendMessage( iCryptOwner, IMESSAGE_GETATTRIBUTE, &iterations,
							  CRYPT_OPTION_KEYING_ITERATIONS );
	if( cryptStatusError( status ) || iterations < MIN_KEYING_ITERATIONS )
		iterations = MIN_KEYING_ITERATIONS;

	/* Create an encryption context and derive the user password into it */
	status = createStrongEncryptionContext( &iCryptContext, iCryptOwner );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE,
							  &iterations, CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, ( void * ) password, passwordLength );
		status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEYING_VALUE );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Determine the size of the exported key and write the encrypted data
	   content field */
	status = iCryptExportKey( NULL, 0, &exportedKeySize, CRYPT_FORMAT_CMS, 
							  iSessionKeyContext, iCryptContext );
	if( cryptStatusOK( status ) )
		{
		void *dataPtr;
		int length;

		writeSet( stream, exportedKeySize );
		status = sMemGetDataBlockRemaining( stream, &dataPtr, &length );
		if( cryptStatusOK( status ) )
			{
			status = iCryptExportKey( dataPtr, length, &exportedKeySize,
									  CRYPT_FORMAT_CMS, iSessionKeyContext, 
									  iCryptContext );
			}
		if( cryptStatusOK( status ) )
			status = sSkip( stream, exportedKeySize );
		}

	/* Clean up */
	krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Write the private key wrapped using the session key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int writeWrappedPrivateKey( OUT_BUFFER( wrappedKeyMaxLength, \
											  *wrappedKeyLength ) 
									void *wrappedKey, 
								   IN_LENGTH_SHORT_MIN( 16 ) \
									const int wrappedKeyMaxLength,
								   OUT_LENGTH_SHORT_Z int *wrappedKeyLength,
								   IN_HANDLE const CRYPT_HANDLE iPrivKeyContext,
								   IN_HANDLE const CRYPT_CONTEXT iSessionKeyContext,
								   IN_ALGO const CRYPT_ALGO_TYPE pkcAlgo )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	STREAM encDataStream;
	int length = DUMMY_INIT, status;

	assert( isWritePtr( wrappedKey, wrappedKeyMaxLength ) );
	assert( isWritePtr( wrappedKeyLength, sizeof( int ) ) );

	REQUIRES( wrappedKeyMaxLength >= 16 && \
			  wrappedKeyMaxLength < MAX_INTLENGTH_SHORT );
	REQUIRES( isHandleRangeValid( iPrivKeyContext ) );
	REQUIRES( isHandleRangeValid( iSessionKeyContext ) );
	REQUIRES( pkcAlgo >= CRYPT_ALGO_FIRST_PKC && \
			  pkcAlgo <= CRYPT_ALGO_LAST_PKC );

	/* Clear return values */
	memset( wrappedKey, 0, min( 16, wrappedKeyMaxLength ) );
	*wrappedKeyLength = 0;

	/* Export the wrapped private key */
	setMechanismWrapInfo( &mechanismInfo, wrappedKey, wrappedKeyMaxLength, 
						  NULL, 0, iPrivKeyContext, iSessionKeyContext );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT,
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP );
	if( cryptStatusOK( status ) )
		length = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		return( status );
	*wrappedKeyLength = length;

	/* Try and check that the wrapped key data no longer contains 
	   identifiable structured data.  We can only do this for RSA keys 
	   because the amount of information present for DLP keys (a single 
	   short integer) is too small to reliably check.  This check is 
	   performed in addition to checks already performed by the encryption 
	   code and the key wrap code */
	if( pkcAlgo != CRYPT_ALGO_RSA )
		return( CRYPT_OK );

	/* For RSA keys the data would be:

		SEQUENCE {
			[3] INTEGER,
			...
			}

	   99.9% of all wrapped keys will fail the initial valid-SEQUENCE check 
	   so we provide an early-out for it */
	sMemConnect( &encDataStream, wrappedKey, *wrappedKeyLength );
	status = readSequence( &encDataStream, &length );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &encDataStream );
		return( CRYPT_OK );
		}

	/* The data must contain at least p and q, or at most all key 
	   components */
	if( length < MIN_PKCSIZE * 2 || length > MAX_PRIVATE_KEYSIZE )
		{
		sMemDisconnect( &encDataStream );
		return( CRYPT_OK );
		}

	/* The first key component is p, encoded as '[3] INTEGER' */
	status = readIntegerTag( &encDataStream, NULL, CRYPT_MAX_PKCSIZE, 
							 &length, 3 );
	if( cryptStatusOK( status ) && \
		( length < MIN_PKCSIZE || length > CRYPT_MAX_PKCSIZE ) )
		status = CRYPT_ERROR;
	sMemDisconnect( &encDataStream );
	if( cryptStatusError( status ) )
		return( CRYPT_OK );

	/* We appear to have plaintext data still present in the buffer, clear 
	   it and warn the user */
	zeroise( wrappedKey, wrappedKeyMaxLength );
	assert( DEBUG_WARN );
	return( CRYPT_ERROR_FAILED );
	}

/****************************************************************************
*																			*
*								Add a Private Key							*
*																			*
****************************************************************************/

/* Add a private key to a PKCS #15 collection */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 6, 10 ) ) \
int pkcs15AddPrivateKey( INOUT PKCS15_INFO *pkcs15infoPtr, 
						 IN_HANDLE const CRYPT_HANDLE iCryptContext,
						 IN_HANDLE const CRYPT_HANDLE iCryptOwner,
						 IN_BUFFER( passwordLength ) const char *password, 
						 IN_LENGTH_NAME const int passwordLength,
						 IN_BUFFER( privKeyAttributeSize ) \
							const void *privKeyAttributes, 
						 IN_LENGTH_SHORT const int privKeyAttributeSize,
						 IN_ALGO const CRYPT_ALGO_TYPE pkcCryptAlgo, 
						 IN_LENGTH_PKC const int modulusSize, 
						 INOUT ERROR_INFO *errorInfo )
	{
	CRYPT_CONTEXT iSessionKeyContext;
	MECHANISM_WRAP_INFO mechanismInfo;
	STREAM stream;
	BYTE envelopeHeaderBuffer[ 256 + 8 ];
	void *newPrivKeyData = pkcs15infoPtr->privKeyData;
	int newPrivKeyDataSize, newPrivKeyOffset = DUMMY_INIT;
	int privKeySize = DUMMY_INIT, extraDataSize = 0;
	int envelopeHeaderSize, envelopeContentSize, keyTypeTag, status;

	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( password, passwordLength ) );
	assert( isReadPtr( privKeyAttributes, privKeyAttributeSize ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( iCryptOwner ) );
	REQUIRES( passwordLength >= MIN_NAME_LENGTH && \
			  passwordLength < MAX_ATTRIBUTE_SIZE );
	REQUIRES( privKeyAttributeSize > 0 && \
			  privKeyAttributeSize < MAX_INTLENGTH_SHORT );
	REQUIRES( pkcCryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
			  pkcCryptAlgo <= CRYPT_ALGO_LAST_PKC );
	REQUIRES( modulusSize >= MIN_PKCSIZE && \
			  modulusSize <= CRYPT_MAX_PKCSIZE );
	REQUIRES( errorInfo != NULL );

	/* Get the tag for encoding the key data */
	status = getKeyTypeTag( CRYPT_UNUSED, pkcCryptAlgo, &keyTypeTag );
	if( cryptStatusError( status ) )
		return( status );

	/* Create a session key context and generate a key and IV into it.  The 
	   IV would be generated automatically later on when we encrypt data for 
	   the first time but we do it explicitly here to catch any possible 
	   errors at a point where recovery is easier */
	status = createStrongEncryptionContext( &iSessionKeyContext, iCryptOwner );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendNotifier( iSessionKeyContext, IMESSAGE_CTX_GENKEY );
	if( cryptStatusOK( status ) )
		status = krnlSendNotifier( iSessionKeyContext, IMESSAGE_CTX_GENIV );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't create session key to wrap private key" ) );
		}

	/* Calculate the eventual encrypted key size */
	setMechanismWrapInfo( &mechanismInfo, NULL, 0, NULL, 0, iCryptContext,
						  iSessionKeyContext );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT,
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP );
	if( cryptStatusOK( status ) )
		privKeySize = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	ENSURES( privKeySize <= 256 + MAX_PRIVATE_KEYSIZE );

	/* Write the CMS envelope header for the wrapped private key except for 
	   the outermost wrapper, which we have to defer writing until later 
	   since we won't know the wrapped session key or inner CMS header size 
	   until we've written them.  Since we're using KEKRecipientInfo we use 
	   a version of 2 rather than 0 */
	sMemOpen( &stream, envelopeHeaderBuffer, 256 );
	writeShortInteger( &stream, 2, DEFAULT_TAG );
	status = writeWrappedSessionKey( &stream, iSessionKeyContext,
									 iCryptOwner, password, passwordLength );
	if( cryptStatusOK( status ) )
		status = writeCMSencrHeader( &stream, OID_CMS_DATA, 
									 sizeofOID( OID_CMS_DATA ), privKeySize,
									 iSessionKeyContext );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't write envelope header for wrapping private "
				  "key" ) );
		}
	envelopeHeaderSize = stell( &stream );
	envelopeContentSize = envelopeHeaderSize + privKeySize;
	sMemDisconnect( &stream );

	/* Since we haven't been able to write the outer CMS envelope wrapper 
	   yet we need to adjust the overall size for the additional level of
	   encapsulation */
	privKeySize = ( int ) sizeofObject( privKeySize + envelopeHeaderSize );

	/* Calculate the private-key storage size */
	if( pkcCryptAlgo == CRYPT_ALGO_RSA )
		{
		/* RSA keys have an extra element for PKCS #11 compatibility */
		extraDataSize = sizeofShortInteger( modulusSize );
		}
	status = calculatePrivkeyStorage( pkcs15infoPtr, &newPrivKeyData,
									  &newPrivKeyDataSize, privKeySize, 
									  privKeyAttributeSize, 
									  extraDataSize );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	sMemOpen( &stream, newPrivKeyData, newPrivKeyDataSize );

	/* Write the outer header and attributes */
	writeConstructed( &stream, privKeyAttributeSize + \
							   sizeofObject( sizeofObject( privKeySize ) + \
											 extraDataSize ),
					  keyTypeTag );
	swrite( &stream, privKeyAttributes, privKeyAttributeSize );
	writeConstructed( &stream, sizeofObject( privKeySize + extraDataSize ), 
					  CTAG_OB_TYPEATTR );
	status = writeSequence( &stream, privKeySize + extraDataSize );
	if( cryptStatusOK( status ) )
		newPrivKeyOffset = stell( &stream );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
		if( newPrivKeyData != pkcs15infoPtr->privKeyData )
			clFree( "addPrivateKey", newPrivKeyData );
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't write private key attributes" ) );
		}

	/* Write the previously-encoded CMS envelope header and key exchange
	   information and follow it with the encrypted private key.  Since we
	   now know the size of the envelope header (which we couldn't write
	   earlier) we can add this now too */
	writeConstructed( &stream, envelopeContentSize, CTAG_OV_DIRECTPROTECTED );
	status = swrite( &stream, envelopeHeaderBuffer, envelopeHeaderSize );
	if( cryptStatusOK( status ) )
		{
		void *dataPtr;
		int length;

		status = sMemGetDataBlockRemaining( &stream, &dataPtr, &length );
		if( cryptStatusOK( status ) )
			status = writeWrappedPrivateKey( dataPtr, length, &privKeySize, 
											 iCryptContext, iSessionKeyContext, 
											 pkcCryptAlgo );
		}
	if( cryptStatusOK( status ) )
		status = sSkip( &stream, privKeySize );
	if( cryptStatusOK( status ) && pkcCryptAlgo == CRYPT_ALGO_RSA )
		{
		/* RSA keys have an extra element for PKCS #11 compability that we
		   need to kludge onto the end of the private-key data */
		status = writeShortInteger( &stream, modulusSize, DEFAULT_TAG );
		}
	krnlSendNotifier( iSessionKeyContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't wrap private key using session key" ) );
		}
	assert( newPrivKeyDataSize == stell( &stream ) );
	sMemDisconnect( &stream );
	ENSURES( !cryptStatusError( checkObjectEncoding( newPrivKeyData, \
													 newPrivKeyDataSize ) ) );

	/* Replace the old data with the newly-written data */
	replacePrivkeyData( pkcs15infoPtr, newPrivKeyData, 
						newPrivKeyDataSize, newPrivKeyOffset );
	return( CRYPT_OK );
	}
#endif /* USE_PKCS15 */
