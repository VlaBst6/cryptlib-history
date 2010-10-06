/****************************************************************************
*																			*
*						cryptlib PKCS #12 Write Routines					*
*						Copyright Peter Gutmann 1997-2002					*
*																			*
****************************************************************************/

/* This code is based on breakms.c, which breaks the encryption of several of
   MS's extremely broken PKCS #12 implementations.  Because of the security
   problems associated with key files produced by MS software and the fact
   that this format is commonly used to spray private keys around without any
   regard to their sensitivity, cryptlib doesn't support it as a writeable
   format.  As one vendor who shall remain anonymous put it, "We don't want 
   to put our keys anywhere where MS software can get to them" */

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "keyset.h"
  #include "pkcs12.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "enc_dec/asn1_ext.h"
  #include "keyset/keyset.h"
  #include "keyset/pkcs12.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS12

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/****************************************************************************
*																			*
*									Write a Key								*
*																			*
****************************************************************************/

/* Write the PKCS #12 mangling of a CMS wrapper */

static int writeNonCMSheader( STREAM *stream, const BYTE *oid,
							   const int length, const int attrDataLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( oid != NULL );
	assert( length > 0 );
	assert( attrDataLength > 0 );

	writeSequence( stream, ( int ) \
				   ( sizeofOID( oid ) + \
				     sizeofObject( sizeofObject( length ) ) + \
					 sizeofObject( attrDataLength ) ) );
	writeOID( stream, oid );
	writeConstructed( stream, ( int ) sizeofObject( length ), 0 );
	return( writeSequence( stream, length ) );
	}

/* Write a PKCS #12 item ("safeBag").  We can't write this directly to the
   output stream but have to buffer it via an intermediate stream so that we 
   can MAC it */

static int writeItem( STREAM *stream, const PKCS12_INFO *pkcs12info,
					  const BOOLEAN isPrivateKey, const BOOLEAN macData )
	{
	const PKCS12_OBJECT_INFO *pkcs12objectInfo = \
			isPrivateKey ? &pkcs12info->keyInfo : &pkcs12info->certInfo;
	STREAM memStream;
	BYTE buffer[ 256 + 8 ];
	const int idDataSize = ( int ) \
						( sizeofOID( OID_PKCS9_LOCALKEYID ) + \
						  sizeofObject( \
							sizeofObject( 1 ) ) );
	const int labelDataSize = ( int ) \
						( sizeofOID( OID_PKCS9_FRIENDLYNAME ) + \
						  sizeofObject( \
							sizeofObject( pkcs12info->labelLength * 2 ) ) );
	const int attrDataSize = ( int ) \
						( sizeofObject( idDataSize ) + \
						  sizeofObject( labelDataSize ) );
	int i, j, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( pkcs12info, sizeof( PKCS12_INFO ) ) );

	/* Write the item wrapper and item data */
	sMemOpen( &memStream, buffer, 256 );
	if( isPrivateKey )
		{
		writeNonCMSheader( &memStream, OID_PKCS12_SHROUDEDKEYBAG,
						   pkcs12objectInfo->dataSize, attrDataSize );
		}
	else
		{
		writeNonCMSheader( &memStream, OID_PKCS12_CERTBAG, ( int ) \
						   ( sizeofOID( OID_PKCS9_X509CERTIFICATE ) + \
							 sizeofObject( \
								sizeofObject( pkcs12objectInfo->dataSize ) ) ),
							 attrDataSize );
		writeOID( &memStream, OID_PKCS9_X509CERTIFICATE );
		writeConstructed( &memStream, ( int ) \
						  sizeofObject( pkcs12objectInfo->dataSize ), 0 );
		writeOctetStringHole( &memStream, pkcs12objectInfo->dataSize, 
							  DEFAULT_TAG );
		}
	assert( stell( &memStream ) < 256 );
	swrite( stream, buffer, stell( &memStream ) );
	status = swrite( stream, pkcs12objectInfo->data, 
					 pkcs12objectInfo->dataSize );
	if( cryptStatusError( status ) )
		{
		sMemClose( &memStream );
		return( status );
		}

	/* Mac the payload data if necessary */
	if( macData )
		{
		status = krnlSendMessage( pkcs12info->iMacContext, IMESSAGE_CTX_HASH,
								  buffer, stell( &memStream ) );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( pkcs12info->iMacContext, 
									  IMESSAGE_CTX_HASH, 
									  ( MESSAGE_CAST ) pkcs12objectInfo->data, 
									  pkcs12objectInfo->dataSize );
			}
		if( cryptStatusError( status ) )
			{
			sMemClose( &memStream );
			return( status );
			}
		}
	sMemClose( &memStream );

	/* Write the item's ID and label.  These are supposedly optional, but
	   some apps will break if they're not present.  We have to keep the ID
	   short (rather than using, say, a keyID) because some apps assume that 
	   it's a 32-bit int or a similar type of value */
	sMemOpen( &memStream, buffer, 256 );
	writeSet( &memStream, attrDataSize );
	writeSequence( &memStream, idDataSize );
	writeOID( &memStream, OID_PKCS9_LOCALKEYID );
	writeSet( &memStream, sizeofObject( 1 ) );
	writeOctetStringHole( &memStream, 1, DEFAULT_TAG );
	sputc( &memStream, pkcs12info->index );
	writeSequence( &memStream, labelDataSize );
	writeOID( &memStream, OID_PKCS9_FRIENDLYNAME );
	writeSet( &memStream, ( int ) sizeofObject( pkcs12info->labelLength * 2 ) );
	writeGenericHole( &memStream, pkcs12info->labelLength * 2,
					  BER_STRING_BMP );
	for( i = 0, j = 0; i < pkcs12info->labelLength && \
					   i < CRYPT_MAX_TEXTSIZE; i++ )
		{
		/* Convert the ASCII string into a BMP string */
		sputc( &memStream, 0 );
		sputc( &memStream, pkcs12info->label[ i ] );
		}
	if( i >= CRYPT_MAX_TEXTSIZE )
		retIntError();
	assert( stell( &memStream ) < 256 );
	status = swrite( stream, buffer, stell( &memStream ) );
	if( cryptStatusError( status ) )
		{
		sMemClose( &memStream );
		return( status );
		}

	/* Mac the attribute data if necessary */
	if( macData )
		{
		status = krnlSendMessage( pkcs12info->iMacContext, 
								  IMESSAGE_CTX_HASH, buffer, 
								  stell( &memStream ) );
		if( cryptStatusError( status ) )
			{
			sMemClose( &memStream );
			return( status );
			}
		}
	sMemClose( &memStream );

	return( CRYPT_OK );
	}

/* Flush a PKCS #12 collection to a stream */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int pkcs12Flush( INOUT STREAM *stream, 
				 IN_ARRAY( noPkcs12objects ) const PKCS12_INFO *pkcs12info, 
				 IN_LENGTH_SHORT const int noPkcs12objects )
	{
	STREAM memStream;
	MESSAGE_DATA msgData;
	BYTE buffer[ 32 + 8 ];
	BOOLEAN privateKeyPresent = FALSE;
	int safeDataSize = DUMMY_INIT, authSafeDataSize, macDataSize;
	int i, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( pkcs12info, \
					   sizeof( PKCS12_INFO ) * noPkcs12objects ) );

	REQUIRES( noPkcs12objects >= 1 && \
			  noPkcs12objects < MAX_INTLENGTH_SHORT );

	/* Determine the overall size of the objects */
	sMemNullOpen( &memStream );
	for( i = 0; i < noPkcs12objects && i < FAILSAFE_ITERATIONS_MED; i++ )
		{
		if( pkcs12info[ i ].keyInfo.dataSize > 0 )
			{
			privateKeyPresent = TRUE;
			status = writeItem( &memStream, pkcs12info, TRUE, FALSE );
			}
		if( pkcs12info[ i ].certInfo.dataSize > 0 )
			status = writeItem( &memStream, pkcs12info, FALSE, FALSE );
		}
	ENSURES( i < FAILSAFE_ITERATIONS_MED );
	if( cryptStatusOK( status ) )
		safeDataSize = stell( &memStream );
	sMemClose( &memStream );
	if( cryptStatusError( status ) )
		return( status );
	if( !privateKeyPresent )
		{
		/* If there's no data present, let the caller know that the keyset
		   is empty */
		return( OK_SPECIAL );
		}
	authSafeDataSize = ( int ) \
					sizeofObject( \
						sizeofObject( \
							sizeofOID( OID_CMS_DATA ) + \
							sizeofObject( \
								sizeofObject( sizeofObject( safeDataSize ) ) ) ) );
	macDataSize = ( int ) \
				sizeofObject( \
					sizeofAlgoID( CRYPT_ALGO_SHA ) + \
					sizeofObject( 20 ) ) + \
				sizeofObject( pkcs12info->macSaltSize ) + \
				sizeofShortInteger( pkcs12info->macIterations );

	/* Write the outermost (authSafe) layer of cruft */
	writeSequence( stream, ( int ) \
				   sizeofShortInteger( 3 ) + \
				   sizeofObject( \
						sizeofOID( OID_CMS_DATA ) + \
						sizeofObject( \
							sizeofObject( authSafeDataSize ) ) ) + \
				   sizeofObject( macDataSize ) );
	writeShortInteger( stream, 3, DEFAULT_TAG );
	status = writeCMSheader( stream, OID_CMS_DATA, sizeofOID( OID_CMS_DATA ),
							 authSafeDataSize, TRUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Create an intermediate memory stream so we can MAC the data before we
	   write it to disk */
	sMemOpen( &memStream, buffer, 32 );

	/* Write and MAC the next layer (safe) of cruft */
	writeSequence( &memStream, ( int ) \
				   sizeofObject( \
						sizeofOID( OID_CMS_DATA ) + \
						sizeofObject( \
							sizeofObject( sizeofObject( safeDataSize ) ) ) ) );
	status = writeCMSheader( &memStream, OID_CMS_DATA, 
							 sizeofOID( OID_CMS_DATA ),
							 sizeofObject( safeDataSize ), TRUE );
	if( cryptStatusOK( status ) )
		{
		writeSequence( &memStream, safeDataSize );
		assert( stell( &memStream ) < 32 );
		swrite( stream, buffer, stell( &memStream ) );
		status = krnlSendMessage( pkcs12info->iMacContext, 
								  IMESSAGE_CTX_HASH, buffer, 
								  stell( &memStream ) );
		}
	sMemClose( &memStream );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the individual objects */
	for( i = 0; cryptStatusOK( status ) && i < MAX_PKCS12_OBJECTS; i++ )
		{
		if( pkcs12info[ i ].keyInfo.dataSize > 0 )
			writeItem( stream, pkcs12info, TRUE, TRUE );
		if( pkcs12info[ i ].certInfo.dataSize > 0 )
			writeItem( stream, pkcs12info, FALSE, TRUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Wrap up the MACing and write the MAC data.  Despite the fact that the
	   algorithm being used is HMAC, the OID we have to write is the one for 
	   plain SHA-1 */
	status = krnlSendMessage( pkcs12info->iMacContext, IMESSAGE_CTX_HASH, 
							  "", 0 );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( pkcs12info->iMacContext, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	writeSequence( stream, macDataSize );
	writeSequence( stream, sizeofAlgoID( CRYPT_ALGO_SHA ) + \
						   sizeofObject( 20 ) );
	writeAlgoID( stream, CRYPT_ALGO_SHA );
	writeOctetString( stream, buffer, msgData.length, DEFAULT_TAG );
	writeOctetString( stream, pkcs12info->macSalt, pkcs12info->macSaltSize,
					  DEFAULT_TAG );
	status = writeShortInteger( stream, pkcs12info->macIterations, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );

	return( sflush( stream ) );
	}

/****************************************************************************
*																			*
*									Add a Key								*
*																			*
****************************************************************************/

/* Write an encrypted private key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writePrivateKey( INOUT PKCS12_OBJECT_INFO *keyObjectInfo,
							IN_HANDLE const CRYPT_HANDLE iPrivKeyContext,
							IN_HANDLE const CRYPT_HANDLE iKeyWrapContext )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	STREAM stream;
	int privKeyInfoSize, pbeInfoDataSize, status;

	assert( isWritePtr( keyObjectInfo, sizeof( PKCS12_OBJECT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iPrivKeyContext ) );
	REQUIRES( isHandleRangeValid( iKeyWrapContext ) );

	/* Calculate the eventual encrypted key size and allocate storage for it */
	setMechanismWrapInfo( &mechanismInfo, NULL, 0, NULL, 0, iPrivKeyContext,
						  iKeyWrapContext );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT, 
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP_PKCS8 );
	privKeyInfoSize = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( ( keyObjectInfo->data = clAlloc( "setItemFunction", \
										 privKeyInfoSize + 64 ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	keyObjectInfo->dataSize = privKeyInfoSize + 64;

	/* Calculate the size of the key-derivation information */
	pbeInfoDataSize = ( int ) sizeofObject( keyObjectInfo->saltSize ) + \
							  sizeofShortInteger( keyObjectInfo->iterations );

	/* Write the key-derivation information */
	sMemOpen( &stream, ( void * ) keyObjectInfo->data, 
			  keyObjectInfo->dataSize );
	writeSequence( &stream,
				   sizeofOID( OID_PKCS12_PBEWITHSHAAND3KEYTRIPLEDESCBC ) + \
				   ( int ) sizeofObject( pbeInfoDataSize ) );
	writeOID( &stream, OID_PKCS12_PBEWITHSHAAND3KEYTRIPLEDESCBC );
	writeSequence( &stream, pbeInfoDataSize );
	writeOctetString( &stream, keyObjectInfo->salt, keyObjectInfo->saltSize, 
					  DEFAULT_TAG );
	writeShortInteger( &stream, keyObjectInfo->iterations, DEFAULT_TAG );
	status = writeOctetStringHole( &stream, privKeyInfoSize, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}
	ENSURES( rangeCheck( stell( &stream ), privKeyInfoSize, 
						 keyObjectInfo->dataSize ) );

	/* Write the wrapped key. This will be a read-only object, but in order 
	   to intialise it we have to temporarily make it non-const */
	setMechanismWrapInfo( &mechanismInfo,
						  ( BYTE * ) keyObjectInfo->data + \
									 ( int ) stell( &stream ),
						  privKeyInfoSize, NULL, 0, iPrivKeyContext,
						  iKeyWrapContext );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_EXPORT, 
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP_PKCS8 );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}
	keyObjectInfo->dataSize = ( int ) stell( &stream ) + privKeyInfoSize;
	sMemDisconnect( &stream );
	ENSURES( !cryptStatusError( \
					checkObjectEncoding( keyObjectInfo->data, \
										 keyObjectInfo->dataSize ) ) );

	return( CRYPT_OK );
	}

/* Add an item to the PKCS #12 keyset */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int setItemFunction( INOUT KEYSET_INFO *keysetInfoPtr,
							IN_HANDLE const CRYPT_HANDLE cryptHandle,
							IN_ENUM( KEYMGMT_ITEM ) \
								const KEYMGMT_ITEM_TYPE itemType,
							IN_BUFFER_OPT( passwordLength ) const char *password, 
							IN_LENGTH_NAME_Z const int passwordLength,
							IN_FLAGS( KEYMGMT ) const int flags )
	{
	CRYPT_CONTEXT iKeyWrapContext;
	CRYPT_ALGO_TYPE cryptAlgo;
	PKCS12_INFO *pkcs12info = keysetInfoPtr->keyData;
	PKCS12_OBJECT_INFO *keyObjectInfo = &pkcs12info->keyInfo;
	BOOLEAN certPresent = FALSE, contextPresent;
	BOOLEAN pkcs12keyPresent = ( keyObjectInfo->dataSize > 0 ) ? TRUE : FALSE;
	const int noPkcs12objects = keysetInfoPtr->keyDataNoObjects;
	int value, status;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );
	assert( isWritePtr( pkcs12info, \
						sizeof( PKCS12_INFO ) * noPkcs12objects ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS12 );
	REQUIRES( isHandleRangeValid( cryptHandle ) );
	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			  itemType == KEYMGMT_ITEM_PRIVATEKEY || \
			  itemType == KEYMGMT_ITEM_SECRETKEY || \
			  itemType == KEYMGMT_ITEM_KEYMETADATA );
	REQUIRES( ( password == NULL && passwordLength == 0 ) || \
			  ( password != NULL && \
				passwordLength >= MIN_NAME_LENGTH && \
				passwordLength < MAX_ATTRIBUTE_SIZE ) );
	REQUIRES( ( ( itemType == KEYMGMT_ITEM_PUBLICKEY || \
				  itemType == KEYMGMT_ITEM_KEYMETADATA ) && \
				password == NULL && passwordLength == 0 ) || \
			  ( ( itemType == KEYMGMT_ITEM_PRIVATEKEY || \
				  itemType == KEYMGMT_ITEM_SECRETKEY ) && \
				password != NULL && passwordLength != 0 ) );
	REQUIRES( flags == KEYMGMT_FLAG_NONE );

	/* If there's already a key and certificate present, we can't add 
	   anything else.  This check also catches the (invalid) case of a 
	   certificate being present without a corresponding private key */
	if( pkcs12info->certInfo.dataSize > 0 )
		{
		retExt( CRYPT_ERROR_OVERFLOW, 
				( CRYPT_ERROR_OVERFLOW, KEYSET_ERRINFO, 
				  "No more room in keyset to add this item" ) );
		}

	/* Check the object and extract ID information from it */
	status = krnlSendMessage( cryptHandle, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_PKC );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
								  &cryptAlgo, CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) && cryptAlgo != CRYPT_ALGO_RSA )
			{
			retExtArg( CRYPT_ARGERROR_NUM1, 
					   ( CRYPT_ARGERROR_NUM1, KEYSET_ERRINFO, 
						 "PKCS #12 keysets can only store RSA keys and "
						 "certificates" ) );
			}
		}
	if( cryptStatusError( status ) )
		{
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
		}
	contextPresent = cryptStatusOK( krnlSendMessage( cryptHandle,
								IMESSAGE_CHECK, NULL,
								MESSAGE_CHECK_PKC_PRIVATE ) ) ? TRUE : FALSE;

	/* If there's a certificate present, make sure that it's something that 
	   can be stored.  We don't treat the wrong type as an error since we 
	   can still store the public/private key components even if we don't 
	   store the certificate */
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) && \
		( value == CRYPT_CERTTYPE_CERTIFICATE || \
		  value == CRYPT_CERTTYPE_CERTCHAIN ) )
		{
		/* If the certificate isn't signed, we can't store it in this 
		   state */
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
								  &value, CRYPT_CERTINFO_IMMUTABLE );
		if( cryptStatusError( status ) || !value )
			{
			retExt( CRYPT_ERROR_NOTINITED, 
					( CRYPT_ERROR_NOTINITED, KEYSET_ERRINFO, 
					  "Certificate being added is incomplete (unsigned)" ) );
			}
		certPresent = TRUE;
		if( !pkcs12keyPresent )
			{
			/* We can't add a certificate unless there's already a key 
			   present.  Since PKCS #12 doesn't store any indexing 
			   information we have no idea whether the two actually belong 
			   together, so we just have to hope for the best */
			retExt( CRYPT_ERROR_NOTINITED, 
					( CRYPT_ERROR_NOTINITED, KEYSET_ERRINFO, 
					  "No key present that corresponds to the certificate "
					  "being added" ) );
			}
		}
	else
		{
		/* If we're trying to add a standalone key and there's already one
		   present, we can't add another one */
		if( pkcs12keyPresent )
			{
			retExt( CRYPT_ERROR_INITED, 
					( CRYPT_ERROR_INITED, KEYSET_ERRINFO, 
					  "No more room in keyset to add this item" ) );
			}
		}

	/* If we're adding a private key, make sure that there's a password 
	   present.  Conversely, if there's a password present make sure that 
	   we're adding a private key */
	if( pkcs12keyPresent )
		{
		/* We're adding a certificate, there can't be a password present.  
		   Some PKCS #12 implementations encrypt public certificates for no
		   adequately explained reason, we always store them as plaintext
		   since they are, after all, *public* certificates */
		if( password != NULL )
			return( CRYPT_ARGERROR_NUM1 );
		}
	else
		{
		/* We're adding a private key, there must be a password present */
		if( password == NULL )
			return( CRYPT_ARGERROR_STR1 );
		}

	/* Get what little index information PKCS #12 stores with a key */
	if( !pkcs12keyPresent )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, pkcs12info->label, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_LABEL );
		if( cryptStatusError( status ) )
			return( status );
		pkcs12info->labelLength = msgData.length;
		pkcs12info->index = 1;
		}

	/* We're ready to go, lock the object for our exclusive use */
	status = krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_CURSORFIRST,
							  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		( void ) krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_FALSE, 
								  CRYPT_IATTRIBUTE_LOCKED );
		return( status );
		}

	/* Write the certificate if necessary.  We do this one first because 
	   it's the easiest to back out of.  PKCS #12 only stores the individual
	   certificate that's associated with the private key rather than a
	   complete certificate chain, so we only add the leaf certificate 
	   rather than all certificates in the chain */
	if( certPresent )
		{
		PKCS12_OBJECT_INFO *certObjectInfo = &pkcs12info->certInfo;
		MESSAGE_DATA msgData;

		/* Get the encoded certificate */
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( cryptHandle, IMESSAGE_CRT_EXPORT,
								  &msgData, 
								  CRYPT_CERTFORMAT_CERTIFICATE );
		if( cryptStatusOK( status ) && \
			( certObjectInfo->data = clAlloc( "setItemFunction", \
											  msgData.length ) ) == NULL )
			status = CRYPT_ERROR_MEMORY;
		if( cryptStatusOK( status ) )
			{
			msgData.data = ( void * ) certObjectInfo->data;
			status = krnlSendMessage( cryptHandle, IMESSAGE_CRT_EXPORT,
									  &msgData, 
									  CRYPT_CERTFORMAT_CERTIFICATE );
			if( cryptStatusOK( status ) )
				certObjectInfo->dataSize = msgData.length;
			else
				{
				clFree( "setItemFunction", 
						( void * ) certObjectInfo->data );
				certObjectInfo->data = NULL;
				}
			}

		/* If there's no context to add, return now */
		if( cryptStatusError( status ) || pkcs12keyPresent )
			{
			( void ) krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
									  MESSAGE_VALUE_FALSE, 
									  CRYPT_IATTRIBUTE_LOCKED );
			retExt( status, 
					( status, KEYSET_ERRINFO, 
					  "Couldn't extract certificate data from "
					  "certificate" ) );
			}
		}

	/* Create the key wrap context and the MAC context (if necessary) from 
	   the password */
	status = createPkcs12KeyWrapContext( keyObjectInfo, 
										 keysetInfoPtr->ownerHandle, 
										 password, passwordLength,
										 &iKeyWrapContext, TRUE );
	if( cryptStatusOK( status ) && pkcs12info->iMacContext == CRYPT_ERROR )
		{
		status = createPkcs12MacContext( pkcs12info, 
										 keysetInfoPtr->ownerHandle, 
										 password, passwordLength, 
										 &pkcs12info->iMacContext, FALSE );
		}
	if( cryptStatusError( status ) )
		{
		pkcs12freeEntry( pkcs12info );
		( void ) krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_FALSE, 
								  CRYPT_IATTRIBUTE_LOCKED );
		retExt( status, 
				( status, KEYSET_ERRINFO, 
				  "Couldn't create session/MAC key to secure private "
				  "key" ) );
		}
	pkcs12info->macInitialised = TRUE;

	/* Write the encrypted and MACed private key */
	status = writePrivateKey( keyObjectInfo, cryptHandle, 
							  iKeyWrapContext );
	( void ) krnlSendMessage( cryptHandle, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_FALSE, 
							  CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		{
		pkcs12freeEntry( pkcs12info );
		krnlSendNotifier( iKeyWrapContext, IMESSAGE_DECREFCOUNT );
		retExt( status, 
				( status, KEYSET_ERRINFO, 
				  "Couldn't write wrapped private key data" ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Keyset Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initPKCS12set( INOUT KEYSET_INFO *keysetInfoPtr )
	{
	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS12 );

	/* Set the access method pointers */
	keysetInfoPtr->setItemFunction = setItemFunction;

	return( CRYPT_OK );
	}
#endif /* USE_PKCS12 */
