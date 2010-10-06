/****************************************************************************
*																			*
*						cryptlib PKCS #12 Read Routines						*
*						Copyright Peter Gutmann 1997-2010					*
*																			*
****************************************************************************/

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

/* OID information used to read a PKCS #12 keyset */

static const CMS_CONTENT_INFO FAR_BSS oidInfoEncryptedData = { 0, 2 };

static const FAR_BSS OID_INFO keyDataOIDinfo[] = {
	{ OID_CMS_ENCRYPTEDDATA, TRUE, &oidInfoEncryptedData },
	{ OID_CMS_DATA, FALSE },
	{ NULL, 0 }, { NULL, 0 }
	};

static const FAR_BSS OID_INFO keyBagOIDinfo[] = {
	{ OID_PKCS12_SHROUDEDKEYBAG, 0 },
	{ NULL, 0 }, { NULL, 0 }
	};

/* OID information used to read decrypted PKCS #12 objects */

static const FAR_BSS OID_INFO certBagOIDinfo[] = {
	{ OID_PKCS12_CERTBAG, 0 },
	{ NULL, 0 }, { NULL, 0 }
	};
static const FAR_BSS OID_INFO certOIDinfo[] = {
	{ OID_PKCS9_X509CERTIFICATE, 0 },
	{ NULL, 0 }, { NULL, 0 }
	};

/* Protection algorithms used for encrypted keys and certificates, and a 
   mapping from PKCS #12 to cryptlib equivalents.  Beyond these there are
   also 40- and 128-bit RC4 and 128-bit RC2, but nothing seems to use
   them.  40-bit RC2 is used by Windows to, uhh, "protect" public
   certificates so we have to support it in order to be able to read
   certificates (see the comment in keymgmt/pkcs12.c for details on how
   the 40-bit RC2 key is handled) */

enum { PKCS12_ALGO_NONE, PKCS12_ALGO_3DES_192, PKCS12_ALGO_3DES_128, 
	   PKCS12_ALGO_RC2_40 };

typedef struct {
	const CRYPT_ALGO_TYPE cryptAlgo;
	const int keySize;
	} PKCS12_ALGO_MAP;

static const PKCS12_ALGO_MAP algoMap3DES_192 = { CRYPT_ALGO_3DES, bitsToBytes( 192 ) };
static const PKCS12_ALGO_MAP algoMap3DES_128 = { CRYPT_ALGO_3DES, bitsToBytes( 128 ) };
static const PKCS12_ALGO_MAP algoMapRC2_40 = { CRYPT_ALGO_RC2, bitsToBytes( 40 ) };

static const FAR_BSS OID_INFO encryptionOIDinfo[] = {
	{ OID_PKCS12_PBEWITHSHAAND3KEYTRIPLEDESCBC, PKCS12_ALGO_3DES_192, 
	  &algoMap3DES_192 },
	{ OID_PKCS12_PBEWITHSHAAND2KEYTRIPLEDESCBC, PKCS12_ALGO_3DES_128,
	  &algoMap3DES_128 },
	{ OID_PKCS12_PBEWITHSHAAND40BITRC2CBC, PKCS12_ALGO_RC2_40,
	  &algoMapRC2_40 },
	{ NULL, 0 }, { NULL, 0 }
	};

/* PKCS #12 attributes.  This is a subset of the full range that can be 
   used, we skip any that we don't care about using a wildcard OID match */

enum { PKCS12_ATTRIBUTE_NONE, PKCS12_ATTRIBUTE_LABEL, PKCS12_ATTRIBUTE_ID };

static const FAR_BSS OID_INFO attributeOIDinfo[] = {
	{ OID_PKCS9_FRIENDLYNAME, PKCS12_ATTRIBUTE_LABEL },
	{ OID_PKCS9_LOCALKEYID, PKCS12_ATTRIBUTE_ID },
	{ WILDCARD_OID, PKCS12_ATTRIBUTE_NONE },
	{ NULL, 0 }, { NULL, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Read protection algorithm information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readProtAlgoInfo( INOUT STREAM *stream, 
							 OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
							 OUT_INT_SHORT_Z int *keySize )
	{
	const OID_INFO *oidInfoPtr;
	const PKCS12_ALGO_MAP *algoMapInfoPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtr( keySize, sizeof( int ) ) );

	/* Clear return values */
	*cryptAlgo = CRYPT_ALGO_NONE;
	*keySize = CRYPT_ERROR;

	/* Read the wrapper and the protection algorithm OID and extract the
	   protection information parameters for it */
	readSequence( stream, NULL );
	status = readOIDEx( stream, encryptionOIDinfo, 
						FAILSAFE_ARRAYSIZE( encryptionOIDinfo, OID_INFO ), 
						&oidInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	algoMapInfoPtr = oidInfoPtr->extraInfo;
	*cryptAlgo = algoMapInfoPtr->cryptAlgo;
	*keySize = algoMapInfoPtr->keySize;

	return( CRYPT_OK );
	}

/* Read key-derivation information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
static int readKeyDerivationInfo( INOUT STREAM *stream, 
								  OUT_BUFFER( saltMaxLen, *saltLen ) void *salt,
								  IN_LENGTH_SHORT_MIN( 16 ) const int saltMaxLen,
								  OUT_LENGTH_SHORT_Z int *saltLen,
								  OUT_INT_SHORT_Z int *iterations )
	{
	long intValue;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( salt, saltMaxLen ) );
	assert( isWritePtr( saltLen, sizeof( int ) ) );
	assert( isWritePtr( iterations, sizeof( int ) ) );

	REQUIRES( saltMaxLen >= 16 && saltMaxLen < MAX_INTLENGTH_SHORT );

	/* Clear return values */
	memset( salt, 0, min( 16, saltMaxLen ) );
	*saltLen = *iterations = 0;

	/* Read the wrapper and salt value */
	readSequence( stream, NULL );
	status = readOctetString( stream, salt, saltLen, 1, saltMaxLen );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the iteration count and make sure that it's within a sensible
	   range */
	status = readShortInteger( stream, &intValue );
	if( cryptStatusError( status ) )
		return( status );
	if( intValue < 1 || intValue >= MAX_KEYSETUP_ITERATIONS )
		return( CRYPT_ERROR_BADDATA );
	*iterations = ( int ) intValue;

	return( CRYPT_OK );
	}

/* Unwrap and import an encrypted certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5, 7 ) ) \
static int importCertificate( const PKCS12_OBJECT_INFO *certObjectInfo,
							  IN_HANDLE const CRYPT_USER cryptOwner,
							  IN_BUFFER( passwordLen ) const void *password,
							  IN_LENGTH_NAME const int passwordLen,
							  INOUT_BUFFER_FIXED( certObjectDataLen ) \
									void *certObjectData,
							  IN_LENGTH_SHORT const int certObjectDataLen,
							  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iDataCert )
	{
	CRYPT_CONTEXT iWrapContext;
	STREAM stream;
	long length;
	int certDataSize, status;

	assert( isReadPtr( certObjectInfo, sizeof( PKCS12_OBJECT_INFO ) ) );
	assert( isReadPtr( password, passwordLen ) );
	assert( isWritePtr( certObjectData, certObjectDataLen ) );
	assert( isWritePtr( iDataCert, sizeof( CRYPT_CERTIFICATE ) ) );

	REQUIRES( cryptOwner == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( cryptOwner ) );
	REQUIRES( passwordLen >= MIN_NAME_LENGTH && \
			  passwordLen <= CRYPT_MAX_TEXTSIZE );
	REQUIRES( certObjectDataLen > MIN_OBJECT_SIZE && \
			  certObjectDataLen < MAX_INTLENGTH_SHORT );

	/* Clear return value */
	*iDataCert = CRYPT_ERROR;

	/* Create the wrap context used to decrypt the public certificate data */
	status = createPkcs12KeyWrapContext( ( PKCS12_OBJECT_INFO * ) certObjectInfo, 
										 cryptOwner, password, passwordLen, 
										 &iWrapContext, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Decrypt the certificate */
	status = krnlSendMessage( iWrapContext, IMESSAGE_CTX_DECRYPT, 
							  certObjectData, certObjectDataLen );
	krnlSendNotifier( iWrapContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the decryption succeeded.  We have to be a bit careful
	   here because there are so many garbled certificates used with the
	   equally-garbled PKCS #12 format that an invalid object doesn't
	   necessarily imply that an incorrect decryption key was used.  To 
	   avoid false positives, if we get an invalid encoding we try and read 
	   the outer layer of wrapping around the certificate object, and if 
	   that succeeds then it's a valid decrypt of a garbled certificate 
	   rather than an invalid key leading to an invalid certificate */
	status = length = checkObjectEncoding( certObjectData, 
										   certObjectDataLen );
	if( cryptStatusError( status ) )
		{
		sMemConnect( &stream, certObjectData, certObjectDataLen );
		readSequence( &stream, NULL );
		status = readSequence( &stream, NULL );
		sMemDisconnect( &stream );
		return( cryptStatusError( status ) ? \
				CRYPT_ERROR_WRONGKEY : CRYPT_ERROR_BADDATA );
		}
	certDataSize = length;

	/* Import the certificate as a data-only certificate.  At this point we 
	   have two redundant CMS headers, one within the other, with the nested 
	   inner header of the outer CMS header being the start of the inner CMS 
	   header.  To handle this we read the outer CMS header with the 
	   READCMS_FLAG_WRAPPERONLY flag set to avoid reading the start of the
	   inner header, which is then read by the second readCMSheader() 
	   call */
	sMemConnect( &stream, certObjectData, certDataSize );
	readSequence( &stream, NULL );
	status = readCMSheader( &stream, certBagOIDinfo, 
							FAILSAFE_ARRAYSIZE( certBagOIDinfo, OID_INFO ), 
							NULL, READCMS_FLAG_WRAPPERONLY );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	status = readCMSheader( &stream, certOIDinfo, 
							FAILSAFE_ARRAYSIZE( certOIDinfo, OID_INFO ), 
							&length, READCMS_FLAG_INNERHEADER | \
									 READCMS_FLAG_DEFINITELENGTH );
	if( cryptStatusOK( status ) && \
		( length < MIN_OBJECT_SIZE || length > MAX_INTLENGTH_SHORT ) )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	status = importCertFromStream( &stream, iDataCert, cryptOwner,
								   CRYPT_ICERTTYPE_DATAONLY, 
								   ( int ) length );
	sMemDisconnect( &stream );

	return( status );
	}

/* Import an encrypted private key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5, 10 ) ) \
static int importPrivateKey( const PKCS12_OBJECT_INFO *keyObjectInfo,
							 IN_HANDLE const CRYPT_USER cryptOwner,
							 IN_BUFFER( passwordLen ) const void *password,
							 IN_LENGTH_NAME const int passwordLen,
							 IN_BUFFER( keyObjectDataLen ) const void *keyObjectData,
							 IN_LENGTH_SHORT const int keyObjectDataLen,
							 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
							 IN_BUFFER_OPT( labelLength ) const void *label,
							 IN_LENGTH_SHORT_Z const int labelLength,
							 OUT_HANDLE_OPT CRYPT_CERTIFICATE *iPrivKeyContext )
	{
	CRYPT_CONTEXT iCryptContext, iWrapContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MECHANISM_WRAP_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	int status;

	assert( isReadPtr( keyObjectInfo, sizeof( PKCS12_OBJECT_INFO ) ) );
	assert( isReadPtr( password, passwordLen ) );
	assert( isReadPtr( keyObjectData, keyObjectDataLen) );
	assert( ( label == NULL && labelLength == 0 ) || \
			isReadPtr( label, labelLength ) );
	assert( isWritePtr( iPrivKeyContext, sizeof( CRYPT_CERTIFICATE ) ) );

	REQUIRES( cryptOwner == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( cryptOwner ) );
	REQUIRES( passwordLen >= MIN_NAME_LENGTH && \
			  passwordLen <= CRYPT_MAX_TEXTSIZE );
	REQUIRES( keyObjectDataLen > MIN_OBJECT_SIZE && \
			  keyObjectDataLen < MAX_INTLENGTH_SHORT );
	REQUIRES( ( label == NULL && labelLength == 0 ) || \
			  ( label != NULL && \
				labelLength > 0 && labelLength < MAX_INTLENGTH_SHORT ) );
	REQUIRES( isPkcAlgo( cryptAlgo ) );

	/* Clear return value */
	*iPrivKeyContext = CRYPT_ERROR;

	/* Create the wrap context used to unwrap the private key */
	status = createPkcs12KeyWrapContext( ( PKCS12_OBJECT_INFO * ) keyObjectInfo, 
										 cryptOwner, password, passwordLen, 
										 &iWrapContext, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the private-key object to import the key data into and set the 
	   key label.  We have to set the label before we load the key or the key 
	   load will be blocked by the kernel */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iWrapContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	iCryptContext = createInfo.cryptHandle;
	if( label != NULL )
		{ 
		setMessageData( &msgData, ( MESSAGE_CAST ) label, \
						min( labelLength, CRYPT_MAX_TEXTSIZE ) ); 
		}
	else
		{ 
		setMessageData( &msgData, ( MESSAGE_CAST ) "Dummy label", 11 ); 
		}
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_LABEL );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iWrapContext, IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Import the encrypted private key into the PKC context */
	setMechanismWrapInfo( &mechanismInfo, ( MESSAGE_CAST * ) keyObjectData, 
						  keyObjectDataLen, NULL, 0, iCryptContext, 
						  iWrapContext );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT, 
							  &mechanismInfo, 
							  MECHANISM_PRIVATEKEYWRAP_PKCS8 );
	clearMechanismInfo( &mechanismInfo );
	krnlSendNotifier( iWrapContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iPrivKeyContext = iCryptContext;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Read PKCS #12 Object Information					*
*																			*
****************************************************************************/

/* Read an object's attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readObjectAttributes( INOUT STREAM *stream, 
								 INOUT PKCS12_INFO *pkcs12info )
	{
	int endPos, length, iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs12info, sizeof( PKCS12_INFO ) ) );

	/* Determine how big the collection of attributes is */
	status = readSet( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;

	/* Read the collection of attributes */
	for( iterationCount = 0;
		 stell( stream ) < endPos && \
			iterationCount < FAILSAFE_ITERATIONS_MED;
		 iterationCount++ )
		{
		BYTE stringBuffer[ ( CRYPT_MAX_TEXTSIZE * 2 ) + 8 ];
		int attributeType, stringLength, srcIndex, destIndex;

		/* Read the outer wrapper and determine the attribute type based on
		   the OID */
		readSequence( stream, NULL );
		status = readOID( stream, attributeOIDinfo, 
						  FAILSAFE_ARRAYSIZE( attributeOIDinfo, OID_INFO ), 
						  &attributeType );
		if( cryptStatusError( status ) )
			return( status );

		/* Read the wrapper around the attribute payload */
		status = readSet( stream, &length );
		if( cryptStatusError( status ) )
			return( status );

		switch( attributeType )
			{
			case PKCS12_ATTRIBUTE_NONE:
				/* It's a don't-care attribute, skip it */
				if( length > 0 )
					status = sSkip( stream, length );
				break;

			case PKCS12_ATTRIBUTE_LABEL:
				/* Read the label, translating it from Unicode.  We assume
				   that it's just widechar ASCII/latin-1 (which always seems
				   to be the case), which avoids OS-specific i18n 
				   headaches */
				status = readCharacterString( stream, stringBuffer, 
									CRYPT_MAX_TEXTSIZE * 2, &stringLength,
									BER_STRING_BMP );
				if( cryptStatusError( status ) )
					break;
				for( srcIndex = destIndex = 0; srcIndex < stringLength;
					 srcIndex +=2, destIndex++ )
					{
					pkcs12info->label[ destIndex ] = \
								stringBuffer[ srcIndex + 1 ];
					}
				pkcs12info->labelLength = destIndex;
				break;

			case PKCS12_ATTRIBUTE_ID:
				/* It's a binary-blob ID, usually a 32-bit little-endian 
				   integer, remember it in case it's needed later */
				status = readOctetString( stream, pkcs12info->id, 
										  &pkcs12info->idLength, 
										  1, CRYPT_MAX_HASHSIZE );
				break;

			default:
				retIntError();
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( CRYPT_OK );
	}

/* Read object information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readObjectInfo( INOUT STREAM *stream, 
						   OUT PKCS12_OBJECT_INFO *pkcs12objectInfo,
						   const BOOLEAN isPrivateKey,
						   INOUT ERROR_INFO *errorInfo )
	{
	const char *objectName = isPrivateKey ? "private-key" : "certificate";
	int payloadOffset = DUMMY_INIT, payloadLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs12objectInfo, sizeof( PKCS12_OBJECT_INFO ) ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( errorInfo != NULL );

	/* Clear return value */
	memset( pkcs12objectInfo, 0, sizeof( PKCS12_OBJECT_INFO ) );

	/* If we're reading a private key then it's held within CMS Data which
	   in turn contains a pkcs12ShroudedKeyBag, strip the encapsulation to 
	   get to the encryption information */
	if( isPrivateKey )
		{
		status = readCMSheader( stream, keyBagOIDinfo, 
						   FAILSAFE_ARRAYSIZE( keyBagOIDinfo, OID_INFO ),
						   NULL, READCMS_FLAG_NONE );
		}
	else
		{
		/* We're reading a public certificate held within CMS EncryptedData, 
		   skip the encapsulation to get to the encryption information */
		readSequence( stream, NULL );
		status = readFixedOID( stream, OID_CMS_DATA, 
							   sizeofOID( OID_CMS_DATA ) );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid %s object header", objectName ) );
		}

	/* Read the encryption algorithm information */
	status = readProtAlgoInfo( stream, &pkcs12objectInfo->cryptAlgo,
							   &pkcs12objectInfo->keySize );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid %s protection algorithm", objectName ) );
		}
	
	/* Read the key-derivation parameters */
	status = readKeyDerivationInfo( stream, pkcs12objectInfo->salt,
									CRYPT_MAX_HASHSIZE, 
									&pkcs12objectInfo->saltSize,
									&pkcs12objectInfo->iterations );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid %s protection parameters", objectName ) );
		}

	/* Read the start of the encrypted content.  This has a variety of 
	   encapsulations depending on how its hidden inside the PKCS #12 
	   object so we read it as a generic object.  readGenericHole()
	   disallows indefinite-length encodings so we know that the returned 
	   payload length will have a definite value */
	status = readGenericHole( stream, &payloadLength, MIN_OBJECT_SIZE, 
							  DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		payloadOffset = stell( stream );
		status = sSkip( stream, payloadLength );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid %s payload data", objectName ) );
		}
	pkcs12objectInfo->payloadOffset = payloadOffset;
	pkcs12objectInfo->payloadSize = payloadLength;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read PKCS #12 Keys								*
*																			*
****************************************************************************/

/* Read a single object in a keyset */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int readObject( INOUT STREAM *stream, 
					   OUT PKCS12_INFO *pkcs12info, 
					   const BOOLEAN isPrivateKey,
					   INOUT ERROR_INFO *errorInfo )
	{
	PKCS12_OBJECT_INFO *pkcs12objectInfo = \
				isPrivateKey ? &pkcs12info->keyInfo : &pkcs12info->certInfo;
	STREAM objectStream;
	BYTE buffer[ MIN_OBJECT_SIZE + 8 ];
	const char *objectName = isPrivateKey ? "private-key" : "certificate";
	void *objectData;
	int headerSize = DUMMY_INIT, objectLength = DUMMY_INIT, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs12info, sizeof( PKCS12_INFO ) ) );
	
	REQUIRES( errorInfo != NULL );

	/* Clear return values */
	memset( pkcs12info, 0, sizeof( PKCS12_INFO ) );

	/* Read the current object.  We can't use getObjectLength() here because 
	   we're reading from a file rather than a memory stream so we have to
	   grab the first MIN_OBJECT_SIZE bytes from the file stream and decode
	   them to see what's next */
	status = sread( stream, buffer, MIN_OBJECT_SIZE );
	if( cryptStatusOK( status ) )
		{
		STREAM headerStream;

		sMemConnect( &headerStream, buffer, MIN_OBJECT_SIZE );
		status = readGenericHole( &headerStream, &objectLength, 
								  MIN_OBJECT_SIZE, DEFAULT_TAG );
		if( cryptStatusOK( status ) )
			headerSize = stell( &headerStream );
		sMemDisconnect( &headerStream );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't read %s object data", objectName ) );
		}
	if( objectLength < MIN_OBJECT_SIZE || \
		objectLength > MAX_INTLENGTH_SHORT )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid %s object length %d", objectName, objectLength ) );
		}

	/* Allocate storage for the object and copy the already-read portion to 
	   the start of the storage */
	objectLength += headerSize;
	if( ( objectData = clAlloc( "readObject", objectLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memcpy( objectData, buffer, MIN_OBJECT_SIZE );

	/* Read the remainder of the object into the memory buffer and check 
	   that the overall object is valid */
	status = sread( stream, ( BYTE * ) objectData + MIN_OBJECT_SIZE,
					objectLength - MIN_OBJECT_SIZE );
	if( cryptStatusOK( status ) )
		status = checkObjectEncoding( objectData, objectLength );
	if( cryptStatusError( status ) )
		{
		clFree( "readObject", objectData );
		retExt( status, 
				( status, errorInfo, 
				  "Invalid %s object data", objectName ) );
		}

	/* Read the object information from the in-memory object data */
	sMemConnect( &objectStream, objectData, objectLength );
	status = readObjectInfo( &objectStream, pkcs12objectInfo, isPrivateKey, 
							 errorInfo );
	if( cryptStatusOK( status ) && stell( &objectStream ) < objectLength )
		{
		/* There are object attributes present, read these as well.  Note 
		   that these apply to the overall set of objects, so we read them
		   into the general information rather than the per-object 
		   information */
		status = readObjectAttributes( &objectStream, pkcs12info );
		}
	sMemDisconnect( &objectStream );
	if( cryptStatusError( status ) )
		{
		clFree( "readObject", objectData );
		retExt( status, 
				( status, errorInfo, "Invalid %s information",
				  isPrivateKey ? "private key" : "certificate" ) );
		}

	/* Remember the encoded object data */
	pkcs12objectInfo->data = objectData;
	pkcs12objectInfo->dataSize = objectLength;
	ENSURES( rangeCheck( pkcs12objectInfo->payloadOffset, 
						 pkcs12objectInfo->payloadSize,
						 pkcs12objectInfo->dataSize ) );

	return( CRYPT_OK );
	}

/* Read an entire keyset */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int readPkcs12Keyset( INOUT STREAM *stream, 
					  OUT_ARRAY( maxNoPkcs12objects ) PKCS12_INFO *pkcs12info, 
					  IN_LENGTH_SHORT const int maxNoPkcs12objects, 
					  IN_LENGTH const long endPos,
					  INOUT ERROR_INFO *errorInfo )
	{
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs12info, sizeof( PKCS12_INFO ) * \
									maxNoPkcs12objects ) );
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );

	REQUIRES( maxNoPkcs12objects >= 1 && \
			  maxNoPkcs12objects < MAX_INTLENGTH_SHORT );
	REQUIRES( endPos > 0 && endPos > stell( stream ) && \
			  endPos < MAX_INTLENGTH );

	/* Clear return value */
	memset( pkcs12info, 0, sizeof( PKCS12_INFO ) * maxNoPkcs12objects );

	/* Scan all of the objects in the keyset */
	for( status = CRYPT_OK, iterationCount = 0;
		 cryptStatusOK( status ) && stell( stream ) < endPos && \
			iterationCount < FAILSAFE_ITERATIONS_MED; iterationCount++ )
		{
		PKCS12_INFO *pkcs12infoPtr = &pkcs12info[ 0 ];
					/* Because of the lack of indexing information we can't 
					   connect multiple keys and certificates, so we have to 
					   assume that whatever we find in the way of keys and 
					   certificates is connected.  This means that there's 
					   effectively only one set of objects present, which is 
					   also implied by MAX_PKCS12_OBJECTS being 1 */
		PKCS12_INFO localPkcs12Info;
		int isCertificate;

		/* Read the CMS header encapsulation for the object and the first
		   layer of inner nesting.  At this point we get to more PKCS #12 
		   stupidity, if we hit CMS EncryptedData (isCertificate == TRUE) 
		   then it's actually a certificate (that doesn't need to be 
		   encrypted), and if we hit CMS Data (isCertificate == FALSE) then 
		   it's a private key wrapped within a bizarre reinvention of CMS 
		   EncryptedData that's nested within the CMS Data */
		status = isCertificate = \
			readCMSheader( stream, keyDataOIDinfo, 
						   FAILSAFE_ARRAYSIZE( keyDataOIDinfo, OID_INFO ),
						   NULL, READCMS_FLAG_NONE );
		if( !cryptStatusError( status ) && !isCertificate )
			{
			/* Skip the SET OF PKCS12Bag encapsulation */
			status = readSequence( stream, NULL );
			}
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA, 
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Invalid PKCS #12 object header" ) );
			}

		/* Read the object */
		status = readObject( stream, &localPkcs12Info, !isCertificate, 
							 errorInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* We now run into yet another problem with PKCS #12's lack of 
		   indexing information.  The PKCS #15 code would now do a 
		   findEntry() to find the entry that matches what we've just read 
		   and attach that to whatever's already present for an existing 
		   entry if required (so for example it'd attach a certificate to a 
		   previously-read private key), however with PKCS #12 there's no 
		   way to do this so we have to assume that there's just one private 
		   key matched up with one certificate, and nothing else.  It's a 
		   bit unclear how we should respond to the presence of multiple 
		   keys and certificates, in theory we could ignore all but the 
		   first one, but there's no way to tell if e.g. the first 
		   certificate belongs with the second key, so we treat any further 
		   keys and certificates as an error */
		if( isCertificate )
			{
			if( pkcs12infoPtr->certInfo.data != NULL )
				{
				pkcs12freeObjectEntry( &pkcs12infoPtr->certInfo );
				retExt( CRYPT_ERROR_BADDATA, 
						( CRYPT_ERROR_BADDATA, errorInfo, 
						  "Multiple conflicting certificates found in "
						  "keyset" ) );
				}
			memcpy( &pkcs12infoPtr->certInfo, &localPkcs12Info.certInfo, 
					sizeof( PKCS12_OBJECT_INFO ) );
			}
		else
			{
			if( pkcs12infoPtr->keyInfo.data != NULL )
				{
				pkcs12freeObjectEntry( &pkcs12infoPtr->keyInfo );
				retExt( CRYPT_ERROR_BADDATA, 
						( CRYPT_ERROR_BADDATA, errorInfo, 
						  "Multiple conflicting keys found in keyset" ) );
				}
			memcpy( &pkcs12infoPtr->keyInfo, &localPkcs12Info.keyInfo, 
					sizeof( PKCS12_OBJECT_INFO ) );
			}
		if( pkcs12infoPtr->labelLength <= 0 && \
			localPkcs12Info.labelLength > 0 )
			{
			memcpy( pkcs12infoPtr->label, localPkcs12Info.label,
					localPkcs12Info.labelLength );
			pkcs12infoPtr->labelLength = localPkcs12Info.labelLength;
			}
		if( pkcs12infoPtr->idLength <= 0 && \
			localPkcs12Info.idLength > 0 )
			{
			memcpy( pkcs12infoPtr->id, localPkcs12Info.id,
					localPkcs12Info.idLength );
			pkcs12infoPtr->idLength = localPkcs12Info.idLength;
			}
		}
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*									Get a Key								*
*																			*
****************************************************************************/

#if 0	/* Crack an RC2-40 key.  Call as 'keyCrack( certData, certDataSize )'
		   before the 'importCertificate()' call.  A more efficient version
		   of this is in ctx_rc2.c, the following code is really only 
		   present for testing the process with known-key data */

#pragma message( "#############################" )
#pragma message( "Building PKCS #12 key-cracker" )
#pragma message( "#############################" )

static int keyCrack( const void *encData, const int length )
	{
	CRYPT_CONTEXT cryptContext;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	BYTE data[ 32 ], key[ 32 ], *keyPtr = key + 14;
	int i, status;

	/* Test file: IV =  17 17 F1 B0 94 E8 EE F8		encData + 0
				  PT =	06 0B 2A 86 48 86 F7 0D
						-----------------------
				  XOR:	11 1C DB 36 DC 6E 19 F5 

	   So encr. above = CT block 2.
					  =	9C 4E 66 8A C7 6B 97 F5		encData + 8

	   Actual:    IV =  6F A0 7E A5 65 00 65 6C		encData + 0
				  PT =	06 0B 2A 86 48 86 F7 0D
						-----------------------
				  XOR:	69 AB 54 23 2D 86 92 61 

	   So encr. above = CT block 2.
					  =	34 AA F1 83 BD 9C C0 15		encData + 8 */
	
//	memcpy( data, "\x17\x17\xF1\xB0\x94\xE8\xEE\xF8", 8 );
	memcpy( data, "\x6F\xA0\x7E\xA5\x65\x00\x65\x6C", 8 );
	for( i = 0; i < 8; i++ )
		data[ i ] ^= i[ "\x06\x0B\x2A\x86\x48\x86\xF7\x0D" ];

	memcpy( key, "PKCS#12PKCS#12", 14 );
	memset( key + 14, 0, 5 );

//	memcpy( keyPtr, "\x13\x25\x0c\x1a\x60", 5 );	// Test PKCS #12 file, file #1.
//	memcpy( keyPtr, "\x2C\x28\x14\xC4\x01", 5 );	// "Tellus" PKCS #12 file, file #2

	for( i = 0; i < 256; i++ )
		{
		int keyIndex;

		printf( "Trying keys %02X xx.\n", i );
		fflush( stdout );
		while( keyPtr[ 0 ] == i )
			{
			setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_RC2 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
									  &createInfo, OBJECT_TYPE_CONTEXT );
			if( cryptStatusError( status ) )
				return( status );
			cryptContext = createInfo.cryptHandle;
			setMessageData( &msgData, key, 19 );
			status = krnlSendMessage( cryptContext, IMESSAGE_SETATTRIBUTE_S, 
									  &msgData, CRYPT_CTXINFO_KEY );
			if( cryptStatusOK( status ) )
				{
				setMessageData( &msgData, ( MESSAGE_CAST ) encData, 8 );
				status = krnlSendMessage( cryptContext, IMESSAGE_SETATTRIBUTE_S, 
										  &msgData, CRYPT_CTXINFO_IV );
				}
			if( cryptStatusOK( status ) )
				{
#if 0	/* For key-crack */
				memcpy( data, ( const BYTE * ) encData + 8, 8 );
				status = krnlSendMessage( cryptContext, IMESSAGE_CTX_DECRYPT, 
										  data, 8 );
#else	/* For full decrypt */
				status = krnlSendMessage( cryptContext, IMESSAGE_CTX_DECRYPT, 
										  ( MESSAGE_CAST ) \
											( ( const BYTE * ) encData + 8 ), 
										  length - 8 );
				DEBUG_DUMP( "crack_result", ( const BYTE * ) encData + 8,
							length - 8 );
#endif /* 0 */
				}
			krnlSendNotifier( cryptContext, IMESSAGE_DECREFCOUNT );
			if( cryptStatusError( status ) )
				return( status );
			if( data[ 0 ] == 0x06 && \
				!memcmp( data, "\x06\x0B\x2A\x86\x48\x86\xF7\x0D", 8 ) )
				{
				printf( "Found at %02X %02X %02X %02X %02X.\n",
						keyPtr[ 0 ], keyPtr[ 1 ], keyPtr[ 2 ],
						keyPtr[ 3 ], keyPtr[ 4 ] );
				fflush( stdout );
				return( CRYPT_OK );
				}
			for( keyIndex = 4; keyIndex >= 0; keyIndex++ )
				{
				keyPtr[ keyIndex ]++;
				if( keyPtr[ keyIndex ] > 0 )
					break;
				}
			if( keyIndex == 1 )
				{
				printf( "Trying keys %02X %02X.\n", 
						keyPtr[ 0 ], keyPtr[ 1 ] );
				fflush( stdout );
				}
			}
		}

	return( CRYPT_OK );
	}
#endif /* 0 */

/* Get a key from a PKCS #12 keyset.  This gets pretty ugly both because 
   PKCS #12 keysets contain no indexing information (making it impossible to 
   look up objects within them) and because in most cases all data, 
   including public keys and certificates, is encrypted.  To handle this we 
   only allow private-key reads, and treat whatever's in the keyset as being 
   a match for any request, since without indexing information there's no 
   way to tell whether it really is a match or not */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
static int getItemFunction( INOUT KEYSET_INFO *keysetInfoPtr,
							OUT_HANDLE_OPT CRYPT_HANDLE *iCryptHandle,
							IN_ENUM( KEYMGMT_ITEM ) \
								const KEYMGMT_ITEM_TYPE itemType,
							IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
							IN_BUFFER( keyIDlength ) const void *keyID, 
							IN_LENGTH_KEYID const int keyIDlength,
							IN_OPT void *auxInfo, 
							INOUT_OPT int *auxInfoLength,
							IN_FLAGS_Z( KEYMGMT ) const int flags )
	{
#ifdef USE_CERTIFICATES
	CRYPT_CERTIFICATE iDataCert = CRYPT_ERROR;
#endif /* USE_CERTIFICATES */
	CRYPT_CONTEXT iCryptContext;
	CRYPT_ALGO_TYPE cryptAlgo = CRYPT_ALGO_RSA;
	const PKCS12_INFO *pkcs12infoPtr = keysetInfoPtr->keyData;
	const int auxInfoMaxLength = *auxInfoLength;
	int status;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );
	assert( isWritePtr( iCryptHandle, sizeof( CRYPT_HANDLE ) ) );
	assert( isReadPtr( keyID, keyIDlength ) );
	assert( ( auxInfo == NULL && auxInfoMaxLength == 0 ) || \
			isReadPtr( auxInfo, auxInfoMaxLength ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS12 );
	REQUIRES( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			  itemType == KEYMGMT_ITEM_PRIVATEKEY );
	REQUIRES( keyIDtype == CRYPT_KEYID_NAME || \
			  keyIDtype == CRYPT_KEYID_URI || \
			  keyIDtype == CRYPT_IKEYID_KEYID || \
			  keyIDtype == CRYPT_IKEYID_PGPKEYID || \
			  keyIDtype == CRYPT_IKEYID_ISSUERID );
	REQUIRES( keyIDlength >= MIN_NAME_LENGTH && \
			  keyIDlength < MAX_ATTRIBUTE_SIZE );
	REQUIRES( ( auxInfo == NULL && *auxInfoLength == 0 ) || \
			  ( auxInfo != NULL && \
				*auxInfoLength > 0 && \
				*auxInfoLength < MAX_INTLENGTH_SHORT ) );
	REQUIRES( flags >= KEYMGMT_FLAG_NONE && flags < KEYMGMT_FLAG_MAX );

	/* Clear return values */
	*iCryptHandle = CRYPT_ERROR;

	/* Only private-key reads are possible */
	if( itemType != KEYMGMT_ITEM_PRIVATEKEY )
		{
		retExt( CRYPT_ERROR_NOTFOUND, 
				( CRYPT_ERROR_NOTFOUND, KEYSET_ERRINFO, 
				  "PKCS #12 keysets only support private-key reads" ) );
		}

	/* Make sure that the components that we need are present */
	if( pkcs12infoPtr->keyInfo.data == NULL )
		{
		/* There's not enough information present to get a private key */
		retExt( CRYPT_ERROR_NOTFOUND, 
				( CRYPT_ERROR_NOTFOUND, KEYSET_ERRINFO, 
				  "No private key data present" ) );
		}

	/* If we're just checking whether an object exists, return now.  If all
	   that we want is the key label, copy it back to the caller and exit */
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		return( CRYPT_OK );
	if( flags & KEYMGMT_FLAG_LABEL_ONLY )
		{
		return( attributeCopyParams( auxInfo, auxInfoMaxLength, 
									 auxInfoLength, pkcs12infoPtr->label, 
									 pkcs12infoPtr->labelLength ) );
		}

	/* Make sure that the user has supplied a password */
	if( auxInfo == NULL )
		return( CRYPT_ERROR_WRONGKEY );

	/* If there's a certiticate present, import it as a data-only certificate
	   object to be attached to the private key */
#ifdef USE_CERTIFICATES
	if( pkcs12infoPtr->certInfo.data != NULL )
		{
		const PKCS12_OBJECT_INFO *certObjectInfo = &pkcs12infoPtr->certInfo;
		BYTE certDataBuffer[ 2048 + 8 ], *certData = certDataBuffer;
		int certDataSize = certObjectInfo->payloadSize, value;

		/* Set up a buffer to decrypt the certificate data */
		if( certDataSize > 2048 )
			{
			if( certDataSize >= MAX_INTLENGTH_SHORT )
				return( CRYPT_ERROR_OVERFLOW );
			if( ( certData = clAlloc( "getItemFunction", certDataSize ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			}
		memcpy( certData, ( BYTE * ) certObjectInfo->data + \
						  certObjectInfo->payloadOffset, certDataSize );

		/* Decrypt and import the certificate */
		status = importCertificate( certObjectInfo, keysetInfoPtr->ownerHandle, 
									auxInfo, *auxInfoLength, certData, 
									certDataSize, &iDataCert );
		if( cryptStatusError( status ) )
			{
			zeroise( certData, certDataSize );
			if( certData != certDataBuffer )
				clFree( "getItemFunction", certData );
			retExt( status, 
					( status, KEYSET_ERRINFO, 
					  "Couldn't recreate certificate from stored "
					  "certificate data" ) );
			}
		
		/* In yet another piece of design brilliance, the PKC algorithm 
		   that's needed to create the public/private-key context is stored
		   inside the encrypted key data, so we can't create a context to 
		   import the key data into until we've already imported the key
		   data.  To get around this we read the PKC algorithm from the
		   certificate that corresponds to the key.  If there's no 
		   certificate present we default to CRYPT_ALGO_RSA, which is almost
		   always the case anyway */
		status = krnlSendMessage( iDataCert, IMESSAGE_GETATTRIBUTE, &value,
								  CRYPT_IATTRIBUTE_CERTKEYALGO );
		if( cryptStatusOK( status ) )
			cryptAlgo = value;
		}
#endif /* USE_CERTIFICATES */

	/* Import the wrapped private key */
	status = importPrivateKey( &pkcs12infoPtr->keyInfo, 
					keysetInfoPtr->ownerHandle, auxInfo, *auxInfoLength, 
					( const BYTE * ) pkcs12infoPtr->keyInfo.data + \
									 pkcs12infoPtr->keyInfo.payloadOffset,
					pkcs12infoPtr->keyInfo.payloadSize, cryptAlgo,
					( pkcs12infoPtr->labelLength > 0 ) ? \
						pkcs12infoPtr->label : NULL, 
					pkcs12infoPtr->labelLength, &iCryptContext );
	if( cryptStatusError( status ) )
		{
		if( iDataCert != CRYPT_ERROR )
			krnlSendNotifier( iDataCert, IMESSAGE_DECREFCOUNT );
		retExt( status, 
				( status, KEYSET_ERRINFO, 
				  "Couldn't unwrap and import private key" ) );
		}

#ifdef USE_CERTIFICATES
	/* Connect the data-only certificate object to the private-key context 
	   if necessary.  This is an internal object used only by the context so 
	   we tell the kernel to mark it as owned by the context only */
	if( iDataCert != CRYPT_ERROR )
		{
		status = krnlSendMessage( iCryptContext, IMESSAGE_SETDEPENDENT, 
								  &iDataCert, SETDEP_OPTION_NOINCREF );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
			krnlSendNotifier( iDataCert, IMESSAGE_DECREFCOUNT );
			retExt( status, 
					( status, KEYSET_ERRINFO, 
					  "Couldn't attach certificate to key" ) );
			}
		}
#endif /* USE_CERTIFICATES */
	*iCryptHandle = iCryptContext;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Keyset Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initPKCS12get( INOUT KEYSET_INFO *keysetInfoPtr )
	{
	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS12 );

	/* Set the access method pointers */
	keysetInfoPtr->getItemFunction = getItemFunction;

	return( CRYPT_OK );
	}
#endif /* USE_PKCS12 */
