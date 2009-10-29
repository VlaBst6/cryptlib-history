/****************************************************************************
*																			*
*						cryptlib PKCS #15 Read Routines						*
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

/* OID information used to read a PKCS #15 file */

static const OID_INFO FAR_BSS dataOIDinfo[] = {
	{ OID_CMS_DATA, CRYPT_OK },
	{ NULL, 0 }, { NULL, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Translate the PKCS #15 usage flags into cryptlib permitted actions.  The
   PKCS #11 use of the 'derive' flag to mean 'allow key agreement' is a bit
   of a kludge, we map it to allowing keyagreement export and import if it's
   a key-agreement algorithm, if there are further constraints they'll be
   handled by the attached certificate.  The PKCS #15 nonRepudiation flag 
   doesn't have any definition so we can't do anything with it, although we 
   may need to translate it to allowing signing and/or verification if 
   implementations appear that expect it to be used this way */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int getPermittedActions( IN_FLAGS( PKCS15_USAGE ) const int usageFlags,
								IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								OUT_FLAGS_Z( ACTION ) int *usage )
	{
	int actionFlags = ACTION_PERM_NONE_ALL;

	REQUIRES( usageFlags >= PKSC15_USAGE_FLAG_NONE && \
			  usageFlags < PKCS15_USAGE_FLAG_MAX );
	REQUIRES( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
			  cryptAlgo <= CRYPT_ALGO_LAST_PKC );

	/* Clear return value */
	*usage = ACTION_PERM_NONE;

	if( usageFlags & ( PKCS15_USAGE_ENCRYPT | PKCS15_USAGE_WRAP ) )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL );
	if( usageFlags & ( PKCS15_USAGE_DECRYPT | PKCS15_USAGE_UNWRAP ) )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
	if( usageFlags & PKCS15_USAGE_SIGN )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );
	if( usageFlags & PKCS15_USAGE_VERIFY )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL );
	if( isKeyxAlgo( cryptAlgo ) && ( usageFlags & PKCS15_USAGE_DERIVE ) )
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		/* If there are any restrictions on the key usage we have to make it
		   internal-only because of RSA's signature/encryption duality */
		if( !( ( usageFlags & ( PKCS15_USAGE_ENCRYPT | PKCS15_USAGE_WRAP | \
								PKCS15_USAGE_DECRYPT | PKCS15_USAGE_UNWRAP ) ) && \
			   ( usageFlags & ( PKCS15_USAGE_SIGN | PKCS15_USAGE_VERIFY ) ) ) )
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
		}
	else
		{
		/* Because of the special-case data formatting requirements for DLP
		   algorithms we make the usage internal-only */
		actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
		}
	if( actionFlags <= ACTION_PERM_NONE_ALL )
		return( CRYPT_ERROR_PERMISSION );
	*usage = actionFlags;

	return( CRYPT_OK );
	}

/* Copy any new object ID information that we've just read across to the 
   object information */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void copyObjectIdInfo( INOUT PKCS15_INFO *pkcs15infoPtr, 
							  const PKCS15_INFO *pkcs15objectInfo )
	{
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( pkcs15objectInfo, sizeof( PKCS15_INFO ) ) );

	/* If any new ID information has become available, copy it over.  The 
	   keyID defaults to the iD so we only copy the newly-read keyID over if 
	   it's something other than the existing iD */
	if( pkcs15objectInfo->keyIDlength > 0 && \
		( pkcs15infoPtr->iDlength != pkcs15objectInfo->keyIDlength || \
		  memcmp( pkcs15infoPtr->iD, pkcs15objectInfo->keyID,
				  pkcs15objectInfo->keyIDlength ) ) )
		{
		memcpy( pkcs15infoPtr->keyID, pkcs15objectInfo->keyID,
				pkcs15objectInfo->keyIDlength );
		pkcs15infoPtr->keyIDlength = pkcs15objectInfo->keyIDlength;
		}
	if( pkcs15objectInfo->iAndSIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->iAndSID, pkcs15objectInfo->iAndSID,
				pkcs15objectInfo->iAndSIDlength );
		pkcs15infoPtr->iAndSIDlength = pkcs15objectInfo->iAndSIDlength;
		}
	if( pkcs15objectInfo->subjectNameIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->subjectNameID, pkcs15objectInfo->subjectNameID,
				pkcs15objectInfo->subjectNameIDlength );
		pkcs15infoPtr->subjectNameIDlength = pkcs15objectInfo->subjectNameIDlength;
		}
	if( pkcs15objectInfo->issuerNameIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->issuerNameID, pkcs15objectInfo->issuerNameID,
				pkcs15objectInfo->issuerNameIDlength );
		pkcs15infoPtr->issuerNameIDlength = pkcs15objectInfo->issuerNameIDlength;
		}
	if( pkcs15objectInfo->pgp2KeyIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->pgp2KeyID, pkcs15objectInfo->pgp2KeyID,
				pkcs15objectInfo->pgp2KeyIDlength );
		pkcs15infoPtr->pgp2KeyIDlength = pkcs15objectInfo->pgp2KeyIDlength;
		}
	if( pkcs15objectInfo->openPGPKeyIDlength > 0 )
		{
		memcpy( pkcs15infoPtr->openPGPKeyID, pkcs15objectInfo->openPGPKeyID,
				pkcs15objectInfo->openPGPKeyIDlength );
		pkcs15infoPtr->openPGPKeyIDlength = pkcs15objectInfo->openPGPKeyIDlength;
		}
	}

/* Copy any new object payload information that we've just read across to 
   the object information */

STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int copyObjectPayloadInfo( INOUT PKCS15_INFO *pkcs15infoPtr, 
								  const PKCS15_INFO *pkcs15objectInfo,
								  IN_BUFFER( objectLength ) const void *object, 
								  IN_LENGTH_SHORT const int objectLength,
								  IN_ENUM( PKCS15_OBJECT ) \
									const PKCS15_OBJECT_TYPE type )
	{
	assert( isWritePtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( pkcs15objectInfo, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( object, objectLength ) );

	REQUIRES( objectLength > 0 && objectLength < MAX_INTLENGTH_SHORT );
	REQUIRES( type > PKCS15_OBJECT_NONE && type < PKCS15_OBJECT_LAST );

	switch( type )
		{
		case PKCS15_OBJECT_PUBKEY:
			pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
			pkcs15infoPtr->pubKeyData = ( void * ) object;
			pkcs15infoPtr->pubKeyDataSize = objectLength;
			pkcs15infoPtr->pubKeyOffset = pkcs15objectInfo->pubKeyOffset;
			pkcs15infoPtr->pubKeyUsage = pkcs15objectInfo->pubKeyUsage;
			break;

		case PKCS15_OBJECT_PRIVKEY:
			pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
			pkcs15infoPtr->privKeyData = ( void * ) object;
			pkcs15infoPtr->privKeyDataSize = objectLength;
			pkcs15infoPtr->privKeyOffset = pkcs15objectInfo->privKeyOffset;
			pkcs15infoPtr->privKeyUsage = pkcs15objectInfo->privKeyUsage;
			break;

		case PKCS15_OBJECT_CERT:
			if( pkcs15infoPtr->type == PKCS15_SUBTYPE_NONE )
				pkcs15infoPtr->type = PKCS15_SUBTYPE_CERT;
			pkcs15infoPtr->certData = ( void * ) object;
			pkcs15infoPtr->certDataSize = objectLength;
			pkcs15infoPtr->certOffset = pkcs15objectInfo->certOffset;
			pkcs15infoPtr->trustedUsage = pkcs15objectInfo->trustedUsage;
			pkcs15infoPtr->implicitTrust = pkcs15objectInfo->implicitTrust;
			break;

		case PKCS15_OBJECT_SECRETKEY:
			/* We don't try and return an error for this, it's not something
			   that we can make use of but if it's ever reached it just ends 
			   up as an empty (non-useful) object entry */
			DEBUG_DIAG(( "Found secret-key object" ));
			assert( DEBUG_WARN );
			break;

		case PKCS15_OBJECT_DATA:
			pkcs15infoPtr->type = PKCS15_SUBTYPE_DATA;
			pkcs15infoPtr->dataType = pkcs15objectInfo->dataType;
			pkcs15infoPtr->dataData = ( void * ) object;
			pkcs15infoPtr->dataDataSize = objectLength;
			pkcs15infoPtr->dataOffset = pkcs15objectInfo->dataOffset;
			break;

		default:
			/* We don't try and return an error for this, it's not something
			   that we can make use of but if it's ever reached it just ends 
			   up as an empty (non-useful) object entry */
			DEBUG_DIAG(( "Found unknown object type %d", type ));
			assert( DEBUG_WARN );
			break;
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read Public Key Components						*
*																			*
****************************************************************************/

/* Read public-key components from a PKCS #15 object entry */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 8, 9, 10, 11, 12 ) ) \
int readPublicKeyComponents( const PKCS15_INFO *pkcs15infoPtr,
							 IN_HANDLE const CRYPT_KEYSET iCryptKeysetCallback,
							 IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
							 IN_BUFFER( keyIDlength ) const void *keyID, 
							 IN_LENGTH_KEYID const int keyIDlength,
							 const BOOLEAN publicComponentsOnly,
							 IN_HANDLE const CRYPT_DEVICE iDeviceObject, 
							 OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContextPtr,
							 OUT_HANDLE_OPT CRYPT_CERTIFICATE *iDataCertPtr,
							 OUT_FLAGS_Z( ACTION ) int *pubkeyActionFlags, 
							 OUT_FLAGS_Z( ACTION ) int *privkeyActionFlags, 
							 INOUT ERROR_INFO *errorInfo )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	CRYPT_CONTEXT iCryptContext;
	CRYPT_CERTIFICATE iDataCert = CRYPT_ERROR;
	STREAM stream;
	int status;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( isReadPtr( keyID, keyIDlength ) );
	assert( isWritePtr( iCryptContextPtr, sizeof( CRYPT_CONTEXT ) ) );
	assert( isWritePtr( iDataCertPtr, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isWritePtr( pubkeyActionFlags, sizeof( int ) ) );
	assert( isWritePtr( privkeyActionFlags, sizeof( int ) ) );

	REQUIRES( isHandleRangeValid( iCryptKeysetCallback ) );
	REQUIRES( keyIDtype == CRYPT_KEYID_NAME || \
			  keyIDtype == CRYPT_KEYID_URI || \
			  keyIDtype == CRYPT_IKEYID_KEYID || \
			  keyIDtype == CRYPT_IKEYID_PGPKEYID || \
			  keyIDtype == CRYPT_IKEYID_ISSUERID );
	REQUIRES( keyIDlength >= MIN_NAME_LENGTH && \
			  keyIDlength < MAX_ATTRIBUTE_SIZE );
	REQUIRES( iDeviceObject == SYSTEM_OBJECT_HANDLE || \
			  isHandleRangeValid( iDeviceObject ) );
	REQUIRES( errorInfo != NULL );

	/* Clear return values */
	*iCryptContextPtr = CRYPT_ERROR;
	*iDataCertPtr = CRYPT_ERROR;
	*pubkeyActionFlags = *privkeyActionFlags = ACTION_PERM_NONE;

	/* If we're creating a public-key context we create the certificate or 
	   PKC context normally, if we're creating a private-key context we 
	   create a data-only certificate (if there's certificate information 
	   present) and a partial PKC context ready to accept the private key 
	   components.  If there's a certificate present then we take all of the 
	   information that we need from the certificate, otherwise we use the 
	   public-key data */
	if( pkcs15infoPtr->certData != NULL )
		{
		/* There's a certificate present, import it and reconstruct the
		   public-key information from it if we're creating a partial PKC 
		   context */
		status = iCryptImportCertIndirect( &iCryptContext,
								iCryptKeysetCallback, keyIDtype, keyID,
								keyIDlength, publicComponentsOnly ? \
									KEYMGMT_FLAG_NONE : \
									KEYMGMT_FLAG_DATAONLY_CERT );
		if( cryptStatusError( status ) )
			{
			retExt( status, 
					( status, errorInfo, 
					  "Couldn't recreate certificate from stored "
					  "certificate data" ) );
			}
		if( !publicComponentsOnly )
			{
			DYNBUF pubKeyDB;

			/* We got the certificate, now create the public part of the 
			   context from the certificate's encoded public-key 
			   components */
			iDataCert = iCryptContext;
			status = dynCreate( &pubKeyDB, iDataCert, 
								CRYPT_IATTRIBUTE_SPKI );
			if( cryptStatusError( status ) )
				return( status );
			sMemConnect( &stream, dynData( pubKeyDB ),
						 dynLength( pubKeyDB ) );
			status = iCryptReadSubjectPublicKey( &stream, &iCryptContext,
												 iDeviceObject, TRUE );
			sMemDisconnect( &stream );
			dynDestroy( &pubKeyDB );
			if( cryptStatusError( status ) )
				{
				krnlSendNotifier( iDataCert, IMESSAGE_DECREFCOUNT );
				retExt( status, 
						( status, errorInfo, 
						  "Couldn't recreate public key from "
						  "certificate" ) );
				}
			}
		}
	else
		{
		const int pubKeyStartOffset = pkcs15infoPtr->pubKeyOffset;
		const int pubKeyTotalSize = pkcs15infoPtr->pubKeyDataSize;

		/* There's no certificate present, create the public-key context
		   directly */
		REQUIRES( rangeCheck( pubKeyStartOffset, 
							  pubKeyTotalSize - pubKeyStartOffset,
							  pubKeyTotalSize ) );
		sMemConnect( &stream, 
					 ( BYTE * ) pkcs15infoPtr->pubKeyData + pubKeyStartOffset,
					 pubKeyTotalSize - pubKeyStartOffset );
		status = iCryptReadSubjectPublicKey( &stream, &iCryptContext,
											 iDeviceObject, 
											 !publicComponentsOnly );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			{
			retExt( status, 
					( status, errorInfo, 
					  "Couldn't recreate public key from stored public key "
					  "data" ) );
			}
		}

	/* Get the permitted usage flags for each object type that we'll be
	   instantiating.  If there's a public key present we apply its usage
	   flags to whichever PKC context we create, even if it's done indirectly
	   via the certificate import.  Since the private key can also perform 
	   the actions of the public key we set its action flags to the union of 
	   the two */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && pkcs15infoPtr->pubKeyData != NULL )
		{
		status = getPermittedActions( pkcs15infoPtr->pubKeyUsage, cryptAlgo,
									  pubkeyActionFlags );
		}
	if( cryptStatusOK( status ) && !publicComponentsOnly )
		{
		status = getPermittedActions( pkcs15infoPtr->privKeyUsage, cryptAlgo,
									  privkeyActionFlags );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		if( iDataCert != CRYPT_ERROR )
			krnlSendNotifier( iDataCert, IMESSAGE_DECREFCOUNT );
		retExt( status, 
				( status, errorInfo, 
				  "Public/private key usage flags don't allow any type of "
				  "key usage" ) );
		}

	/* Return the newly-created objects to the caller */
	*iCryptContextPtr = iCryptContext;
	*iDataCertPtr = iDataCert;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Read Public/Private Key Components					*
*																			*
****************************************************************************/

/* Read private-key components from a PKCS #15 object entry */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 6 ) ) \
int readPrivateKeyComponents( const PKCS15_INFO *pkcs15infoPtr,
							  IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							  IN_BUFFER( passwordLength ) const void *password, 
							  IN_LENGTH_NAME const int passwordLength, 
							  const BOOLEAN isStorageObject, 
							  INOUT ERROR_INFO *errorInfo )
	{
	CRYPT_CONTEXT iSessionKey;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MECHANISM_WRAP_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	QUERY_INFO queryInfo = DUMMY_INIT_STRUCT, contentQueryInfo;
	STREAM stream;
	const int privKeyStartOffset = pkcs15infoPtr->privKeyOffset;
	const int privKeyTotalSize = pkcs15infoPtr->privKeyDataSize;
	void *encryptedKey, *encryptedContent = DUMMY_INIT_PTR;
	int encryptedContentLength = DUMMY_INIT;
	int tag, status;

	assert( isReadPtr( pkcs15infoPtr, sizeof( PKCS15_INFO ) ) );
	assert( ( isStorageObject && \
			  password == NULL && passwordLength == 0 ) || \
			( !isStorageObject && \
			  isReadPtr( password, passwordLength ) ) );

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( ( isStorageObject && \
				password == NULL && passwordLength == 0 ) || \
			  ( !isStorageObject && \
				passwordLength >= MIN_NAME_LENGTH && \
				passwordLength < MAX_ATTRIBUTE_SIZE ) );
	REQUIRES( errorInfo != NULL );

	/* Skip the outer wrapper, version number, and header for the SET OF 
	   EncryptionInfo, and query the exported key information to determine 
	   the parameters required to reconstruct the decryption key */
	REQUIRES( rangeCheck( privKeyStartOffset, 
						  privKeyTotalSize - privKeyStartOffset,
						  privKeyTotalSize ) );
	sMemConnect( &stream,
				 ( BYTE * ) pkcs15infoPtr->privKeyData + privKeyStartOffset,
				 privKeyTotalSize - privKeyStartOffset );
	tag = status = peekTag( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( tag == CTAG_OV_FUTUREUSE )
		{
		/* Future versions of cryptlib will use AuthEnvelopedData to protect
		   keys which will presumably be identified with a new tag because
		   CTAG_OV_DIRECTPROTECTED implies EnvelopedData.  For forwards-
		   compatibility we check for this tag and warn the user about it */
		retExt( CRYPT_ERROR_NOTAVAIL, 
				( CRYPT_ERROR_NOTAVAIL, errorInfo, 
				  "Key is protected using AuthEnvelopedData, this requires "
				  "a newer version of cryptlib to process" ) );
		}
	if( isStorageObject )
		{
		BYTE storageID[ KEYID_SIZE + 8 ];
		int length;

		/* If this is a PKCS #15 storage object then it'll contain only 
		   private-key metadata, with the content being merely a reference
		   to external hardware, so we just read the storage object
		   reference and save it to the dummy context */
		if( tag != BER_SEQUENCE )
			{
			sMemDisconnect( &stream );
			retExt( CRYPT_ERROR_BADDATA, 
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Expected device storage ID, not item type %02X",
					  tag ) );
			}
		readSequence( &stream, NULL );
		status = readOctetString( &stream, storageID, &length, 
								  KEYID_SIZE, KEYID_SIZE );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		setMessageData( &msgData, storageID, KEYID_SIZE );
		return( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S,
								 &msgData, CRYPT_IATTRIBUTE_DEVICESTORAGEID ) );
		}
	readConstructed( &stream, NULL, CTAG_OV_DIRECTPROTECTED );
	readShortInteger( &stream, NULL );
	status = readSet( &stream, NULL );
	if( cryptStatusOK( status ) )
		status = queryAsn1Object( &stream, &queryInfo );
	if( cryptStatusOK( status ) && \
		queryInfo.type != CRYPT_OBJECT_ENCRYPTED_KEY )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		retExt( status, 
				( status, errorInfo, 
				  "Invalid encrypted key data header" ) );
		}
	status = sMemGetDataBlock( &stream, &encryptedKey, queryInfo.size );
	if( cryptStatusOK( status ) )
		status = readUniversal( &stream );	/* Skip the exported key */
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}

	/* Read the header for the encrypted key and make sure that all of the
	   data is present in the stream */
	status = readCMSencrHeader( &stream, dataOIDinfo, 
								FAILSAFE_ARRAYSIZE( dataOIDinfo, OID_INFO ), 
								&iSessionKey, &contentQueryInfo );
	if( cryptStatusOK( status ) )
		{
		encryptedContentLength = contentQueryInfo.size;
		status = sMemGetDataBlock( &stream, &encryptedContent, 
								   encryptedContentLength );
		if( cryptStatusOK( status ) && \
			( encryptedContentLength == CRYPT_UNUSED || \
			  encryptedContentLength < MIN_OBJECT_SIZE || \
			  encryptedContentLength > MAX_INTLENGTH_SHORT ) )
			{
			/* Indefinite length or too-small object */
			status = CRYPT_ERROR_BADDATA;
			}
		}
	zeroise( &contentQueryInfo, sizeof( QUERY_INFO ) );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		retExt( status, 
				( status, errorInfo, "Invalid encrypted key data header" ) );
		}

	/* Create an encryption context, derive the user password into it using 
	   the given parameters, and import the session key.  If there's an 
	   error in the parameters stored with the exported key we'll get an arg 
	   or attribute error when we try to set the attribute so we translate 
	   it into an error code which is appropriate for the situation */
	setMessageCreateObjectInfo( &createInfo, queryInfo.cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		{
		zeroise( &queryInfo, sizeof( QUERY_INFO ) );
		return( status );
		}
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE, 
							  &queryInfo.cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
								  &queryInfo.keySetupAlgo,
								  CRYPT_CTXINFO_KEYING_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
								  &queryInfo.keySetupIterations,
								  CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, queryInfo.salt, queryInfo.saltLength );
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEYING_SALT );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, ( MESSAGE_CAST ) password, passwordLength );
		status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEYING_VALUE );
		}
	if( cryptStatusOK( status ) )
		{
		status = iCryptImportKey( encryptedKey, queryInfo.size,
								  CRYPT_FORMAT_CRYPTLIB, 
								  createInfo.cryptHandle, iSessionKey, NULL );
		}
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );
		if( cryptArgError( status ) )
			status = CRYPT_ERROR_BADDATA;
		retExt( status, 
				( status, errorInfo, 
				  "Couldn't create decryption context for private key from "
				  "user password" ) );
		}

	/* Import the encrypted key into the PKC context */
	setMechanismWrapInfo( &mechanismInfo, ( MESSAGE_CAST ) encryptedContent,
						  encryptedContentLength, NULL, 0, iCryptContext,
						  iSessionKey );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_IMPORT,
							  &mechanismInfo, MECHANISM_PRIVATEKEYWRAP );
	clearMechanismInfo( &mechanismInfo );
	krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		/* We can end up here due to a whole range of possible low-level 
		   problems, to make things easier on the caller we provide a 
		   somewhat more detailed breakdown of possible causes */
		switch( status )
			{
			case CRYPT_ERROR_WRONGKEY:
				retExt( status,
						( status, errorInfo, 
						  "Couldn't unwrap private key, probably due to "
						  "incorrect decryption key being used" ) );

			case CRYPT_ERROR_BADDATA:
				retExt( status,
						( status, errorInfo, 
						  "Private key data corrupted or invalid" ) );

			case CRYPT_ERROR_INVALID:
				retExt( status,
						( status, errorInfo, 
						  "Private key components failed validity check" ) );

			default:
				retExt( status,
						( status, errorInfo, 
						  "Couldn't unwrap/import private key" ) );
			}
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read a Keyset								*
*																			*
****************************************************************************/

/* Read a single object in a keyset */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 6 ) ) \
static int readObject( INOUT STREAM *stream, 
					   INOUT PKCS15_INFO *pkcs15objectInfo, 
					   OUT_BUFFER_ALLOC( *objectLengthPtr ) void **objectPtrPtr, 
					   OUT_LENGTH_SHORT_Z int *objectLengthPtr,
					   IN_ENUM( PKCS15_OBJECT ) const PKCS15_OBJECT_TYPE type, 
					   INOUT ERROR_INFO *errorInfo )
	{
	STREAM objectStream;
	BYTE buffer[ MIN_OBJECT_SIZE + 8 ];
	void *objectData;
	int headerSize = DUMMY_INIT, objectLength = DUMMY_INIT, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs15objectInfo, sizeof( PKCS15_INFO ) ) );
	assert( isWritePtr( objectPtrPtr, sizeof( void * ) ) );
	assert( isWritePtr( objectLengthPtr, sizeof( int ) ) );
	
	REQUIRES( type > PKCS15_OBJECT_NONE && type < PKCS15_OBJECT_LAST );
	REQUIRES( errorInfo != NULL );

	/* Clear return values */
	memset( pkcs15objectInfo, 0, sizeof( PKCS15_INFO ) );
	*objectPtrPtr = NULL;
	*objectLengthPtr = 0;

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
				  "Couldn't read PKCS #15 object data" ) );
		}
	if( objectLength < MIN_OBJECT_SIZE || \
		objectLength > MAX_INTLENGTH_SHORT )
		{
		retExt( status, 
				( status, errorInfo, 
				  "Invalid PKCS #15 object length %d", objectLength ) );
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
				( status, errorInfo, "Invalid PKCS #15 object data" ) );
		}

	/* Read the object attributes from the in-memory object data */
	sMemConnect( &objectStream, objectData, objectLength );
	status = readObjectAttributes( &objectStream, pkcs15objectInfo, type, 
								   errorInfo );
	sMemDisconnect( &objectStream );
	if( cryptStatusError( status ) )
		{
		clFree( "readObject", objectData );
		return( status );
		}

	/* Remember the encoded object data */
	*objectPtrPtr = objectData;
	*objectLengthPtr = objectLength;

	return( CRYPT_OK );
	}

/* Read an entire keyset */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
int readKeyset( INOUT STREAM *stream, 
				OUT_ARRAY( maxNoPkcs15objects ) PKCS15_INFO *pkcs15info, 
				IN_LENGTH_SHORT const int maxNoPkcs15objects, 
				IN_LENGTH const long endPos,
				INOUT ERROR_INFO *errorInfo )
	{
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( pkcs15info, sizeof( PKCS15_INFO ) ) );

	REQUIRES( maxNoPkcs15objects >= 1 && \
			  maxNoPkcs15objects < MAX_INTLENGTH_SHORT );
	REQUIRES( endPos > 0 && endPos > stell( stream ) && \
			  endPos < MAX_INTLENGTH );
	REQUIRES( errorInfo != NULL );

	/* Clear return value */
	memset( pkcs15info, 0, sizeof( PKCS15_INFO ) * maxNoPkcs15objects );

	/* Scan all of the objects in the file */
	for( status = CRYPT_OK, iterationCount = 0;
		 cryptStatusOK( status ) && stell( stream ) < endPos && \
			iterationCount < FAILSAFE_ITERATIONS_MED; iterationCount++ )
		{
		static const MAP_TABLE tagToTypeTbl[] = {
			{ CTAG_PO_PRIVKEY, PKCS15_OBJECT_PRIVKEY },
			{ CTAG_PO_PUBKEY, PKCS15_OBJECT_PUBKEY },
			{ CTAG_PO_TRUSTEDPUBKEY, PKCS15_OBJECT_PUBKEY },
			{ CTAG_PO_SECRETKEY, PKCS15_OBJECT_SECRETKEY },
			{ CTAG_PO_CERT, PKCS15_OBJECT_CERT },
			{ CTAG_PO_TRUSTEDCERT, PKCS15_OBJECT_CERT },
			{ CTAG_PO_USEFULCERT, PKCS15_OBJECT_CERT },
			{ CTAG_PO_DATA, PKCS15_OBJECT_DATA },
			{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
			};
		PKCS15_OBJECT_TYPE type = PKCS15_OBJECT_NONE;
		int tag, value, innerEndPos, innerIterationCount;

		/* Map the object tag to a PKCS #15 object type */
		tag = peekTag( stream );
		if( cryptStatusError( tag ) )
			return( tag );
		tag = EXTRACT_CTAG( tag );
		status = mapValue( tag, &value, tagToTypeTbl,
						   FAILSAFE_ARRAYSIZE( tagToTypeTbl, MAP_TABLE ) );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA, 
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Invalid PKCS #15 object type %02X", tag ) );
			}
		type = value;

		/* Read the [n] [0] wrapper to find out what we're dealing with.  
		   Note that we set the upper limit at MAX_INTLENGTH rather than
		   MAX_INTLENGTH_SHORT because some keysets with many large objects 
		   may have a combined group-of-objects length larger than 
		   MAX_INTLENGTH_SHORT */
		readConstructed( stream, NULL, tag );
		status = readConstructed( stream, &innerEndPos, CTAG_OV_DIRECT );
		if( cryptStatusError( status ) )
			return( status );
		if( innerEndPos < MIN_OBJECT_SIZE || innerEndPos >= MAX_INTLENGTH )
			{
			retExt( CRYPT_ERROR_BADDATA, 
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Invalid PKCS #15 object data size %d", 
					  innerEndPos ) );
			}
		innerEndPos += stell( stream );

		/* Scan all objects of this type */
		for( innerIterationCount = 0;
			 stell( stream ) < innerEndPos && \
				innerIterationCount < FAILSAFE_ITERATIONS_LARGE; 
			 innerIterationCount++ )
			{
			PKCS15_INFO pkcs15objectInfo, *pkcs15infoPtr = NULL;
			void *object;
			int objectLength;

			/* Read the object */
			status = readObject( stream, &pkcs15objectInfo, &object,
								 &objectLength, type, errorInfo );
			if( cryptStatusError( status ) )
				return( status );

			/* If we read an object with associated ID information, find out 
			   where to add the object data */
			if( pkcs15objectInfo.iDlength > 0 )
				{
				pkcs15infoPtr = findEntry( pkcs15info, maxNoPkcs15objects, 
										   CRYPT_KEYIDEX_ID, 
										   pkcs15objectInfo.iD,
										   pkcs15objectInfo.iDlength,
										   KEYMGMT_FLAG_NONE );
				}
			if( pkcs15infoPtr == NULL )
				{
				int index;

				/* This personality isn't present yet, find out where we can 
				   add the object data and copy the fixed object information 
				   over */
				pkcs15infoPtr = findFreeEntry( pkcs15info, 
											   maxNoPkcs15objects, &index );
				if( pkcs15infoPtr == NULL )
					{
					clFree( "readKeyset", object );
					retExt( CRYPT_ERROR_OVERFLOW, 
							( CRYPT_ERROR_OVERFLOW, errorInfo, 
							  "No more room in keyset to add further items" ) );
					}
				pkcs15infoPtr->index = index;
				memcpy( pkcs15infoPtr, &pkcs15objectInfo, 
						sizeof( PKCS15_INFO ) );
				}

			/* Copy over any ID information */
			copyObjectIdInfo( pkcs15infoPtr, &pkcs15objectInfo );

			/* Copy over any other new information that may have become
			   available.  The semantics when multiple date ranges are 
			   present (for example one for a key and one for a certificate) 
			   are a bit uncertain, we use the most recent date available on 
			   the assumption that this reflects the newest information */
			if( pkcs15objectInfo.validFrom > pkcs15infoPtr->validFrom )
				pkcs15infoPtr->validFrom = pkcs15objectInfo.validFrom;
			if( pkcs15objectInfo.validTo > pkcs15infoPtr->validTo )
				pkcs15infoPtr->validTo = pkcs15objectInfo.validTo;

			/* Copy the payload over */
			copyObjectPayloadInfo( pkcs15infoPtr, &pkcs15objectInfo,
								   object, objectLength, type );
			}
		ENSURES( innerIterationCount < FAILSAFE_ITERATIONS_LARGE );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( CRYPT_OK );
	}
#endif /* USE_PKCS15 */
