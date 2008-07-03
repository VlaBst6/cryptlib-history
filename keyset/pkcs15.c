/****************************************************************************
*																			*
*						  cryptlib PKCS #15 Routines						*
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

/* Each PKCS #15 file can contain information for multiple personalities 
   (although it's extremely unlikely to contain more than one or two), we 
   allow a maximum of MAX_PKCS15_OBJECTS per file in order to discourage 
   them from being used as general-purpose public-key keysets, which they're 
   not supposed to be.  A setting of 16 objects consumes ~2K of memory 
   (16 x ~128) and seems like a sensible upper bound so we choose that as 
   the limit */

#ifdef CONFIG_CONSERVE_MEMORY
  #define MAX_PKCS15_OBJECTS	8
#else
  #define MAX_PKCS15_OBJECTS	16
#endif /* CONFIG_CONSERVE_MEMORY */

#ifdef USE_PKCS15

/* OID information used to read a PKCS #15 file */

static const CMS_CONTENT_INFO FAR_BSS oidInfoPkcs15Data = { 0, 0 };

static const OID_INFO FAR_BSS keyFileOIDinfo[] = {
	{ OID_PKCS15_CONTENTTYPE, CRYPT_OK, &oidInfoPkcs15Data },
	{ NULL, 0 }, { NULL, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Get the hash of various certificate name fields */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5 ) ) \
int getCertID( IN_HANDLE const CRYPT_HANDLE iCryptHandle, 
			   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE nameType, 
			   OUT_BUFFER( nameIdMaxLen, *nameIdLen ) BYTE *nameID, 
			   IN_LENGTH_SHORT_MIN( KEYID_SIZE ) const int nameIdMaxLen,
			   OUT_LENGTH_SHORT_Z int *nameIdLen )
	{
	HASHFUNCTION_ATOMIC hashFunctionAtomic;
	DYNBUF idDB;
	int status;

	assert( isWritePtr( nameID, nameIdMaxLen ) );
	assert( isWritePtr( nameIdLen, sizeof( int ) ) );

	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( nameType == CRYPT_IATTRIBUTE_SPKI || \
			  nameType == CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER || \
			  nameType == CRYPT_IATTRIBUTE_SUBJECT || \
			  nameType == CRYPT_IATTRIBUTE_ISSUER );
	REQUIRES( nameIdMaxLen >= KEYID_SIZE && \
			  nameIdMaxLen < MAX_INTLENGTH_SHORT );

	/* Clear return value */
	*nameIdLen = 0;

	/* Get the attribute data and hash algorithm information and hash the 
	   attribute to get the ID */
	status = dynCreate( &idDB, iCryptHandle, nameType );
	if( cryptStatusError( status ) )
		return( status );
	getHashAtomicParameters( CRYPT_ALGO_SHA1, &hashFunctionAtomic, NULL );
	hashFunctionAtomic( nameID, nameIdMaxLen, dynData( idDB ), 
						dynLength( idDB ) );
	dynDestroy( &idDB );
	*nameIdLen = nameIdMaxLen;

	return( CRYPT_OK );
	}

/* Locate an object based on an ID */

#define matchID( src, srcLen, dest, destLen ) \
		( ( srcLen ) > 0 && ( srcLen ) == ( destLen ) && \
		  !memcmp( ( src ), ( dest ), ( destLen ) ) )

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
PKCS15_INFO *findEntry( IN_ARRAY( noPkcs15objects ) const PKCS15_INFO *pkcs15info,
						IN_LENGTH_SHORT const int noPkcs15objects,
						IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
						IN_BUFFER_OPT( keyIDlength ) const void *keyID, 
						IN_LENGTH_KEYID_Z const int keyIDlength,
						IN_FLAGS_Z( KEYMGMT ) const int requestedUsage )
	{
	int i;

	assert( isReadPtr( pkcs15info, \
					   sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( ( keyID == NULL && keyIDlength == 0 ) || \
			isReadPtr( keyID, keyIDlength ) );

	REQUIRES_N( noPkcs15objects >= 1 && \
				noPkcs15objects < MAX_INTLENGTH_SHORT );
	REQUIRES_N( keyIDtype == CRYPT_KEYID_NAME || \
				keyIDtype == CRYPT_KEYID_URI || \
				keyIDtype == CRYPT_IKEYID_KEYID || \
				keyIDtype == CRYPT_IKEYID_PGPKEYID || \
				keyIDtype == CRYPT_IKEYID_ISSUERID || \
				keyIDtype == CRYPT_KEYIDEX_ID || \
				keyIDtype == CRYPT_KEYIDEX_SUBJECTNAMEID );
	REQUIRES_N( ( keyID == NULL && keyIDlength == 0 ) || \
				( keyID != NULL && \
				  keyIDlength >= MIN_NAME_LENGTH && \
				  keyIDlength < MAX_ATTRIBUTE_SIZE ) );
	REQUIRES_N( requestedUsage >= KEYMGMT_FLAG_NONE && \
				requestedUsage < KEYMGMT_FLAG_MAX );
	REQUIRES_N( ( requestedUsage & KEYMGMT_MASK_USAGEOPTIONS ) != \
				KEYMGMT_MASK_USAGEOPTIONS );

	/* If there's no ID to search on, don't try and do anything.  This can
	   occur when we're trying to build a chain and the necessary chaining
	   data isn't present */
	if( keyID == NULL || keyIDlength <= 0 )
		return( NULL );

	/* Try and locate the appropriate object in the PKCS #15 collection */
	for( i = 0; i < noPkcs15objects && i < FAILSAFE_ITERATIONS_MED; i++ )
		{
		const PKCS15_INFO *pkcs15infoPtr = &pkcs15info[ i ];
		const int compositeUsage = pkcs15infoPtr->pubKeyUsage | \
								   pkcs15infoPtr->privKeyUsage;

		/* If there's no entry at this position, continue */
		if( pkcs15infoPtr->type == PKCS15_SUBTYPE_NONE )
			continue;

		/* If there's an explicit usage requested, make sure that the key 
		   usage matches this.  This can get slightly complex because the 
		   advertised usage isn't necessarily the same as the usage 
		   permitted by the associated certificate (PKCS #11 apps are 
		   particularly good at setting bogus usage types) and the overall 
		   result can be further influenced by trusted usage settings, so 
		   all that we check for here is an indicated usage for the key 
		   matching the requested usage */
		if( ( requestedUsage & KEYMGMT_FLAG_USAGE_CRYPT ) && \
			!( compositeUsage & ENCR_USAGE_MASK ) )
			continue;
		if( ( requestedUsage & KEYMGMT_FLAG_USAGE_SIGN ) && \
			!( compositeUsage & SIGN_USAGE_MASK ) )
			continue;

		/* Check for a match based on the ID type */
		switch( keyIDtype )
			{
			case CRYPT_KEYID_NAME:
			case CRYPT_KEYID_URI:
				if( matchID( pkcs15infoPtr->label, pkcs15infoPtr->labelLength,
							 keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_IKEYID_KEYID:
				if( matchID( pkcs15infoPtr->keyID, pkcs15infoPtr->keyIDlength,
							 keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_IKEYID_PGPKEYID:
				/* For the PGP keyID we compare both IDs for the reasons 
				   given in the PGP keyset read code */
				if( matchID( pkcs15infoPtr->pgp2KeyID,
							 pkcs15infoPtr->pgp2KeyIDlength, keyID,
							 keyIDlength ) || \
					matchID( pkcs15infoPtr->openPGPKeyID,
							 pkcs15infoPtr->openPGPKeyIDlength, keyID,
							 keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_IKEYID_ISSUERID:
				if( matchID( pkcs15infoPtr->iAndSID,
							 pkcs15infoPtr->iAndSIDlength, keyID,
							 keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_KEYIDEX_ID:
				if( matchID( pkcs15infoPtr->iD, pkcs15infoPtr->iDlength,
							 keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			case CRYPT_KEYIDEX_SUBJECTNAMEID:
				if( matchID( pkcs15infoPtr->subjectNameID,
							 pkcs15infoPtr->subjectNameIDlength, keyID,
							 keyIDlength ) )
					return( ( PKCS15_INFO * ) pkcs15infoPtr );
				break;

			default:
				retIntError_Null();
			}
		}
	ENSURES_N( i < FAILSAFE_ITERATIONS_MED );

	/* If we're trying to match on the PGP key ID and didn't find anything,
	   retry it using the first PGP_KEYID_SIZE bytes of the object ID.  This
	   is necessary because calculation of the OpenPGP ID requires the
	   presence of data that may not be present in non-PGP keys so we can't
	   calculate a real OpenPGP ID but have to use the next-best thing 
	   (sol lucet omnibus) */
	if( keyIDtype == CRYPT_IKEYID_PGPKEYID )
		{
		for( i = 0; i < noPkcs15objects && i < FAILSAFE_ITERATIONS_MED; i++ )
			{
			const PKCS15_INFO *pkcs15infoPtr = &pkcs15info[ i ];

			if( pkcs15infoPtr->type != PKCS15_SUBTYPE_NONE && \
				pkcs15infoPtr->iDlength >= PGP_KEYID_SIZE && \
				!memcmp( keyID, pkcs15infoPtr->iD, PGP_KEYID_SIZE ) )
				return( ( PKCS15_INFO * ) pkcs15infoPtr );
			}
		ENSURES_N( i < FAILSAFE_ITERATIONS_MED );
		}

	return( NULL );
	}

/* Find a free PKCS #15 entry */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
PKCS15_INFO *findFreeEntry( IN_ARRAY( noPkcs15objects ) \
								const PKCS15_INFO *pkcs15info,
							IN_LENGTH_SHORT const int noPkcs15objects, 
							OUT_OPT_LENGTH_SHORT_Z int *index )
	{
	int i;

	assert( isReadPtr( pkcs15info, \
					   sizeof( PKCS15_INFO ) * noPkcs15objects ) );
	assert( ( index == NULL ) || isWritePtr( index, sizeof( int ) ) );

	REQUIRES_N( noPkcs15objects >= 1 && \
				noPkcs15objects < MAX_INTLENGTH_SHORT );

	/* Clear return value */
	if( index != NULL )
		*index = CRYPT_ERROR;

	for( i = 0; i < noPkcs15objects && i < FAILSAFE_ITERATIONS_MED; i++ )
		{
		if( pkcs15info[ i ].type == PKCS15_SUBTYPE_NONE )
			break;
		}
	ENSURES_N( i < FAILSAFE_ITERATIONS_MED );
	if( i >= noPkcs15objects )
		return( NULL );

	if( index != NULL )
		{
		/* Remember the index value (used for enumerating PKCS #15 entries) 
		   for this entry */
		*index = i;
		}
	return( ( PKCS15_INFO * ) &pkcs15info[ i ] );
	}

/* Free object entries */

STDC_NONNULL_ARG( ( 1 ) ) \
void pkcs15freeEntry( INOUT PKCS15_INFO *pkcs15info )
	{
	assert( isWritePtr( pkcs15info, sizeof( PKCS15_INFO ) ) );

	if( pkcs15info->pubKeyData != NULL )
		{
		zeroise( pkcs15info->pubKeyData, pkcs15info->pubKeyDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->pubKeyData );
		}
	if( pkcs15info->privKeyData != NULL )
		{
		zeroise( pkcs15info->privKeyData, pkcs15info->privKeyDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->privKeyData );
		}
	if( pkcs15info->certData != NULL )
		{
		zeroise( pkcs15info->certData, pkcs15info->certDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->certData );
		}
	if( pkcs15info->dataData != NULL )
		{
		zeroise( pkcs15info->dataData, pkcs15info->dataDataSize );
		clFree( "pkcs15freeEntry", pkcs15info->dataData );
		}
	zeroise( pkcs15info, sizeof( PKCS15_INFO ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
static void pkcs15Free( INOUT_ARRAY( noPkcs15objects ) PKCS15_INFO *pkcs15info, 
						IN_LENGTH_SHORT const int noPkcs15objects )
	{
	int i;

	assert( isWritePtr( pkcs15info, \
						sizeof( PKCS15_INFO ) * noPkcs15objects ) );

	REQUIRES_V( noPkcs15objects >= 1 && \
				noPkcs15objects < MAX_INTLENGTH_SHORT );

	for( i = 0; i < noPkcs15objects && i < FAILSAFE_ITERATIONS_MED; i++ )
		pkcs15freeEntry( &pkcs15info[ i ] );
	ENSURES_V( i < FAILSAFE_ITERATIONS_MED );
	zeroise( pkcs15info, sizeof( PKCS15_INFO ) * noPkcs15objects );
	}

/* Get the PKCS #15 validity information from a certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int getValidityInfo( INOUT PKCS15_INFO *pkcs15info,
					 IN_HANDLE const CRYPT_HANDLE cryptHandle )
	{
	MESSAGE_DATA msgData;
	time_t validFrom, validTo;
	int status;

	assert( isWritePtr( pkcs15info, sizeof( PKCS15_INFO ) ) );

	REQUIRES( isHandleRangeValid( cryptHandle ) );

	/* Remember the validity information for later.  We always update the 
	   validity (even if it's already set) since we may be replacing an 
	   older certificate with a newer one */
	setMessageData( &msgData, &validFrom, sizeof( time_t ) );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_VALIDFROM );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, &validTo, sizeof( time_t ) );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_VALIDTO );
	if( cryptStatusError( status ) )
		return( status );
	if( pkcs15info->validTo > validTo )
		{
		/* There's an existing, newer certificate already present, make sure 
		   that we don't try and add the new one */
		return( CRYPT_ERROR_DUPLICATE );
		}
	pkcs15info->validFrom = validFrom;
	pkcs15info->validTo = validTo;

	return( CRYPT_OK );
	}

/* Read the header of a PKCS #15 keyset */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPkcs15header( INOUT STREAM *stream, 
							 OUT_INT_Z long *endPosPtr )
	{
	long endPos, dataEndPos;
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( endPosPtr, sizeof( long ) ) );

	/* Clear return value */
	*endPosPtr = 0;

	/* Read the outer header and make sure that the length information is 
	   valid */
	status = readCMSheader( stream, keyFileOIDinfo, 
							FAILSAFE_ARRAYSIZE( keyFileOIDinfo, OID_INFO ), 
							&dataEndPos, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's indefinite-length data, don't try and go any further (the 
	   general length check below will also catch this, but we make the 
	   check explicit here) */
	if( dataEndPos == CRYPT_UNUSED )
		return( CRYPT_ERROR_BADDATA );

	/* Make sure that the length information is sensible.  readCMSheader() 
	   reads the version number field at the start of the content so we have 
	   to adjust the stream position for this when we calculate the data end 
	   position */
	endPos = ( stell( stream ) - sizeofShortInteger( 0 ) ) + dataEndPos;
	if( dataEndPos < MIN_OBJECT_SIZE || dataEndPos >= MAX_INTLENGTH || \
		endPos < 16 + MIN_OBJECT_SIZE || endPos >= MAX_INTLENGTH )
		return( CRYPT_ERROR_BADDATA );
	*endPosPtr = endPos;

	/* Skip the key management information if there is any and read the 
	   inner wrapper */
	status = value = peekTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( value == MAKE_CTAG( 0 ) )
		readUniversal( stream );
	return( readLongSequence( stream, NULL ) );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* A PKCS #15 keyset can contain multiple keys and whatnot, so when we open
   it we parse the contents into memory for later use */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initFunction( INOUT KEYSET_INFO *keysetInfoPtr, 
						 STDC_UNUSED const char *name,
						 STDC_UNUSED const int nameLength,
						 IN_ENUM( CRYPT_KEYOPT ) const CRYPT_KEYOPT_TYPE options )
	{
	PKCS15_INFO *pkcs15info;
	STREAM *stream = &keysetInfoPtr->keysetFile->stream;
	long endPos = DUMMY_INIT;
	int status;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 );
	REQUIRES( name == NULL && nameLength == 0 );
	REQUIRES( options >= CRYPT_KEYOPT_NONE && options < CRYPT_KEYOPT_LAST );

	/* If we're opening an existing keyset skip the outer header, optional
	   keyManagementInfo, and inner header.  We do this before we perform any
	   setup operations to weed out potential problem files */
	if( options != CRYPT_KEYOPT_CREATE )
		{
		status = readPkcs15header( stream, &endPos );
		if( cryptStatusError( status ) )
			retExt( status, 
					( status, KEYSET_ERRINFO, 
					  "Invalid PKCS #15 keyset header" ) );
		}

	/* Allocate the PKCS #15 object information */
	if( ( pkcs15info = clAlloc( "initFunction", \
								sizeof( PKCS15_INFO ) * \
								MAX_PKCS15_OBJECTS ) ) == NULL )
		{
		if( options != CRYPT_KEYOPT_CREATE )
			{
			/* Reset the stream position to account for the header 
			   information that we've already read */
			sseek( stream, 0 ) ;
			}
		return( CRYPT_ERROR_MEMORY );
		}
	memset( pkcs15info, 0, sizeof( PKCS15_INFO ) * MAX_PKCS15_OBJECTS );
	keysetInfoPtr->keyData = pkcs15info;
	keysetInfoPtr->keyDataSize = sizeof( PKCS15_INFO ) * MAX_PKCS15_OBJECTS;
	keysetInfoPtr->keyDataNoObjects = MAX_PKCS15_OBJECTS;

	/* If this is a newly-created keyset, there's nothing left to do */
	if( options == CRYPT_KEYOPT_CREATE )
		return( CRYPT_OK );

	/* Read all of the keys in the keyset */
	status = readKeyset( &keysetInfoPtr->keysetFile->stream, pkcs15info,
						 MAX_PKCS15_OBJECTS, endPos, KEYSET_ERRINFO );
	if( cryptStatusError( status ) )
		{
		pkcs15Free( pkcs15info, MAX_PKCS15_OBJECTS );
		clFree( "initFunction", keysetInfoPtr->keyData );
		keysetInfoPtr->keyData = NULL;
		keysetInfoPtr->keyDataSize = 0;
		if( options != CRYPT_KEYOPT_CREATE )
			{
			/* Reset the stream position to account for the header 
			   information that we've already read */
			sseek( stream, 0 ) ;
			}
		return( status );
		}

	return( CRYPT_OK );
	}

/* Shut down the PKCS #15 state, flushing information to disk if necessary */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int shutdownFunction( INOUT KEYSET_INFO *keysetInfoPtr )
	{
	int status = CRYPT_OK;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 );

	/* If the contents have been changed, allocate a working I/O buffer for 
	   the duration of the flush and commit the changes to disk */
	if( keysetInfoPtr->flags & KEYSET_DIRTY )
		{
		STREAM *stream = &keysetInfoPtr->keysetFile->stream;
		BYTE buffer[ STREAM_BUFSIZE + 8 ];

		sseek( stream, 0 );
		sioctl( stream, STREAM_IOCTL_IOBUFFER, buffer, STREAM_BUFSIZE );
		status = pkcs15Flush( stream, keysetInfoPtr->keyData, 
							  keysetInfoPtr->keyDataNoObjects );
		sioctl( stream, STREAM_IOCTL_IOBUFFER, NULL, 0 );
		if( status == OK_SPECIAL )
			{
			keysetInfoPtr->flags |= KEYSET_EMPTY;
			status = CRYPT_OK;
			}
		}

	/* Free the PKCS #15 object information */
	if( keysetInfoPtr->keyData != NULL )
		{
		pkcs15Free( keysetInfoPtr->keyData, keysetInfoPtr->keyDataNoObjects );
		zeroise( keysetInfoPtr->keyData, keysetInfoPtr->keyDataSize );
		clFree( "shutdownFunction", keysetInfoPtr->keyData );
		}

	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, KEYSET_ERRINFO, 
				  "Couldn't send PKCS #15 data to persistent storage" ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Keyset Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setAccessMethodPKCS15( INOUT KEYSET_INFO *keysetInfoPtr )
	{
	int status;

	assert( isWritePtr( keysetInfoPtr, sizeof( KEYSET_INFO ) ) );

	REQUIRES( keysetInfoPtr->type == KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 );

	/* Set the access method pointers */
	keysetInfoPtr->initFunction = initFunction;
	keysetInfoPtr->shutdownFunction = shutdownFunction;
	status = initPKCS15get( keysetInfoPtr );
	if( cryptStatusOK( status ) )
		status = initPKCS15set( keysetInfoPtr );
	return( status );
	}
#endif /* USE_PKCS15 */
