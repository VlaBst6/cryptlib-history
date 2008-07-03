/****************************************************************************
*																			*
*					  cryptlib De-enveloping Routines						*
*					 Copyright Peter Gutmann 1996-2008						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "envelope.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "envelope/envelope.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_ENVELOPES

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* OID information used to read enveloped data */

static const CMS_CONTENT_INFO FAR_BSS oidInfoSignedData = { 0, 3 };
static const CMS_CONTENT_INFO FAR_BSS oidInfoEnvelopedData = { 0, 2 };
static const CMS_CONTENT_INFO FAR_BSS oidInfoDigestedData = { 0, 2 };
static const CMS_CONTENT_INFO FAR_BSS oidInfoEncryptedData = { 0, 2 };
static const CMS_CONTENT_INFO FAR_BSS oidInfoCompressedData = { 0, 0 };
static const CMS_CONTENT_INFO FAR_BSS oidInfoAuthData = { 0, 0 };
static const CMS_CONTENT_INFO FAR_BSS oidInfoAuthEnvData = { 0, 0 };

static const OID_INFO FAR_BSS envelopeOIDinfo[] = {
	{ OID_CMS_DATA, ACTION_NONE },
	{ OID_CMS_SIGNEDDATA, ACTION_SIGN, &oidInfoSignedData },
	{ OID_CMS_ENVELOPEDDATA, ACTION_KEYEXCHANGE, &oidInfoEnvelopedData },
	{ OID_CMS_DIGESTEDDATA, ACTION_HASH, &oidInfoDigestedData },
	{ OID_CMS_ENCRYPTEDDATA, ACTION_CRYPT, &oidInfoEncryptedData },
	{ OID_CMS_COMPRESSEDDATA, ACTION_COMPRESS, &oidInfoCompressedData },
	{ OID_CMS_AUTHDATA, ACTION_MAC, &oidInfoAuthData },
	{ OID_CMS_AUTHENVDATA, ACTION_MAC, &oidInfoAuthEnvData },
	{ OID_CMS_TSTOKEN, ACTION_NONE },
	{ OID_MS_SPCINDIRECTDATACONTEXT, ACTION_NONE },
	{ OID_CRYPTLIB_RTCSREQ, ACTION_NONE },
	{ OID_CRYPTLIB_RTCSRESP, ACTION_NONE },
	{ OID_CRYPTLIB_RTCSRESP_EXT, ACTION_NONE },
	{ NULL, 0 }, { NULL, 0 }
	};

static const OID_INFO FAR_BSS nestedContentOIDinfo[] = {
	{ OID_CMS_DATA, CRYPT_CONTENT_DATA },
	{ OID_CMS_SIGNEDDATA, CRYPT_CONTENT_SIGNEDDATA },
	{ OID_CMS_ENVELOPEDDATA, CRYPT_CONTENT_ENVELOPEDDATA },
	{ OID_CMS_ENCRYPTEDDATA, CRYPT_CONTENT_ENCRYPTEDDATA },
	{ OID_CMS_COMPRESSEDDATA, CRYPT_CONTENT_COMPRESSEDDATA },
	{ OID_CMS_AUTHDATA, CRYPT_CONTENT_AUTHDATA },
	{ OID_CMS_AUTHENVDATA, CRYPT_CONTENT_AUTHENVDATA },
	{ OID_CMS_TSTOKEN, CRYPT_CONTENT_TSTINFO },
	{ OID_MS_SPCINDIRECTDATACONTEXT, CRYPT_CONTENT_SPCINDIRECTDATACONTEXT },
	{ OID_CRYPTLIB_RTCSREQ, CRYPT_CONTENT_RTCSREQUEST },
	{ OID_CRYPTLIB_RTCSRESP, CRYPT_CONTENT_RTCSRESPONSE },
	{ OID_CRYPTLIB_RTCSRESP_EXT, CRYPT_CONTENT_RTCSRESPONSE_EXT },
	{ NULL, 0 }, { NULL, 0 }
	};

/* Sanity-check the envelope state */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheck( const ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Make sure that general envelope state is in order */
	if( !( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) )
		return( FALSE );
	if( envelopeInfoPtr->deenvState < DEENVSTATE_NONE || \
		envelopeInfoPtr->deenvState >= DEENVSTATE_LAST )
		return( FALSE );

	/* Make sure that the buffer position is within bounds */
	if( envelopeInfoPtr->buffer == NULL || \
		envelopeInfoPtr->bufPos < 0 || \
		envelopeInfoPtr->bufPos > envelopeInfoPtr->bufSize || \
		envelopeInfoPtr->bufSize < MIN_BUFFER_SIZE || \
		envelopeInfoPtr->bufSize >= MAX_INTLENGTH )
		return( FALSE );

	return( TRUE );
	}

/* Add information about an object to an envelope's content information list.  
   The content information can be supplied in one of two ways, either 
   implicitly via the data in the stream or explicitly via a QUERY_INFO
   structure */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int addContentListItem( INOUT ENVELOPE_INFO *envelopeInfoPtr,
							   INOUT_OPT STREAM *stream, 
							   OUT_OPT QUERY_INFO *externalQueryInfoPtr,
							   OUT_LENGTH_SHORT_Z int *itemSize )
	{
	QUERY_INFO queryInfo, *queryInfoPtr = ( externalQueryInfoPtr == NULL ) ? \
										  &queryInfo : externalQueryInfoPtr;
	CONTENT_LIST *contentListItem;
	BYTE *contentListObjectPtr = NULL;
	int objectSize = 0, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( ( stream == NULL && \
			  isWritePtr( externalQueryInfoPtr, sizeof( QUERY_INFO ) ) ) || \
			( isWritePtr( stream, sizeof( STREAM ) ) && \
			  externalQueryInfoPtr == NULL ) );
	assert( isWritePtr( itemSize, sizeof( int ) ) );

	REQUIRES( ( stream == NULL && externalQueryInfoPtr != NULL ) || \
			  ( stream != NULL && externalQueryInfoPtr == NULL ) );

	/* Clear return value */
	*itemSize = 0;

	/* Make sure that there's room to add another list item */
	if( !moreContentItemsPossible( envelopeInfoPtr->contentList ) )
		return( CRYPT_ERROR_OVERFLOW );

	/* Find the size of the object, allocate a buffer for it, and copy it
	   across */
	if( externalQueryInfoPtr == NULL )
		{
		/* See what we've got.  This call verifies that all of the object 
		   data is present in the stream so in theory we don't have to check 
		   the following reads, but we check them anyway just to be sure */
		status = queryAsn1Object( stream, queryInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		objectSize = ( int ) queryInfoPtr->size;

		/* If it's a valid but unrecognised object type (a new RecipientInfo 
		   type that was added after this version of cryptlib was released), 
		   skip it and continue (if there are no recognised RecipientInfo 
		   types, the code will automatically fall back to asking the user 
		   for a raw session key).  Alternatively, we could just add it to 
		   the content list as an unrecognised object type, but this would 
		   lead to confusion for the caller when non-object-types appear 
		   when they query the current component */
		if( queryInfoPtr->type == CRYPT_OBJECT_NONE )
			{
			status = sSkip( stream, objectSize );
			if( cryptStatusError( status ) )
				return( status );
			*itemSize = objectSize;

			return( CRYPT_OK );
			}

		/* Read the object data into memory */
		if( ( contentListObjectPtr = clAlloc( "addContentListItem", \
											  objectSize ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		status = sread( stream, contentListObjectPtr, objectSize );
		if( cryptStatusError( status ) )
			{
			clFree( "addContentListItem", contentListObjectPtr );
			return( status );
			}
		}
	ENSURES( ( externalQueryInfoPtr != NULL ) || \
			 ( queryInfoPtr->size > 0 && \
			   queryInfoPtr->size < MAX_INTLENGTH ) );
			 /* If the query info is supplied externally it's a template that
			    doesn't correspond to any actual data */

	/* Allocate memory for the new content list item and copy information on
	   the item across */
	status = createContentListItem( &contentListItem, 
					envelopeInfoPtr->memPoolState, queryInfoPtr->formatType, 
					contentListObjectPtr, objectSize,
					( queryInfoPtr->type == CRYPT_OBJECT_SIGNATURE ) ? \
						TRUE : FALSE );
	if( cryptStatusError( status ) )
		{
		if( contentListObjectPtr == NULL )
			clFree( "addContentListItem", contentListObjectPtr );
		return( status );
		}
	if( externalQueryInfoPtr != NULL )
		{
		CONTENT_ENCR_INFO *encrInfo = &contentListItem->clEncrInfo;

		/* It's externally-supplied crypto algorithm details from an
		   encrypted data header */
		contentListItem->envInfo = CRYPT_ENVINFO_SESSIONKEY;
		encrInfo->cryptAlgo = queryInfoPtr->cryptAlgo;
		encrInfo->cryptMode = queryInfoPtr->cryptMode;
		if( queryInfoPtr->ivLength > 0 )
			{
			REQUIRES( queryInfoPtr->ivLength > 0 && \
					  queryInfoPtr->ivLength <= CRYPT_MAX_IVSIZE );
			memcpy( encrInfo->saltOrIV, queryInfoPtr->iv, 
					queryInfoPtr->ivLength );
			encrInfo->saltOrIVsize = queryInfoPtr->ivLength;
			}
		}
	if( queryInfoPtr->type == CRYPT_OBJECT_PKCENCRYPTED_KEY || \
		queryInfoPtr->type == CRYPT_OBJECT_SIGNATURE )
		{
		/* Remember the details of the enveloping info that we require to 
		   continue */
		if( queryInfoPtr->type == CRYPT_OBJECT_PKCENCRYPTED_KEY )
			contentListItem->envInfo = CRYPT_ENVINFO_PRIVATEKEY;
		else
			{
			contentListItem->envInfo = CRYPT_ENVINFO_SIGNATURE;
			contentListItem->clSigInfo.hashAlgo = queryInfoPtr->hashAlgo;
			}
		if( queryInfoPtr->formatType == CRYPT_FORMAT_CMS )
			{
			REQUIRES( rangeCheck( queryInfoPtr->iAndSStart, 
								  queryInfoPtr->iAndSLength, objectSize ) );
			contentListItem->issuerAndSerialNumber = contentListObjectPtr + \
													 queryInfoPtr->iAndSStart;
			contentListItem->issuerAndSerialNumberSize = queryInfoPtr->iAndSLength;
			}
		else
			{
			REQUIRES( queryInfoPtr->keyIDlength > 0 && \
					  queryInfoPtr->keyIDlength <= CRYPT_MAX_HASHSIZE );
			memcpy( contentListItem->keyID, queryInfoPtr->keyID,
					queryInfoPtr->keyIDlength );
			contentListItem->keyIDsize = queryInfoPtr->keyIDlength;
			}
		REQUIRES( rangeCheck( queryInfoPtr->dataStart, 
							  queryInfoPtr->dataLength, objectSize ) );
		contentListItem->payload = contentListObjectPtr + \
								   queryInfoPtr->dataStart;
		contentListItem->payloadSize = queryInfoPtr->dataLength;
		if( queryInfoPtr->type == CRYPT_OBJECT_SIGNATURE && \
			queryInfoPtr->formatType == CRYPT_FORMAT_CMS && \
			queryInfoPtr->unauthAttributeStart > 0 )
			{
			CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;

			REQUIRES( rangeCheck( queryInfoPtr->unauthAttributeStart,
								  queryInfoPtr->unauthAttributeLength, 
								  objectSize ) );
			sigInfo->extraData2 = contentListObjectPtr + \
								  queryInfoPtr->unauthAttributeStart;
			sigInfo->extraData2Length = queryInfoPtr->unauthAttributeLength;
			}
		}
	if( queryInfoPtr->type == CRYPT_OBJECT_ENCRYPTED_KEY )
		{
		CONTENT_ENCR_INFO *encrInfo = &contentListItem->clEncrInfo;

		/* Remember the details of the enveloping info that we require to 
		   continue */
		if( queryInfoPtr->keySetupAlgo != CRYPT_ALGO_NONE )
			{
			contentListItem->envInfo = CRYPT_ENVINFO_PASSWORD;
			encrInfo->keySetupAlgo = queryInfoPtr->keySetupAlgo;
			encrInfo->keySetupIterations = queryInfoPtr->keySetupIterations;
			if( queryInfoPtr->saltLength > 0 )
				{
				REQUIRES( queryInfoPtr->saltLength > 0 && \
						  queryInfoPtr->saltLength <= CRYPT_MAX_HASHSIZE );
				memcpy( encrInfo->saltOrIV, queryInfoPtr->salt,
						queryInfoPtr->saltLength );
				encrInfo->saltOrIVsize = queryInfoPtr->saltLength;
				}
			}
		else
			contentListItem->envInfo = CRYPT_ENVINFO_KEY;
		encrInfo->cryptAlgo = queryInfoPtr->cryptAlgo;
		encrInfo->cryptMode = queryInfoPtr->cryptMode;
		REQUIRES( rangeCheck( queryInfoPtr->dataStart, 
							  queryInfoPtr->dataLength, objectSize ) );
		contentListItem->payload = contentListObjectPtr + \
								   queryInfoPtr->dataStart;
		contentListItem->payloadSize = queryInfoPtr->dataLength;
		}
	appendContentListItem( envelopeInfoPtr, contentListItem );
	*itemSize = ( int ) queryInfoPtr->size;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Header Processing Routines						*
*																			*
****************************************************************************/

/* Process the outer CMS envelope header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processEnvelopeHeader( INOUT ENVELOPE_INFO *envelopeInfoPtr, 
								  INOUT STREAM *stream, 
								  OUT_ENUM_OPT( DEENV_STATE ) DEENV_STATE *state )
	{
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( state, sizeof( DEENV_STATE ) ) );

	/* Clear return value */
	*state = DEENVSTATE_NONE;

	/* Read the outer CMS header */
	status = readCMSheader( stream, envelopeOIDinfo,
							FAILSAFE_ARRAYSIZE( envelopeOIDinfo, OID_INFO ),
							&envelopeInfoPtr->payloadSize, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Determine the next state to continue processing */
	switch( status )
		{
		case ACTION_KEYEXCHANGE:
#ifdef USE_KEA
			status = peekTag( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( status != BER_SET )
				{
				/* There may be key agreement data present, try and read the 
				   start of the [0] IMPLICIT SEQUENCE { [0] SET OF Certificate } */
				readConstructed( stream, NULL, 0 );
				status = readConstructed( stream, NULL, 0 );
				if( cryptStatusError( status ) )
					return( status );
				}
#endif /* USE_KEA */
			envelopeInfoPtr->usage = ACTION_CRYPT;
			*state = DEENVSTATE_SET_ENCR;
			break;

		case ACTION_CRYPT:
			envelopeInfoPtr->usage = ACTION_CRYPT;
			*state = DEENVSTATE_ENCRCONTENT;
			break;

		case ACTION_SIGN:
			envelopeInfoPtr->usage = ACTION_SIGN;
			*state = DEENVSTATE_SET_HASH;
			break;

		case ACTION_MAC:
			/* MACd envelopes have key exchange information at the start 
			   just like ACTION_KEYEXCHANGE but the later processing is 
			   different, so we treat them as a special case here */
			envelopeInfoPtr->usage = ACTION_MAC;
			*state = DEENVSTATE_SET_ENCR;
			break;

		case ACTION_COMPRESS:
			/* With compressed data all that we need to do is check that the 
			   fixed AlgorithmIdentifier is present and set up the 
			   decompression stream, after which we go straight to the 
			   content */
			status = readGenericAlgoID( stream, OID_ZLIB, 
										sizeofOID( OID_ZLIB ) ); 
			if( cryptStatusError( status ) )
				return( status );
			envelopeInfoPtr->usage = ACTION_COMPRESS;
#ifdef USE_COMPRESSION
			if( inflateInit( &envelopeInfoPtr->zStream ) != Z_OK )
				return( CRYPT_ERROR_MEMORY );
			envelopeInfoPtr->flags |= ENVELOPE_ZSTREAMINITED;
			*state = DEENVSTATE_CONTENT;
#else
			return( CRYPT_ERROR_NOTAVAIL );
#endif /* USE_COMPRESSION */
			break;

		case ACTION_NONE:
			/* Since we're going straight to the data payload there's no 
			   nested content type so we explicitly set it to "data" */
			envelopeInfoPtr->contentType = CRYPT_CONTENT_DATA;
			*state = DEENVSTATE_DATA;
			break;

		default:
			retIntError();
		}

	return( CRYPT_OK );
	}

/* Process the encrypted content header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processEncryptionHeader( INOUT ENVELOPE_INFO *envelopeInfoPtr, 
									INOUT STREAM *stream )
	{
	QUERY_INFO queryInfo;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Read the encrypted content header */
	status = readCMSencrHeader( stream, nestedContentOIDinfo, 
						FAILSAFE_ARRAYSIZE( nestedContentOIDinfo, OID_INFO ),
						NULL, &queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	envelopeInfoPtr->contentType = status;
	envelopeInfoPtr->payloadSize = queryInfo.size;

	/* We've reached encrypted data, we can't go any further until we can 
	   either recover the session key from a key exchange object or are fed 
	   the session key directly */
	if( envelopeInfoPtr->actionList == NULL )
		{
		int dummy;

		/* Since the content can be indefinite-length we clear the size 
		   field to give it a sensible setting */
		queryInfo.size = 0;
		return( addContentListItem( envelopeInfoPtr, NULL, &queryInfo, 
									&dummy ) );
		}
	REQUIRES( envelopeInfoPtr->actionList != NULL && \
			  envelopeInfoPtr->actionList->action == ACTION_CRYPT );

	/* If the session key was recovered from a key exchange action but we 
	   ran out of input data before we could read the encryptedContent info 
	   it'll be present in the action list so we use it to set things up for 
	   the decryption.  This can only happen if the caller pushes in just 
	   enough data to get past the key exchange actions but not enough to 
	   recover the encryptedContent info and then pushes in a key exchange 
	   action in response to the CRYPT_ERROR_UNDERFLOW error */
	return( initEnvelopeEncryption( envelopeInfoPtr,
							envelopeInfoPtr->actionList->iCryptHandle,
							queryInfo.cryptAlgo, queryInfo.cryptMode,
							queryInfo.iv, queryInfo.ivLength,
							FALSE ) );
	}

/* Process the hash object header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processHashHeader( INOUT ENVELOPE_INFO *envelopeInfoPtr, 
							  INOUT STREAM *stream )
	{
	CRYPT_ALGO_TYPE hashAlgo = DUMMY_INIT;
	CRYPT_CONTEXT iHashContext;
	ACTION_LIST *actionListPtr;
	int iterationCount, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Create the hash object from the data */
	status = readContextAlgoID( stream, &iHashContext, NULL, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE,
								  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );

	/* Check whether an identical hash action is already present either 
	   through being supplied externally or from a duplicate entry in the 
	   set */
	for( actionListPtr = envelopeInfoPtr->actionList, iterationCount = 0;
		 actionListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED; 
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		CRYPT_ALGO_TYPE actionHashAlgo;

		status = krnlSendMessage( actionListPtr->iCryptHandle,
								  IMESSAGE_GETATTRIBUTE, &actionHashAlgo, 
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) && actionHashAlgo == hashAlgo )
			{
			/* There's a duplicate action present, destroy the one that 
			   we've just created and continue */
			krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
			return( CRYPT_OK );
			}
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	/* We didn't find any duplicates, append the new hash action to the 
	   action list and remember that hashing is now active */
	status = addAction( &envelopeInfoPtr->actionList, 
						envelopeInfoPtr->memPoolState, 
						( envelopeInfoPtr->usage == ACTION_MAC ) ? \
							ACTION_MAC : ACTION_HASH, iHashContext );
	if( cryptStatusError( status ) )
		return( status );
	envelopeInfoPtr->dataFlags |= ENVDATA_HASHACTIONSACTIVE;
	
	ENSURES( envelopeInfoPtr->actionList != NULL && \
			 ( envelopeInfoPtr->actionList->action == ACTION_HASH || \
			   envelopeInfoPtr->actionList->action == ACTION_MAC ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Trailer Processing Routines						*
*																			*
****************************************************************************/

/* Process EOCs that separate the payload from the trailer */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processPayloadEOCs( INOUT ENVELOPE_INFO *envelopeInfoPtr, 
							   INOUT STREAM *stream )
	{
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* If the payload has an indefinite-length encoding, make sure that the
	   required EOCs are present */
	if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED )
		{
		if( ( status = checkEOC( stream ) ) != TRUE || \
			( status = checkEOC( stream ) ) != TRUE )
			{
			return( cryptStatusError( status ) ? \
					status : CRYPT_ERROR_BADDATA );
			}

		return( CRYPT_OK );
		}

	/* If the data was encoded using a mixture of definite and indefinite 
	   encoding there may be EOC's present even though the length is known 
	   so we skip them if necessary */
	if( ( status = checkEOC( stream ) ) == TRUE )
		status = checkEOC( stream );
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}

/* Complete processing of the authenticated payload */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completePayloadProcessing( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* When we reach this point there may still be unhashed data left in the 
	   buffer.  It won't have been hashed yet because the hashing is 
	   performed when the data is copied out, after unwrapping and 
	   deblocking and whatnot, so we hash it before we wrap up the 
	   hashing */
	if( envelopeInfoPtr->dataLeft > 0 )
		{
		int status;

		status = envelopeInfoPtr->processExtraData( envelopeInfoPtr,
													envelopeInfoPtr->buffer,
													envelopeInfoPtr->dataLeft );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Wrap up the hashing */
	return( envelopeInfoPtr->processExtraData( envelopeInfoPtr, "", 0 ) );
	}

/* Process the signed data trailer */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processSignedTrailer( INOUT ENVELOPE_INFO *envelopeInfoPtr, 
								 INOUT STREAM *stream, 
								 INOUT_ENUM( DEENV_STATE ) DEENV_STATE *state )
	{
	DEENV_STATE newState;
	int tag, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( state, sizeof( DEENV_STATE ) ) );

	/* Read the SignedData EOC's if necessary */
	status = processPayloadEOCs( envelopeInfoPtr, stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Check whether there's a certificate chain to follow */
	tag = peekTag( stream );
	if( cryptStatusError( tag ) )
		return( tag );
	newState = ( tag == MAKE_CTAG( 0 ) ) ? \
			   DEENVSTATE_CERTSET : DEENVSTATE_SET_SIG;

	/* If we've seen all of the signed data complete the hashing */
	if( !( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) )
		{
		status = completePayloadProcessing( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Move on to the next state */
	*state = newState;
	return( CRYPT_OK );
	}

/* Process the MACd data trailer */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processMacTrailer( INOUT ENVELOPE_INFO *envelopeInfoPtr, 
							  INOUT STREAM *stream, 
							  OUT_BOOL BOOLEAN *failedMAC )
	{
	MESSAGE_DATA msgData;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	int hashSize, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( failedMAC, sizeof( BOOLEAN ) ) );

	/* Clear return value */
	*failedMAC = FALSE;

	/* Read the AuthenticatedData EOC's if necessary */
	status = processPayloadEOCs( envelopeInfoPtr, stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the MAC value that follows the payload */
	status = readOctetString( stream, hash, &hashSize, 16, 
							  CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Complete the payload processing and compare the read MAC value with 
	   the calculated one */
	status = completePayloadProcessing( envelopeInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, hash, hashSize );
	status = krnlSendMessage( envelopeInfoPtr->actionList->iCryptHandle, 
							  IMESSAGE_COMPARE, &msgData, 
							  MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		{
		/* Unlike signatures a failed MAC check (reported as a CRYPT_ERROR
		   comparison result) is detected immediately rather than after the
		   payload processing has completed.  However if we bail out now 
		   then any later checks of things like signature metadata will fail 
		   because the envelope regards processing as still being incomplete 
		   so we have to continue processing data until we at least get the 
		   envelope to the finished state */
		assert( status == CRYPT_ERROR );
		*failedMAC = TRUE;
		}

	return( CRYPT_OK );
	}

/* Process any remaining EOCs.  This gets a bit complicated because there 
   can be a variable number of EOCs depending on where definite and 
   indefinite encodings were used so we look for at least one EOC and at 
   most a number that depends on the data type being processed */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int processEOCTrailer( INOUT STREAM *stream, 
							  IN_ENUM_OPT( ACTION ) const ACTION_TYPE usage )
	{
	const int noEOCs = ( usage == ACTION_NONE ) ? 2 : \
					   ( usage == ACTION_SIGN || \
						 usage == ACTION_MAC ) ? 3 : \
					   ( usage == ACTION_COMPRESS ) ? 5 : 4;
	int i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( usage >= ACTION_NONE && usage < ACTION_LAST );

	/* Consume any EOCs up to the maximum amount possible.  In theory we 
	   could be rather liberal with trailing EOCs since it's not really 
	   necessary for the caller to push in every last one, however if we
	   assume that seeing at least one EOC is enough to signal the end of
	   all content this can lead to problems if adding the EOCs occurs
	   over a pushData boundary.  What can happen here is that the code will 
	   see the start of the string of EOCs on the first push, record the 
	   end-of-data-reached state, and then report a CRYPT_ERROR_COMPLETE 
	   when the remainder of the string of EOCs are pushed the next time
	   round.  To avoid this problem we have to be pedantic and require
	   that callers push all EOCs */
	for( i = 0; i < noEOCs; i++ )
		{
		const int value = checkEOC( stream );
		if( cryptStatusError( value ) )
			return( value );
		if( value == FALSE )
			return( CRYPT_ERROR_BADDATA );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Process Envelope Preamble/Postamble					*
*																			*
****************************************************************************/

/* Process the non-data portions of an envelope.  This is a complex event-
   driven state machine, but instead of reading along a (hypothetical
   Turing-machine) tape someone has taken the tape and cut it into bits and
   keeps feeding them to us and saying "See what you can do with this" (and
   occasionally "Where's the bloody spoons?").  The following code implements
   this state machine.

	Encr. with key exchange: SET_ENCR -> ENCR -> ENCRCONTENT -> DATA
	Encr.: ENCRCONTENT -> DATA
	Signed: SET_HASH -> HASH -> CONTENT -> DATA
	MACd: SET_ENCR -> ENCR -> HASH -> CONTENT -> DATA */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int processPreamble( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	DEENV_STATE state = envelopeInfoPtr->deenvState;
	STREAM stream;
	int remainder, streamPos = 0, iterationCount = 0, status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	
	REQUIRES( sanityCheck( envelopeInfoPtr ) );

	sMemConnect( &stream, envelopeInfoPtr->buffer, envelopeInfoPtr->bufPos );

	/* If we haven't started doing anything yet try and read the outer
	   header fields */
	if( state == DEENVSTATE_NONE )
		{
		status = processEnvelopeHeader( envelopeInfoPtr, &stream, &state );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Invalid CMS envelope header" ) );
			}

		/* Remember how far we got */
		streamPos = stell( &stream );
		}

	/* Keep consuming information until we either run out of input or reach 
	   the data payload.  Although in theory we should really use 
	   FAILSAFE_ITERATIONS_MED for this loop, in practice we have to use
	   FAILSAFE_ITERATIONS_LARGE because it's possible to generate S/MIME 
	   messages with large numbers of recipients for mailing lists.  This 
	   would never occur in any normal usage, but we have to allow for it for
	   mailing-list use */
	while( state != DEENVSTATE_DONE && \
		   iterationCount++ < FAILSAFE_ITERATIONS_LARGE )
		{
		/* Read the start of the SET OF RecipientInfo/SET OF 
		   DigestAlgorithmIdentifier */
		if( state == DEENVSTATE_SET_ENCR )
			{
			long setLongLength;

			/* Read the SET tag and length.  We have to read the length as
			   a long value in order to handle cases where there's a large 
			   amount of key management data involving a great many 
			   recipients */
			status = readLongSet( &stream, &setLongLength );
			if( cryptStatusError( status ) )
				{
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid SET OF RecipientInfo header", 35 );
				break;
				}
			envelopeInfoPtr->hdrSetLength = setLongLength;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given (setLength == CRYPT_UNUSED) we 
			   have to look for the EOC after each entry read */
			streamPos = stell( &stream );
			state = DEENVSTATE_ENCR;
			}
		if( state == DEENVSTATE_SET_HASH )
			{
			int setLength;

			/* Read the SET tag and length */
			status = readSetI( &stream, &setLength );
			if( cryptStatusError( status ) )
				{
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid SET OF DigestAlgorithmIdentifier "
								"header", 47 );
				break;
				}
			envelopeInfoPtr->hdrSetLength = setLength;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given (setLength == CRYPT_UNUSED) we 
			   have to look for the EOC after each entry read */
			streamPos = stell( &stream );
			state = DEENVSTATE_HASH;
			}

		/* Read and remember a key exchange object from an EncryptionKeyInfo
		   record */
		if( state == DEENVSTATE_ENCR )
			{
			int contentItemLength;

			/* Add the object to the content information list */
			status = addContentListItem( envelopeInfoPtr, &stream, NULL, 
										 &contentItemLength );
			if( cryptStatusError( status ) )
				{
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid EncryptionKeyInfo key exchange "
								"record", 45 );
				break;
				}

			/* Remember where we are and move on to the next state if
			   necessary */
			streamPos = stell( &stream );
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				if( contentItemLength > envelopeInfoPtr->hdrSetLength )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}
				envelopeInfoPtr->hdrSetLength -= contentItemLength;
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					{
					state = ( envelopeInfoPtr->usage == ACTION_MAC ) ? \
							DEENVSTATE_HASH : DEENVSTATE_ENCRCONTENT;
					}
				}
			else
				{
				const int value = checkEOC( &stream );
				if( cryptStatusError( value ) )
					{
					status = value;
					break;
					}
				if( value == TRUE )
					{
					state = ( envelopeInfoPtr->usage == ACTION_MAC ) ? \
							DEENVSTATE_HASH : DEENVSTATE_ENCRCONTENT;
					}
				}
			}

		/* Read the encrypted content information */
		if( state == DEENVSTATE_ENCRCONTENT )
			{
			status = processEncryptionHeader( envelopeInfoPtr, &stream );
			if( cryptStatusError( status ) )
				{
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid encrypted content header", 32 );
				break;
				}

			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
			state = DEENVSTATE_DATA;
			if( envelopeInfoPtr->actionList == NULL )
				{
				/* If we haven't got a session key to decrypt the data that
				   follows we can't go beyond this point */
				status = CRYPT_ENVELOPE_RESOURCE;
				break;
				}
			}

		/* Read and remember a MAC object from a MACAlgorithmIdentifier
		   record */
		if( state == DEENVSTATE_HASH && \
			envelopeInfoPtr->usage == ACTION_MAC )
			{
			status = processHashHeader( envelopeInfoPtr, &stream );
			if( cryptStatusError( status ) )
				{
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid hashed/MACd content header", 34 );
				break;
				}

			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
			state = DEENVSTATE_CONTENT;
			}

		/* Read and remember a hash object from a DigestAlgorithmIdentifier
		   record */
		if( state == DEENVSTATE_HASH )
			{
			status = processHashHeader( envelopeInfoPtr, &stream );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state if
			   necessary */
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				const int hashInfoLength = stell( &stream ) - streamPos;
				if( hashInfoLength < 0 || \
					hashInfoLength > envelopeInfoPtr->hdrSetLength )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}
				envelopeInfoPtr->hdrSetLength -= hashInfoLength;
				streamPos = stell( &stream );
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					state = DEENVSTATE_CONTENT;
				}
			else
				{
				const int value = checkEOC( &stream );
				if( cryptStatusError( value ) )
					{
					status = value;
					break;
					}
				if( value == TRUE )
					state = DEENVSTATE_CONTENT;
				}
			}

		/* Read the encapsulated content header */
		if( state == DEENVSTATE_CONTENT )
			{
			int contentType;

			status = contentType = \
				readCMSheader( &stream, nestedContentOIDinfo,
							   FAILSAFE_ARRAYSIZE( nestedContentOIDinfo, OID_INFO ),
							   &envelopeInfoPtr->payloadSize, TRUE );
			if( cryptStatusError( status ) )
				{
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid encapsulated content header", 35 );
				break;
				}
			envelopeInfoPtr->contentType = contentType;

			/* If there's no content included and it's not an attributes-only
			   message then this is a detached signature with the content 
			   supplied anderswhere */
			if( envelopeInfoPtr->payloadSize == 0 && \
				!( envelopeInfoPtr->flags & ENVELOPE_ATTRONLY ) )
				envelopeInfoPtr->flags |= ENVELOPE_DETACHED_SIG;

			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
			state = ( envelopeInfoPtr->payloadSize == 0 && \
					  ( envelopeInfoPtr->flags & ( ENVELOPE_DETACHED_SIG | \
												   ENVELOPE_ATTRONLY ) ) ) ? \
					DEENVSTATE_DONE : DEENVSTATE_DATA;

			/* If this is MACd data and we haven't loaded a key to MAC the 
			   data that follows we can't go beyond this point */
			if( envelopeInfoPtr->usage == ACTION_MAC )
				{
				if( envelopeInfoPtr->actionList == NULL )
					{
					status = CRYPT_ENVELOPE_RESOURCE;
					break;
					}
				REQUIRES( envelopeInfoPtr->actionList->action == ACTION_MAC );
				status = krnlSendMessage( envelopeInfoPtr->actionList->iCryptHandle,
										  IMESSAGE_CHECK, NULL, 
										  MESSAGE_CHECK_MAC );
				if( cryptStatusError( status ) )
					{
					status = CRYPT_ENVELOPE_RESOURCE;
					break;
					}
				}
			}

		/* Start the decryption process if necessary */
		if( state == DEENVSTATE_DATA )
			{
			/* Synchronise the data stream processing to the start of the
			   encrypted data and move back to the start of the data
			   stream */
			status = envelopeInfoPtr->syncDeenvelopeData( envelopeInfoPtr,
														  &stream );
			if( cryptStatusError( status ) )
				{
				setErrorString( ENVELOPE_ERRINFO, 
								"Couldn't synchronise envelope state prior "
								"to data payload processing", 68 );
				break;
				}
			streamPos = 0;	/* Data has been resync'd with start of stream */

			/* We're done */
			state = DEENVSTATE_DONE;

			ENSURES( checkActions( envelopeInfoPtr ) );
			}
		}
	sMemDisconnect( &stream );
	if( iterationCount >= FAILSAFE_ITERATIONS_LARGE )
		{
		/* Technically this would be an overflow but that's a recoverable
		   error so we make it a BADDATA, which is really what it is */
		return( CRYPT_ERROR_BADDATA );
		}
	envelopeInfoPtr->deenvState = state;

	ENSURES( streamPos >= 0 && streamPos < MAX_INTLENGTH && \
			 envelopeInfoPtr->bufPos - streamPos >= 0 );

	/* Consume the input that we've processed so far by moving everything 
	   past the current position down to the start of the envelope buffer */
	remainder = envelopeInfoPtr->bufPos - streamPos;
	REQUIRES( remainder >= 0 && remainder < MAX_INTLENGTH && \
			  streamPos + remainder <= envelopeInfoPtr->bufSize );
	if( remainder > 0 && streamPos > 0 )
		{
		memmove( envelopeInfoPtr->buffer, envelopeInfoPtr->buffer + streamPos,
				 remainder );
		}
	envelopeInfoPtr->bufPos = remainder;
	ENSURES( sanityCheck( envelopeInfoPtr ) );
	if( cryptStatusError( status ) )
		return( status );

	/* If all went OK but we're still not out of the header information,
	   return an underflow error */
	return( ( state != DEENVSTATE_DONE ) ? \
			CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
	}

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1 ) ) \
static int processPostamble( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	DEENV_STATE state = envelopeInfoPtr->deenvState;
	STREAM stream;
	BOOLEAN failedMAC = FALSE;
	int remainder, streamPos = 0, iterationCount = 0, status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( sanityCheck( envelopeInfoPtr ) );

	/* If that's all that there is, return */
	if( state == DEENVSTATE_NONE && \
		( envelopeInfoPtr->usage != ACTION_SIGN && \
		  envelopeInfoPtr->usage != ACTION_MAC ) && \
		envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		{
		/* Definite-length data with no trailer, there's nothing left to 
		   process */
		envelopeInfoPtr->deenvState = DEENVSTATE_DONE;
		return( CRYPT_OK );
		}

	/* If there's not enough data left in the stream to do anything, don't 
	   try and go any further */
	if( envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft < 2 )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Start reading the trailer data from the end of the payload */
	sMemConnect( &stream, envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
				 envelopeInfoPtr->bufPos - envelopeInfoPtr->dataLeft );

	/* If we haven't started doing anything yet figure out what we should be
	   looking for */
	if( state == DEENVSTATE_NONE )
		{
		switch( envelopeInfoPtr->usage )
			{
			case ACTION_SIGN:
				status = processSignedTrailer( envelopeInfoPtr, &stream, 
											   &state );
				break;

			case ACTION_MAC:
				status = processMacTrailer( envelopeInfoPtr, &stream, 
											&failedMAC );
				if( cryptStatusOK( status ) )
					{
					state = \
						( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
						DEENVSTATE_EOC : DEENVSTATE_DONE;
					}
				break;

			default:
				/* Just look for EOC's */
				state = DEENVSTATE_EOC;
				break;
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			setErrorString( ENVELOPE_ERRINFO, 
							"Invalid CMS signed/MACd data trailer", 36 );
			}
		streamPos = stell( &stream );
		}

	/* Keep consuming information until we run out of input or reach the end
	   of the data */
	while( state != DEENVSTATE_DONE && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED )
		{
		/* Read the certificate chain */
		if( state == DEENVSTATE_CERTSET )
			{
			int certSetLength;

			/* Read the certificate chain into the aux.buffer.  We can't 
			   import it yet at this point because we need the SignerInfo to 
			   definitively identify the leaf certificate.  Usually there's 
			   only one leaf but there will be more than one if there are 
			   multiple signatures present or if the sending app decides to 
			   shovel in assorted (non-relevant) certificates */
			status = getStreamObjectLength( &stream, &certSetLength );
			if( cryptStatusError( status ) )
				{
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid signing certificate chain header", 
								40 );
				break;
				}
			if( envelopeInfoPtr->auxBuffer == NULL )
				{
				/* Allocate a buffer for the certificate chain if necessary.  
				   This may already be allocated if the previous attempt to 
				   read the chain failed due to there being insufficient 
				   data in the envelope buffer */
				if( ( envelopeInfoPtr->auxBuffer = \
						clAlloc( "processPostamble", certSetLength ) ) == NULL )
					{
					status = CRYPT_ERROR_MEMORY;
					break;
					}
				envelopeInfoPtr->auxBufSize = certSetLength;
				}
			ENSURES( envelopeInfoPtr->auxBufSize == certSetLength );
			status = sread( &stream, envelopeInfoPtr->auxBuffer,
							envelopeInfoPtr->auxBufSize );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
			state = DEENVSTATE_SET_SIG;
			}

		/* Read the start of the SET OF Signature */
		if( state == DEENVSTATE_SET_SIG )
			{
			int setLength;

			/* Read the SET tag and length */
			status = readSetI( &stream, &setLength );
			if( cryptStatusError( status ) )
				{
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid SET OF Signature header", 31 );
				break;
				}
			envelopeInfoPtr->hdrSetLength = setLength;

			/* Remember where we are and move on to the next state.  Some
			   implementations use the indefinite-length encoding for this so
			   if there's no length given we have to look for the EOC after
			   each entry read */
			streamPos = stell( &stream );
			state = DEENVSTATE_SIG;
			}

		/* Read and remember a signature object from a Signature record */
		if( state == DEENVSTATE_SIG )
			{
			int contentItemLength;

			/* Add the object to the content information list */
			status = addContentListItem( envelopeInfoPtr, &stream, NULL,
										 &contentItemLength );
			if( cryptStatusError( status ) )
				{
				setErrorString( ENVELOPE_ERRINFO, 
								"Invalid CMS signature record", 28 );
				break;
				}

			/* Remember where we are and move on to the next state if
			   necessary */
			streamPos = stell( &stream );
			if( envelopeInfoPtr->hdrSetLength != CRYPT_UNUSED )
				{
				if( contentItemLength < 0 || \
					contentItemLength > envelopeInfoPtr->hdrSetLength )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}
				envelopeInfoPtr->hdrSetLength -= contentItemLength;
				if( envelopeInfoPtr->hdrSetLength <= 0 )
					{
					state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
							DEENVSTATE_EOC : DEENVSTATE_DONE;
					}
				}
			else
				{
				const int value = checkEOC( &stream );
				if( cryptStatusError( value ) )
					{
					status = value;
					setErrorString( ENVELOPE_ERRINFO, 
									"Invalid CMS EOC trailer", 23 );
					break;
					}
				if( value == TRUE )
					{
					state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
							DEENVSTATE_EOC : DEENVSTATE_DONE;
					}
				}
			}

		/* Handle end-of-contents octets */
		if( state == DEENVSTATE_EOC )
			{
			status = processEOCTrailer( &stream, envelopeInfoPtr->usage );
			if( cryptStatusError( status ) )
				break;

			/* We're done */
			streamPos = stell( &stream );
			state = DEENVSTATE_DONE;
			break;
			}
		}
	sMemDisconnect( &stream );
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		{
		/* We can only go once through the loop on a MAC check, so we 
		   shouldn't get here with a failed MAC */
		ENSURES( !failedMAC );

		/* Technically this would be an overflow but that's a recoverable
		   error so we make it a BADDATA, which is really what it is */
		return( CRYPT_ERROR_BADDATA );
		}
	envelopeInfoPtr->deenvState = state;
	ENSURES( streamPos >= 0 && streamPos < MAX_INTLENGTH );

	/* Consume the input that we've processed so far by moving everything 
	   past the current position down to the start of the memory buffer:

									 bufPos
										| bufSize
										v	v
		+-----------+-------+-----------+---+
		|  dataLeft	|		|			|	|
		+-----------+-------+-----------+---+
					|<--+-->|<-- rem -->|
						|
					streamPos */
	remainder = envelopeInfoPtr->bufPos - \
				( envelopeInfoPtr->dataLeft + streamPos );
	REQUIRES( remainder >= 0 && remainder < MAX_INTLENGTH && \
			  envelopeInfoPtr->dataLeft + streamPos + \
					remainder <= envelopeInfoPtr->bufPos );
	if( remainder > 0 && streamPos > 0 )
		{
		memmove( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
				 envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft + streamPos,
				 remainder );
		}
	envelopeInfoPtr->bufPos = envelopeInfoPtr->dataLeft + remainder;
	ENSURES( sanityCheck( envelopeInfoPtr ) );
	if( failedMAC )
		{
		/* If the MAC check failed then this overrides any other status */
		return( CRYPT_ERROR_SIGNATURE );
		}
	if( cryptStatusError( status ) )
		{
		/* If we got an underflow error but there's payload data left to be 
		   copied out convert the status to OK since the caller can still
		   continue before they need to copy in more data.  Since there's
		   more data left to process we return OK_SPECIAL to tell the 
		   calling function not to perform any cleanup */
		if( status == CRYPT_ERROR_UNDERFLOW && envelopeInfoPtr->dataLeft > 0 )
			return( OK_SPECIAL );

		return( status );
		}

	/* If all went OK but we're still not out of the header information, 
	   return an underflow error */
	return( ( state != DEENVSTATE_DONE ) ? CRYPT_ERROR_UNDERFLOW : CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initCMSDeenveloping( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES_V( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE );

	/* Set the access method pointers */
	envelopeInfoPtr->processPreambleFunction = processPreamble;
	envelopeInfoPtr->processPostambleFunction = processPostamble;
	envelopeInfoPtr->checkAlgo = cmsCheckAlgo;

	/* Set up the processing state information */
	envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
	}
#endif /* USE_ENVELOPES */
