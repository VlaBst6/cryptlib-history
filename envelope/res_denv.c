/****************************************************************************
*																			*
*					cryptlib De-enveloping Information Management			*
*						Copyright Peter Gutmann 1996-2008					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "envelope.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "pgp.h"
#else
  #include "envelope/envelope.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/* The maximum number of content items that we can add to a content list.
   We should use FAILSAFE_ITERATIONS_MED but encrypted messages sent to very 
   large distribution lists can have a number of per-recipient wrapped keys 
   that exceed this value */

#define MAX_CONTENT_ITEMS	FAILSAFE_ITERATIONS_LARGE - 1

#ifdef USE_ENVELOPES

/****************************************************************************
*																			*
*						Content List Management Functions					*
*																			*
****************************************************************************/

/* Check whether more content items can be added to a content list */

CHECK_RETVAL_BOOL \
BOOLEAN moreContentItemsPossible( IN_OPT const CONTENT_LIST *contentListPtr )
	{
	int contentListCount;

	assert( contentListPtr == NULL || \
			isReadPtr( contentListPtr, sizeof( ACTION_LIST ) ) );

	for( contentListCount = 0;
		 contentListPtr != NULL && contentListCount < FAILSAFE_ITERATIONS_LARGE;
		 contentListPtr = contentListPtr->next, contentListCount++ );
	ENSURES_B( contentListCount < FAILSAFE_ITERATIONS_LARGE );

	return( ( contentListCount < MAX_CONTENT_ITEMS ) ? TRUE : FALSE );
	}

/* Create a content list item */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int createContentListItem( OUT_PTR CONTENT_LIST **newContentListItemPtrPtr,
						   INOUT MEMPOOL_STATE memPoolState, 
						   IN_ENUM( CRYPT_FORMAT ) \
							const CRYPT_FORMAT_TYPE formatType,
						   IN_BUFFER_OPT( objectSize ) const void *object, 
						   IN_LENGTH_Z const int objectSize,
							const BOOLEAN isSigObject )
	{
	CONTENT_LIST *newItem;

	assert( isWritePtr( newContentListItemPtrPtr, \
						sizeof( CONTENT_LIST * ) ) );
	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( objectSize == 0 || isReadPtr( object, objectSize ) );

	REQUIRES( formatType > CRYPT_FORMAT_NONE && \
			  formatType < CRYPT_FORMAT_LAST );
	REQUIRES( ( object == NULL && objectSize == 0 ) || \
			  ( object != NULL && \
				objectSize > 0 && objectSize < MAX_INTLENGTH ) );

	if( ( newItem = getMemPool( memPoolState, \
								sizeof( CONTENT_LIST ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newItem, 0, sizeof( CONTENT_LIST ) );
	newItem->formatType = formatType;
	newItem->object = object;
	newItem->objectSize = objectSize;
	if( isSigObject )
		{
		newItem->flags = CONTENTLIST_ISSIGOBJ;
		newItem->clSigInfo.iSigCheckKey = CRYPT_ERROR;
		newItem->clSigInfo.iExtraData = CRYPT_ERROR;
		newItem->clSigInfo.iTimestamp = CRYPT_ERROR;
		}
	*newContentListItemPtrPtr = newItem;

	return( CRYPT_OK );
	}

/* Add an item to the content list */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int appendContentListItem( INOUT ENVELOPE_INFO *envelopeInfoPtr,
						   INOUT CONTENT_LIST *contentListItem )
	{
	CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentList;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( contentListPtr == NULL || \
			isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );

	/* Find the end of the list and add the new item */
	if( contentListPtr != NULL )
		{
		int iterationCount = 0;
		
		for( contentListPtr = envelopeInfoPtr->contentList, \
				iterationCount = 0;
			 contentListPtr->next != NULL && \
			   iterationCount < FAILSAFE_ITERATIONS_LARGE;
			contentListPtr = contentListPtr->next, iterationCount++ );
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
		}
	insertDoubleListElements( &envelopeInfoPtr->contentList, contentListPtr,
							  contentListItem, contentListItem );

	return( CRYPT_OK );
	}

/* Delete a content list */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
int deleteContentList( INOUT MEMPOOL_STATE memPoolState,
					   INOUT_PTR CONTENT_LIST **contentListHeadPtrPtr )
	{
	CONTENT_LIST *contentListCursor;
	int iterationCount;

	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( isWritePtr( contentListHeadPtrPtr, sizeof( CONTENT_LIST * ) ) );

	for( contentListCursor = *contentListHeadPtrPtr, iterationCount = 0;
		 contentListCursor != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		CONTENT_LIST *contentListItem = contentListCursor;

		contentListCursor = contentListCursor->next;

		/* Destroy any attached objects if necessary */
		if( contentListItem->flags & CONTENTLIST_ISSIGOBJ )
			{
			CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;

			if( sigInfo->iSigCheckKey != CRYPT_ERROR )
				krnlSendNotifier( sigInfo->iSigCheckKey, IMESSAGE_DECREFCOUNT );
			if( sigInfo->iExtraData != CRYPT_ERROR )
				krnlSendNotifier( sigInfo->iExtraData, IMESSAGE_DECREFCOUNT );
			if( sigInfo->iTimestamp != CRYPT_ERROR )
				krnlSendNotifier( sigInfo->iTimestamp, IMESSAGE_DECREFCOUNT );
			}

		/* Erase and free the object buffer if necessary */
		deleteDoubleListElement( contentListHeadPtrPtr, contentListItem );
		if( contentListItem->object != NULL )
			{
			/* Clear the object.  We have to cheat a bit here with pointer
			   casting, the 'const' indicates that the object data is never 
			   modified while it's in the content list but it has to be
			   modified in a manner of speaking when we delete it */
			zeroise( ( void * ) contentListItem->object, 
					 contentListItem->objectSize );
			clFree( "deleteContentList", ( void * ) contentListItem->object );
			}
		zeroise( contentListItem, sizeof( CONTENT_LIST ) );
		freeMemPool( memPoolState, contentListItem );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );

	*contentListHeadPtrPtr = NULL;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Process Signature Data 							*
*																			*
****************************************************************************/

/* Process timestamps */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processTimestamp( INOUT CONTENT_LIST *contentListPtr, 
							 IN_BUFFER( timestampLength ) const void *timestamp, 
							 IN_LENGTH_MIN( MIN_CRYPT_OBJECTSIZE ) \
								const int timestampLength )
	{
	CRYPT_ENVELOPE iTimestampEnvelope;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	const int bufSize = max( timestampLength + 128, MIN_BUFFER_SIZE );
	int status;

	assert( isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( timestamp, timestampLength ) );

	REQUIRES( timestampLength >= MIN_CRYPT_OBJECTSIZE && \
			  timestampLength < MAX_INTLENGTH );

	/* Create an envelope to contain the timestamp data.  We can't use the
	   internal enveloping API for this because we want to retain the final
	   envelope and not just recover the data contents (which for a 
	   timestamp will be empty anyway) */
	setMessageCreateObjectInfo( &createInfo, CRYPT_FORMAT_AUTO );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_ENVELOPE );
	if( cryptStatusError( status ) )
		return( status );
	iTimestampEnvelope = createInfo.cryptHandle;

	/* Push in the timestamp data */
	status = krnlSendMessage( iTimestampEnvelope, IMESSAGE_SETATTRIBUTE,
							  ( MESSAGE_CAST ) &bufSize, 
							  CRYPT_ATTRIBUTE_BUFFERSIZE );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, ( MESSAGE_CAST ) timestamp, \
						timestampLength );
		status = krnlSendMessage( iTimestampEnvelope, IMESSAGE_ENV_PUSHDATA,
								  &msgData, 0 );
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iTimestampEnvelope, IMESSAGE_ENV_PUSHDATA, 
								  &msgData, 0 );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iTimestampEnvelope, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* We've got the timestamp info in a sub-envelope, remember it for
	   later */
	contentListPtr->clSigInfo.iTimestamp = iTimestampEnvelope;
	return( CRYPT_OK );
	}

/* Process CMS unauthenticated attributes.  We can't handle these as
   standard CMS attributes since the only thing that we're likely to see 
   here is a countersignature, which isn't an attribute in the normal 
   sense */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processUnauthAttributes( INOUT CONTENT_LIST *contentListPtr,
									IN_BUFFER( unauthAttrLength ) \
										const void *unauthAttr,
									IN_LENGTH_MIN( MIN_CRYPT_OBJECTSIZE ) \
										const int unauthAttrLength )
	{
	STREAM stream;
	int iterationCount, status;

	assert( isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( unauthAttr, unauthAttrLength ) );

	REQUIRES( unauthAttrLength >= MIN_CRYPT_OBJECTSIZE && \
			  unauthAttrLength < MAX_INTLENGTH );

	/* Make sure that the unauthenticated attributes are OK.  Normally this
	   is done when we import the attributes but since we can't import
	   them we have to perform the check explicitly here */
	if( cryptStatusError( checkObjectEncoding( unauthAttr, 
											   unauthAttrLength ) ) )
		return( CRYPT_ERROR_BADDATA );

	/* Process each attribute */
	sMemConnect( &stream, unauthAttr, unauthAttrLength );
	status = readConstructed( &stream, NULL, 1 );
	for( iterationCount = 0;
		 cryptStatusOK( status ) && \
			sMemDataLeft( &stream ) >= MIN_CRYPT_OBJECTSIZE && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE; 
		 iterationCount++ )
		{
		BYTE oid[ MAX_OID_SIZE + 8 ];
		void *dataPtr;
		int oidLength, length = DUMMY_INIT;

		/* See what we've got */
		readSequence( &stream, NULL );
		status = readEncodedOID( &stream, oid, MAX_OID_SIZE, &oidLength, 
								 BER_OBJECT_IDENTIFIER );
		if( cryptStatusOK( status ) )
			status = readSet( &stream, &length );
		if( cryptStatusError( status ) )
			break;

		/* If it's something that we don't recognise, skip it and continue */
		if( oidLength != sizeofOID( OID_TSP_TSTOKEN ) || \
			memcmp( oid, OID_TSP_TSTOKEN, oidLength ) )
			{
			status = readUniversal( &stream );
			continue;
			}

		/* We've got a timestamp.  We can't really do much with this at the 
		   moment since although it quacks like a countersignature, in the 
		   PKIX tradition it's subtly (and gratuitously) incompatible in 
		   various ways so that it can't be verified as a standard 
		   countersignature (video meliora proboque deteriora sequor).  
		   Amusingly, the RFC actually states that this is a stupid way to 
		   do things.  Specifically, instead of using the normal MUST/SHOULD 
		   it first states that the sensible solution to the problem is to 
		   use a countersignature, and then goes on to mandate something 
		   that isn't a countersignature.  Since this isn't the sensible 
		   solution, it's obviously the stupid one.  QED */
		if( length < MIN_CRYPT_OBJECTSIZE )
			{
			/* It's too short to be a valid timestamp */
			status = CRYPT_ERROR_UNDERFLOW;
			continue;
			}
		status = sMemGetDataBlock( &stream, &dataPtr, length );
		if( cryptStatusOK( status ) )
			status = sSkip( &stream, length );
		if( cryptStatusOK( status ) )
			status = processTimestamp( contentListPtr, dataPtr, length );
		/* Continue in the loop with the cryptStatusOK() check */
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	sMemDisconnect( &stream );

	return( status );
	}

/* Perform additional checks beyond those performed for a standard 
   signature as required by CMS signatures */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
static int checkCmsSignatureInfo( INOUT CONTENT_LIST *contentListPtr, 
								  IN_HANDLE const CRYPT_HANDLE iHashContext,
								  IN_HANDLE const CRYPT_HANDLE iSigCheckContext,
								  IN_ENUM( CRYPT_CONTENT ) \
									const CRYPT_CONTENT_TYPE contentType,
								  INOUT ERROR_INFO *errorInfo )
	{
	CONTENT_SIG_INFO *sigInfo = &contentListPtr->clSigInfo;
	int status;

	assert( isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isWritePtr( errorInfo, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( isHandleRangeValid( iSigCheckContext ) );
	REQUIRES( contentType > CRYPT_CONTENT_NONE && \
			  contentType < CRYPT_CONTENT_LAST );

	/* If it's CMS signed data then the signature check key should be 
	   included with the signed data as a certificate chain, however it's 
	   possible (though unlikely) that the certificates may be unrelated to 
	   the signature, in which case the caller will have provided the 
	   signature check key from an external source */
	status = iCryptCheckSignature( contentListPtr->object, 
								   contentListPtr->objectSize, 
								   CRYPT_FORMAT_CMS,
								   ( sigInfo->iSigCheckKey == CRYPT_ERROR ) ? \
									iSigCheckContext : sigInfo->iSigCheckKey,
								   iHashContext, CRYPT_UNUSED,
								   &sigInfo->iExtraData );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, errorInfo, 
				  "Signature verification failed" ) );
		}

	/* If there are authenticated attributes present we have to perform an 
	   extra check to make sure that the content-type specified in the 
	   authenticated attributes matches the actual data content type */
	if( sigInfo->iExtraData != CRYPT_ERROR )
		{
		int signatureContentType;

		status = krnlSendMessage( sigInfo->iExtraData, IMESSAGE_GETATTRIBUTE, 
								  &signatureContentType, 
								  CRYPT_CERTINFO_CMS_CONTENTTYPE );
		if( cryptStatusError( status ) || \
			signatureContentType != contentType )
			{
			retExt( CRYPT_ERROR_SIGNATURE,
					( CRYPT_ERROR_SIGNATURE, errorInfo, 
					  "Content-type in authenticated attributes doesn't "
					  "match actual content type" ) );
			}
		}

	/* If there are unauthenticated attributes present, process them.  We 
	   don't record the processing status for these to ensure that some 
	   random error in the non signature-related attributes doesn't 
	   invalidate an otherwise OK signature */
	if( sigInfo->extraData2 != NULL )
		{
		const int localStatus = \
				processUnauthAttributes( contentListPtr, sigInfo->extraData2,
										 sigInfo->extraData2Length );
		if( cryptStatusError( localStatus ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, errorInfo, 
					  "Invalid unauthenticated attribute data") );
			}
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Process Encryption Data							*
*																			*
****************************************************************************/

/* Import a wrapped session key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int importSessionKey( const CONTENT_LIST *contentListPtr,
							 IN_HANDLE const CRYPT_CONTEXT iImportContext,
							 OUT_HANDLE_OPT CRYPT_CONTEXT *iSessionKeyContext )
	{
	CRYPT_CONTEXT iSessionKey;
	const CONTENT_LIST *sessionKeyInfoPtr;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int iterationCount, status;

	assert( isReadPtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isWritePtr( iSessionKeyContext, sizeof( CRYPT_CONTEXT ) ) );

	REQUIRES( isHandleRangeValid( iImportContext ) );

	/* Clear return value */
	*iSessionKeyContext = CRYPT_ERROR;

#ifdef USE_PGP
	/* PGP doesn't provide separate session key information with the
	   encrypted data but wraps it up alongside the encrypted key so we
	   can't import the wrapped key into a context via the standard key
	   import functions but instead have to create the context as part of
	   the unwrap process */
	if( contentListPtr->formatType == CRYPT_FORMAT_PGP )
		{
		return( iCryptImportKey( contentListPtr->object,
								 contentListPtr->objectSize,
								 CRYPT_FORMAT_PGP, iImportContext,
								 CRYPT_UNUSED, iSessionKeyContext ) );
		}
#endif /* USE_PGP */

	/* Look for the information required to recreate the session key context */
	for( sessionKeyInfoPtr = contentListPtr, iterationCount = 0;
		 sessionKeyInfoPtr != NULL && \
			sessionKeyInfoPtr->envInfo != CRYPT_ENVINFO_SESSIONKEY && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 sessionKeyInfoPtr = sessionKeyInfoPtr->next, iterationCount++ );
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	if( sessionKeyInfoPtr == NULL )
		{
		/* We need to read more data before we can recreate the session key */
		return( CRYPT_ERROR_UNDERFLOW );
		}

	/* Create the session key context and import the encrypted session key */
	setMessageCreateObjectInfo( &createInfo,
								sessionKeyInfoPtr->clEncrInfo.cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iSessionKey = createInfo.cryptHandle;
	status = krnlSendMessage( iSessionKey, IMESSAGE_SETATTRIBUTE,
							  ( MESSAGE_CAST ) &sessionKeyInfoPtr->clEncrInfo.cryptMode,
							  CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		{
		status = iCryptImportKey( contentListPtr->object,
								  contentListPtr->objectSize,
								  contentListPtr->formatType, iImportContext, 
								  iSessionKey, NULL );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iSessionKey, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iSessionKeyContext = iSessionKey;
	return( CRYPT_OK );
	}

/* Set up the envelope decryption using an added or recovered session key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int initSessionKeyDecryption( INOUT ENVELOPE_INFO *envelopeInfoPtr,
									 IN_HANDLE \
										const CRYPT_CONTEXT iSessionKeyContext,
									 const BOOLEAN isRecoveredSessionKey )
	{
	ACTION_RESULT actionResult;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( isHandleRangeValid( iSessionKeyContext ) );

	/* If we recovered the session key from a key exchange action rather 
	   than having it passed directly to us by the user, try and set up the 
	   decryption */
	if( isRecoveredSessionKey )
		{
		const CONTENT_LIST *contentListPtr;
		int iterationCount;
		
		/* If we got as far as the encrypted data (indicated by the fact 
		   that there's content info present) we can set up the decryption.  
		   If we didn't get this far it'll be set up by the de-enveloping 
		   code when we reach it */
		for( contentListPtr = envelopeInfoPtr->contentList, iterationCount = 0;
			 contentListPtr != NULL && \
				contentListPtr->envInfo != CRYPT_ENVINFO_SESSIONKEY && \
				iterationCount < FAILSAFE_ITERATIONS_LARGE;
			 contentListPtr = contentListPtr->next, iterationCount++ );
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
		if( contentListPtr != NULL )
			{
			const CONTENT_ENCR_INFO *encrInfo = &contentListPtr->clEncrInfo;

			/* We've got to the encrypted data, set up the decryption */
			status = initEnvelopeEncryption( envelopeInfoPtr, 
							iSessionKeyContext, encrInfo->cryptAlgo, 
							encrInfo->cryptMode, encrInfo->saltOrIV, 
							encrInfo->saltOrIVsize, FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* Add the recovered session encryption action to the action list */
	actionResult = checkAction( envelopeInfoPtr->actionList, ACTION_CRYPT,
								iSessionKeyContext );
	if( actionResult == ACTION_RESULT_ERROR || \
		actionResult == ACTION_RESULT_INITED )
		return( CRYPT_ERROR_INITED );
	status = addAction( &envelopeInfoPtr->actionList,
						envelopeInfoPtr->memPoolState, ACTION_CRYPT,
						iSessionKeyContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Notify the kernel that the session key context is attached to the
	   envelope.  This is an internal object used only by the envelope so we
	   tell the kernel not to increment its reference count when it attaches
	   it */
	return( krnlSendMessage( envelopeInfoPtr->objectHandle, 
							 IMESSAGE_SETDEPENDENT, 
							 ( MESSAGE_CAST ) &iSessionKeyContext, 
							 SETDEP_OPTION_NOINCREF ) );
	}

/****************************************************************************
*																			*
*							Add De-enveloping Information 					*
*																			*
****************************************************************************/

/* Add signature verification information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int findHashActionFunction( const ACTION_LIST *actionListPtr,
								   IN_INT_Z const int hashAlgo )
	{
	CRYPT_ALGO_TYPE actionCryptAlgo;
	int status;

	assert( isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );

	REQUIRES( hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			  hashAlgo <= CRYPT_ALGO_LAST_HASH );

	/* Check to see if it's the action that we want */
	status = krnlSendMessage( actionListPtr->iCryptHandle,
							  IMESSAGE_GETATTRIBUTE, &actionCryptAlgo,
							  CRYPT_CTXINFO_ALGO );
	return( ( actionCryptAlgo == hashAlgo ) ? CRYPT_OK : CRYPT_ERROR );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int addSignatureInfo( INOUT ENVELOPE_INFO *envelopeInfoPtr,
							 INOUT CONTENT_LIST *contentListPtr,
							 IN_HANDLE const CRYPT_HANDLE sigCheckContext,
							 const BOOLEAN isExternalKey )
	{
	CONTENT_SIG_INFO *sigInfo = &contentListPtr->clSigInfo;
	ACTION_LIST *actionListPtr;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );

	REQUIRES( isHandleRangeValid( sigCheckContext ) );

	/* If we've already processed this entry, return the cached processing 
	   result */
	if( contentListPtr->flags & CONTENTLIST_PROCESSED )
		return( sigInfo->processingResult );

	/* Find the hash action that we need to check this signature.  If we 
	   can't find one, return a bad signature error since something must 
	   have altered the algorithm ID for the hash */
	actionListPtr = findActionIndirect( envelopeInfoPtr->actionList,
										findHashActionFunction,
										sigInfo->hashAlgo );
	if( actionListPtr == NULL || actionListPtr->action != ACTION_HASH )
		{
		contentListPtr->flags |= CONTENTLIST_PROCESSED;
		sigInfo->processingResult = CRYPT_ERROR_SIGNATURE;
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, ENVELOPE_ERRINFO,
				  "Signature hash algorithm doesn't match hash algorithm "
				  "applied to enveloped data" ) );
		}

	/* Check the signature */
	if( contentListPtr->formatType == CRYPT_FORMAT_CMS )
		{
		status = checkCmsSignatureInfo( contentListPtr, 
										actionListPtr->iCryptHandle,
										sigCheckContext,
										envelopeInfoPtr->contentType,
										ENVELOPE_ERRINFO );
		}
	else
		{
		status = iCryptCheckSignature( contentListPtr->object,
								contentListPtr->objectSize,
								contentListPtr->formatType, sigCheckContext,
								actionListPtr->iCryptHandle, CRYPT_UNUSED, 
								NULL );
		if( cryptStatusError( status ) )
			{
			setErrorString( ENVELOPE_ERRINFO, 
							"Signature verification failed", 29 );
			}

		/* If it's a format that includes signing key info remember the key 
		   that was used to check the signature in case the user wants to 
		   query it later */
		if( contentListPtr->formatType != CRYPT_FORMAT_PGP )
			{
			krnlSendNotifier( sigCheckContext, IMESSAGE_INCREFCOUNT );
			sigInfo->iSigCheckKey = sigCheckContext;
			if( isExternalKey )
				contentListPtr->flags |= CONTENTLIST_EXTERNALKEY;
			}
		}

	/* Remember the processing result so that we don't have to repeat the 
	   processing if queried again.  Since we don't need the encoded 
	   signature data any more after this point we can free it */
	clFree( "addSignatureInfo", ( void * ) contentListPtr->object );
	contentListPtr->object = NULL;
	contentListPtr->objectSize = 0;
	contentListPtr->flags |= CONTENTLIST_PROCESSED;
	sigInfo->processingResult = cryptArgError( status ) ? \
								CRYPT_ERROR_SIGNATURE : status;
	return( status );
	}

/* Add a password for decryption of a private key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int addPrivkeyPasswordInfo( INOUT ENVELOPE_INFO *envelopeInfoPtr,
								   const CONTENT_LIST *contentListPtr,
								   IN_BUFFER( passwordLength ) const void *password, 
								   IN_RANGE( 1, CRYPT_MAX_TEXTSIZE ) \
									const int passwordLength )
	{
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	int type, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isReadPtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( password, passwordLength ) );

	REQUIRES( passwordLength > 0 && passwordLength <= CRYPT_MAX_TEXTSIZE );

	/* Make sure that there's a keyset available to pull the key from */
	if( envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR )
		{
		setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_KEYSET_DECRYPT,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Make sure that we're trying to send the password to something for
	   which it makes sense.  Private-key sources aren't just keysets but
	   can also be devices, but if we're trying to send a password to a 
	   device to get a private key then something's gone wrong since it 
	   should be retrieved automatically from the device, which was unlocked
	   via a PIN or password when a session with it was established */
	status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset,
							  IMESSAGE_GETATTRIBUTE, &type,
							  CRYPT_IATTRIBUTE_TYPE );
	if( cryptStatusError( status ) || type != OBJECT_TYPE_KEYSET )
		{
		/* This one is very difficult to report appropriately, the best that
		   we can do is report the wrong key for this type of object */
		setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_KEYSET_DECRYPT,
					  CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ERROR_WRONGKEY );
		}

	/* Try and get the key information */
	if( contentListPtr->issuerAndSerialNumber == NULL )
		{
		setMessageKeymgmtInfo( &getkeyInfo,
				( contentListPtr->formatType == CRYPT_FORMAT_PGP ) ? \
				CRYPT_IKEYID_PGPKEYID : CRYPT_IKEYID_KEYID,
				contentListPtr->keyID, contentListPtr->keyIDsize,
				( MESSAGE_CAST ) password, passwordLength, 
				KEYMGMT_FLAG_USAGE_CRYPT );
		}
	else
		{
		setMessageKeymgmtInfo( &getkeyInfo,
				CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
				contentListPtr->issuerAndSerialNumber,
				contentListPtr->issuerAndSerialNumberSize,
				( MESSAGE_CAST ) password, passwordLength, 
				KEYMGMT_FLAG_USAGE_CRYPT );
		}
	status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo,
							  KEYMGMT_ITEM_PRIVATEKEY );
	if( cryptStatusError( status ) )
		{
		retExtObj( status,
				   ( status, ENVELOPE_ERRINFO,
				     envelopeInfoPtr->iDecryptionKeyset,
					 "Couldn't retrieve private key from decryption "
					 "keyset/device" ) );
		}

	/* We managed to get the private key, push it into the envelope.  If the
	   call succeeds this will import the session key and delete the 
	   required-information list, after which we don't need the private key
	   any more */
	status = envelopeInfoPtr->addInfo( envelopeInfoPtr, 
									   CRYPT_ENVINFO_PRIVATEKEY,
									   getkeyInfo.cryptHandle );
	krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Add a decryption password */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 7 ) ) \
static int addPasswordInfo( const CONTENT_LIST *contentListPtr,
							IN_BUFFER( passwordLength ) const void *password, 
							IN_RANGE( 1, CRYPT_MAX_TEXTSIZE ) \
								const int passwordLength,
							IN_HANDLE_OPT const CRYPT_CONTEXT iMacContext,
							OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iNewContext,
							IN_ENUM( CRYPT_FORMAT ) \
								const CRYPT_FORMAT_TYPE formatType,
							INOUT ERROR_INFO *errorInfo )
	{
	CRYPT_CONTEXT iCryptContext;
	const CONTENT_ENCR_INFO *encrInfo = &contentListPtr->clEncrInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isReadPtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( password, passwordLength ) );
	assert( ( isHandleRangeValid( iMacContext ) && iNewContext == NULL ) || \
			( iMacContext == CRYPT_UNUSED && \
			  isWritePtr( iNewContext, sizeof( CRYPT_CONTEXT ) ) ) );
	assert( isWritePtr( errorInfo, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( ( isHandleRangeValid( iMacContext ) && iNewContext == NULL ) || \
			  ( iMacContext == CRYPT_UNUSED && iNewContext != NULL ) );
	REQUIRES( formatType > CRYPT_FORMAT_NONE && \
			  formatType < CRYPT_FORMAT_LAST );
	REQUIRES( formatType != CRYPT_FORMAT_PGP || iNewContext != NULL );
			  /* PGP can't perform MACing, only encryption */

	/* Clear return value */
	if( iNewContext != NULL )
		*iNewContext = CRYPT_ERROR;

	/* Create the appropriate encryption context and derive the key into it */
	setMessageCreateObjectInfo( &createInfo, encrInfo->cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT, 
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iCryptContext = createInfo.cryptHandle;
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE,
							  ( MESSAGE_CAST ) &encrInfo->cryptMode,
							  CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		{
#ifdef USE_PGP
		if( formatType == CRYPT_FORMAT_PGP )
			{
			status = pgpPasswordToKey( iCryptContext, CRYPT_UNUSED,
							password, passwordLength, encrInfo->keySetupAlgo,
							( encrInfo->saltOrIVsize > 0 ) ? \
								encrInfo->saltOrIV : NULL, encrInfo->saltOrIVsize,
							encrInfo->keySetupIterations );
			}
		else
#endif /* USE_PGP */
			{
			MESSAGE_DATA msgData;

			/* Load the derivation information into the context */
			status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE,
									  ( MESSAGE_CAST ) &encrInfo->keySetupIterations,
									  CRYPT_CTXINFO_KEYING_ITERATIONS );
			if( cryptStatusOK( status ) )
				{
				setMessageData( &msgData, ( MESSAGE_CAST ) encrInfo->saltOrIV,
								encrInfo->saltOrIVsize );
				status = krnlSendMessage( iCryptContext,
									IMESSAGE_SETATTRIBUTE_S, &msgData,
									CRYPT_CTXINFO_KEYING_SALT );
				}
			if( cryptStatusOK( status ) )
				{
				setMessageData( &msgData, ( MESSAGE_CAST ) password, 
								passwordLength );
				status = krnlSendMessage( iCryptContext,
									IMESSAGE_SETATTRIBUTE_S, &msgData,
									CRYPT_CTXINFO_KEYING_VALUE );
				}
			}
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, errorInfo,
				  "Couldn't derive key-import key from password" ) );
		}

	/* In PGP there isn't any encrypted session key so the context created 
	   from the password becomes the bulk encryption context and we're done */
	if( formatType == CRYPT_FORMAT_PGP )
		{
		*iNewContext = iCryptContext;

		return( CRYPT_OK );
		}

	/* Recover the session key using the password context and destroy it 
	   when we're done with it */
	if( iNewContext == NULL )
		{
		/* The target is a MAC context (which has already been set up), load
		   the session key directly into it */
		status = iCryptImportKey( contentListPtr->object, 
								  contentListPtr->objectSize,
								  contentListPtr->formatType, 
								  iCryptContext, iMacContext, NULL );
		}
	else
		{
		/* The target is an encryption context, recreate it from the 
		   encrypted session key information */
		status = importSessionKey( contentListPtr, iCryptContext, 
								   iNewContext );
		}
	krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, errorInfo,
				  "Couldn't recover wrapped session key" ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					De-enveloping Information Management Functions			*
*																			*
****************************************************************************/

/* Try and match what's being added to an information object in the content 
   list */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int matchInfoObject( OUT_PTR CONTENT_LIST **contentListPtrPtr,
							const ENVELOPE_INFO *envelopeInfoPtr,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE envInfo )
	{
	CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentListCurrent;
	const BOOLEAN privateKeyFetch = \
		( envInfo == CRYPT_ENVINFO_PASSWORD && \
		  envelopeInfoPtr->iDecryptionKeyset != CRYPT_ERROR ) ? TRUE : FALSE;
	int iterationCount;

	assert( isWritePtr( contentListPtrPtr, sizeof( CONTENT_LIST * ) ) );
	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( envInfo == CRYPT_IATTRIBUTE_ATTRONLY || \
			  ( envInfo > CRYPT_ENVINFO_FIRST && \
				envInfo < CRYPT_ENVINFO_LAST ) );

	/* Clear return value */
	*contentListPtrPtr = NULL;

	/* If we're adding meta-information there's nothing to check */
	if( envInfo == CRYPT_IATTRIBUTE_ATTRONLY || \
		envInfo == CRYPT_ENVINFO_KEYSET_SIGCHECK || \
		envInfo == CRYPT_ENVINFO_KEYSET_ENCRYPT || \
		envInfo == CRYPT_ENVINFO_KEYSET_DECRYPT || \
		envInfo == CRYPT_ENVINFO_HASH )
		return( CRYPT_OK );

	/* If there's already a content-list item selected, make sure that the 
	   information that we're adding matches the current information object.  
	   The one exception to this is that we can be passed password 
	   information when we require a private key if the private key is 
	   encrypted */
	if( contentListPtr != NULL )
		{
		if( contentListPtr->envInfo != envInfo && \
			!( contentListPtr->envInfo == CRYPT_ENVINFO_PRIVATEKEY && \
			   privateKeyFetch ) )
			return( CRYPT_ARGERROR_VALUE );

		*contentListPtrPtr = contentListPtr;
		return( CRYPT_OK );
		}

	/* Look for the first information object that matches the supplied 
	   information */
	for( contentListPtr = envelopeInfoPtr->contentList, iterationCount = 0;
		 contentListPtr != NULL && contentListPtr->envInfo != envInfo && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 contentListPtr = contentListPtr->next, iterationCount++ );
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	if( contentListPtr == NULL && privateKeyFetch )
		{
		/* If we didn't find a direct match and we've been given a password, 
		   check for a private key that can (potentially) be decrypted using 
		   the password.  This requires both a keyset/device to fetch the 
		   key from and a private key as the required info type */
		for( contentListPtr = envelopeInfoPtr->contentList, iterationCount = 0;
			 contentListPtr != NULL && \
				contentListPtr->envInfo != CRYPT_ENVINFO_PRIVATEKEY && \
				iterationCount < FAILSAFE_ITERATIONS_LARGE;
			 contentListPtr = contentListPtr->next, iterationCount++ );
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
		}
	if( contentListPtr == NULL )
		return( CRYPT_ARGERROR_VALUE );

	*contentListPtrPtr = contentListPtr;
	return( CRYPT_OK );
	}

/* Complete the addition of information to an envelope */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completeEnvelopeInfoUpdate( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Destroy the content list, which at this point will contain only (now-
	   irrelevant) key exchange items */
	deleteContentList( envelopeInfoPtr->memPoolState,
					   &envelopeInfoPtr->contentList );
	envelopeInfoPtr->contentList = envelopeInfoPtr->contentListCurrent = NULL;

	/* If the only error was an information required error, we've now
	   resolved the problem and can continue */
	if( envelopeInfoPtr->errorState == CRYPT_ENVELOPE_RESOURCE )
		{
		envelopeInfoPtr->errorState = CRYPT_OK;

		/* The envelope is ready to process data, move it into the high
		   state.  Normally this is handled in the data-push code but this
		   leads to a race condition when all the data being pushed is
		   buffered inside the envelope, requiring only that processing be
		   enabled by adding a resource.  Once the resource is added the
		   only action left for the caller to perform is a flush, so they 
		   expect that high-state actions should succeed even though the
		   envelope state machine wouldn't move the envelope into the high
		   state until some data action (in this case a flush) is 
		   initiated.  To avoid this problem we move the envelope into the
		   high state as soon as the resource blockage has been cleared,
		   since any high-state-only information (for example the nested
		   content type) will now be available */
		return( krnlSendMessage( envelopeInfoPtr->objectHandle, 
								 IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
								 CRYPT_IATTRIBUTE_INITIALISED ) );
		}

	return( CRYPT_OK );
	}

/* Add de-enveloping information to an envelope */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int addDeenvelopeInfo( INOUT ENVELOPE_INFO *envelopeInfoPtr,
							  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE envInfo,
							  IN_INT_Z const int value )
	{
	CRYPT_HANDLE cryptHandle = ( CRYPT_HANDLE ) value;
	CRYPT_CONTEXT iNewContext = DUMMY_INIT;
	CRYPT_ATTRIBUTE_TYPE localEnvInfo = envInfo;
	CONTENT_LIST *contentListPtr;
	BOOLEAN isExternalKey = TRUE;
	int status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( envInfo == CRYPT_IATTRIBUTE_ATTRONLY || \
			  ( envInfo > CRYPT_ENVINFO_FIRST && \
				envInfo < CRYPT_ENVINFO_LAST ) );

	/* A signature-check object can be passed in as a special-case type
	   CRYPT_ENVINFO_SIGNATURE_RESULT to indicate that the object was 
	   obtained internally (for example by instantiating it from an attached 
	   certificate chain) and doesn't require various special-case 
	   operations that are applied to user-supplied objects.  If this is the 
	   case we convert it to a standard CRYPT_ENVINFO_SIGNATURE and remember 
	   that it's an internally-supplied key */
	if( envInfo == CRYPT_ENVINFO_SIGNATURE_RESULT )
		{
		localEnvInfo = CRYPT_ENVINFO_SIGNATURE;
		isExternalKey = FALSE;
		}

	/* Since we can add one of a multitude of necessary information types 
	   we need to check to make sure that what we're adding is appropriate.  
	   We do this by trying to match what's being added to the first 
	   information object of the correct type */
	status = matchInfoObject( &contentListPtr, envelopeInfoPtr, 
							  localEnvInfo );
	if( cryptStatusError( status ) )
		{
		retExtArg( status,
				   ( status, ENVELOPE_ERRINFO,
					 "Added item doesn't match %s envelope information "
					 "object",
					 ( envelopeInfoPtr->contentListCurrent != NULL ) ? \
						"currently selected" : "any" ) );
		}

	/* Process non-encryption-related enveloping info */
	switch( localEnvInfo )
		{
		case CRYPT_IATTRIBUTE_ATTRONLY:
			/* This is off by default so we should only be turning it on */
			REQUIRES( value == TRUE );

			envelopeInfoPtr->flags |= ENVELOPE_ATTRONLY;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_KEYSET_SIGCHECK:
		case CRYPT_ENVINFO_KEYSET_ENCRYPT:
		case CRYPT_ENVINFO_KEYSET_DECRYPT:
			/* It's keyset information, keep a record of it for later use */
			return( addKeysetInfo( envelopeInfoPtr, localEnvInfo, 
								   cryptHandle ) );

		case CRYPT_ENVINFO_HASH:
			{
			ACTION_LIST *actionListItem;

			/* The user is checking a detached signature, remember the hash 
			   for later.  In theory we should also check the state of the 
			   hash context, however PGP requires that it not be completed 
			   (since it needs to hash further data) and everything else 
			   requires that it be completed, but we don't know at this 
			   point whether we're processing PGP or non-PGP data so we 
			   can't perform any checking here */
			if( envelopeInfoPtr->actionList != NULL )
				{
				/* There's already a hash action present, we can't add 
				   anything further */
				setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_HASH,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}

			/* Make sure that we can still add another action */
			if( !moreActionsPossible( envelopeInfoPtr->actionList ) )
				return( CRYPT_ERROR_OVERFLOW );

			/* Add the hash as an action list item */
			status = addActionEx( &actionListItem, 
								  &envelopeInfoPtr->actionList,
								  envelopeInfoPtr->memPoolState, 
								  ACTION_HASH, cryptHandle );
			if( cryptStatusError( status ) )
				return( status );
			return( krnlSendNotifier( cryptHandle, IMESSAGE_INCREFCOUNT ) );
			}

		case CRYPT_ENVINFO_SIGNATURE:
			/* It's a signature object, check the signature and exit */
			return( addSignatureInfo( envelopeInfoPtr, contentListPtr,
									  cryptHandle, isExternalKey ) );
		}

	/* Make sure that we can still add another action */
	if( !moreActionsPossible( envelopeInfoPtr->actionList ) )
		return( CRYPT_ERROR_OVERFLOW );

	/* Anything that's left at this point related to envelope decryption */
	switch( localEnvInfo )
		{
		case CRYPT_ENVINFO_PRIVATEKEY:
		case CRYPT_ENVINFO_KEY:
			/* Import the session key using the KEK */
			status = importSessionKey( contentListPtr, cryptHandle, 
									   &iNewContext );
			break;

		case CRYPT_ENVINFO_SESSIONKEY:
			{
			/* If we've been given the session key directly then we must 
			   have reached the encrypted data so we take a copy and set 
			   up the decryption with it */
			const CONTENT_ENCR_INFO *encrInfo = &contentListPtr->clEncrInfo;

			status = initEnvelopeEncryption( envelopeInfoPtr, cryptHandle,
							encrInfo->cryptAlgo, encrInfo->cryptMode,
							encrInfo->saltOrIV, encrInfo->saltOrIVsize, TRUE );
			if( cryptStatusOK( status ) )
				{
				/* The session key context is the newly-created internal 
				   one */
				iNewContext = envelopeInfoPtr->iCryptContext;
				}
			break;
			}

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );

	/* We've now got the session key, if we recovered it from a key exchange
	   action (rather than having it passed directly to us by the user) try
	   and set up the decryption */
	if( envelopeInfoPtr->usage != ACTION_MAC )
		{
		status = initSessionKeyDecryption( envelopeInfoPtr, iNewContext,
							( localEnvInfo != CRYPT_ENVINFO_SESSIONKEY ) ? \
								TRUE : FALSE );
		if( cryptStatusError( status ) )
			{
			if( localEnvInfo != CRYPT_ENVINFO_SESSIONKEY )
				krnlSendNotifier( iNewContext, IMESSAGE_DECREFCOUNT );
			if( status == CRYPT_ERROR_INITED )
				{
				/* If the attribute that we added to recover the session key 
				   is already present, provide extended error information */
				setErrorInfo( envelopeInfoPtr, localEnvInfo, 
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				}
			return( status );
			}
		}

	/* Complete the envelope information update */
	return( completeEnvelopeInfoUpdate( envelopeInfoPtr ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int addDeenvelopeInfoString( INOUT ENVELOPE_INFO *envelopeInfoPtr,
									IN_RANGE( CRYPT_ENVINFO_PASSWORD, \
											  CRYPT_ENVINFO_PASSWORD ) \
										const CRYPT_ATTRIBUTE_TYPE envInfo,
									IN_BUFFER( valueLength ) const void *value, 
									IN_RANGE( 1, CRYPT_MAX_TEXTSIZE ) \
										const int valueLength )
	{
	CRYPT_CONTEXT iNewContext = DUMMY_INIT;
	CONTENT_LIST *contentListPtr;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isReadPtr( value, valueLength ) );

	REQUIRES( envInfo == CRYPT_ENVINFO_PASSWORD );
	REQUIRES( valueLength > 0 && valueLength < MAX_ATTRIBUTE_SIZE );

	/* Since we can add one of a multitude of necessary information types, 
	   we need to check to make sure that what we're adding is appropriate.  
	   We do this by trying to match what's being added to the first 
	   information object of the correct type */
	status = matchInfoObject( &contentListPtr, envelopeInfoPtr, envInfo );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, ENVELOPE_ERRINFO,
				  "Added item doesn't match any envelope information "
				  "object" ) );
		}

	/* If we've been given a password and we need private key information, 
	   it's the password required to decrypt the key so we treat this 
	   specially.  This action recursively calls addDeenvelopeInfo() with 
	   the processed private key so we don't have to fall through to the 
	   session-key processing code below like the other key-handling 
	   actions */
	if( contentListPtr->envInfo == CRYPT_ENVINFO_PRIVATEKEY )
		{
		return( addPrivkeyPasswordInfo( envelopeInfoPtr, contentListPtr,
										value, valueLength ) );
		}

	/* Make sure that we can still add another action */
	if( envelopeInfoPtr->usage != ACTION_MAC && \
		!moreActionsPossible( envelopeInfoPtr->actionList ) )
		return( CRYPT_ERROR_OVERFLOW );

	/* We've been given a standard decryption password, create a decryption 
	   context for it, derive the key from the password, and use it to 
	   import the session/MAC key */
	if( envelopeInfoPtr->usage == ACTION_MAC )
		{
		if( envelopeInfoPtr->actionList == NULL )
			return( CRYPT_ERROR_NOTINITED );
		status = addPasswordInfo( contentListPtr, value, valueLength, 
								  envelopeInfoPtr->actionList->iCryptHandle, 
								  NULL, envelopeInfoPtr->type, 
								  ENVELOPE_ERRINFO );
		}
	else
		{
		status = addPasswordInfo( contentListPtr, value, valueLength, 
								  CRYPT_UNUSED, &iNewContext,
								  envelopeInfoPtr->type, ENVELOPE_ERRINFO );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* We've recovered the session key, try and set up the decryption */
	if( envelopeInfoPtr->usage != ACTION_MAC )
		{
		status = initSessionKeyDecryption( envelopeInfoPtr, iNewContext, 
										   TRUE );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( iNewContext, IMESSAGE_DECREFCOUNT );
			if( status == CRYPT_ERROR_INITED )
				{
				/* If the attribute that we added to recover the session key 
				   is already present, provide extended error information */
				setErrorInfo( envelopeInfoPtr, envInfo, 
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				}
			return( status );
			}
		}

	/* Complete the envelope information update */
	return( completeEnvelopeInfoUpdate( envelopeInfoPtr ) );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initDenvResourceHandling( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	
	REQUIRES_V( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE );

	/* Set the access method pointers */
	envelopeInfoPtr->addInfo = addDeenvelopeInfo;
	envelopeInfoPtr->addInfoString = addDeenvelopeInfoString;
	}
#endif /* USE_ENVELOPES */
