/****************************************************************************
*																			*
*					cryptlib Envelope Attribute Routines					*
*					  Copyright Peter Gutmann 1996-2007						*
*																			*
****************************************************************************/

#include "crypt.h"
#ifdef INC_ALL
  #include "envelope.h"
#else
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

#ifdef USE_ENVELOPES

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitError( INOUT ENVELOPE_INFO *envelopeInfoPtr,
					  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  IN_ENUM( CRYPT_ERRTYPE ) const CRYPT_ERRTYPE_TYPE errorType, 
					  IN_ERROR const int status )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );
	REQUIRES( errorType > CRYPT_ERRTYPE_NONE && \
			  errorType < CRYPT_ERRTYPE_LAST );
	REQUIRES( cryptStatusError( status ) );

	setErrorInfo( envelopeInfoPtr, errorLocus, errorType );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorInited( INOUT ENVELOPE_INFO *envelopeInfoPtr,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( envelopeInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT, 
					   CRYPT_ERROR_INITED ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorNotInited( INOUT ENVELOPE_INFO *envelopeInfoPtr,
							   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( envelopeInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT, 
					   CRYPT_ERROR_NOTINITED ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorNotFound( INOUT ENVELOPE_INFO *envelopeInfoPtr,
							  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( envelopeInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT, 
					   CRYPT_ERROR_NOTFOUND ) );
	}

/* Reset the internal virtual cursor in a content-list item after we've 
   moved the attribute cursor */

STDC_NONNULL_ARG( ( 1 ) ) \
static void resetVirtualCursor( INOUT CONTENT_LIST *contentListPtr )
	{
	assert( isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );

	if( !( contentListPtr->flags & CONTENTLIST_ISSIGOBJ ) )
		return;
	contentListPtr->clSigInfo.attributeCursorEntry = \
									CRYPT_ENVINFO_SIGNATURE_RESULT;
	}

/* Move the internal virtual cursor within a content-list item */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN moveVirtualCursor( INOUT CONTENT_LIST *contentListPtr,
								  IN_ENUM( ATTR ) const ATTR_TYPE attrGetType )
	{
	static const CRYPT_ATTRIBUTE_TYPE attributeOrderList[] = {
				CRYPT_ENVINFO_SIGNATURE_RESULT, CRYPT_ENVINFO_SIGNATURE,
				CRYPT_ENVINFO_SIGNATURE_EXTRADATA, CRYPT_ENVINFO_TIMESTAMP, 
				CRYPT_ATTRIBUTE_NONE, CRYPT_ATTRIBUTE_NONE };
	CONTENT_SIG_INFO *sigInfo = &contentListPtr->clSigInfo;
	CRYPT_ATTRIBUTE_TYPE attributeType = sigInfo->attributeCursorEntry;
	BOOLEAN doContinue;
	int iterationCount;

	assert( isWritePtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	
	REQUIRES( attrGetType == ATTR_NEXT || attrGetType == ATTR_PREV );
	REQUIRES( sigInfo->attributeCursorEntry != CRYPT_ATTRIBUTE_NONE );

	for( doContinue = TRUE, iterationCount = 0;
		 doContinue && iterationCount < FAILSAFE_ITERATIONS_SMALL;
		 iterationCount++ )
		{
		int i;

		/* Find the position of the current sub-attribute in the attribute 
		   order list and use that to get its successor/predecessor sub-
		   attribute */
		for( i = 0; 
			 attributeOrderList[ i ] != attributeType && \
				attributeOrderList[ i ] != CRYPT_ATTRIBUTE_NONE && \
				i < FAILSAFE_ARRAYSIZE( attributeOrderList, CRYPT_ATTRIBUTE_TYPE ); 
			 i++ );
		ENSURES( i < FAILSAFE_ARRAYSIZE( attributeOrderList, \
										 CRYPT_ATTRIBUTE_TYPE ) );
		if( attributeOrderList[ i ] == CRYPT_ATTRIBUTE_NONE )
			{
			/* We've reached the first/last sub-attribute within the current 
			   item/group, tell the caller that there are no more sub-
			   attributes present and they have to move on to the next 
			   group */
			return( FALSE );
			}
		if( attrGetType == ATTR_PREV )
			attributeType = ( i < 1 ) ? CRYPT_ATTRIBUTE_NONE : \
										attributeOrderList[ i - 1 ];
		else
			attributeType = attributeOrderList[ i + 1 ];
		if( attributeType == CRYPT_ATTRIBUTE_NONE )
			{
			/* We've reached the first/last sub-attribute within the current 
			   item/group, exit as before */
			return( FALSE );
			}

		/* Check whether the required sub-attribute is present.  If not, we
		   continue and try the next one */
		doContinue = FALSE;
		switch( attributeType )
			{
			case CRYPT_ENVINFO_SIGNATURE_RESULT:
				break;	/* Always present */
				
			case CRYPT_ENVINFO_SIGNATURE:
				if( sigInfo->iSigCheckKey == CRYPT_ERROR )
					doContinue = TRUE;
				break;
	
			case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
				if( sigInfo->iExtraData == CRYPT_ERROR )
					doContinue = TRUE;
				break;

			case CRYPT_ENVINFO_TIMESTAMP:
				if( sigInfo->iTimestamp == CRYPT_ERROR )
					doContinue = TRUE;
				break;

			default:
				retIntError_Boolean();
			}
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_SMALL );
	sigInfo->attributeCursorEntry = attributeType;
	
	return( TRUE );
	}

/* Callback function used to provide external access to content list-
   internal fields */

CHECK_RETVAL_PTR \
static const void *getAttrFunction( IN_OPT TYPECAST( CONTENT_LIST * ) \
										const void *attributePtr, 
									OUT_OPT_ATTRIBUTE_Z \
										CRYPT_ATTRIBUTE_TYPE *groupID, 
									OUT_OPT_ATTRIBUTE_Z \
										CRYPT_ATTRIBUTE_TYPE *attributeID, 
									OUT_OPT_ATTRIBUTE_Z \
										CRYPT_ATTRIBUTE_TYPE *instanceID,
									IN_ENUM( ATTR ) const ATTR_TYPE attrGetType )
	{
	CONTENT_LIST *contentListPtr = ( CONTENT_LIST * ) attributePtr;
	BOOLEAN subGroupMove;

	assert( contentListPtr == NULL || \
			isReadPtr( contentListPtr, sizeof( CONTENT_LIST ) ) );
	assert( groupID == NULL || \
			isWritePtr( groupID, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( attributeID == NULL || \
			isWritePtr( attributeID, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( instanceID == NULL || \
			isWritePtr( instanceID, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );

	REQUIRES_N( attrGetType > ATTR_NONE && attrGetType < ATTR_LAST );

	/* Clear return values */
	if( groupID != NULL )
		*groupID = CRYPT_ATTRIBUTE_NONE;
	if( attributeID != NULL )
		*attributeID = CRYPT_ATTRIBUTE_NONE;
	if( instanceID != NULL )
		*instanceID = CRYPT_ATTRIBUTE_NONE;

	/* Move to the next or previous attribute if required.  This isn't just a
	   case of following the prev/next links because some content-list items
	   contain an entire attribute group so positioning by attribute within
	   these only changes the current selection within the group (== content-
	   list item) rather than moving to the previous/next entry.  Because of 
	   this we have to special-case the code for composite items (currently 
	   only signature objects meet this definition) and allow virtual 
	   positioning within the item */
	if( contentListPtr == NULL )
		return( NULL );
	subGroupMove = ( ( attrGetType == ATTR_PREV || \
					   attrGetType == ATTR_NEXT ) && \
					 ( contentListPtr->flags & CONTENTLIST_ISSIGOBJ ) ) ? \
				   TRUE : FALSE;
	if( subGroupMove )
		subGroupMove = moveVirtualCursor( contentListPtr, attrGetType );

	/* If we're moving by group, move to the next/previous content list
	   item and reset the internal virtual cursor.  Note that we always 
	   advance the cursor to the next/prev attribute, it's up to the calling 
	   code to manage attribute by attribute vs.group by group moves */
	if( !subGroupMove && attrGetType != ATTR_CURRENT )
		{
		contentListPtr = ( attrGetType == ATTR_PREV ) ? \
						 contentListPtr->prev : contentListPtr->next;
		if( contentListPtr != NULL )
			resetVirtualCursor( contentListPtr );
		}
	if( contentListPtr == NULL )
		return( NULL );

	/* Return ID information to the caller.  We only return the group ID if
	   we've moved within the attribute group, if we've moved from one group
	   to another we leave it cleared because envelopes can contain multiple
	   groups with the same ID and returning an ID identical to the one from
	   the group that we've moved out of would make it look as if we're still 
	   within the same group.  Note that this relies on the behaviour of the
	   attribute-move functions, which first get the current group using 
	   ATTR_CURRENT and then move to the next or previous using ATTR_NEXT/
	   PREV */
	if( groupID != NULL && ( attrGetType == ATTR_CURRENT || subGroupMove ) )
		*groupID = contentListPtr->envInfo;
	if( attributeID != NULL && \
		( contentListPtr->flags & CONTENTLIST_ISSIGOBJ ) )
		*attributeID = contentListPtr->clSigInfo.attributeCursorEntry;
	return( contentListPtr );
	}

/* Instantiate a certificate chain from a collection of certificates */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int instantiateCertChain( INOUT CONTENT_LIST *contentListItem, 
								 IN_BUFFER( certChainDataLength ) \
									const void *certChainData, 
								 IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
									const int certChainDataLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( contentListItem, sizeof( CONTENT_LIST ) ) );
	assert( isReadPtr( certChainData, certChainDataLength ) );

	REQUIRES( contentListItem->flags & CONTENTLIST_ISSIGOBJ );
	REQUIRES( certChainDataLength >= MIN_CRYPT_OBJECTSIZE && \
			  certChainDataLength < MAX_INTLENGTH_SHORT );

	/* Instantiate the certificate chain.  Since this isn't a true 
	   certificate chain (in the sense of being degenerate PKCS #7 
	   SignedData) but only a context-tagged SET OF Certificate, we notify 
	   the certificate management code of this when it performs the import */
	setMessageCreateObjectIndirectInfo( &createInfo, certChainData,
						certChainDataLength, CRYPT_ICERTTYPE_CMS_CERTSET );
	if( contentListItem->issuerAndSerialNumber == NULL )
		{
		createInfo.arg2 = CRYPT_IKEYID_KEYID;
		createInfo.strArg2 = contentListItem->keyID;
		createInfo.strArgLen2 = contentListItem->keyIDsize;
		}
	else
		{
		createInfo.arg2 = CRYPT_IKEYID_ISSUERANDSERIALNUMBER;
		createInfo.strArg2 = contentListItem->issuerAndSerialNumber;
		createInfo.strArgLen2 = contentListItem->issuerAndSerialNumberSize;
		}
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		contentListItem->clSigInfo.iSigCheckKey = createInfo.cryptHandle;
	return( status );
	}

/* Get information on the attribute at the current attribute-cursor 
   position.  This isn't quite as simple as it sounds because trying to 
   obtain the info may require a decrypt or key-import operation in order
   to obtain it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getCurrentAttributeInfo( INOUT ENVELOPE_INFO *envelopeInfoPtr,
									OUT_INT_Z int *valuePtr )
	{
	CONTENT_LIST *contentListItem = envelopeInfoPtr->contentListCurrent;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( valuePtr, sizeof( int ) ) );

	REQUIRES( contentListItem != NULL );

	/* Clear return value */
	*valuePtr = 0;

	/* If we need something other than a private key or we need a private 
	   key but there's no keyset present to fetch it from, just report what 
	   we need and exit */
	if( contentListItem->envInfo != CRYPT_ENVINFO_PRIVATEKEY || \
		envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR )
		{
		*valuePtr = contentListItem->envInfo;
		return( CRYPT_OK );
		}

	/* There's a decryption keyset available, try and get the required key 
	   from it.  Even though we're accessing the key by (unique) key ID we 
	   still specify the key type preference in case there's some problem 
	   with the ID info.  This means that we return a more meaningful error 
	   message now rather than a usage-related one when we try to use the 
	   key.

	   Unlike signature check keyset access, we retry the access every time 
	   we're called because we may be talking to a device that has a trusted 
	   authentication path which is outside our control so that the first 
	   read fails if the user hasn't entered their PIN but a second read 
	   once they've entered it will succeed */
	if( contentListItem->issuerAndSerialNumber == NULL )
		{
		setMessageKeymgmtInfo( &getkeyInfo, 
						( contentListItem->formatType == CRYPT_FORMAT_PGP ) ? \
							CRYPT_IKEYID_PGPKEYID : CRYPT_IKEYID_KEYID, 
						contentListItem->keyID, contentListItem->keyIDsize, 
						NULL, 0, KEYMGMT_FLAG_USAGE_CRYPT );
		}
	else
		{
		setMessageKeymgmtInfo( &getkeyInfo, 
						CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
						contentListItem->issuerAndSerialNumber,
						contentListItem->issuerAndSerialNumberSize,
						NULL, 0, KEYMGMT_FLAG_USAGE_CRYPT );
		}
	status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset, 
							  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
							  KEYMGMT_ITEM_PRIVATEKEY );
	if( cryptArgError( status ) )
		{
		/* Make sure that any argument errors arising from this internal key 
		   fetch don't get propagated back up to the caller.  Note that this 
		   error is converted to a CRYPT_OK later on (see the comment further 
		   down) but we perform the cleanup here to keep things tidy */
		status = CRYPT_ERROR_NOTFOUND;
		}

	/* If we managed to get the private key (either bcause it wasn't 
	   protected by a password if it's in a keyset or because it came from a 
	   device), push it into the envelope.  If the call succeeds this will 
	   import the session key and delete the required-information list.

	   What to do when this operation fails is a bit tricky since the 
	   supposedly idempotent step of reading an attribute can have side-
	   effects if it results in a key being read from a crypto device that 
	   in turn is used to import a wrapped session key.  Changing the
	   externally-visible behaviour isn't really an option because the 
	   import is normally triggered by the addition of unwrap keying 
	   material but in this case it's already present, and the caller has
	   nothing to add to trigger the import.  Conversely though it's a bit
	   confusing to report side-effects of the (invisible) key-unwrap 
	   process to the caller in response to an attribute read.  However, 
	   masking the details entirely can lead the caller down a blind alley 
	   in which they apparently need to add an unwrap key but it's already
	   been added via the device and the unwrap process failed.

	   A compromise solution is to select the return values the definitely
	   indicate that there's no chance of continuing and report those, and
	   otherwise to indicate that an unwrap key is needed.  The only return
	   value that's really a ne pas ultra in this case is 
	   CRYPT_ERROR_BADDATA, all others are potentially recoverable or at 
	   least misleading if returned in this context (for example 
	   CRYPT_ERROR_NOTAVAIL interpreted in the context of read-current-
	   attribute has a very different meaning than in the context of unwrap-
	   key) */
	if( cryptStatusOK( status ) )
		{
		status = envelopeInfoPtr->addInfo( envelopeInfoPtr, 
										   CRYPT_ENVINFO_PRIVATEKEY,
										   getkeyInfo.cryptHandle );
		krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( status == CRYPT_ERROR_BADDATA )
			{
			/* We've reached a cant-continue condition, report it to the
			   caller */
			*valuePtr = CRYPT_ATTRIBUTE_NONE;
			return( CRYPT_ERROR_BADDATA );
			}
		}

	/* If we got the key, there's nothing else needed.  If we didn't we still 
	   return an OK status since the caller is asking us for the resource 
	   which is required and not the status of any background operation that 
	   was performed while trying to obtain it */
	*valuePtr = cryptStatusError( status ) ? \
					envelopeInfoPtr->contentListCurrent->envInfo : \
					CRYPT_ATTRIBUTE_NONE;
	return( CRYPT_OK );
	}

/* Get the result of the signature-check process and the key used for 
   signing.  Since the signature check is performed on-demand this can 
   require a considerable amount of additional work */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getSignatureResult( INOUT ENVELOPE_INFO *envelopeInfoPtr,
							   OUT_INT_Z int *valuePtr )
	{
	CRYPT_HANDLE iCryptHandle;
	const CONTENT_SIG_INFO *sigInfo;
	CONTENT_LIST *contentListItem = envelopeInfoPtr->contentListCurrent;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( valuePtr, sizeof( int ) ) );

	REQUIRES( envelopeInfoPtr->usage == ACTION_MAC || \
			  contentListItem != NULL );

	/* Clear return value */
	*valuePtr = 0;

	/* If it's a MACd envelope then the signature result isn't held in a 
	   content list as for the other signatures since the "signature" is 
	   just a MAC tag appended to the data.  The appropriate value to return 
	   here is a bit tricky since an attacker could corrupt the MAC tag and 
	   force a less severe error like CRYPT_ERROR_UNDERFLOW (by truncating 
	   the data).  However we can only get here once we've reached the 
	   finished state, which means that all of the data (including the MAC 
	   tag) has been successfully processed.  This means that any persistent 
	   error state is regarded as the equivalent of a signature error */
	if( envelopeInfoPtr->usage == ACTION_MAC )
		{
		*valuePtr = ( envelopeInfoPtr->errorState != CRYPT_OK ) ? \
					CRYPT_ERROR_SIGNATURE : CRYPT_OK;
		return( CRYPT_OK );
		}

	REQUIRES( contentListItem != NULL );

	/* Make sure that the content list item is of the appropriate type, and 
	   if we've already done this one don't process it a second time.  This 
	   check is also performed by the addInfo() code but we duplicate it 
	   here (just for the signature-result attribute) to avoid having to do 
	   an unnecessary key fetch for non-CMS signatures */
	sigInfo = &contentListItem->clSigInfo;
	if( contentListItem->envInfo != CRYPT_ENVINFO_SIGNATURE )
		return( exitErrorNotFound( envelopeInfoPtr, 
								   CRYPT_ENVINFO_SIGNATURE_RESULT ) );
	if( contentListItem->flags & CONTENTLIST_PROCESSED )
		{
		*valuePtr = sigInfo->processingResult;
		return( CRYPT_OK );
		}

	/* If there's an encoded certificate chain present and it hasn't been 
	   instantiated as a certificate object yet, instantiate it now.  We 
	   don't check the return value since a failure isn't fatal, we can 
	   still perform the signature check with a key pulled from a keyset */
	if( sigInfo->iSigCheckKey == CRYPT_ERROR && \
		envelopeInfoPtr->auxBuffer != NULL )
		{
		( void ) instantiateCertChain( contentListItem, 
									   envelopeInfoPtr->auxBuffer, 
									   envelopeInfoPtr->auxBufSize );
		}

	/* If we have a key instantiated from a certificate chain, use that to 
	   check the signature.  In theory we could also be re-using the key 
	   from an earlier, not-completed check, however this is only retained 
	   if the check succeeds (to allow a different key to be tried if the 
	   check fails) so in practice this never occurs */
	if( sigInfo->iSigCheckKey != CRYPT_ERROR )
		{
		/* Add the signature-check key with the special type 
		   CRYPT_ENVINFO_SIGNATURE_RESULT to indicate that it's been 
		   provided internally rather than being supplied by the user */
		*valuePtr = envelopeInfoPtr->addInfo( envelopeInfoPtr,
											  CRYPT_ENVINFO_SIGNATURE_RESULT, 
											  sigInfo->iSigCheckKey );
		return( CRYPT_OK );
		}

	/* We don't have a signature check key available (for example from a CMS 
	   certificate chain), make sure that there's a keyset available to pull 
	   the key from and get the key from it */
	if( envelopeInfoPtr->iSigCheckKeyset == CRYPT_ERROR )
		return( exitErrorNotInited( envelopeInfoPtr, 
									CRYPT_ENVINFO_KEYSET_SIGCHECK ) );

	/* Try and get the required key.  Even though we're accessing the key by 
	   (unique) key ID we still specify the key type preference in case 
	   there's some problem with the ID info.  This means that we return a 
	   more meaningful error message now rather than a usage-related one 
	   when we try to use the key */
	if( contentListItem->issuerAndSerialNumber == NULL )
		{
		setMessageKeymgmtInfo( &getkeyInfo, 
					( contentListItem->formatType == CRYPT_FORMAT_PGP ) ? \
						CRYPT_IKEYID_PGPKEYID : CRYPT_IKEYID_KEYID, 
					contentListItem->keyID, contentListItem->keyIDsize, 
					NULL, 0, KEYMGMT_FLAG_USAGE_SIGN );
		}
	else
		{
		setMessageKeymgmtInfo( &getkeyInfo,
					CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
					contentListItem->issuerAndSerialNumber,
					contentListItem->issuerAndSerialNumberSize,
					NULL, 0, KEYMGMT_FLAG_USAGE_SIGN );
		}
	status = krnlSendMessage( envelopeInfoPtr->iSigCheckKeyset, 
							  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
							  KEYMGMT_ITEM_PUBLICKEY );
	if( cryptStatusError( status ) )
		{
		retExtObj( status,
				   ( status, ENVELOPE_ERRINFO, 
				     envelopeInfoPtr->iSigCheckKeyset,
					 "Couldn't retrieve signature-check key from keyset" ) );
		}
	iCryptHandle = getkeyInfo.cryptHandle;

	/* Push the public key into the envelope, which performs the signature 
	   check.  Adding the key increments its reference count since the key 
	   is usually user-supplied and we need to keep a reference for use by 
	   the envelope, however since the key that we're using here is an 
	   internal-use-only key we don't want to do this so we decrement it 
	   again after it's been added.  In addition we add the signature-check 
	   key with the special type CRYPT_ENVINFO_SIGNATURE_RESULT to indicate 
	   that it's been provided internally rather than being user-supplied */
	*valuePtr = envelopeInfoPtr->addInfo( envelopeInfoPtr,
										  CRYPT_ENVINFO_SIGNATURE_RESULT, 
										  iCryptHandle );
	krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );

	/* If the key wasn't used for the signature check (i.e. it wasn't stored 
	   in the content list for later use, which means it isn't needed any 
	   more), discard it */
	if( sigInfo->iSigCheckKey == CRYPT_ERROR )
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getSignatureKey( INOUT ENVELOPE_INFO *envelopeInfoPtr,
							OUT_INT_Z int *valuePtr )
	{
	CRYPT_CERTIFICATE sigCheckCert;
	CONTENT_LIST *contentListItem = envelopeInfoPtr->contentListCurrent;
	CONTENT_SIG_INFO *sigInfo = &contentListItem->clSigInfo;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( valuePtr, sizeof( int ) ) );

	REQUIRES( contentListItem != NULL );

	/* Clear return value */
	*valuePtr = 0;

	/* If there's no signing key present try and instantiate it from an 
	   attached certificate chain */
	if( sigInfo->iSigCheckKey == CRYPT_ERROR )
		{
		if( envelopeInfoPtr->auxBuffer == NULL )
			{
			/* There's no attached certificate chain to recover the signing 
			   key from, we can't go any further */
			return( exitErrorNotFound( envelopeInfoPtr, 
									   CRYPT_ENVINFO_SIGNATURE ) );
			}
		status = instantiateCertChain( contentListItem,
									   envelopeInfoPtr->auxBuffer, 
									   envelopeInfoPtr->auxBufSize );
		if( cryptStatusError( status ) )
			return( exitError( envelopeInfoPtr, CRYPT_ENVINFO_SIGNATURE, 
							   CRYPT_ERRTYPE_ATTR_VALUE, status ) );
		}

	/* If we instantiated the signature-check key ourselves (either from a 
	   keyset or from envelope data) rather than having it supplied 
	   externally, we're done */
	if( !( contentListItem->flags & CONTENTLIST_EXTERNALKEY ) )
		{
		krnlSendNotifier( sigInfo->iSigCheckKey, IMESSAGE_INCREFCOUNT );
		*valuePtr = sigInfo->iSigCheckKey;

		return( CRYPT_OK );
		}

	/* The signature check key was externally supplied by the caller.  If 
	   they added a private key+certificate combination as the signature 
	   check key then this will return a supposed signature-check 
	   certificate that actually has private-key capabilities.  Even adding 
	   a simple certificate (+ public key context for the signature check) 
	   can be dangerous since it can act as a subliminal channel if it's 
	   passed on to a different user (although exactly how this would be 
	   exploitable is another question entirely).  To avoid this problem we 
	   completely isolate the added signature check key by returning a copy 
	   of the associated certificate object */
	status = krnlSendMessage( sigInfo->iSigCheckKey, IMESSAGE_GETATTRIBUTE, 
							  &sigCheckCert, CRYPT_IATTRIBUTE_CERTCOPY );
	if( cryptStatusError( status ) )
		return( exitError( envelopeInfoPtr, CRYPT_ENVINFO_SIGNATURE, 
						   CRYPT_ERRTYPE_ATTR_VALUE, status ) );

	/* We've created a new instantiation of the signature check key which is 
	   distinct from the externally-supplied original, replace the existing 
	   one with the new one and return it to the caller */
	krnlSendNotifier( sigInfo->iSigCheckKey, IMESSAGE_DECREFCOUNT );
	*valuePtr = sigInfo->iSigCheckKey = sigCheckCert;

	return( CRYPT_OK );
	}

/* Check an attribute add that isn't handled by the table-driven 
   general-purpose checks in setContextAttribute() */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 5 ) ) \
static int checkOtherAttribute( INOUT ENVELOPE_INFO *envelopeInfoPtr,
								IN_INT_Z const int value, 
								IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute,
								OUT_ENUM_OPT( ACTION ) ACTION_TYPE *usage,
								OUT_ENUM_OPT( MESSAGE_CHECK ) \
									MESSAGE_CHECK_TYPE *checkType )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( usage, sizeof( ACTION_TYPE ) ) );

	REQUIRES( value >= 0 && value < MAX_INTLENGTH );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Clear return values */
	*usage = ACTION_NONE;
	*checkType = MESSAGE_CHECK_NONE;

	switch( attribute )
		{
		case CRYPT_OPTION_ENCR_ALGO:
			if( !envelopeInfoPtr->checkAlgo( value, 
							isStreamCipher( value ) ? CRYPT_MODE_OFB : \
							( envelopeInfoPtr->type == CRYPT_FORMAT_PGP ) ? \
							CRYPT_MODE_CFB : CRYPT_MODE_CBC ) )
				return( CRYPT_ARGERROR_VALUE );
			envelopeInfoPtr->defaultAlgo = value;
			return( OK_SPECIAL );

		case CRYPT_OPTION_ENCR_HASH:
			if( !envelopeInfoPtr->checkAlgo( value, CRYPT_MODE_NONE ) )
				return( CRYPT_ARGERROR_VALUE );
			envelopeInfoPtr->defaultHash = value;
			return( OK_SPECIAL );

		case CRYPT_OPTION_ENCR_MAC:
			if( !envelopeInfoPtr->checkAlgo( value, CRYPT_MODE_NONE ) )
				return( CRYPT_ARGERROR_VALUE );
			envelopeInfoPtr->defaultMAC = value;
			return( OK_SPECIAL );

		case CRYPT_ENVINFO_DATASIZE:
			if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_DATASIZE ) );
			return( CRYPT_OK );

		case CRYPT_ENVINFO_CONTENTTYPE:
			/* Exactly what's supposed to happen when PGP is asked to sign 
			   non-plain-data is ill-defined.  No command-line PGP option 
			   will generate this type of message, and the RFCs don't 
			   specify the behaviour (in fact RFC 1991's description of PGP 
			   signing is completely wrong).  In practice PGP hashes and 
			   signs the payload contents of a PGP literal data packet, 
			   however if there are extra layers of processing between the 
			   signing and literal packets (e.g. compression or encryption) 
			   then what gets hashed isn't specified.  If it's always the 
			   payload of the final (literal) data packet we'd have to be 
			   able to burrow down through arbitrary amounts of further data 
			   and processing in order to get to the payload data to hash 
			   (this also makes things like mail gateways that only allow 
			   signed messages through infeasible unless the gateway holds 
			   everyone's private key in order to get at the plaintext to 
			   hash).  Because of this problem we disallow any attempts to 
			   set a content-type other than plain data if we're signing a 
			   PGP-format message */
			if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
				envelopeInfoPtr->usage == ACTION_SIGN && \
				value != CRYPT_CONTENT_DATA )
				return( CRYPT_ARGERROR_VALUE );

			/* For user-friendliness we allow overwriting a given content 
			   type with the same type, which is useful for cases when 
			   cryptlib automatically presets the type based on other
			   information */
			if( envelopeInfoPtr->contentType && \
				envelopeInfoPtr->contentType != value )
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_CONTENTTYPE ) );
			return( CRYPT_OK );

		case CRYPT_ENVINFO_INTEGRITY:
			/* The integrity-protection flag can't be reset to a value of 
			   CRYPT_INTEGRITY_NONE once it's been set to a higher level.  
			   If it could be reset then the caller could set non-MAC-
			   compatible options by clearing the flag and then setting it 
			   again afterwards */
			if( envelopeInfoPtr->usage != ACTION_NONE )
				return( CRYPT_ERROR_INITED );
			return( CRYPT_OK );

		case CRYPT_ENVINFO_SIGNATURE:
			*checkType = ( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) ? \
							MESSAGE_CHECK_PKC_SIGCHECK : \
							MESSAGE_CHECK_PKC_SIGN;
			if( envelopeInfoPtr->usage != ACTION_NONE && \
				envelopeInfoPtr->usage != ACTION_SIGN )
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_SIGNATURE ) );
			if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
				envelopeInfoPtr->contentType == CRYPT_CONTENT_DATA )
				{
				/* See the long comment for CRYPT_ENVINFO_CONTENTTYPE */
				return( CRYPT_ARGERROR_VALUE );
				}
			*usage = ACTION_SIGN;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
			if( envelopeInfoPtr->type != CRYPT_FORMAT_CMS && \
				envelopeInfoPtr->type != CRYPT_FORMAT_SMIME )
				return( CRYPT_ARGERROR_VALUE );
			if( envelopeInfoPtr->usage != ACTION_NONE && \
				envelopeInfoPtr->usage != ACTION_SIGN )
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_SIGNATURE_EXTRADATA ) );
			return( CRYPT_OK );

		case CRYPT_ENVINFO_ORIGINATOR:
			*checkType = MESSAGE_CHECK_PKC_KA_EXPORT;
			if( envelopeInfoPtr->usage != ACTION_NONE && \
				envelopeInfoPtr->usage != ACTION_CRYPT )
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_ORIGINATOR ) );
			*usage = ACTION_CRYPT;
			if( envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR )
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_ORIGINATOR ) );
			return( CRYPT_OK );

		case CRYPT_ENVINFO_KEYSET_ENCRYPT:
			*checkType = MESSAGE_CHECK_PKC_ENCRYPT_AVAIL;
			if( envelopeInfoPtr->iEncryptionKeyset != CRYPT_ERROR )
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_KEYSET_ENCRYPT ) );
			return( CRYPT_OK );

		case CRYPT_ENVINFO_KEYSET_DECRYPT:
			*checkType = MESSAGE_CHECK_PKC_DECRYPT_AVAIL;
			if( envelopeInfoPtr->iDecryptionKeyset != CRYPT_ERROR )
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_KEYSET_DECRYPT ) );
			return( CRYPT_OK );

		case CRYPT_ENVINFO_KEYSET_SIGCHECK:
			*checkType = MESSAGE_CHECK_PKC_SIGCHECK_AVAIL;
			if( envelopeInfoPtr->iSigCheckKeyset != CRYPT_ERROR )
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_KEYSET_SIGCHECK ) );
			return( CRYPT_OK );

		}

	retIntError();
	}

/****************************************************************************
*																			*
*								Get Attributes								*
*																			*
****************************************************************************/

/* Get a numeric/boolean attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getEnvelopeAttribute( INOUT ENVELOPE_INFO *envelopeInfoPtr,
						  OUT_INT_Z int *valuePtr, 
						  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( valuePtr, sizeof( int ) ) );

	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Clear return value */
	*valuePtr = 0;

	/* Generic attributes are valid for all envelope types */
	if( attribute == CRYPT_ATTRIBUTE_BUFFERSIZE )
		{
		*valuePtr = envelopeInfoPtr->bufSize;
		return( CRYPT_OK );
		}
	if( attribute == CRYPT_ATTRIBUTE_ERRORTYPE )
		{
		*valuePtr = envelopeInfoPtr->errorType;
		return( CRYPT_OK );
		}
	if( attribute == CRYPT_ATTRIBUTE_ERRORLOCUS )
		{
		*valuePtr = envelopeInfoPtr->errorLocus;
		return( CRYPT_OK );
		}

	/* If we're de-enveloping PGP data, make sure that the attribute is valid 
	   for PGP envelopes.  We can't perform this check via the ACLs because 
	   the data type isn't known at envelope creation time so there's a 
	   single generic de-envelope type for which the ACLs allow the union of 
	   all de-enveloping attribute types.  The following check weeds out the 
	   ones that don't work for PGP */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
		attribute == CRYPT_ENVINFO_SIGNATURE_EXTRADATA )
		return( CRYPT_ARGERROR_VALUE );

	/* Make sure that the attribute is valid for this envelope type and state */
	switch( attribute )
		{
		case CRYPT_OPTION_ENCR_ALGO:
		case CRYPT_OPTION_ENCR_HASH:
		case CRYPT_OPTION_ENCR_MAC:
			/* Algorithm types are valid only for enveloping */
			if( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE )
				return( CRYPT_ARGERROR_OBJECT );
			break;
					
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ENVINFO_SIGNATURE_RESULT:
		case CRYPT_ENVINFO_SIGNATURE:
		case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
		case CRYPT_ENVINFO_TIMESTAMP:
			/* The following checks aren't strictly necessary since we can 
			   get some information as soon as it's available, but it leads 
			   to less confusion (for example without this check we can get 
			   signer info long before we can get the signature results, 
			   which could be misinterpreted to mean that the signature is 
			   bad) and forces the caller to do things cleanly */
			if( envelopeInfoPtr->usage == ACTION_SIGN && \
				envelopeInfoPtr->state != STATE_FINISHED )
				return( CRYPT_ERROR_INCOMPLETE );
			if( envelopeInfoPtr->usage == ACTION_MAC && \
				attribute == CRYPT_ENVINFO_SIGNATURE_RESULT )
				{
				if( envelopeInfoPtr->state != STATE_FINISHED )
					return( CRYPT_ERROR_INCOMPLETE );

				/* If it's a MACd envelope then the signature result isn't 
				   held in a content list as for the other signatures since 
				   the "signature" is just a MAC tag appended to the data, 
				   so there's no need to check for the presence of a content 
				   list */
				break;
				}

			/* We're querying something that resides in the content list, 
			   make sure that there's a content list present.  If it's 
			   present but nothing is selected, select the first entry */
			if( envelopeInfoPtr->contentListCurrent == NULL )
				{
				if( envelopeInfoPtr->contentList == NULL )
					return( exitErrorNotFound( envelopeInfoPtr, 
											   attribute ) );
				envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
				resetVirtualCursor( envelopeInfoPtr->contentListCurrent );
				}
			break;

		default:
			REQUIRES( attribute == CRYPT_ENVINFO_COMPRESSION || \
					  attribute == CRYPT_ENVINFO_CONTENTTYPE || \
					  attribute == CRYPT_ENVINFO_INTEGRITY || \
					  attribute == CRYPT_ENVINFO_DETACHEDSIGNATURE || \
					  attribute == CRYPT_IATTRIBUTE_ATTRONLY );
		}

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
		case CRYPT_ATTRIBUTE_CURRENT:
			return( getCurrentAttributeInfo( envelopeInfoPtr, valuePtr ) );

		case CRYPT_OPTION_ENCR_ALGO:
			if( envelopeInfoPtr->defaultAlgo == CRYPT_ALGO_NONE )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_OPTION_ENCR_ALGO ) );
			*valuePtr = envelopeInfoPtr->defaultAlgo;
			return( CRYPT_OK );

		case CRYPT_OPTION_ENCR_HASH:
			if( envelopeInfoPtr->defaultHash == CRYPT_ALGO_NONE )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_OPTION_ENCR_HASH ) );
			*valuePtr = envelopeInfoPtr->defaultHash;
			return( CRYPT_OK );

		case CRYPT_OPTION_ENCR_MAC:
			if( envelopeInfoPtr->defaultMAC == CRYPT_ALGO_NONE )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_OPTION_ENCR_MAC ) );
			*valuePtr = envelopeInfoPtr->defaultMAC;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_COMPRESSION:
			if( envelopeInfoPtr->usage == ACTION_NONE )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_ENVINFO_COMPRESSION ) );
			*valuePtr = ( envelopeInfoPtr->usage == ACTION_COMPRESS ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_CONTENTTYPE:
			if( envelopeInfoPtr->contentType == CRYPT_CONTENT_NONE )
				return( exitErrorNotFound( envelopeInfoPtr, 
										   CRYPT_ENVINFO_CONTENTTYPE ) );
			*valuePtr = envelopeInfoPtr->contentType;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_DETACHEDSIGNATURE:
			/* If this isn't signed data or we haven't sorted out the 
			   content details yet we don't know whether it's a detached 
			   signature or not.  We have to make an exception for PGP 
			   signed data because the PGP format doesn't record whether a 
			   signature is a detached signature or not.  To resolve this, 
			   the lower-level de-enveloping code takes a guess based on 
			   whether the user has manually added a hash for signed-data 
			   processing or not.  Because of this the detached-signature 
			   status can change from (apparently-)false before adding the 
			   hash to (apparently-)true after adding it, but there's not 
			   much that we can do about this */
			if( envelopeInfoPtr->usage != ACTION_SIGN || \
				( envelopeInfoPtr->type != CRYPT_FORMAT_PGP && \
				  envelopeInfoPtr->contentType == CRYPT_CONTENT_NONE ) )
				return( exitErrorNotFound( envelopeInfoPtr, 
										   CRYPT_ENVINFO_DETACHEDSIGNATURE ) );
			*valuePtr = ( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_SIGNATURE_RESULT:
			return( getSignatureResult( envelopeInfoPtr, valuePtr ) );

		case CRYPT_ENVINFO_INTEGRITY:
			*valuePtr = ( envelopeInfoPtr->usage == ACTION_MAC ) ? \
						CRYPT_INTEGRITY_MACONLY : CRYPT_INTEGRITY_NONE;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_SIGNATURE:
			return( getSignatureKey( envelopeInfoPtr, valuePtr ) );

		case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
		case CRYPT_ENVINFO_TIMESTAMP:
			{
			CRYPT_HANDLE iCryptHandle;
			CONTENT_LIST *contentListItem = \
								envelopeInfoPtr->contentListCurrent;

			assert( contentListItem != NULL );

			/* Make sure that there's extra data present */
			iCryptHandle = \
				( attribute == CRYPT_ENVINFO_SIGNATURE_EXTRADATA ) ? \
					contentListItem->clSigInfo.iExtraData : \
					contentListItem->clSigInfo.iTimestamp;
			if( iCryptHandle == CRYPT_ERROR )
				return( exitErrorNotFound( envelopeInfoPtr, attribute ) );

			/* Return it to the caller */
			krnlSendNotifier( iCryptHandle, IMESSAGE_INCREFCOUNT );
			*valuePtr = iCryptHandle;

			return( CRYPT_OK );
			}

		case CRYPT_IATTRIBUTE_ATTRONLY:
			/* If this isn't signed data we don't know whether it's an 
			   attributes-only message or not */
			if( envelopeInfoPtr->usage != ACTION_SIGN )
				return( exitErrorNotFound( envelopeInfoPtr, 
										   CRYPT_IATTRIBUTE_ATTRONLY ) );

			*valuePtr = ( envelopeInfoPtr->flags & ENVELOPE_ATTRONLY ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );
		}

	retIntError();
	}

/* Get a string attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getEnvelopeAttributeS( INOUT ENVELOPE_INFO *envelopeInfoPtr,
						   INOUT MESSAGE_DATA *msgData, 
						   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	CONTENT_LIST *contentListItem;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( msgData, sizeof( MESSAGE_DATA ) ) );

	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* If we're querying something that resides in the content list make
	   sure that there's a content list present.  If it's present but 
	   nothing is selected, select the first entry */
	if( attribute == CRYPT_ENVINFO_PRIVATEKEY_LABEL && \
		envelopeInfoPtr->contentListCurrent == NULL )
		{
		if( envelopeInfoPtr->contentList == NULL )
			return( exitErrorNotFound( envelopeInfoPtr, 
									   CRYPT_ENVINFO_PRIVATEKEY_LABEL ) );
		envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
		resetVirtualCursor( envelopeInfoPtr->contentListCurrent );
		}

	/* Generic attributes are valid for all envelope types */
	if( attribute == CRYPT_ENVINFO_PRIVATEKEY_LABEL )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		char label[ CRYPT_MAX_TEXTSIZE + 8 ];

		/* Make sure that the current required resource is a private key and
		   that there's a keyset available to pull the key from */
		contentListItem = envelopeInfoPtr->contentListCurrent;
		if( contentListItem->envInfo != CRYPT_ENVINFO_PRIVATEKEY )
			return( exitErrorNotFound( envelopeInfoPtr, 
									   CRYPT_ENVINFO_PRIVATEKEY_LABEL ) );
		if( envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR )
			return( exitErrorNotInited( envelopeInfoPtr, 
										CRYPT_ENVINFO_KEYSET_DECRYPT ) );

		/* Try and get the key label information.  Since we're accessing the 
		   key by (unique) key ID there's no real need to specify a 
		   preference for encryption keys */
		if( contentListItem->issuerAndSerialNumber == NULL )
			{
			setMessageKeymgmtInfo( &getkeyInfo, 
								   ( contentListItem->formatType == CRYPT_FORMAT_PGP ) ? \
								   CRYPT_IKEYID_PGPKEYID : CRYPT_IKEYID_KEYID, 
								   contentListItem->keyID,
								   contentListItem->keyIDsize,
								   label, CRYPT_MAX_TEXTSIZE,
								   KEYMGMT_FLAG_LABEL_ONLY );
			}
		else
			{
			setMessageKeymgmtInfo( &getkeyInfo, 
								   CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
								   contentListItem->issuerAndSerialNumber,
								   contentListItem->issuerAndSerialNumberSize,
								   label, CRYPT_MAX_TEXTSIZE,
								   KEYMGMT_FLAG_LABEL_ONLY );
			}
		status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset,
								  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
								  KEYMGMT_ITEM_PRIVATEKEY );
		if( cryptStatusError( status ) )
			{
			retExtObj( status,
					   ( status, ENVELOPE_ERRINFO,
					     envelopeInfoPtr->iDecryptionKeyset,
						 "Couldn't retrieve private-key label from "
						 "keyset/device" ) );
			}
		return( attributeCopy( msgData, getkeyInfo.auxInfo,
							   getkeyInfo.auxInfoLength ) );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*								Set Attributes								*
*																			*
****************************************************************************/

/* Set a numeric/boolean attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setEnvelopeAttribute( INOUT ENVELOPE_INFO *envelopeInfoPtr,
						  IN_INT_Z const int value, 
						  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	MESSAGE_CHECK_TYPE checkType = MESSAGE_CHECK_NONE;
	ACTION_TYPE usage = ACTION_NONE;
	typedef struct {
		const CRYPT_ATTRIBUTE_TYPE type;	/* Attribute type */
		const ACTION_TYPE usage;			/* Corresponding usage type */
		const MESSAGE_CHECK_TYPE checkType;	/*  and check type */
		} CHECK_INFO;
	static const CHECK_INFO checkTable[] = {
		/* The following checks are fairly stereotyped and can be selected 
		   via a lookup table.  Envelope attributes that require more
		   specialised checking are handled via custom code in a case 
		   statement */
#ifdef USE_COMPRESSION
		{ CRYPT_ENVINFO_COMPRESSION, ACTION_COMPRESS, MESSAGE_CHECK_NONE },
#endif /* USE_COMPRESSION */
		{ CRYPT_ENVINFO_KEY, ACTION_CRYPT, MESSAGE_CHECK_CRYPT },
		{ CRYPT_ENVINFO_PUBLICKEY, ACTION_CRYPT, MESSAGE_CHECK_PKC_ENCRYPT },
		{ CRYPT_ENVINFO_PRIVATEKEY, ACTION_CRYPT, MESSAGE_CHECK_PKC_DECRYPT },
		{ CRYPT_ENVINFO_SESSIONKEY, ACTION_CRYPT, MESSAGE_CHECK_CRYPT },
		{ CRYPT_ENVINFO_HASH, ACTION_SIGN, MESSAGE_CHECK_HASH },
		{ CRYPT_ENVINFO_TIMESTAMP, ACTION_SIGN, MESSAGE_CHECK_NONE },
		{ CRYPT_ENVINFO_DETACHEDSIGNATURE, ACTION_SIGN, MESSAGE_CHECK_NONE },
		{ CRYPT_IATTRIBUTE_INCLUDESIGCERT, ACTION_SIGN, MESSAGE_CHECK_NONE },
		{ CRYPT_IATTRIBUTE_ATTRONLY, ACTION_SIGN, MESSAGE_CHECK_NONE },
		{ CRYPT_ATTRIBUTE_NONE, ACTION_NONE }, { CRYPT_ATTRIBUTE_NONE, ACTION_NONE }
		};
	int i, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( ( attribute == CRYPT_ENVINFO_COMPRESSION || \
				attribute == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
				attribute == CRYPT_ATTRIBUTE_CURRENT ) || 
				/* Compression = CRYPT_UNUSED, CURRENT = cursor positioning 
				   code */
			  ( value >= 0 && value < MAX_INTLENGTH ) );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Generic attributes are valid for all envelope types */
	if( attribute == CRYPT_ATTRIBUTE_BUFFERSIZE )
		{
		envelopeInfoPtr->bufSize = value;
		return( CRYPT_OK );
		}

	/* If it's meta-information, process it now */
	if( attribute == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
		attribute == CRYPT_ATTRIBUTE_CURRENT )
		{
		const CONTENT_LIST *contentListCursor;

		/* If it's an absolute positioning code, pre-set the attribute
		   cursor if required */
		if( value == CRYPT_CURSOR_FIRST || value == CRYPT_CURSOR_LAST )
			{
			if( envelopeInfoPtr->contentList == NULL )
				return( CRYPT_ERROR_NOTFOUND );

			ENSURES( envelopeInfoPtr->contentList != NULL );

			/* If it's an absolute attribute positioning code, reset the
			   attribute cursor to the start of the list before we try to
			   move it and if it's an attribute positioning code initialise 
			   the attribute cursor if necessary */
			if( attribute == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
				envelopeInfoPtr->contentListCurrent == NULL )
				{
				envelopeInfoPtr->contentListCurrent = \
										envelopeInfoPtr->contentList;
				if( envelopeInfoPtr->contentListCurrent != NULL )
					resetVirtualCursor( envelopeInfoPtr->contentListCurrent );
				}

			/* If there are no attributes present, return the appropriate 
			   error code */
			if( envelopeInfoPtr->contentListCurrent == NULL )
				{
				return( ( value == CRYPT_CURSOR_FIRST || \
						  value == CRYPT_CURSOR_LAST ) ? \
							CRYPT_ERROR_NOTFOUND : \
							CRYPT_ERROR_NOTINITED );
				}
			}
		else
			{
			/* It's a relative positioning code, return a not-inited error
			   rather than a not-found error if the cursor isn't set since
			   there may be attributes present but the cursor hasn't been
			   initialised yet by selecting the first or last absolute
			   attribute */
			if( envelopeInfoPtr->contentListCurrent == NULL )
				return( CRYPT_ERROR_NOTINITED );
			}
		ENSURES( envelopeInfoPtr->contentListCurrent != NULL );

		/* Move the cursor */
		contentListCursor = ( const CONTENT_LIST * ) \
			attributeMoveCursor( envelopeInfoPtr->contentListCurrent, 
								 getAttrFunction, attribute, value );
		if( contentListCursor == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		envelopeInfoPtr->contentListCurrent = \
								( CONTENT_LIST * ) contentListCursor;
		return( CRYPT_OK );
		}

	/* In general we can't add new enveloping information once we've started
	   processing data */
	if( envelopeInfoPtr->state != STATE_PREDATA )
		{
		/* We can't add new information once we've started enveloping */
		if( !( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) )
			return( CRYPT_ERROR_INITED );

		/* We can only add signature check information once we've started
		   de-enveloping */
		if( attribute != CRYPT_ENVINFO_SIGNATURE )
			return( CRYPT_ERROR_INITED );
		}

	/* If we're de-enveloping PGP data, make sure that the attribute is 
	   valid for PGP envelopes.  We can't perform this check via the ACLs 
	   because the data type isn't known at envelope creation time so 
	   there's a single generic de-envelope type for which the ACLs allow 
	   the union of all de-enveloping attribute types.  The following check 
	   weeds out the ones that don't work for PGP */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		{
		if( attribute == CRYPT_OPTION_ENCR_MAC || \
			attribute == CRYPT_ENVINFO_INTEGRITY || \
			attribute == CRYPT_ENVINFO_KEY || \
			attribute == CRYPT_ENVINFO_SESSIONKEY )
			return( CRYPT_ARGERROR_VALUE );
		if( attribute == CRYPT_ENVINFO_HASH && \
			!( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG ) )
			{
			/* We can add a hash if we're creating a detached signature */
			return( CRYPT_ARGERROR_VALUE );
			}
		}

	/* Since the information may not be used for quite some time after it's
	   added we do some preliminary checking here to allow us to return an
	   error code immediately rather than from some deeply-buried function an
	   indeterminate time in the future.  Since much of the checking is
	   similar, we use a table-driven check for most types and fall back to
	   custom checking for special cases */
	for( i = 0; checkTable[ i ].type != ACTION_NONE && \
				i < FAILSAFE_ARRAYSIZE( checkTable, CHECK_INFO ); i++ )
		{
		if( checkTable[ i ].type == attribute )
			{
			if( envelopeInfoPtr->usage != ACTION_NONE && \
				envelopeInfoPtr->usage != checkTable[ i ].usage )
				return( exitErrorInited( envelopeInfoPtr, attribute ) );
			usage = checkTable[ i ].usage;
			checkType = checkTable[ i ].checkType;
			break;
			}
		}
	ENSURES( i < FAILSAFE_ARRAYSIZE( checkTable, CHECK_INFO ) );
	if( usage != ACTION_NONE )
		{
		/* Make sure that the usage requirements for the item that we're 
		   about to add are consistent */
		if( envelopeInfoPtr->usage != ACTION_NONE && \
			envelopeInfoPtr->usage != usage )
			return( exitErrorInited( envelopeInfoPtr, 
									 attribute ) );
		}
	else
		{
		/* It's not a general class of action, perform special-case usage 
		   checking */
		status = checkOtherAttribute( envelopeInfoPtr, value, attribute, 
									  &usage, &checkType );
		if( cryptStatusError( status ) )
			{
			/* An attribute that's handled internally will return OK_SPECIAL 
			   to indicate that there's nothing further to do */
			if( status == OK_SPECIAL )
				return( CRYPT_OK );

			return( status );
			}
		}

	if( checkType != MESSAGE_CHECK_NONE )
		{
		/* Check the object as appropriate.  A key agreement key can also act
		   as a public key because of the way KEA works so if a check for a
		   straight public key fails we try again to see if it's a key
		   agreement key with import capabilities */
		status = krnlSendMessage( value, IMESSAGE_CHECK, NULL, checkType );
		if( status == CRYPT_ARGERROR_OBJECT && \
			attribute == CRYPT_ENVINFO_PUBLICKEY )
			status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
									  MESSAGE_CHECK_PKC_KA_IMPORT );
		if( cryptStatusError( status ) )
			return( CRYPT_ARGERROR_NUM1 );

		/* Make sure that the object corresponds to a representable algorithm
		   type.  Note that this check isn't totally foolproof on de-
		   enveloping PGP data since the user can push in the hash context 
		   before they push in the signed data (to signifiy the use of a 
		   detached signature) so it'd be checked using the default (CMS) 
		   algorithm values rather than the PGP ones */
		if( checkType == MESSAGE_CHECK_PKC_ENCRYPT || \
			checkType == MESSAGE_CHECK_PKC_DECRYPT || \
			checkType == MESSAGE_CHECK_PKC_SIGN || \
			checkType == MESSAGE_CHECK_PKC_SIGCHECK || \
			checkType == MESSAGE_CHECK_CRYPT || \
			checkType == MESSAGE_CHECK_HASH || \
			checkType == MESSAGE_CHECK_MAC )
			{
			CRYPT_ALGO_TYPE algorithm;
			CRYPT_MODE_TYPE mode = CRYPT_MODE_NONE;

			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
									  &algorithm, CRYPT_CTXINFO_ALGO );
			if( cryptStatusOK( status ) && checkType == MESSAGE_CHECK_CRYPT )
				{
				/* It's a conventional-encryption context, get the mode as 
				   well */
				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, 
										  &mode, CRYPT_CTXINFO_MODE );
				}
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_NUM1 );
			if( !envelopeInfoPtr->checkAlgo( algorithm, mode ) )
				return( CRYPT_ERROR_NOTAVAIL );
			}

		/* If we're using CMS enveloping then the object must have an 
		   initialised certificate of the correct type associated with it.  
		   Most of this will be caught by the kernel but there are a couple 
		   of special cases (e.g. an attribute certificate where the main 
		   object is a PKC context) which are missed by the general kernel 
		   checks */
		if( ( attribute == CRYPT_ENVINFO_SIGNATURE || \
			  attribute == CRYPT_ENVINFO_PUBLICKEY || \
			  attribute == CRYPT_ENVINFO_PRIVATEKEY || \
			  attribute == CRYPT_ENVINFO_ORIGINATOR ) && 
			( envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
			  envelopeInfoPtr->type == CRYPT_FORMAT_SMIME ) )
			{
			int inited, certType;

			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, &inited, 
									  CRYPT_CERTINFO_IMMUTABLE );
			if( cryptStatusError( status ) || !inited )
				return( CRYPT_ARGERROR_NUM1 );
			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
									  &certType, CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) ||
				( certType != CRYPT_CERTTYPE_CERTIFICATE && \
				  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
				return( CRYPT_ARGERROR_NUM1 );
			}
		}

	/* Add it to the envelope */
	status = envelopeInfoPtr->addInfo( envelopeInfoPtr, attribute,
									   value );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_INITED )
			return( exitErrorInited( envelopeInfoPtr, attribute ) );
		return( status );
		}
	if( usage != ACTION_NONE )
		{
		/* The action was successfully added, update the usage if 
		   necessary */
		envelopeInfoPtr->usage = usage;
		}
	return( CRYPT_OK );
	}

/* Set a string attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int setEnvelopeAttributeS( INOUT ENVELOPE_INFO *envelopeInfoPtr,
						   IN_BUFFER( dataLength ) const void *data,
						   IN_LENGTH const int dataLength,
						   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	ACTION_TYPE usage = ACTION_NONE;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isReadPtr( data, dataLength ) );

	REQUIRES( dataLength > 0 && dataLength < MAX_INTLENGTH );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_ENVINFO_PASSWORD:
			/* Set the envelope usage type based on the fact that we've been
			   fed a password */
			if( envelopeInfoPtr->usage == ACTION_NONE )
				usage = ACTION_CRYPT;
			else
				{
				if( envelopeInfoPtr->usage != ACTION_CRYPT && \
					envelopeInfoPtr->usage != ACTION_MAC )
					return( exitErrorInited( envelopeInfoPtr, 
											 CRYPT_ENVINFO_PASSWORD ) );
				}

			/* In general we can't add new enveloping information once we've
			   started processing data */
			if( envelopeInfoPtr->state != STATE_PREDATA && \
				!( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) )
				{
				/* We can't add new information once we've started enveloping */
				return( exitErrorInited( envelopeInfoPtr, 
										 CRYPT_ENVINFO_PASSWORD ) );
				}

			/* Add it to the envelope */
			status = envelopeInfoPtr->addInfoString( envelopeInfoPtr,
								CRYPT_ENVINFO_PASSWORD, data, dataLength );
			break;

		case CRYPT_ENVINFO_RECIPIENT:
			{
			MESSAGE_KEYMGMT_INFO getkeyInfo;

			/* Set the envelope usage type based on the fact that we've been
			   fed a recipient email address */
			if( envelopeInfoPtr->usage != ACTION_NONE && \
				envelopeInfoPtr->usage != ACTION_CRYPT )
				return( CRYPT_ARGERROR_VALUE );
			usage = ACTION_CRYPT;

			/* Make sure that there's a keyset available to pull the 
			   recipient's key from */
			if( envelopeInfoPtr->iEncryptionKeyset == CRYPT_ERROR )
				return( exitErrorNotInited( envelopeInfoPtr, 
											CRYPT_ENVINFO_KEYSET_ENCRYPT ) );

			/* Try and read the recipient's key from the keyset.  Some 
			   keysets (particularly PKCS #11 devices, for which apps set 
			   the usage flags more or less at random) may not be able to 
			   differentiate between encryption and signature keys based on 
			   the information that they have.  This isn't a problem when 
			   matching a key based on a unique ID but with the use of the 
			   recipient name as the ID there could be multiple possible 
			   matches.  Before we try and use the key we therefore perform 
			   an extra check here to make sure that it really is an 
			   encryption-capable key */
			setMessageKeymgmtInfo( &getkeyInfo, CRYPT_KEYID_URI, data, 
								   dataLength, NULL, 0, 
								   KEYMGMT_FLAG_USAGE_CRYPT );
			status = krnlSendMessage( envelopeInfoPtr->iEncryptionKeyset,
									  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
									  KEYMGMT_ITEM_PUBLICKEY );
			if( status == CRYPT_ERROR_NOTFOUND )
				{
				/* Technically what we're looking for is an email address
				   (since this facility is meant for email encryption, thus
				   the "recipient" in the name) but it's possible that it's 
				   being used in a more general manner to mean "any random
				   key label", so if the fetch based on email address fails
				   we try again with a fetch based on name */
				setMessageKeymgmtInfo( &getkeyInfo, CRYPT_KEYID_NAME, data, 
									   dataLength, NULL, 0, 
									   KEYMGMT_FLAG_USAGE_CRYPT );
				status = krnlSendMessage( envelopeInfoPtr->iEncryptionKeyset,
										  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
										  KEYMGMT_ITEM_PUBLICKEY );
				}
			if( cryptStatusError( status ) )
				{
				retExtObj( status,
						   ( status, ENVELOPE_ERRINFO,
						     envelopeInfoPtr->iEncryptionKeyset,
							 "Couldn't retrieve encryption key from keyset" ) );
				}
			if( cryptStatusError( \
					krnlSendMessage( getkeyInfo.cryptHandle, IMESSAGE_CHECK, 
									 NULL, MESSAGE_CHECK_PKC_ENCRYPT ) ) )
				{
				krnlSendNotifier( getkeyInfo.cryptHandle,
								  IMESSAGE_DECREFCOUNT );
				return( CRYPT_ERROR_NOTFOUND );
				}
			if( cryptStatusOK( status ) )
				{
				/* We got the key, add it to the envelope */
				status = envelopeInfoPtr->addInfo( envelopeInfoPtr,
												   CRYPT_ENVINFO_PUBLICKEY,
												   getkeyInfo.cryptHandle );
				krnlSendNotifier( getkeyInfo.cryptHandle,
								  IMESSAGE_DECREFCOUNT );
				}
			break;
			}

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_INITED )
			return( exitErrorInited( envelopeInfoPtr, attribute ) );
		return( status );
		}
	if( usage != ACTION_NONE )
		{
		/* The action was successfully added, update the usage if 
		   necessary */
		envelopeInfoPtr->usage = usage;
		}
	return( CRYPT_OK );
	}

#endif /* USE_ENVELOPES */