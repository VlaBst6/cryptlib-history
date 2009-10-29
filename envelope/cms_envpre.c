/****************************************************************************
*																			*
*						cryptlib CMS Pre-enveloping Routines				*
*					    Copyright Peter Gutmann 1996-2008					*
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
*						Encrypted Content Pre-processing					*
*																			*
****************************************************************************/

/* Pre-process information for encrypted enveloping */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processKeyexchangeAction( INOUT ENVELOPE_INFO *envelopeInfoPtr,
									 INOUT ACTION_LIST *actionListPtr,
									 IN_HANDLE_OPT \
										const CRYPT_DEVICE iCryptDevice )
	{
	CRYPT_ALGO_TYPE cryptAlgo = DUMMY_INIT;
	int status;
#ifdef USE_KEA
	BYTE originatorDomainParams[ CRYPT_MAX_HASHSIZE + 8 ];
	int originatorDomainParamSize = 0;
#endif /* USE_KEA */

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( actionListPtr, sizeof( ACTION_LIST ) ) );
	
	REQUIRES( actionListPtr != NULL && \
			  ( actionListPtr->action == ACTION_KEYEXCHANGE_PKC || \
				actionListPtr->action == ACTION_KEYEXCHANGE ) );
	REQUIRES( iCryptDevice == CRYPT_UNUSED || \
			  isHandleRangeValid( iCryptDevice ) );

	/* If the session key/MAC context is tied to a device make sure that the 
	   key exchange object is in the same device */
	if( iCryptDevice != CRYPT_UNUSED )
		{
		CRYPT_DEVICE iKeyexDevice;

		status = krnlSendMessage( actionListPtr->iCryptHandle,
								  MESSAGE_GETDEPENDENT, &iKeyexDevice,
								  OBJECT_TYPE_DEVICE );
		if( cryptStatusError( status ) || iCryptDevice != iKeyexDevice )
			{
			setErrorInfo( envelopeInfoPtr, 
						  ( envelopeInfoPtr->usage == ACTION_CRYPT ) ? \
							CRYPT_ENVINFO_SESSIONKEY : CRYPT_ENVINFO_INTEGRITY,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

#ifdef USE_KEA
	/* If there's an originator chain present get the originator's domain
	   parameters */
	if( envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, originatorDomainParams,
						 CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( envelopeInfoPtr->iExtraCertChain,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_KEY_KEADOMAINPARAMS );
		if( cryptStatusError( status ) )
			return( status );
		originatorDomainParamSize = msgData.length;
		}

	/* If it's a key agreement action make sure that there's originator info 
	   present and that the domain parameters match */
	if( actionListPtr->action == ACTION_KEYEXCHANGE_PKC && \
		cryptStatusOK( krnlSendMessage( actionListPtr->iCryptHandle,
										IMESSAGE_CHECK, NULL,
										MESSAGE_CHECK_PKC_KA_EXPORT ) ) )
		{
		MESSAGE_DATA msgData;
		BYTE domainParams[ CRYPT_MAX_HASHSIZE + 8 ];

		if( originatorDomainParamSize <= 0 )
			{
			setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_ORIGINATOR,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		setMessageData( &msgData, domainParams, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( actionListPtr->iCryptHandle,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_KEY_KEADOMAINPARAMS );
		if( cryptStatusError( status ) )
			return( status );
		if( ( originatorDomainParamSize != msgData.length ) || \
			memcmp( originatorDomainParams, domainParams,
					originatorDomainParamSize ) )
			{
			setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_ORIGINATOR,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}
#endif /* USE_KEA */

	/* Remember that we now have a controlling action and connect the
	   controller to the subject */
	REQUIRES( envelopeInfoPtr->actionList != NULL );
	envelopeInfoPtr->actionList->flags &= ~ACTION_NEEDSCONTROLLER;
	actionListPtr->associatedAction = envelopeInfoPtr->actionList;

	/* Evaluate the size of the exported action.  If it's a conventional key
	   exchange we force the use of the CMS format since there's no reason 
	   to use the cryptlib format */
	status = iCryptExportKey( NULL, 0, &actionListPtr->encodedSize, 
						( actionListPtr->action == ACTION_KEYEXCHANGE ) ? \
							CRYPT_FORMAT_CMS : envelopeInfoPtr->type,
						envelopeInfoPtr->actionList->iCryptHandle,
						actionListPtr->iCryptHandle );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( actionListPtr->iCryptHandle,
								  IMESSAGE_GETATTRIBUTE, &cryptAlgo,
								  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );

	/* If there are any key exchange actions that will result in indefinite-
	   length encodings present we can't use a definite-length encoding for 
	   the key exchange actions */
	return( ( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? OK_SPECIAL : CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int cmsPreEnvelopeEncrypt( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	CRYPT_DEVICE iCryptDevice = CRYPT_UNUSED;
	ACTION_LIST *actionListPtr;
	BOOLEAN hasIndefSizeActions = FALSE;
	int totalSize, iterationCount, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( envelopeInfoPtr->usage == ACTION_CRYPT || \
			  envelopeInfoPtr->usage == ACTION_MAC );

#ifdef USE_KEA
	/* If there's originator info present find out what it'll take to encode 
	   it into the envelope header */
	if( envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR )
		{
		MESSAGE_DATA msgData;
		int status;

		/* Determine how big the originator certificate chain will be */
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( envelopeInfoPtr->iExtraCertChain,
								  IMESSAGE_CRT_EXPORT, &msgData,
								  CRYPT_ICERTFORMAT_CERTSET );
		if( cryptStatusError( status ) )
			return( status );
		envelopeInfoPtr->extraDataSize = msgData.length;

		/* If we have very long originator certificate chains the auxBuffer 
		   may not be large enough to contain the resulting chain, so we have to
		   expand it to handle the chain */
		if( envelopeInfoPtr->auxBufSize < envelopeInfoPtr->extraDataSize + 64 )
			{
			REQUIRES( envelopeInfoPtr->auxBuffer == NULL );
			if( ( envelopeInfoPtr->auxBuffer = \
					clDynAlloc( "preEnvelopeEncrypt", \
								envelopeInfoPtr->extraDataSize + 64 ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			envelopeInfoPtr->auxBufSize = envelopeInfoPtr->extraDataSize + 64;
			}
		}
#endif /* USE_KEA */

	/* If there are no key exchange actions present we're done */
	if( envelopeInfoPtr->preActionList == NULL )
		return( CRYPT_OK );

	/* Create the session/MAC key if necessary */
	if( envelopeInfoPtr->actionList == NULL )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Make sure that we can still add another action */
		if( !moreActionsPossible( envelopeInfoPtr->actionList ) )
			return( CRYPT_ERROR_OVERFLOW );

		/* Create a default encryption action and add it to the action
		   list */
		setMessageCreateObjectInfo( &createInfo,
							( envelopeInfoPtr->usage == ACTION_CRYPT ) ? \
								envelopeInfoPtr->defaultAlgo : \
								envelopeInfoPtr->defaultMAC );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		status = krnlSendNotifier( createInfo.cryptHandle, 
								   IMESSAGE_CTX_GENKEY );
		if( cryptStatusOK( status ) )
			{
			status = addAction( &envelopeInfoPtr->actionList,
								envelopeInfoPtr->memPoolState,
								envelopeInfoPtr->usage,
								createInfo.cryptHandle );
			}
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}
	else
		{
		/* If the session key/MAC context is tied to a device get its handle 
		   so that we can check that all key exchange objects are also in the 
		   same device */
		status = krnlSendMessage( envelopeInfoPtr->actionList->iCryptHandle,
								  MESSAGE_GETDEPENDENT, &iCryptDevice,
								  OBJECT_TYPE_DEVICE );
		if( cryptStatusError( status ) )
			iCryptDevice = CRYPT_UNUSED;
		}
	REQUIRES( envelopeInfoPtr->actionList != NULL );

	/* Notify the kernel that the session key/MAC context is attached to the
	   envelope.  This is an internal object used only by the envelope so we 
	   tell the kernel not to increment its reference count when it attaches 
	   it */
	status = krnlSendMessage( envelopeInfoPtr->objectHandle, 
							  IMESSAGE_SETDEPENDENT,
							  &envelopeInfoPtr->actionList->iCryptHandle,
							  SETDEP_OPTION_NOINCREF );
	if( cryptStatusError( status ) )
		return( status );

	/* Now walk down the list of key exchange actions evaluating their size
	   and connecting each one to the session key/MAC action */
	totalSize = 0; 
	for( actionListPtr = envelopeInfoPtr->preActionList, iterationCount = 0;
		 actionListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED; 
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		status = processKeyexchangeAction( envelopeInfoPtr, actionListPtr,
										   iCryptDevice );
		if( cryptStatusError( status ) )
			{
			/* An OK_SPECIAL state means that this keyex action will result 
			   in an indefinite-length encoding */
			if( status != OK_SPECIAL )
				return( status );
			hasIndefSizeActions = TRUE;
			}
		totalSize += actionListPtr->encodedSize;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );
	envelopeInfoPtr->cryptActionSize = hasIndefSizeActions ? \
									   CRYPT_UNUSED : totalSize;
	ENSURES( ( envelopeInfoPtr->cryptActionSize == CRYPT_UNUSED ) || \
			 ( envelopeInfoPtr->cryptActionSize > 0 && \
			   envelopeInfoPtr->cryptActionSize < MAX_INTLENGTH ) );

	/* If we're MACing the data, hashing is now active */
	if( envelopeInfoPtr->usage == ACTION_MAC )
		envelopeInfoPtr->dataFlags |= ENVDATA_HASHACTIONSACTIVE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Signed Content Pre-processing						*
*																			*
****************************************************************************/

/* Set up any necessary signature parameters such as signature attributes 
   and timestamps if necessary */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
int cmsInitSigParams( const ACTION_LIST *actionListPtr,
					  IN_ENUM( CRYPT_FORMAT ) const CRYPT_FORMAT_TYPE formatType,
					  IN_HANDLE const CRYPT_USER iCryptOwner,
					  OUT SIGPARAMS *sigParams )
	{
	const CRYPT_CERTIFICATE signingAttributes = actionListPtr->iExtraData;
	int useDefaultAttributes, status;

	REQUIRES( formatType == CRYPT_FORMAT_CRYPTLIB || \
			  formatType == CRYPT_FORMAT_CMS || \
			  formatType == CRYPT_FORMAT_SMIME );
	REQUIRES( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( iCryptOwner ) );

	assert( isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );
	assert( isWritePtr( sigParams, sizeof( SIGPARAMS ) ) );

	initSigParams( sigParams );

	/* If it's a raw signature there are no additional signing parameters */
	if( formatType == CRYPT_FORMAT_CRYPTLIB )
		return( CRYPT_OK );

	/* Add the timestamping session if there's one present */
	if( actionListPtr->iTspSession != CRYPT_ERROR )
		sigParams->iTspSession = actionListPtr->iTspSession;

	/* If the caller has specified signing attributes, use those */
	if( signingAttributes != CRYPT_ERROR )
		{
		sigParams->iAuthAttr = signingAttributes;
		return( CRYPT_OK );
		}

	/* There are no siging attributes specified (which can only happen under 
	   circumstances controlled by the pre-envelope signing code) we either 
	   get the signing code to add the default ones for us or use none at 
	   all if the use of default attributes is disabled */
	status = krnlSendMessage( iCryptOwner, IMESSAGE_GETATTRIBUTE,  
							  &useDefaultAttributes,
							  CRYPT_OPTION_CMS_DEFAULTATTRIBUTES );
	if( cryptStatusError( status ) )
		return( status );
	if( useDefaultAttributes )
		sigParams->useDefaultAuthAttr = TRUE;

	return( CRYPT_OK );
	}

/* Process signing certificates and match the content-type in the 
   authenticated attributes with the signed content type if it's anything 
   other than 'data' (the data content-type is added automatically) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processSigningCerts( INOUT ENVELOPE_INFO *envelopeInfoPtr,
							    INOUT ACTION_LIST *actionListPtr )
	{
	int value, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( actionListPtr, sizeof( ACTION_LIST ) ) );

	/* If we're including signing certificates and there are multiple 
	   signing certificates present add the currently-selected one to the 
	   overall certificate collection */
	if( !( envelopeInfoPtr->flags & ENVELOPE_NOSIGNINGCERTS ) && \
		envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR )
		{
		status = krnlSendMessage( envelopeInfoPtr->iExtraCertChain,
								  IMESSAGE_SETATTRIBUTE,
								  &actionListPtr->iCryptHandle,
								  CRYPT_IATTRIBUTE_CERTCOLLECTION );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If there's no content-type present and the signed content type isn't 
	   'data' or it's an S/MIME envelope, create signing attributes to hold 
	   the content-type and smimeCapabilities */
	if( actionListPtr->iExtraData == CRYPT_ERROR && \
		( envelopeInfoPtr->contentType != CRYPT_CONTENT_DATA || \
		  envelopeInfoPtr->type == CRYPT_FORMAT_SMIME ) )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		setMessageCreateObjectInfo( &createInfo,
									CRYPT_CERTTYPE_CMS_ATTRIBUTES );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusError( status ) )
			return( status );
		actionListPtr->iExtraData = createInfo.cryptHandle;
		}

	/* If there are no signed attributes, we're done */
	if( actionListPtr->iExtraData == CRYPT_ERROR )
		return( CRYPT_OK );

	/* Make sure that the content-type in the attributes matches the actual 
	   content type by deleting any existing content-type if necessary and 
	   adding our one (quietly fixing things is easier than trying to report 
	   this error back to the caller - ex duobus malis minimum eligendum 
	   est) */
	if( krnlSendMessage( actionListPtr->iExtraData, IMESSAGE_GETATTRIBUTE, 
						 &value, CRYPT_CERTINFO_CMS_CONTENTTYPE ) != CRYPT_ERROR_NOTFOUND )
		{
		/* We ignore the return status from the deletion since the status 
		   from the add that follows will be more meaningful to the caller */
		( void ) krnlSendMessage( actionListPtr->iExtraData, 
								  IMESSAGE_DELETEATTRIBUTE, NULL, 
								  CRYPT_CERTINFO_CMS_CONTENTTYPE );
		}
	return( krnlSendMessage( actionListPtr->iExtraData, 
							 IMESSAGE_SETATTRIBUTE, 
							 &envelopeInfoPtr->contentType, 
							 CRYPT_CERTINFO_CMS_CONTENTTYPE ) );
	}

/* Pre-process information for signed enveloping */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processSignatureAction( INOUT ENVELOPE_INFO *envelopeInfoPtr,
								   INOUT ACTION_LIST *actionListPtr )
	{
	CRYPT_ALGO_TYPE cryptAlgo = DUMMY_INIT;
	SIGPARAMS sigParams;
	int signatureSize, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isWritePtr( actionListPtr, sizeof( ACTION_LIST ) ) );

	REQUIRES( actionListPtr->action == ACTION_SIGN && \
			  actionListPtr->associatedAction != NULL );

	/* Process signing certificates and fix up the content-type in the 
	   authenticated attributes if necessary */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
		envelopeInfoPtr->type == CRYPT_FORMAT_SMIME )
		{
		status = processSigningCerts( envelopeInfoPtr, actionListPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Set up any necessary signature parameters such as signature 
	  attributes and timestamps if necessary */
	status = cmsInitSigParams( actionListPtr, envelopeInfoPtr->type, 
							   envelopeInfoPtr->ownerHandle, 
							   &sigParams );
	if( cryptStatusError( status ) )
		return( status );

	/* Evaluate the size of the exported action */
	status = iCryptCreateSignature( NULL, 0, &signatureSize, 
						envelopeInfoPtr->type, actionListPtr->iCryptHandle,
						actionListPtr->associatedAction->iCryptHandle,
						( envelopeInfoPtr->type == CRYPT_FORMAT_CRYPTLIB ) ? \
							NULL : &sigParams );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( actionListPtr->iCryptHandle,
								  IMESSAGE_GETATTRIBUTE, &cryptAlgo,
								  CRYPT_CTXINFO_ALGO );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( isDlpAlgo( cryptAlgo ) || isEccAlgo( cryptAlgo ) || \
		actionListPtr->iTspSession != CRYPT_ERROR )
		{
		/* If there are any signature actions that will result in indefinite-
		   length encodings present then we can't use a definite-length 
		   encoding for the signature */
		envelopeInfoPtr->dataFlags |= ENVDATA_HASINDEFTRAILER;
		actionListPtr->encodedSize = CRYPT_UNUSED;
		}
	else
		{
		actionListPtr->encodedSize = signatureSize;
		envelopeInfoPtr->signActionSize += signatureSize;
		}
	if( envelopeInfoPtr->dataFlags & ENVDATA_HASINDEFTRAILER )
		envelopeInfoPtr->signActionSize = CRYPT_UNUSED;
	ENSURES( ( envelopeInfoPtr->signActionSize == CRYPT_UNUSED ) || \
			 ( envelopeInfoPtr->signActionSize > 0 && \
			   envelopeInfoPtr->signActionSize < MAX_INTLENGTH ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int cmsPreEnvelopeSign( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr = envelopeInfoPtr->postActionList;
	int iterationCount, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( envelopeInfoPtr->usage == ACTION_SIGN );

	/* Make sure that there's at least one signing action present */
	if( actionListPtr == NULL )
		return( CRYPT_ERROR_NOTINITED );

	assert( isWritePtr( actionListPtr, sizeof( ACTION_LIST ) ) );

	REQUIRES( actionListPtr->associatedAction != NULL );

	/* If we're generating a detached signature the content is supplied
	   externally and has zero size */
	if( envelopeInfoPtr->flags & ENVELOPE_DETACHED_SIG )
		envelopeInfoPtr->payloadSize = 0;

	/* If it's an attributes-only message it must be zero-length CMS signed
	   data with signing attributes present */
	if( envelopeInfoPtr->flags & ENVELOPE_ATTRONLY )
		{
		if( envelopeInfoPtr->type != CRYPT_FORMAT_CMS || \
			actionListPtr->iExtraData == CRYPT_ERROR )
			{
			setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_SIGNATURE_EXTRADATA,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		if( envelopeInfoPtr->payloadSize > 0 )
			{
			setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_DATASIZE,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ERROR_INITED );
			}
		}

	/* If it's a CMS envelope we have to write the signing certificate chain
	   alongside the signatures as extra data unless it's explicitly 
	   excluded so we record how large the info will be for later */
	if( ( envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
		  envelopeInfoPtr->type == CRYPT_FORMAT_SMIME ) && \
		!( envelopeInfoPtr->flags & ENVELOPE_NOSIGNINGCERTS ) )
		{
		if( actionListPtr->next != NULL )
			{
			MESSAGE_CREATEOBJECT_INFO createInfo;

			/* There are multiple sets of signing certificates present, 
			   create a signing-certificate meta-object to hold the overall 
			   set of certificates */
			setMessageCreateObjectInfo( &createInfo,
										CRYPT_CERTTYPE_CERTCHAIN );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_DEV_CREATEOBJECT,
									  &createInfo, OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );
			envelopeInfoPtr->iExtraCertChain = createInfo.cryptHandle;
			}
		else
			{
			MESSAGE_DATA msgData;

			/* There's a single signing certificate present, determine its 
			   size */
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( actionListPtr->iCryptHandle,
									  IMESSAGE_CRT_EXPORT, &msgData,
									  CRYPT_ICERTFORMAT_CERTSET );
			if( cryptStatusError( status ) )
				return( status );
			envelopeInfoPtr->extraDataSize = msgData.length;
			}
		}

	/* Evaluate the size of each signature action */
	for( actionListPtr = envelopeInfoPtr->postActionList, iterationCount = 0; 
		 actionListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED;
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		status = processSignatureAction( envelopeInfoPtr, actionListPtr );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );
	if( envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR )
		{
		MESSAGE_DATA msgData;

		/* We're writing the signing certificate chain and there are 
		   multiple signing certificates present, get the size of the 
		   overall certificate collection */
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( envelopeInfoPtr->iExtraCertChain,
								  IMESSAGE_CRT_EXPORT, &msgData,
								  CRYPT_ICERTFORMAT_CERTSET );
		if( cryptStatusError( status ) )
			return( status );
		envelopeInfoPtr->extraDataSize = msgData.length;
		}
	ENSURES( envelopeInfoPtr->extraDataSize >= 0 && \
			 envelopeInfoPtr->extraDataSize < MAX_INTLENGTH );

	/* Hashing is now active (you have no chance to survive make your 
	   time) */
	envelopeInfoPtr->dataFlags |= ENVDATA_HASHACTIONSACTIVE;

	return( CRYPT_OK );
	}
#endif /* USE_ENVELOPES */
