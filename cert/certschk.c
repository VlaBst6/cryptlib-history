/****************************************************************************
*																			*
*					Certificate Signature Checking Routines					*
*						Copyright Peter Gutmann 1997-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Generate a nameID or issuerID.  These are needed when storing/retrieving a
   certificate to/from an database keyset, which can't handle the awkward
   heirarchical IDs usually used in certificates.  There are two types of 
   IDs, the nameID which is an SHA-1 hash of the DN and is used for 
   certificates, and the issuerID which is an SHA-1 hash of the 
   IssuerAndSerialNumber and is used for CRLs and CMS */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int generateCertID( IN_BUFFER( dnLength ) const void *dn, 
						   IN_LENGTH_SHORT const int dnLength,
						   IN_BUFFER_OPT( serialNumberLength ) \
								const void *serialNumber,
						   IN_LENGTH_SHORT_Z const int serialNumberLength, 
						   OUT_BUFFER( certIdMaxLength, KEYID_SIZE ) \
								BYTE *certID, 
						   IN_LENGTH_SHORT_MIN( KEYID_SIZE ) \
								const int certIdMaxLength )
	{
	HASHFUNCTION_ATOMIC hashFunctionAtomic;
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo;
	STREAM stream;
	BYTE buffer[ MAX_SERIALNO_SIZE + 8 + 8 ];
	int status;

	assert( isReadPtr( dn, dnLength ) );
	assert( ( serialNumber == NULL && serialNumberLength == 0 ) || \
			( isReadPtr( serialNumber, serialNumberLength ) && \
			  serialNumberLength <= MAX_SERIALNO_SIZE ) );
	assert( isWritePtr( certID, certIdMaxLength ) );

	REQUIRES( ( serialNumber == NULL && serialNumberLength == 0 ) || \
			  ( serialNumber != NULL && \
			    serialNumberLength > 0 && \
				serialNumberLength <= MAX_SERIALNO_SIZE ) );
	REQUIRES( certIdMaxLength >= KEYID_SIZE && \
			  certIdMaxLength < MAX_INTLENGTH_SHORT );

	/* Clear return value */
	memset( certID, 0, min( 16, certIdMaxLength ) );

	/* Get the hash algorithm information */
	getHashAtomicParameters( CRYPT_ALGO_SHA1, &hashFunctionAtomic, NULL );
	getHashParameters( CRYPT_ALGO_SHA1, &hashFunction, NULL );

	/* If it's a pure DN hash we don't have to perform any encoding */
	if( serialNumber == NULL )
		{
		hashFunctionAtomic( certID, certIdMaxLength, dn, dnLength );

		return( CRYPT_OK );
		}

	/* Write the relevant information to a buffer and hash the data to get
	   the ID */
	sMemOpen( &stream, buffer, MAX_SERIALNO_SIZE + 8 );
	status = writeSequence( &stream, 
							dnLength + sizeofInteger( serialNumber, \
													  serialNumberLength ) );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}
	hashFunction( hashInfo, NULL, 0, buffer, stell( &stream ), 
				  HASH_STATE_START );
	hashFunction( hashInfo, NULL, 0, dn, dnLength, HASH_STATE_CONTINUE );
	sseek( &stream, 0 );
	status = writeInteger( &stream, serialNumber, serialNumberLength,
						   DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		hashFunction( hashInfo, certID, certIdMaxLength, buffer, 
					  stell( &stream ), HASH_STATE_END );
		}
	sMemClose( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*							Validity/Revocation Checking 					*
*																			*
****************************************************************************/

/* Check the entries in an RTCS or OCSP response object against a 
   certificate store.  The semantics for this one are a bit odd, the source 
   information for the check is from a request but the destination 
   information is in a response.  Since we don't have a copy-and-verify 
   function we do the checking from the response even though technically 
   it's the request data that's being checked */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkRTCSResponse( INOUT CERT_INFO *certInfoPtr,
							  IN_HANDLE const CRYPT_KEYSET iCryptKeyset )
	{
	VALIDITY_INFO *validityInfo;
	BOOLEAN isInvalid = FALSE;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptKeyset ) );

	/* Walk down the list of validity entries fetching status information
	   on each one from the certificate store */
	for( validityInfo = certInfoPtr->cCertVal->validityInfo;
		 validityInfo != NULL; validityInfo = validityInfo->next )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		int status;

		/* Determine the validity of the object */
		setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_CERTID,
							   validityInfo->data, KEYID_SIZE, NULL, 0,
							   KEYMGMT_FLAG_CHECK_ONLY );
		status = krnlSendMessage( iCryptKeyset, IMESSAGE_KEY_GETKEY,
								  &getkeyInfo, KEYMGMT_ITEM_PUBLICKEY );
		if( cryptStatusOK( status ) )
			{
			/* The certificate is present and OK, we're done */
			validityInfo->status = TRUE;
			validityInfo->extStatus = CRYPT_CERTSTATUS_VALID;
			}
		else
			{
			/* The certificate isn't present/OK, record the fact that we've 
			   seen at least one invalid certificate */
			validityInfo->status = FALSE;
			validityInfo->extStatus = CRYPT_CERTSTATUS_NOTVALID;
			isInvalid = TRUE;
			}
		}

	/* If at least one certificate was invalid indicate this to the caller.  
	   Note that if there are multiple certificates present in the query 
	   it's up to the caller to step through the list to find out which ones 
	   were invalid */
	return( isInvalid ? CRYPT_ERROR_INVALID : CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkOCSPResponse( INOUT CERT_INFO *certInfoPtr,
					   IN_HANDLE const CRYPT_KEYSET iCryptKeyset )
	{
	REVOCATION_INFO *revocationInfo;
	BOOLEAN isRevoked = FALSE;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptKeyset ) );

	/* Walk down the list of revocation entries fetching status information
	   on each one from the certificate store */
	for( revocationInfo = certInfoPtr->cCertRev->revocations;
		 revocationInfo != NULL; revocationInfo = revocationInfo->next )
		{
		CRYPT_KEYID_TYPE idType = revocationInfo->idType;
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		CERT_INFO *crlEntryInfoPtr;
		REVOCATION_INFO *crlRevocationInfo;
		const BYTE *idPtr = revocationInfo->idPtr;
		int status;

		ENSURES( revocationInfo->idType == CRYPT_KEYID_NONE || \
				 revocationInfo->idType == CRYPT_IKEYID_CERTID || \
				 revocationInfo->idType == CRYPT_IKEYID_ISSUERID );

		/* If it's an OCSPv1 ID and there's no alternate ID information 
		   present we can't really do anything with it because the one-way 
		   hashing process required by the standard destroys the certificate
		   identifying information */
		if( idType == CRYPT_KEYID_NONE )
			{
			if( revocationInfo->altIdType == CRYPT_KEYID_NONE )
				{
				revocationInfo->status = CRYPT_OCSPSTATUS_UNKNOWN;
				continue;
				}

			/* There's an alternate ID present, use that instead */
			idType = revocationInfo->altIdType;
			idPtr = revocationInfo->altID;
			}

		/* Determine the revocation status of the object.  Unfortunately
		   because of the way OCSP returns status information we can't just
		   return a yes/no response but have to perform multiple queries to
		   determine whether a certificate is not revoked, revoked, or 
		   unknown.  Optimising the query strategy is complicated by the 
		   fact that although in theory the most common status will be 
		   not-revoked we could also get a large number of status-unknown 
		   queries, for example if a widely-deployed implementation which is 
		   pointed at a cryptlib-based server gets its ID-hashing wrong and 
		   submits huge numbers of queries with IDs that match no known 
		   certificate.  The best we can do is assume that a not-revoked 
		   status will be the most common and if that fails fall back to a 
		   revoked status check */
		setMessageKeymgmtInfo( &getkeyInfo, idType, idPtr, KEYID_SIZE, 
							   NULL, 0, KEYMGMT_FLAG_CHECK_ONLY );
		status = krnlSendMessage( iCryptKeyset, IMESSAGE_KEY_GETKEY,
								  &getkeyInfo, KEYMGMT_ITEM_PUBLICKEY );
		if( cryptStatusOK( status ) )
			{
			/* The certificate is present and not revoked/OK, we're done */
			revocationInfo->status = CRYPT_OCSPSTATUS_NOTREVOKED;
			continue;
			}

		/* The certificate isn't a currently active cert, if it weren't for 
		   the need to return the CRL-based OCSP status values we could just 
		   return not-OK now but as it is we have to differentiate between 
		   revoked and unknown so we perform a second query, this time of 
		   the revocation information */
		setMessageKeymgmtInfo( &getkeyInfo, idType, idPtr, KEYID_SIZE, 
							   NULL, 0, KEYMGMT_FLAG_NONE );
		status = krnlSendMessage( iCryptKeyset, IMESSAGE_KEY_GETKEY,
								  &getkeyInfo, KEYMGMT_ITEM_REVOCATIONINFO );
		if( cryptStatusError( status ) )
			{
			/* No revocation information found, status is unknown */
			revocationInfo->status = CRYPT_OCSPSTATUS_UNKNOWN;
			continue;
			}

		/* The certificate has been revoked, copy the revocation information 
		   across from the CRL entry */
		status = krnlAcquireObject( getkeyInfo.cryptHandle,
									OBJECT_TYPE_CERTIFICATE,
									( void ** ) &crlEntryInfoPtr,
									CRYPT_ERROR_SIGNALLED );
		if( cryptStatusError( status ) )
			return( status );
		crlRevocationInfo = crlEntryInfoPtr->cCertRev->revocations;
		if( crlRevocationInfo != NULL )
			{
			revocationInfo->revocationTime = \
									crlRevocationInfo->revocationTime;
			if( crlRevocationInfo->attributes != NULL )
				{
				/* We don't check for problems in copying the attributes 
				   since bailing out at this late stage is worse than 
				   missing a few obscure annotations to the revocation */
				( void ) copyRevocationAttributes( &revocationInfo->attributes,
												   crlRevocationInfo->attributes );
				}
			}
		krnlReleaseObject( crlEntryInfoPtr->objectHandle );
		krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );

		/* Record the fact that we've seen at least one revoked certificate */
		revocationInfo->status = CRYPT_OCSPSTATUS_REVOKED;
		isRevoked = TRUE;
		}

	/* If at least one certificate was revoked indicate this to the caller.  
	   Note that if there are multiple certificates present in the query then 
	   it's up to the caller to step through the list to find out which ones 
	   were revoked */
	return( isRevoked ? CRYPT_ERROR_INVALID : CRYPT_OK );
	}

/* Check a certificate using an RTCS or OCSP responder */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkResponder( INOUT CERT_INFO *certInfoPtr,
						   IN_HANDLE const CRYPT_SESSION iCryptSession )
	{
	CRYPT_CERTIFICATE cryptResponse = DUMMY_INIT;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int type, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptSession) );

	status = krnlSendMessage( iCryptSession, IMESSAGE_GETATTRIBUTE, &type,
							  CRYPT_IATTRIBUTE_SUBTYPE );
	if( cryptStatusError( status ) )
		return( status );

	ENSURES( ( type == SUBTYPE_SESSION_RTCS ) || \
			 ( type == SUBTYPE_SESSION_OCSP ) );

	/* Create the request, add the certificate, and add the request to the
	   session */
	setMessageCreateObjectInfo( &createInfo,
							    ( type == SUBTYPE_SESSION_RTCS ) ? \
									CRYPT_CERTTYPE_RTCS_REQUEST : \
									CRYPT_CERTTYPE_OCSP_REQUEST );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					&certInfoPtr->objectHandle, CRYPT_CERTINFO_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptSession, IMESSAGE_SETATTRIBUTE,
					&createInfo.cryptHandle, CRYPT_SESSINFO_REQUEST );
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Activate the session and get the response info */
	status = krnlSendMessage( iCryptSession, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_SESSINFO_ACTIVE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptSession, IMESSAGE_GETATTRIBUTE,
								  &cryptResponse, CRYPT_SESSINFO_RESPONSE );
	if( cryptStatusError( status ) )
		return( status );
	if( type == SUBTYPE_SESSION_RTCS )
		{
		int certStatus;

		status = krnlSendMessage( cryptResponse, IMESSAGE_GETATTRIBUTE,
								  &certStatus, CRYPT_CERTINFO_CERTSTATUS );
		if( cryptStatusOK( status ) && \
			( certStatus != CRYPT_CERTSTATUS_VALID ) )
			status = CRYPT_ERROR_INVALID;
		}
	else
		{
		int revocationStatus;

		status = krnlSendMessage( cryptResponse, IMESSAGE_GETATTRIBUTE,
								  &revocationStatus,
								  CRYPT_CERTINFO_REVOCATIONSTATUS );
		if( cryptStatusOK( status ) && \
			( revocationStatus != CRYPT_OCSPSTATUS_NOTREVOKED ) )
			status = CRYPT_ERROR_INVALID;
		}
	krnlSendNotifier( cryptResponse, IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Check a certificate against a CRL */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkCRL( INOUT CERT_INFO *certInfoPtr, 
					 IN_HANDLE const CRYPT_CERTIFICATE iCryptCRL )
	{
	CERT_INFO *crlInfoPtr;
	int i, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptCRL ) );

	/* Check that the CRL is a complete signed CRL and not a newly-created
	   CRL object */
	status = krnlAcquireObject( iCryptCRL, OBJECT_TYPE_CERTIFICATE,
								( void ** ) &crlInfoPtr,
								CRYPT_ARGERROR_VALUE );
	if( cryptStatusError( status ) )
		return( status );
	if( crlInfoPtr->certificate == NULL )
		{
		krnlReleaseObject( crlInfoPtr->objectHandle );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Check the base certificate against the CRL.  If it's been revoked or 
	   there's only a single certificate present, exit */
	status = checkRevocation( certInfoPtr, crlInfoPtr );
	if( cryptStatusError( status ) || \
		certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN )
		{
		krnlReleaseObject( crlInfoPtr->objectHandle );
		return( status );
		}

	/* It's a certificate chain, check every remaining certificate in the 
	   chain against the CRL.  In theory this is pointless because a CRL can 
	   only contain information for a single certificate in the chain, 
	   however the caller may have passed us a CRL for an intermediate 
	   certificate (in which case the check for the leaf certificate was 
	   pointless).  In any case it's easier to just do the check for all 
	   certificates than to determine which certificate the CRL applies to 
	   so we check for all certificates */
	for( i = 0; i < certInfoPtr->cCertCert->chainEnd && \
				i < MAX_CHAINLENGTH; i++ )
		{
		CERT_INFO *certChainInfoPtr;

		/* Check this certificate against the CRL */
		status = krnlAcquireObject( certInfoPtr->cCertCert->chain[ i ],
									OBJECT_TYPE_CERTIFICATE,
									( void ** ) &certChainInfoPtr,
									CRYPT_ERROR_SIGNALLED );
		if( cryptStatusOK( status ) )
			{
			status = checkRevocation( certChainInfoPtr, crlInfoPtr );
			krnlReleaseObject( certChainInfoPtr->objectHandle );
			}

		/* If the certificate has been revoked remember which one is the 
		   revoked certificate and exit */
		if( cryptStatusError( status ) )
			{
			certInfoPtr->cCertCert->chainPos = i;
			break;
			}
		}
	ENSURES( i < MAX_CHAINLENGTH );

	krnlReleaseObject( crlInfoPtr->objectHandle );
	return( status );
	}

/****************************************************************************
*																			*
*							Signature Checking Functions					*
*																			*
****************************************************************************/

/* Check a certificate against an issuer certificate.  The trustAnchorCheck 
   flag is used when we're checking an explicit trust anchor, for which we
   only need to check the signature if it's self-signed.  The 
   shortCircuitCheck flag is used when checking subject:issuer pairs inside 
   certificate chains, which have already been checked by the chain-handling 
   code so a full (re-)check isn't necessary any more */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 7, 8 ) ) \
int checkCertDetails( INOUT CERT_INFO *subjectCertInfoPtr,
					  INOUT_OPT CERT_INFO *issuerCertInfoPtr,
					  IN_HANDLE_OPT const CRYPT_CONTEXT iIssuerPubKey,
					  IN_OPT const X509SIG_FORMATINFO *formatInfo,
					  const BOOLEAN trustAnchorCheck,
					  const BOOLEAN shortCircuitCheck,
					  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						CRYPT_ATTRIBUTE_TYPE *errorLocus,
					  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
						CRYPT_ERRTYPE_TYPE *errorType )
	{
	int status;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL || \
			isWritePtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( formatInfo == NULL || \
			isReadPtr( formatInfo, sizeof( X509SIG_FORMATINFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( iIssuerPubKey == CRYPT_UNUSED || \
			  isHandleRangeValid( iIssuerPubKey ) );

	/* If there's an issuer certificate present check the validity of the
	   subject certificate based on it.  If it's not present all that we can 
	   do is perform a pure signature check with the context */
	if( issuerCertInfoPtr != NULL )
		{
		status = checkCert( subjectCertInfoPtr, issuerCertInfoPtr, 
							shortCircuitCheck, errorLocus, errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If the signature has already been checked or there's no signature-
	   check key present we're done.  The latter can occur when we're
	   checking a data-only certificate in a cert chain chain.  This is safe 
	   because these certificates can only occur when we're reading them 
	   from an (implicitly trusted) private key store */
	if( ( subjectCertInfoPtr->flags & CERT_FLAG_SIGCHECKED ) || \
		iIssuerPubKey == CRYPT_UNUSED )
		return( CRYPT_OK );

	/* If we're checking an explicit trust anchor and the certificate isn't 
	   self-signed there's nothing further left to check */
	if( trustAnchorCheck && issuerCertInfoPtr != NULL && \
		!( issuerCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) )
		return( CRYPT_OK );

	/* If we're performing a standard check and it's an explicitly-trusted 
	   certificate we're done.  If we're performing a check of a certificate 
	   chain then the chain-handling code will have performed its own 
	   handling of trusted certificates/trust anchors so we don't peform a 
	   second check here */
	if( !shortCircuitCheck )
		{
		if( cryptStatusOK( \
				krnlSendMessage( subjectCertInfoPtr->ownerHandle, 
								 IMESSAGE_USER_TRUSTMGMT,
								 &subjectCertInfoPtr->objectHandle,
								 MESSAGE_TRUSTMGMT_CHECK ) ) )
			return( CRYPT_OK );
		}

	/* Check the signature on the certificate.  If there's a problem with 
	   the issuer's public key it'll be reported as a CRYPT_ARGERROR_NUM1,
	   which the caller has to convert into an appropriate error code */
	status = checkX509signature( subjectCertInfoPtr->certificate, 
								 subjectCertInfoPtr->certificateSize,
								 iIssuerPubKey, formatInfo );
	if( cryptStatusError( status ) )
		{
		MESSAGE_DATA msgData;
		BYTE subjectIssuerID[ CRYPT_MAX_HASHSIZE + 8 ];
		BYTE issuerSubjectID[ CRYPT_MAX_HASHSIZE + 8 ];
		int subjectIDlength, issuerIDlength;

		/* There's on special-case situation in which we can get a 
		   signature-check failure that looks like data corruption and 
		   that's when a CA quietly changes its issuing key without changing 
		   anything else so the certificates chain but the signature check 
		   produces garbage as output due to the use of the incorrect key.  
		   Although it could be argued that a CA that does this is broken, 
		   we try and accomodate it by performing a backup check using 
		   keyIDs if the signature check produces garbled output.  Because 
		   of the complete chaos present in keyIDs we can't do this by 
		   default (it would result in far too many false positives) but 
		   it's safe as a fallback at this point since we're about to report 
		   an error anyway and the worst that can happen is that we return 
		   a slightly inappropriate error message.
		   
		   If there's no issuer certificate provided we also have to exit at 
		   this point because we can't go any further without it */
		if( status != CRYPT_ERROR_BADDATA || issuerCertInfoPtr == NULL )
			return( status );

		/* Get the subject certificate's issuerID and the issuer cert's 
		   subjectID.  We don't bother with the alternative awkward 
		   DN-based ID since what we're really interested in is the ID of 
		   the signing key and it's not worth the extra pain of dealing with 
		   these awkward cert IDs just to try and fix up a slight difference 
		   in error codes */
		setMessageData( &msgData, subjectIssuerID, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( subjectCertInfoPtr->objectHandle, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_BADDATA );
		issuerIDlength = msgData.length;
		setMessageData( &msgData, issuerSubjectID, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( issuerCertInfoPtr->objectHandle, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_BADDATA );
		subjectIDlength = msgData.length;

		/* If the keyIDs don't match then it's a signature error due to 
		   false-positive chaining rather than a data corruption error */
		return( ( ( issuerIDlength != subjectIDlength ) || \
				  memcmp( subjectIssuerID, issuerSubjectID, \
						  issuerIDlength ) ) ? \
				CRYPT_ERROR_SIGNATURE : CRYPT_ERROR_BADDATA );
		}

	/* The signature is OK, we don't need to check it again.  There is a
	   theoretical situation in which this can lead to a false positive
	   which requires first checking the certificate using the correct 
	   issuing CA (which will set the CERT_FLAG_SIGCHECKED flag) and then 
	   checking it again using a second CA cert identical to the first but 
	   with a different key.  In other words the issuer DN chains correctly 
	   but the issuer key is different.  The appropriate behaviour here is 
	   somewhat unclear.  It could be argued that a CA that uses two
	   otherwise identical certificates but with different keys is broken 
	   and therefore behaviour in this situation is undefined.  However we 
	   need to do something with the resulting check and returning the 
	   result of the check with the correct CA certificate even if we're 
	   later passed a second incorrect certificate from the CA seems to be 
	   the most appropriate action since it has in the past been validated 
	   by a certificate from the same CA.  If we want to force the check to 
	   be done with a specific CA key (rather than just the issuing CA's 
	   certificate in general) we could store the fingerprint of the 
	   signing key alongside the CERT_FLAG_SIGCHECKED flag */
	subjectCertInfoPtr->flags |= CERT_FLAG_SIGCHECKED;
	
	return( CRYPT_OK );
	}

/* Check a self-signed certificate object like a cert request or a 
   self-signed certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkSelfSignedCert( INOUT CERT_INFO *certInfoPtr,
								IN_OPT const X509SIG_FORMATINFO *formatInfo )
	{
	CRYPT_CONTEXT iCryptContext = CRYPT_UNUSED;
	CERT_INFO *issuerCertInfoPtr;
	BOOLEAN trustedCertAcquired = FALSE;
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( formatInfo == NULL || \
			isReadPtr( formatInfo, sizeof( X509SIG_FORMATINFO ) ) );

	/* Since there's no signer certificate provided it has to be either 
	   explicitly self-signed or signed by a trusted certificate */
	if( certInfoPtr->flags & CERT_FLAG_SELFSIGNED )
		{
		if( certInfoPtr->iPubkeyContext != CRYPT_ERROR )
			iCryptContext = certInfoPtr->iPubkeyContext;
		issuerCertInfoPtr = certInfoPtr;
		}
	else
		{
		CRYPT_CERTIFICATE iCryptCert = certInfoPtr->objectHandle;

		/* If it's a certificate it may be implicitly trusted */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
			{
			if( cryptStatusOK( \
					krnlSendMessage( certInfoPtr->ownerHandle,
									 IMESSAGE_USER_TRUSTMGMT, &iCryptCert,
									 MESSAGE_TRUSTMGMT_CHECK ) ) )
				{
				/* The certificate is implicitly trusted, we're done */
				return( CRYPT_OK );
				}
			}

		/* If it's not self-signed it has to be signed by a trusted 
		   certificate try and get the trusted certificate */
		status = krnlSendMessage( certInfoPtr->ownerHandle,
								  IMESSAGE_USER_TRUSTMGMT, &iCryptCert,
								  MESSAGE_TRUSTMGMT_GETISSUER );
		if( cryptStatusError( status ) )
			{
			/* There's no trusted signer present indicate that we need
			   something to check the certificate with */
			return( CRYPT_ARGERROR_VALUE );
			}
		status = krnlAcquireObject( iCryptCert, OBJECT_TYPE_CERTIFICATE,
									( void ** ) &issuerCertInfoPtr,
									CRYPT_ERROR_SIGNALLED );
		if( cryptStatusError( status ) )
			return( status );
		iCryptContext = iCryptCert;
		trustedCertAcquired = TRUE;
		}

	/* Check the certificate against the issuing certificate */
	status = checkCertDetails( certInfoPtr, issuerCertInfoPtr, 
							   iCryptContext, formatInfo, FALSE, FALSE,
							   &certInfoPtr->errorLocus, 
							   &certInfoPtr->errorType );
	if( trustedCertAcquired )
		krnlReleaseObject( issuerCertInfoPtr->objectHandle );
	return( cryptArgError( status ) ? CRYPT_ARGERROR_OBJECT : status );
	}

/* Check the validity of a certificate object, either against an issuing 
   key/certificate or against a CRL */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkCertValidity( INOUT CERT_INFO *certInfoPtr, 
					   IN_HANDLE_OPT const CRYPT_HANDLE iSigCheckObject )
	{
	CRYPT_CONTEXT iCryptContext;
	CRYPT_CERTTYPE_TYPE sigCheckKeyType = CRYPT_CERTTYPE_NONE;
	CERT_INFO *issuerCertInfoPtr = NULL;
	OBJECT_TYPE type;
	X509SIG_FORMATINFO formatInfo, *formatInfoPtr = NULL;
	BOOLEAN issuerCertAcquired = FALSE;
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( certInfoPtr->certificate != NULL || \
			  certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE );
	REQUIRES( iSigCheckObject == CRYPT_UNUSED || \
			  isHandleRangeValid( iSigCheckObject ) );

	/* CRMF and OCSP use a b0rken signature format (the authors couldn't 
	   quite manage a cut & paste of two lines of text) so if it's one of 
	   these we have to use nonstandard formatting */
	if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
		{
		/* [1] SEQUENCE */
		setX509FormatInfo( &formatInfo, 1, FALSE );
		formatInfoPtr = &formatInfo;
		}
	else
		{
		if( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST ) 
			{
			/* [0] EXPLICIT SEQUENCE */
			setX509FormatInfo( &formatInfo, 0, TRUE );
			formatInfoPtr = &formatInfo;
			}
		}

	/* If there's no signature checking key supplied the certificate must 
	   be self-signed, either an implicitly self-signed object like a 
	   certificate chain or an explicitly self-signed object like a 
	   certificate request or self-signed certificate */
	if( iSigCheckObject == CRYPT_UNUSED )
		{
		/* If it's a certificate chain it's a (complex) self-signed object 
		   containing more than one certificate so we need a special 
		   function to check the entire chain */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			return( checkCertChain( certInfoPtr ) );

		/* It's an explicitly self-signed object */
		return( checkSelfSignedCert( certInfoPtr, formatInfoPtr ) );
		}

	/* Find out what the signature check object is */
	status = krnlSendMessage( iSigCheckObject, IMESSAGE_GETATTRIBUTE, &type,
							  CRYPT_IATTRIBUTE_TYPE );
	if( cryptStatusOK( status ) && type == OBJECT_TYPE_CERTIFICATE )
		{
		status = krnlSendMessage( iSigCheckObject, IMESSAGE_GETATTRIBUTE,
								  &sigCheckKeyType, 
								  CRYPT_CERTINFO_CERTTYPE );
		}
	if( cryptStatusError( status ) )
		return( cryptArgError( status ) ? CRYPT_ARGERROR_VALUE : status );

	/* Perform a general validity check on the object being checked and the
	   associated verification object.  This is somewhat more strict than
	   the kernel checks since the kernel only knows about valid subtypes
	   but not that some subtypes are only valid in combination with some
	   types of object being checked */
	switch( type )
		{
		case OBJECT_TYPE_CERTIFICATE:
		case OBJECT_TYPE_CONTEXT:
			break;

		case OBJECT_TYPE_KEYSET:
			/* A keyset can only be used as a source of revocation
			   information for checking a certificate or to populate the
			   status fields of an RTCS/OCSP response */
			if( certInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
				certInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT && \
				certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN && \
				certInfoPtr->type != CRYPT_CERTTYPE_RTCS_RESPONSE && \
				certInfoPtr->type != CRYPT_CERTTYPE_OCSP_RESPONSE )
				return( CRYPT_ARGERROR_VALUE );
			break;

		case OBJECT_TYPE_SESSION:
			/* An (RTCS or OCSP) session can only be used as a source of
			   validity/revocation information for checking a certificate */
			if( certInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
				certInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT && \
				certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN )
				return( CRYPT_ARGERROR_VALUE );
			break;

		default:
			return( CRYPT_ARGERROR_VALUE );
		}

	/* If the checking key is a CRL, a keyset that may contain a CRL, or an
	   RTCS or OCSP session then this is a validity/revocation check that 
	   works rather differently from a straight signature check */
	if( type == OBJECT_TYPE_CERTIFICATE && \
		sigCheckKeyType == CRYPT_CERTTYPE_CRL )
		return( checkCRL( certInfoPtr, iSigCheckObject ) );
	if( type == OBJECT_TYPE_KEYSET )
		{
		BYTE issuerID[ CRYPT_MAX_HASHSIZE + 8 ];

		/* If it's an RTCS or OCSP response use the certificate store to fill
		   in the status information fields */
		if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
			return( checkRTCSResponse( certInfoPtr, iSigCheckObject ) );
		if( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE )
			return( checkOCSPResponse( certInfoPtr, iSigCheckObject ) );

		ENSURES( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
				 certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
				 certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );

		/* Generate the issuerID for this certificate and check whether it's 
		   present in the CRL.  Since all we're interested in is a yes/no 
		   answer we tell the keyset to perform a check only */
		status = generateCertID( certInfoPtr->issuerDNptr,
								 certInfoPtr->issuerDNsize,
								 certInfoPtr->cCertCert->serialNumber,
								 certInfoPtr->cCertCert->serialNumberLength,
								 issuerID, CRYPT_MAX_HASHSIZE );
		if( cryptStatusOK( status ) )
			{
			MESSAGE_KEYMGMT_INFO getkeyInfo;

			setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_ISSUERID,
								   issuerID, KEYID_SIZE, NULL, 0,
								   KEYMGMT_FLAG_CHECK_ONLY );
			status = krnlSendMessage( iSigCheckObject, IMESSAGE_KEY_GETKEY,
									  &getkeyInfo,
									  KEYMGMT_ITEM_REVOCATIONINFO );

			/* Reverse the results of the check: OK -> certificate revoked,
			   not found -> certificate not revoked */
			if( cryptStatusOK( status ) )
				status = CRYPT_ERROR_INVALID;
			else
				{
				if( status == CRYPT_ERROR_NOTFOUND )
					status = CRYPT_OK;
				}
			}

		return( status );
		}
	if( type == OBJECT_TYPE_SESSION )
		return( checkResponder( certInfoPtr, iSigCheckObject ) );

	/* If we've been given a self-signed certificate make sure that the 
	   signature check key is the same as the certificate.  To test this we 
	   have to compare both the signing key and if the signature check 
	   object is a certificate, the certificate */
	if( certInfoPtr->flags & CERT_FLAG_SELFSIGNED )
		{
		MESSAGE_DATA msgData;
		BYTE keyID[ KEYID_SIZE + 8 ];

		/* Check that the key in the certificate and the key in the 
		   signature check object are identical */
		setMessageData( &msgData, keyID, KEYID_SIZE );
		status = krnlSendMessage( iSigCheckObject, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( certInfoPtr->objectHandle,
									  IMESSAGE_COMPARE, &msgData,
									  MESSAGE_COMPARE_KEYID );
		if( cryptStatusError( status ) )
			return( CRYPT_ARGERROR_VALUE );

		/* If the signature check object is a certificate (even though 
		   what's being checked is already a self-signed certificate) check 
		   that it's identical to the certificate being checked (which it 
		   must be if the certificate is self-signed).  This may be somewhat 
		   stricter than required but it'll weed out technically valid but 
		   questionable combinations like a certificate request being used 
		   to validate a certificate and misleading ones such as one 
		   certificate chain being used to check a second chain */
		if( type == OBJECT_TYPE_CERTIFICATE )
			{
			status = krnlSendMessage( certInfoPtr->objectHandle,
									  IMESSAGE_COMPARE, 
									  ( void * ) &iSigCheckObject,
									  MESSAGE_COMPARE_CERTOBJ );
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_VALUE );
			}

		/* If it's a certificate chain it's a (complex) self-signed object
		   containing more than one certificate so we need a special 
		   function to check the entire chain */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			return( checkCertChain( certInfoPtr ) );

		return( checkSelfSignedCert( certInfoPtr, formatInfoPtr ) );
		}

	/* The signature check key may be a certificate or a context.  If it's
	   a certificate we get the issuer certificate info and extract the 
	   context from it before continuing */
	if( type == OBJECT_TYPE_CERTIFICATE )
		{
		/* Get the context from the issuer certificate */
		status = krnlSendMessage( iSigCheckObject, IMESSAGE_GETDEPENDENT,
								  &iCryptContext, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( cryptArgError( status ) ? CRYPT_ARGERROR_VALUE : status );

		/* Get the issuer certificate info */
		status = krnlAcquireObject( iSigCheckObject, OBJECT_TYPE_CERTIFICATE,
									( void ** ) &issuerCertInfoPtr,
									CRYPT_ARGERROR_VALUE );
		if( cryptStatusError( status ) )
			return( status );
		issuerCertAcquired = TRUE;
		}
	else
		{
		CRYPT_CERTIFICATE localCert;

		iCryptContext = iSigCheckObject;

		/* It's a context, we may have a certificate present in it so we try
		   to extract that and use it as the issuer certificate if possible.
		   If the issuer certificate isn't present this isn't an error since 
		   it could be just a raw context */
		status = krnlSendMessage( iSigCheckObject, IMESSAGE_GETDEPENDENT,
								  &localCert, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusOK( status ) )
			status = krnlAcquireObject( localCert, OBJECT_TYPE_CERTIFICATE,
										( void ** ) &issuerCertInfoPtr,
										CRYPT_ARGERROR_VALUE );
		if( cryptStatusOK( status ) )
			issuerCertAcquired = TRUE;
		}

	/* Check the certificate against the issuing certificate */
	status = checkCertDetails( certInfoPtr, issuerCertAcquired ? \
									issuerCertInfoPtr : NULL, 
							   iCryptContext, formatInfoPtr, FALSE, FALSE,
							   &certInfoPtr->errorLocus, 
							   &certInfoPtr->errorType );
	if( issuerCertAcquired )
		krnlReleaseObject( issuerCertInfoPtr->objectHandle );
	return( cryptArgError( status ) ? CRYPT_ARGERROR_VALUE : status );
	}
