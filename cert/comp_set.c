/****************************************************************************
*																			*
*							Set Certificate Components						*
*						Copyright Peter Gutmann 1997-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "certattr.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Copy the encoded issuer DN */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyIssuerDnData( INOUT CERT_INFO *destCertInfoPtr,
							 const CERT_INFO *srcCertInfoPtr )
	{
	void *dnDataPtr;

	assert( isWritePtr( destCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( srcCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( srcCertInfoPtr->issuerDNptr != NULL );

	if( ( dnDataPtr = clAlloc( "copyIssuerDnData",
							   srcCertInfoPtr->issuerDNsize ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memcpy( dnDataPtr, srcCertInfoPtr->issuerDNptr,
			srcCertInfoPtr->issuerDNsize );
	destCertInfoPtr->issuerDNptr = destCertInfoPtr->issuerDNdata = dnDataPtr;
	destCertInfoPtr->issuerDNsize = srcCertInfoPtr->issuerDNsize;

	return( CRYPT_OK );
	}

/* Copy revocation information into a CRL or revocation request */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyRevocationInfo( INOUT CERT_INFO *certInfoPtr,
							   const CERT_INFO *revInfoPtr )
	{
	int status = CRYPT_OK;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( revInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
			  certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION );
	REQUIRES( revInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  revInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
			  revInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN || \
			  revInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION );

	/* If there's an issuer name recorded make sure that it matches the one
	   in the certificate that's being added */
	if( certInfoPtr->issuerDNptr != NULL )
		{
		if( certInfoPtr->issuerDNsize != revInfoPtr->issuerDNsize || \
			memcmp( certInfoPtr->issuerDNptr, revInfoPtr->issuerDNptr,
					certInfoPtr->issuerDNsize ) )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			status = CRYPT_ERROR_INVALID;
			}
		}
	else
		{
		/* There's no issuer name present yet, set the CRL issuer name to
		   the certificate's issuer to make sure that we can't add 
		   certificates or sign the CRL with a different issuer.  We do this 
		   here rather than after setting the revocation list entry because 
		   of the difficulty of undoing the revocation entry addition */
		status = copyIssuerDnData( certInfoPtr, revInfoPtr );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Add the certificate information to the revocation list and make it 
	   the currently selected entry.  The ID type isn't quite an
	   issueAndSerialNumber but the checking code eventually converts it 
	   into this form using the supplied issuer certificate DN */
	if( revInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		status = addRevocationEntry( &certInfoPtr->cCertRev->revocations,
									 &certInfoPtr->cCertRev->currentRevocation,
									 CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
									 revInfoPtr->cCertReq->serialNumber,
									 revInfoPtr->cCertReq->serialNumberLength,
									 FALSE );
		}
	else
		{
		status = addRevocationEntry( &certInfoPtr->cCertRev->revocations,
									 &certInfoPtr->cCertRev->currentRevocation,
									 CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
									 revInfoPtr->cCertCert->serialNumber,
									 revInfoPtr->cCertCert->serialNumberLength,
									 FALSE );
		}
	if( status == CRYPT_ERROR_DUPLICATE )
		{
		/* If this certificate is already present in the list set the 
		   extended error code for it */
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		}
	return( status );
	}

/* Copy public key data into a certificate object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int copyPublicKeyInfo( INOUT CERT_INFO *certInfoPtr,
							  IN_HANDLE_OPT const CRYPT_HANDLE cryptHandle,
							  IN_OPT const CERT_INFO *srcCertInfoPtr )
	{
	void *publicKeyInfoPtr;
	int length = DUMMY_INIT, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( ( isHandleRangeValid( cryptHandle ) && \
			  srcCertInfoPtr == NULL ) || \
			( cryptHandle == CRYPT_UNUSED && \
			  isReadPtr( srcCertInfoPtr, sizeof( CERT_INFO ) ) ) );

	REQUIRES( ( isHandleRangeValid( cryptHandle ) && \
				srcCertInfoPtr == NULL ) || \
			  ( cryptHandle == CRYPT_UNUSED && \
			    srcCertInfoPtr != NULL ) );

	/* Make sure that we haven't already got a public key present */
	if( certInfoPtr->iPubkeyContext != CRYPT_ERROR || \
		certInfoPtr->publicKeyInfo != NULL )
		{
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}

	/* If we've been given a data-only certificate copy over the public key 
	   data */
	if( srcCertInfoPtr != NULL )
		{
		REQUIRES( memcmp( srcCertInfoPtr->publicKeyID,
						  "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) );
		REQUIRES( ( ( BYTE * ) srcCertInfoPtr->publicKeyInfo )[ 0 ] == 0x30 );

		length = srcCertInfoPtr->publicKeyInfoSize;
		if( ( publicKeyInfoPtr = clAlloc( "copyPublicKeyInfo", length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		memcpy( publicKeyInfoPtr, srcCertInfoPtr->publicKeyInfo, length );
		certInfoPtr->publicKeyAlgo = srcCertInfoPtr->publicKeyAlgo;
		certInfoPtr->publicKeyFeatures = srcCertInfoPtr->publicKeyFeatures;
		memcpy( certInfoPtr->publicKeyID, srcCertInfoPtr->publicKeyID,
				KEYID_SIZE );
		}
	else
		{
		CRYPT_CONTEXT iCryptContext;
		MESSAGE_DATA msgData;

		/* Get the context handle.  All other checking has already been
		   performed by the kernel */
		status = krnlSendMessage( cryptHandle, IMESSAGE_GETDEPENDENT,
								  &iCryptContext, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( status );
			}
		ENSURES( cryptStatusOK( \
					krnlSendMessage( iCryptContext, IMESSAGE_CHECK, NULL,
									 MESSAGE_CHECK_PKC ) ) );

		/* Get the key information */
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &certInfoPtr->publicKeyAlgo,
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
									  &certInfoPtr->publicKeyFeatures,
									  CRYPT_IATTRIBUTE_KEYFEATURES );
		if( cryptStatusOK( status ) )
			{
			setMessageData( &msgData, certInfoPtr->publicKeyID, KEYID_SIZE );
			status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_IATTRIBUTE_KEYID );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* Copy over the public-key data.  We copy the data rather than
		   keeping a reference to the context for two reasons.  Firstly,
		   when the certificate is transitioned into the high state it will
		   constrain the attached context so a context shared between two
		   certificates could be constrained in unexpected ways.  Secondly, 
		   the context could be a private-key context and attaching that to 
		   a certificate would be rather inappropriate.  Furthermore, the 
		   constraint issue is even more problematic in that a context 
		   constrained by an encryption-only request could then no longer be 
		   used to sign the request or a PKI protocol message containing the 
		   request */
		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
		if( cryptStatusError( status ) )
			return( status );
		length = msgData.length;
		if( ( publicKeyInfoPtr = clAlloc( "copyPublicKeyInfo", length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		msgData.data = publicKeyInfoPtr;
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEY_SPKI );
		if( cryptStatusError( status ) )
			return( status );
		}
	certInfoPtr->publicKeyData = certInfoPtr->publicKeyInfo = \
		publicKeyInfoPtr;
	certInfoPtr->publicKeyInfoSize = length;
	certInfoPtr->flags |= CERT_FLAG_DATAONLY;

	return( CRYPT_OK );
	}

/* Convert a DN in string form into a certificate DN */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getEncodedDn( INOUT CERT_INFO *certInfoPtr, 
						 IN_BUFFER( dnStringLength ) const void *dnString,
						 IN_LENGTH_ATTRIBUTE const int dnStringLength )
	{
	SELECTION_STATE savedState;
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( dnString, dnStringLength ) );

	REQUIRES( dnStringLength > 0 && dnStringLength < MAX_INTLENGTH_SHORT );

	/* If there's already a DN set we can't do anything else */
	saveSelectionState( savedState, certInfoPtr );
	status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, MUST_BE_PRESENT );
	if( cryptStatusOK( status ) && \
		*certInfoPtr->currentSelection.dnPtr == NULL )
		{
		/* There's a DN selected but it's empty, we're OK */
		status = CRYPT_ERROR;
		}
	restoreSelectionState( savedState, certInfoPtr );
	if( cryptStatusOK( status ) )
		return( CRYPT_ERROR_INITED );
	status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, CREATE_IF_ABSENT );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the entire DN from its string form into the selected DN */
	status = readDNstring( certInfoPtr->currentSelection.dnPtr,
						   dnString, dnStringLength );
	if( cryptStatusOK( status ) && \
		certInfoPtr->currentSelection.updateCursor )
		{
		/* If we couldn't update the cursor earlier on because the attribute
		   field in question hadn't been created yet do it now.  Since this 
		   is merely a side-effect of this operation we ignore the return 
		   status and return the main result status */
		( void ) selectGeneralName( certInfoPtr,
									certInfoPtr->currentSelection.generalName,
									MAY_BE_ABSENT );
		}
	return( status );
	}

/* The OCSPv1 ID doesn't contain any usable fields so we pre-encode it when
   the certificate is added to the OCSP request and treat it as a blob 
   thereafter */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeOCSPv1ID( INOUT STREAM *stream, 
						  const CERT_INFO *certInfoPtr,
						  IN_BUFFER( issuerKeyHashLength ) \
								const void *issuerKeyHash,
						  IN_LENGTH_FIXED( KEYID_SIZE ) \
								const int issuerKeyHashLength )
	{
	HASHFUNCTION_ATOMIC hashFunctionAtomic;
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int hashSize;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( issuerKeyHashLength == KEYID_SIZE );
	REQUIRES( certInfoPtr->issuerDNptr != NULL );
	REQUIRES( certInfoPtr->cCertCert->serialNumber != NULL );

	/* Get the issuerName hash */
	getHashAtomicParameters( CRYPT_ALGO_SHA1, &hashFunctionAtomic, &hashSize );
	hashFunctionAtomic( hashBuffer, CRYPT_MAX_HASHSIZE,
						certInfoPtr->issuerDNptr,
						certInfoPtr->issuerDNsize );

	/* Write the request data */
	writeSequence( stream,
			sizeofAlgoID( CRYPT_ALGO_SHA1 ) + \
			sizeofObject( hashSize ) + sizeofObject( hashSize ) + \
			sizeofInteger( certInfoPtr->cCertCert->serialNumber,
						   certInfoPtr->cCertCert->serialNumberLength ) );
	writeAlgoID( stream, CRYPT_ALGO_SHA1 );
	writeOctetString( stream, hashBuffer, hashSize, DEFAULT_TAG );
	writeOctetString( stream, issuerKeyHash, issuerKeyHashLength, 
					  DEFAULT_TAG );
	return( writeInteger( stream, certInfoPtr->cCertCert->serialNumber,
						  certInfoPtr->cCertCert->serialNumberLength,
						  DEFAULT_TAG ) );
	}

/* Sanitise certificate attributes based on a user-supplied template.  This 
   is used to prevent a user from supplying potentially dangerous attributes 
   in a certificate request, for example to request a CA certificate by 
   setting the basicConstraints/keyUsage = CA extensions in the request in a 
   manner that would result in the creation of a CA certificate when the 
   request is processed.  We use an allow-all default rather than deny-all 
   since deny-all would require the caller to specify a vast range of 
   (mostly never-used) attributes to permit when usually all they want to 
   block is the CA flag and equivalent mechanisms */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sanitiseCertAttributes( INOUT CERT_INFO *certInfoPtr,
								   IN_OPT const ATTRIBUTE_LIST *templateListPtr )
	{
	const ATTRIBUTE_LIST *attributeListCursor;
	int iterationCount;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( templateListPtr == NULL || \
			( isReadPtr( templateListPtr, sizeof( ATTRIBUTE_LIST ) ) ) );

	/* If there's no attributes present or no disallowed attribute template,
	   we're done */
	if( certInfoPtr->attributes == NULL || templateListPtr == NULL )
		return( CRYPT_OK );

	/* Walk down the template attribute list applying each one in turn to
	   the certificate attributes */
	for( attributeListCursor = templateListPtr, iterationCount = 0;
		 attributeListCursor != NULL && \
			!isBlobAttribute( attributeListCursor ) && \
			iterationCount < FAILSAFE_ITERATIONS_MAX; 
		 attributeListCursor = attributeListCursor->next, iterationCount++ )
		{
		ATTRIBUTE_LIST *attributeList;
		int value;

		/* Check to see whether there's a constrained attribute present in
		   the certificate attributes and if it is, whether it conflicts 
		   with the constraining attribute */
		attributeList = findAttributeField( certInfoPtr->attributes,
											attributeListCursor->fieldID,
											attributeListCursor->subFieldID );
		if( attributeList == NULL || \
			!( attributeList->intValue & attributeListCursor->intValue ) )
			continue;

		/* If the certificate attribute was provided through the application 
		   of PKI user data (indicated by it having the locked flag set), 
		   allow it even if it conflicts with the constraining attribute.  
		   This is permitted because the PKI user data was explicitly set by 
		   the issuing CA rather than being user-supplied in the certificate 
		   request so it has to be OK, or at least CA-approved */
		if( attributeList->flags & ATTR_FLAG_LOCKED )
			continue;

		/* The attribute contains a value that's disallowed by the
		   constraining attribute, correct it if possible */
		value = attributeList->intValue & ~attributeListCursor->intValue;
		if( !value )
			{
			/* The attribute contains only invalid bits and can't be
			   permitted */
			certInfoPtr->errorLocus = attributeList->fieldID;
			certInfoPtr->errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			return( CRYPT_ERROR_INVALID );
			}
		attributeList->intValue = value;	/* Set adjusted value */
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Serial-Number Routines							*
*																			*
****************************************************************************/

/* Set the serial number for a certificate.  Ideally we would store this as
   a static value in the configuration database but this has three
   disadvantages: Updating the serial number updates the entire 
   configuration database (including things the user might not want
   updated), if the configuration database update fails the serial number 
   never changes, and the predictable serial number allows tracking of the 
   number of certificates which have been issued by the CA.  Because of this 
   we just use a 64-bit nonce if the user doesn't supply a value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setSerialNumber( INOUT CERT_INFO *certInfoPtr, 
					 IN_BUFFER_OPT( serialNumberLength ) const void *serialNumber, 
					 IN_LENGTH_SHORT_Z const int serialNumberLength )
	{
	MESSAGE_DATA msgData;
	BYTE buffer[ 128 + 8 ];
	void *serialNumberPtr;
	int length = ( serialNumberLength > 0 ) ? \
				 serialNumberLength : DEFAULT_SERIALNO_SIZE;
	int bufPos = 0, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( ( serialNumber == NULL && serialNumberLength == 0 ) || \
			( isReadPtr( serialNumber, serialNumberLength ) ) );

	REQUIRES( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
			  certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN || \
			  certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION );
	REQUIRES( ( serialNumber == NULL && serialNumberLength == 0 ) || \
			  ( serialNumber != NULL && \
				serialNumberLength > 0 && \
				serialNumberLength <= MAX_SERIALNO_SIZE ) );

	/* If a serial number has already been set explicitly, don't override
	   it with an implicitly-set one */
	serialNumberPtr = \
			( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION ) ? \
				certInfoPtr->cCertReq->serialNumber : \
				certInfoPtr->cCertCert->serialNumber;
	if( serialNumberPtr != NULL )
		{
		assert( isReadPtr( serialNumberPtr, SERIALNO_BUFSIZE ) );
		ENSURES( serialNumber == NULL && serialNumberLength == 0 );
		return( CRYPT_OK );
		}
	serialNumberPtr = \
			( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION ) ? \
				certInfoPtr->cCertReq->serialNumberBuffer : \
				certInfoPtr->cCertCert->serialNumberBuffer;

	/* If we're using user-supplied serial number data, canonicalise it into
	   a form suitable for use as an INTEGER-hole */
	if( serialNumber != NULL )
		{
		STREAM stream;

		assert( isReadPtr( serialNumber, serialNumberLength ) );

		sMemOpen( &stream, buffer, 128 );
		status = writeInteger( &stream, serialNumber, serialNumberLength,
							   DEFAULT_TAG );
		length = stell( &stream ) - 2;
		sMemDisconnect( &stream );
		bufPos = 2;		/* Skip tag + length */
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		/* Generate a random (but fixed-length) serial number and ensure
		   that the first byte of the value we use is nonzero (to guarantee
		   a DER encoding) and clear the high bit to provide a constant-
		   length ASN.1 encoded value */
		setMessageData( &msgData, buffer, DEFAULT_SERIALNO_SIZE + 1 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		buffer[ 0 ] &= 0x7F;	/* Clear the sign bit */
		if( buffer[ 0 ] == 0 )
			{
			/* The first byte is zero, try for a nonzero byte in the extra
			   data that we fetched.  If that's zero too, just set it to 1 */
			buffer[ 0 ] = buffer[ DEFAULT_SERIALNO_SIZE ] & 0x7F;
			if( buffer[ 0 ] == 0 )
				buffer[ 0 ] = 1;
			}
		}

	/* Copy across the canonicalised serial number value */
	if( length >= SERIALNO_BUFSIZE && \
		( serialNumberPtr = clDynAlloc( "setSerialNumber", length ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	if( certInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION )
		{
		certInfoPtr->cCertReq->serialNumber = serialNumberPtr;
		certInfoPtr->cCertReq->serialNumberLength = length;
		}
	else
		{
		certInfoPtr->cCertCert->serialNumber = serialNumberPtr;
		certInfoPtr->cCertCert->serialNumberLength = length;
		}
	memcpy( serialNumberPtr, buffer + bufPos, length );

	return( CRYPT_OK );
	}

/* Compare a serial number in canonical form to a generic serial number
   with special handling for leading-zero truncation.  This one can get a
   bit tricky because Microsoft fairly consistently encode serial numbers 
   incorrectly so we normalise the values to have no leading zero, which is 
   the lowest common denominator */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
BOOLEAN compareSerialNumber( IN_BUFFER( canonSerialNumberLength ) \
								const void *canonSerialNumber,
							 IN_LENGTH_SHORT const int canonSerialNumberLength,
							 IN_BUFFER( serialNumberLength ) \
								const void *serialNumber,
							 IN_LENGTH_SHORT const int serialNumberLength )
	{
	const BYTE *canonSerialNumberPtr = canonSerialNumber;
	const BYTE *serialNumberPtr = serialNumber;
	int canonSerialLength = canonSerialNumberLength;
	int serialLength = serialNumberLength;

	assert( isReadPtr( canonSerialNumber, canonSerialNumberLength ) );
	assert( isReadPtr( serialNumber, serialNumberLength ) );

	/* Internal serial numbers are canonicalised so all we need to do is 
	   strip a possible leading zero */
	if( canonSerialNumberPtr[ 0 ] == 0 )
		{
		canonSerialNumberPtr++;
		canonSerialLength--;
		}
	ENSURES( canonSerialLength == 0 || canonSerialNumberPtr[ 0 ] );

	/* Serial numbers from external sources can be arbitarily strangely
	   encoded so we strip leading zeroes until we get to actual data */
	while( serialLength > 0 && serialNumberPtr[ 0 ] == 0 )
		{
		serialNumberPtr++;
		serialLength--;
		}

	/* Finally we've got them in a form where we can compare them */
	if( canonSerialLength == serialLength && \
		!memcmp( canonSerialNumberPtr, serialNumberPtr, serialLength ) )
		return( TRUE );

	return( FALSE );
	}

/****************************************************************************
*																			*
*						Copy Certificate Request Info						*
*																			*
****************************************************************************/

/* Copy certificate request info into a certificate object.  This copies the 
   public key context, the DN, any valid attributes, and any other relevant 
   bits and pieces if it's a CRMF request */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyCertReqInfo( INOUT CERT_INFO *certInfoPtr,
							INOUT CERT_INFO *certRequestInfoPtr )
	{
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( certRequestInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( certRequestInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST || \
			  certRequestInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT );

	/* Copy the public key context, the DN, and the attributes.  Type
	   checking has already been performed by the kernel.  We copy the
	   attributes across after the DN because that copy is the hardest to
	   undo: If there are already attributes present then the copied 
	   attributes would be mixed in among them so it's not really possible 
	   to undo the copy later without performing a complex selective 
	   delete */
	status = copyDN( &certInfoPtr->subjectName,
					 certRequestInfoPtr->subjectName );
	if( cryptStatusOK( status ) )
		{
		if( certRequestInfoPtr->flags & CERT_FLAG_DATAONLY )
			{
			status = copyPublicKeyInfo( certInfoPtr, CRYPT_UNUSED,
										certRequestInfoPtr );
			}
		else
			{
			status = copyPublicKeyInfo( certInfoPtr,
										certRequestInfoPtr->iPubkeyContext,
										NULL );
			}
		}
	if( cryptStatusOK( status ) && \
		certRequestInfoPtr->attributes != NULL )
		{
		status = copyAttributes( &certInfoPtr->attributes,
								 certRequestInfoPtr->attributes,
								 &certInfoPtr->errorLocus,
								 &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			deleteDN( &certInfoPtr->subjectName );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a CRMF request there could also be a validity period
	   specified */
	if( certRequestInfoPtr->type == CRYPT_CERTTYPE_REQUEST_CERT )
		{
		const time_t currentTime = getApproxTime();

		/* We don't allow start times backdated by more than a year or end
		   times before the start time.  Since these are trivial things we
		   don't abort if there's a problem but just quietly fix the value */
		if( certRequestInfoPtr->startTime > MIN_TIME_VALUE && \
			certRequestInfoPtr->startTime > currentTime - ( 86400L * 365 ) )
			certInfoPtr->startTime = certRequestInfoPtr->startTime;
		if( certRequestInfoPtr->endTime > MIN_TIME_VALUE && \
			certRequestInfoPtr->endTime > certInfoPtr->startTime )
			certInfoPtr->endTime = certRequestInfoPtr->endTime;
		}

	return( CRYPT_OK );
	}

/* Copy what we need to identify the certificate to be revoked and any 
   revocation information into a certificate object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyRevReqInfo( INOUT CERT_INFO *certInfoPtr,
						   INOUT CERT_INFO *revRequestInfoPtr )
	{
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( revRequestInfoPtr, sizeof( CERT_INFO ) ) );

	status = copyRevocationInfo( certInfoPtr, revRequestInfoPtr );
	if( cryptStatusError( status ) || \
		revRequestInfoPtr->attributes == NULL )
		return( status );
	return( copyRevocationAttributes( &certInfoPtr->attributes,
									  revRequestInfoPtr->attributes ) );
	}

/* Copy revocation information from an RTCS or OCSP request to a response */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyRtcsReqInfo( INOUT CERT_INFO *certInfoPtr,
							INOUT CERT_INFO *rtcsRequestInfoPtr )
	{
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( rtcsRequestInfoPtr, sizeof( CERT_INFO ) ) );

	/* Copy the certificate validity information and extensions */
	status = copyValidityEntries( &certInfoPtr->cCertVal->validityInfo,
								  rtcsRequestInfoPtr->cCertVal->validityInfo );
	if( cryptStatusOK( status ) )
		status = copyOCSPRequestAttributes( &certInfoPtr->attributes,
											rtcsRequestInfoPtr->attributes );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyOcspReqInfo( INOUT CERT_INFO *certInfoPtr,
							INOUT CERT_INFO *ocspRequestInfoPtr )
	{
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( ocspRequestInfoPtr, sizeof( CERT_INFO ) ) );

	/* Copy the revocation information and extensions */
	status = copyRevocationEntries( &certInfoPtr->cCertRev->revocations,
									ocspRequestInfoPtr->cCertRev->revocations );
	if( cryptStatusOK( status ) )
		status = copyOCSPRequestAttributes( &certInfoPtr->attributes,
											ocspRequestInfoPtr->attributes );
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Copy Certificate Template Info						*
*																			*
****************************************************************************/

/* Copy the public key, DN, and any attributes that need to be copied across.  
   We copy the full DN rather than just the encoded form in case the user 
   wants to query the request details after creating it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyToCRMFRequest( INOUT CERT_INFO *crmfRequestInfoPtr,
							  INOUT CERT_INFO *certInfoPtr,
							  const CRYPT_HANDLE iCryptHandle )
	{
	int status;

	assert( isWritePtr( crmfRequestInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	status = copyDN( &crmfRequestInfoPtr->subjectName,
					 certInfoPtr->subjectName );
	if( cryptStatusError( status ) )
		return( status );
	if( crmfRequestInfoPtr->iPubkeyContext == CRYPT_ERROR && \
		crmfRequestInfoPtr->publicKeyInfo == NULL )
		{
		/* Only copy the key across if a key hasn't already been added 
		   earlier as CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO.  Checking for 
		   this special case (rather than returning an error) allows the DN 
		   information from an existing certificate to be copied into a 
		   request for a new key */
		status = copyPublicKeyInfo( crmfRequestInfoPtr, iCryptHandle, NULL );
		}
	if( cryptStatusOK( status ) )
		{
		/* We copy the attributes across after the DN because that copy is 
		   the hardest to undo: If there are already attributes present, the 
		   copied attributes will be mixed in among them so it's not really 
		   possible to undo the copy later without performing a complex 
		   selective delete */
		status = copyCRMFRequestAttributes( &crmfRequestInfoPtr->attributes,
											certInfoPtr->attributes );
		}
	if( cryptStatusError( status ) )
		deleteDN( &crmfRequestInfoPtr->subjectName );

	return( status );
	}

/* Copy across the issuer and subject DN and serial number */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyToCRMFRevRequest( INOUT CERT_INFO *crmfRevRequestInfoPtr,
								 INOUT CERT_INFO *certInfoPtr )
	{
	int status;

	assert( isWritePtr( crmfRevRequestInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* If the info is already present then we can't add it again */
	if( crmfRevRequestInfoPtr->issuerName != NULL )
		{
		setErrorInfo( crmfRevRequestInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}

	/* Copy across the issuer name and allocate the storage that we need to 
	   copy the subject name.  We don't care about any internal structure of 
	   the DNs so we just copy the pre-encoded form, we could in theory copy 
	   the full DN but it isn't really the issuer (creator) of the object so 
	   it's better if it appears to have no issuer DN than a misleading one */
	status = copyIssuerDnData( crmfRevRequestInfoPtr, certInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	status = setSerialNumber( crmfRevRequestInfoPtr,
							  certInfoPtr->cCertCert->serialNumber,
							  certInfoPtr->cCertCert->serialNumberLength );
	if( cryptStatusOK( status ) && \
		( crmfRevRequestInfoPtr->subjectDNdata = \
				  clAlloc( "copyToCRMFRevRequest",
						   certInfoPtr->subjectDNsize ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusError( status ) )
		{
		clFree( "copyToCRMFRevRequest", 
				crmfRevRequestInfoPtr->issuerDNdata );
		crmfRevRequestInfoPtr->issuerDNptr = \
			crmfRevRequestInfoPtr->issuerDNdata = NULL;
		crmfRevRequestInfoPtr->issuerDNsize = 0;
		if( crmfRevRequestInfoPtr->cCertCert->serialNumber != NULL && \
			crmfRevRequestInfoPtr->cCertCert->serialNumber != \
				crmfRevRequestInfoPtr->cCertCert->serialNumberBuffer )
			{
			clFree( "copyToCRMFRevRequest",
					crmfRevRequestInfoPtr->cCertCert->serialNumber );
			}
		crmfRevRequestInfoPtr->cCertCert->serialNumber = NULL;
		return( status );
		}

	/* Copy the subject DN for use in CMP */
	memcpy( crmfRevRequestInfoPtr->subjectDNdata, certInfoPtr->subjectDNptr,
			certInfoPtr->subjectDNsize );
	crmfRevRequestInfoPtr->subjectDNptr = crmfRevRequestInfoPtr->subjectDNdata;
	crmfRevRequestInfoPtr->subjectDNsize = certInfoPtr->subjectDNsize;

	return( CRYPT_OK );
	}

/* Copy the certificate information to the revocation list.  First we make 
   sure that the CA certificate hash (needed for the weird certificate ID) 
   is present.  We add the necessary information as a pre-encoded blob since 
   we can't do much with the ID fields */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyToOCSPRequest( INOUT CERT_INFO *ocspRequestInfoPtr,
							  INOUT CERT_INFO *certInfoPtr )
	{
	STREAM stream;
	DYNBUF essCertDB;
	BYTE idBuffer[ 256 + 8 ], *idBufPtr = idBuffer;
	const int idLength = ( int ) sizeofObject( \
			sizeofAlgoID( CRYPT_ALGO_SHA1 ) + \
			sizeofObject( 20 ) + sizeofObject( 20 ) + \
			sizeofInteger( certInfoPtr->cCertCert->serialNumber, \
						   certInfoPtr->cCertCert->serialNumberLength ) );
	int status;

	assert( isWritePtr( ocspRequestInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Make sure that there's a CA certificate hash present */
	if( !ocspRequestInfoPtr->certHashSet )
		{
		setErrorInfo( ocspRequestInfoPtr, CRYPT_CERTINFO_CACERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Generate the OCSPv1 certificate ID */
	if( idLength > 256 && \
	    ( idBufPtr = clDynAlloc( "copyToOCSPRequest", \
								 idLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	sMemOpen( &stream, idBufPtr, idLength );
	status = writeOCSPv1ID( &stream, certInfoPtr, 
							ocspRequestInfoPtr->certHash, KEYID_SIZE );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		status = addRevocationEntry( &ocspRequestInfoPtr->cCertRev->revocations,
									 &ocspRequestInfoPtr->cCertRev->currentRevocation,
									 CRYPT_KEYID_NONE, idBufPtr,
									 idLength, FALSE );
		}
	if( idBufPtr != idBuffer )
		clFree( "copyToOCSPRequest", idBufPtr );
	if( status == CRYPT_ERROR_DUPLICATE )
		{
		/* If this certificate is already present in the list, set the 
		   extended error code for it */
		setErrorInfo( ocspRequestInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Add the certificate information again as an ESSCertID extension to 
	   work around the problems inherent in OCSPv1 IDs */
	status = dynCreate( &essCertDB, certInfoPtr->objectHandle, 
						CRYPT_IATTRIBUTE_ESSCERTID );
	if( cryptStatusOK( status ) )
		{
		CRYPT_ATTRIBUTE_TYPE dummy1;
		CRYPT_ERRTYPE_TYPE dummy2;

		/* Since this isn't a critical extension (the ESSCertID is just a 
		   backup for the main, albeit not very useful, ID) we continue if 
		   there's a problem adding it */
		( void ) addAttributeField( \
				&ocspRequestInfoPtr->cCertRev->currentRevocation->attributes,
				CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID, CRYPT_ATTRIBUTE_NONE,
				dynData( essCertDB ), dynLength( essCertDB ), ATTR_FLAG_NONE, 
				&dummy1, &dummy2 );
		dynDestroy( &essCertDB );
		}
	return( CRYPT_OK );
	}

/* Copy the certificate hash.  We read the value indirectly since it's 
   computed on demand and may not have been evaluated yet */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyToRTCSRequest( INOUT CERT_INFO *rtcsRequestInfoPtr,
							  INOUT CERT_INFO *certInfoPtr )
	{
	BYTE certHash[ CRYPT_MAX_HASHSIZE + 8 ];
	int certHashLength, status;

	assert( isWritePtr( rtcsRequestInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	status = getCertComponent( certInfoPtr,
							   CRYPT_CERTINFO_FINGERPRINT_SHA, certHash,
							   CRYPT_MAX_HASHSIZE, &certHashLength );
	if( cryptStatusOK( status ) )
		{
		status = addValidityEntry( &rtcsRequestInfoPtr->cCertVal->validityInfo,
								   &rtcsRequestInfoPtr->cCertVal->currentValidity,
								   certHash, certHashLength );
		}
	if( status == CRYPT_ERROR_DUPLICATE )
		{
		/* If this certificate is already present in the list, set the 
		   extended error code for it */
		setErrorInfo( rtcsRequestInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		}
	return( status );
	}

/* Copy user certificate info into a certificate object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyUserCertInfo( INOUT CERT_INFO *certInfoPtr,
							 INOUT CERT_INFO *userCertInfoPtr,
							 IN_HANDLE const CRYPT_HANDLE iCryptHandle )
	{
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( userCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iCryptHandle ) );
	REQUIRES( userCertInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  userCertInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );
	REQUIRES( userCertInfoPtr->certificate != NULL );

	/* If it's an RTCS or OCSP request, remember the responder URL if there's
	   one present.  We can't leave it to be read out of the certificate 
	   because authorityInfoAccess isn't a valid attribute for RTCS/OCSP 
	   requests */
	if( ( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST && \
		  certInfoPtr->cCertVal->responderUrl == NULL ) || \
		( certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST && \
		  certInfoPtr->cCertRev->responderUrl == NULL ) )
		{
		const CRYPT_ATTRIBUTE_TYPE aiaAttribute = \
					( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST ) ? \
					CRYPT_CERTINFO_AUTHORITYINFO_RTCS : \
					CRYPT_CERTINFO_AUTHORITYINFO_OCSP;
		SELECTION_STATE savedState;
		void *responderUrl;
		int urlSize = DUMMY_INIT;

		/* There's no responder URL set, check whether the user certificate 
		   contains a responder URL in the RTCS/OCSP authorityInfoAccess 
		   GeneralName */
		saveSelectionState( savedState, userCertInfoPtr );
		status = selectGeneralName( userCertInfoPtr, aiaAttribute,
									MAY_BE_ABSENT );
		if( cryptStatusOK( status ) )
			status = selectGeneralName( userCertInfoPtr,
										CRYPT_ATTRIBUTE_NONE,
										MUST_BE_PRESENT );
		if( cryptStatusOK( status ) )
			status = getCertComponent( userCertInfoPtr,
								CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
								NULL, 0, &urlSize );
		if( cryptStatusOK( status ) )
			{
			/* There's a responder URL present, copy it to the request */
			if( ( responderUrl = \
						clAlloc( "copyUserCertInfo", urlSize ) ) == NULL )
				status = CRYPT_ERROR_MEMORY;
			else
				{
				status = getCertComponent( userCertInfoPtr,
									CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
									responderUrl, urlSize, &urlSize );
				}
			if( cryptStatusOK( status ) )
				{
				if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST )
					{
					certInfoPtr->cCertVal->responderUrl = responderUrl;
					certInfoPtr->cCertVal->responderUrlSize = urlSize;
					}
				else
					{
					certInfoPtr->cCertRev->responderUrl = responderUrl;
					certInfoPtr->cCertRev->responderUrlSize = urlSize;
					}
				}
			}
		else
			{
			/* If there's no responder URL present it's not a (fatal)
			   error */
			status = CRYPT_OK;
			}
		restoreSelectionState( savedState, userCertInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Copy the required information across to the certificate */
	switch( certInfoPtr->type )
		{
		case CRYPT_CERTTYPE_CRL:
			return( copyRevocationInfo( certInfoPtr, userCertInfoPtr ) );

		case CRYPT_CERTTYPE_REQUEST_CERT:
			return( copyToCRMFRequest( certInfoPtr, userCertInfoPtr,
									   iCryptHandle ) );

		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			return( copyToCRMFRevRequest( certInfoPtr, userCertInfoPtr ) );

		case CRYPT_CERTTYPE_OCSP_REQUEST:
			return( copyToOCSPRequest( certInfoPtr, userCertInfoPtr ) );

		case CRYPT_CERTTYPE_RTCS_REQUEST:
			return( copyToRTCSRequest( certInfoPtr, userCertInfoPtr ) );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*					Copy Miscellaneous Certificate Info						*
*																			*
****************************************************************************/

/* Get the hash of the public key (for an OCSPv1 request), possibly
   overwriting a previous hash if there are multiple entries in the
   request */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyCaCertInfo( INOUT CERT_INFO *certInfoPtr,
						   INOUT CERT_INFO *caCertInfoPtr )
	{
	HASHFUNCTION_ATOMIC hashFunctionAtomic;
	STREAM stream;
	void *dataPtr = DUMMY_INIT_PTR;
	int length, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( caCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( caCertInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  caCertInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );
	REQUIRES( caCertInfoPtr->publicKeyInfo != NULL );

	getHashAtomicParameters( CRYPT_ALGO_SHA1, &hashFunctionAtomic, NULL );

	/* Dig down into the encoded key data to find the weird bits of key that
	   OCSP requires us to hash.  We store the result as the certificate 
	   hash, which is safe because it isn't used for an OCSP request so it 
	   can't be accessed externally */
	sMemConnect( &stream, caCertInfoPtr->publicKeyInfo,
				 caCertInfoPtr->publicKeyInfoSize );
	readSequence( &stream, NULL );	/* Wrapper */
	readUniversal( &stream );		/* AlgoID */
	status = readBitStringHole( &stream, &length, 16, DEFAULT_TAG );
	if( cryptStatusOK( status ) )	/* BIT STRING wrapper */
		status = sMemGetDataBlock( &stream, &dataPtr, length );
	if( cryptStatusError( status ) )
		{
		/* There's a problem with the format of the key */
		assert( DEBUG_WARN );
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CACERTIFICATE,
					  CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ERROR_INVALID );
		}
	hashFunctionAtomic( certInfoPtr->certHash, KEYID_SIZE, dataPtr, length );
	certInfoPtr->certHashSet = TRUE;
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/* Set or modify data in a certificate request based on the PKI user info */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyPkiUserAttributes( INOUT CERT_INFO *certInfoPtr,
								  INOUT ATTRIBUTE_LIST *pkiUserAttributes )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( pkiUserAttributes, sizeof( ATTRIBUTE_LIST ) ) );

	/* There's one rather ugly special-case situation that we have to handle
	   which is when the user has submitted a PnP PKI request for a generic
	   signing certificate but their PKI user info indicates that they're 
	   intended to be a CA user.  The processing flow for this is as follows:

		CMP: readRequestBody()

			Read request into state=high certificate request object;
			Add PKI user info to request;

		ca_issue: caIssuerCert()

			Add request to newly-created certificate object;
			Sign certificate;

	   When augmenting the request with the PKI user info the incoming
	   request will contain a keyUsage of digitalSignature while the PKI
	   user info will contain a keyUsage of keyCertSign and/or crlSign.  We
	   can't fix this up at the CMP level because the request is in the high
	   state and no changes to the attributes can be made (the PKI user info
	   is a special case that can added to an object in the high state but
	   which modifies attributes in it as if it were still in the low state).

	   To avoid the attribute conflict, if we find this situation in the
	   request/pkiUser combination we delete the keyUsage in the request to
	   allow it to be replaced by the pkiUser attributes.  Hardcoding in
	   this special case isn't very elegant but it's the only way to make 
	   the PnP PKI issue work without requiring that the user explicitly
	   specify that they want to be a CA, which makes it rather non-PnP */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   CRYPT_CERTINFO_KEYUSAGE,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && \
		attributeListPtr->intValue == CRYPT_KEYUSAGE_DIGITALSIGNATURE )
		{
		const ATTRIBUTE_LIST *pkiAttributeListPtr = \
				findAttributeField( pkiUserAttributes, CRYPT_CERTINFO_KEYUSAGE,
									CRYPT_ATTRIBUTE_NONE );
		if( pkiAttributeListPtr != NULL && \
			( pkiAttributeListPtr->intValue & ( CRYPT_KEYUSAGE_KEYCERTSIGN | \
												CRYPT_KEYUSAGE_CRLSIGN ) ) )
			{
			/* The certificate contains a digitalSignature keyUsage and the 
			   PKI user info contains a CA usage, delete the digitalSignature 
			   usage to make way for the CA usage */
			deleteAttribute( &certInfoPtr->attributes,
							 &certInfoPtr->attributeCursor, attributeListPtr,
							 certInfoPtr->currentSelection.dnPtr );
			}
		}

	/* Copy the attributes from the PKI user info into the certificate */
	status = copyAttributes( &certInfoPtr->attributes, pkiUserAttributes,
							 &certInfoPtr->errorLocus,
							 &certInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );

	/* The PKI user info contains an sKID that's used to uniquely identify
	   the user, this applies to the user info itself rather than the 
	   certificate that'll be issued from it.  Since this will have been 
	   copied over alongside the other attributes we need to explicitly 
	   delete it before we continue */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		deleteAttribute( &certInfoPtr->attributes,
						 &certInfoPtr->attributeCursor, attributeListPtr,
						 certInfoPtr->currentSelection.dnPtr );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int assemblePkiUserDN( INOUT CERT_INFO *certInfoPtr,
							  const void *pkiUserSubjectName,
							  IN_BUFFER( commonNameLength ) const void *commonName, 
							  IN_LENGTH_SHORT const int commonNameLength )
	{
	STREAM stream;
	void *tempDN = NULL, *tempDNdata;
	int tempDNsize = DUMMY_INIT, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( commonName, commonNameLength ) );

	REQUIRES( pkiUserSubjectName != NULL );
	REQUIRES( commonNameLength > 0 && \
			  commonNameLength < MAX_INTLENGTH_SHORT );

	/* Copy the DN template, append the user-supplied CN, and allocate room 
	   for the encoded form */
	status = copyDN( &tempDN, pkiUserSubjectName );
	if( cryptStatusError( status ) )
		return( status );
	status = insertDNComponent( &tempDN, CRYPT_CERTINFO_COMMONNAME,
								commonName, commonNameLength,
								&certInfoPtr->errorType );
	if( cryptStatusOK( status ) )
		status = tempDNsize = sizeofDN( tempDN );
	if( cryptStatusError( status ) )
		{
		deleteDN( &tempDN );
		return( status );
		}
	if( ( tempDNdata = clAlloc( "assemblePkiUserDN", tempDNsize ) ) == NULL )
		{
		deleteDN( &tempDN );
		return( CRYPT_ERROR_MEMORY );
		}

	/* Replace the existing DN with the new one and set up the encoded 
	   form */
	deleteDN( &certInfoPtr->subjectName );
	certInfoPtr->subjectName = tempDN;
	sMemOpen( &stream, tempDNdata, tempDNsize );
	status = writeDN( &stream, tempDN, DEFAULT_TAG );
	ENSURES( cryptStatusOK( status ) );
	sMemDisconnect( &stream );
	certInfoPtr->subjectDNdata = certInfoPtr->subjectDNptr = tempDNdata;
	certInfoPtr->subjectDNsize = tempDNsize;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyPkiUserInfo( INOUT CERT_INFO *certInfoPtr,
							INOUT CERT_INFO *pkiUserInfoPtr )
	{
	char commonName[ CRYPT_MAX_TEXTSIZE + 8 ];
	int commonNameLength, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( pkiUserInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( pkiUserInfoPtr->type == CRYPT_CERTTYPE_PKIUSER );
	REQUIRES( pkiUserInfoPtr->certificate != NULL );

	/* If there's no DN present in the request try and fill it in from the
	   CA-supplied PKI user info */
	if( certInfoPtr->subjectName == NULL )
		{
		/* If neither the request nor the PKI user info has a DN present we
		   can't continue */
		if( pkiUserInfoPtr->subjectName == NULL )
			return( CRYPT_ERROR_NOTINITED );

		ENSURES( pkiUserInfoPtr->subjectDNptr != NULL );

		/* There's no DN present in the request it's been supplied by the CA 
		   in the PKI user info, copy over the DN and its encoded form from 
		   the user info */
		status = copyDN( &certInfoPtr->subjectName,
						 pkiUserInfoPtr->subjectName );
		if( cryptStatusError( status ) )
			return( status );
		if( ( certInfoPtr->subjectDNdata = \
					clAlloc( "copyPkiUserInfo",
							 pkiUserInfoPtr->subjectDNsize ) ) == NULL )
			{
			deleteDN( &certInfoPtr->subjectName );
			return( CRYPT_ERROR_MEMORY );
			}
		memcpy( certInfoPtr->subjectDNdata, pkiUserInfoPtr->subjectDNptr,
				pkiUserInfoPtr->subjectDNsize );
		certInfoPtr->subjectDNptr = certInfoPtr->subjectDNdata;
		certInfoPtr->subjectDNsize = pkiUserInfoPtr->subjectDNsize;

		/* Copy any additional attributes across */
		return( copyPkiUserAttributes( certInfoPtr,
									   pkiUserInfoPtr->attributes ) );
		}

	/* If there's no PKI user DN with the potential to conflict with the one
	   in the request present, copy any additional attributes across and
	   exit */
	if( pkiUserInfoPtr->subjectName == NULL )
		{
		return( copyPkiUserAttributes( certInfoPtr,
									   pkiUserInfoPtr->attributes ) );
		}

	/* There's both a request DN and PKI user DN present.  If the request
	   contains only a CN, combine it with the PKI user DN and update the
	   request */
	status = getDNComponentValue( certInfoPtr->subjectName,
								  CRYPT_CERTINFO_COMMONNAME, commonName,
								  CRYPT_MAX_TEXTSIZE, &commonNameLength );
	if( cryptStatusOK( status ) )
		{
		void *tempDN = NULL;
		BOOLEAN isCommonNameDN;

		/* Check whether the request DN contains only a CN.  There's no easy
		   way to do this directly, the only way that we can do it is by 
		   creating a temporary DN consisting of only the CN and comparing 
		   it to the request DN */
		status = insertDNComponent( &tempDN, CRYPT_CERTINFO_COMMONNAME,
									commonName, commonNameLength,
									&certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		isCommonNameDN = compareDN( certInfoPtr->subjectName, 
									tempDN, FALSE );
		deleteDN( &tempDN );

		/* If the request DN consists only of a CN, append it to the PKI
		   user DN */
		if( isCommonNameDN )
			{
			status = assemblePkiUserDN( certInfoPtr,
										pkiUserInfoPtr->subjectName,
										commonName, commonNameLength );
			if( cryptStatusError( status ) )
				return( status );

			/* Copy any additional attributes across */
			return( copyPkiUserAttributes( certInfoPtr,
										   pkiUserInfoPtr->attributes ) );
			}
		}

	/* There are full DNs present in both objects, make sure that they're
	   the same and copy any additional attributes across */
	if( !compareDN( certInfoPtr->subjectName,
					pkiUserInfoPtr->subjectName, FALSE ) )
		return( CRYPT_ERROR_INVALID );
	return( copyPkiUserAttributes( certInfoPtr,
								   pkiUserInfoPtr->attributes ) );
	}

/****************************************************************************
*																			*
*							Set Certificate Info							*
*																			*
****************************************************************************/

/* Set XYZZY certificate info */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int setXyzzyInfo( INOUT CERT_INFO *certInfoPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	const int keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
						 CRYPT_KEYUSAGE_NONREPUDIATION | \
						 CRYPT_KEYUSAGE_KEYENCIPHERMENT | \
						 CRYPT_KEYUSAGE_KEYCERTSIGN | \
						 CRYPT_KEYUSAGE_CRLSIGN;
	const time_t currentTime = getApproxTime();
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Make sure that we haven't already set up this certificate as a XYZZY
	   certificate */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   CRYPT_CERTINFO_CERTPOLICYID,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && \
		attributeListPtr->valueLength == sizeofOID( OID_CRYPTLIB_XYZZYCERT ) && \
		!memcmp( attributeListPtr->value, OID_CRYPTLIB_XYZZYCERT,
				 attributeListPtr->valueLength ) )
		{
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_XYZZY,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}

	/* Clear any existing attribute values before trying to set new ones.  
	   We don't check the return values for these operations because 
	   depending on whether a component is present or not we could get a
	   success or error status, and in any case any problem with deleting
	   a present component will be caught when we try and set the new value
	   further on */
	certInfoPtr->startTime = certInfoPtr->endTime = 0;
	( void ) deleteCertComponent( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE );
	( void ) deleteCertComponent( certInfoPtr, 
								  CRYPT_CERTINFO_CERTIFICATEPOLICIES );

	/* Give the certificate a 20-year expiry time, make it a self-signed CA 
	   certificate with all key usage types enabled, and set the policy OID 
	   to identify it as a XYZZY certificate */
	certInfoPtr->startTime = currentTime;
	certInfoPtr->endTime = certInfoPtr->startTime + ( 86400L * 365 * 20 );
	certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
	status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_CA,
							   MESSAGE_VALUE_TRUE, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
								   &keyUsage, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_CERTPOLICYID,
								   OID_CRYPTLIB_XYZZYCERT,
								   sizeofOID( OID_CRYPTLIB_XYZZYCERT ) );
	if( cryptStatusOK( status ) )
		{
		attributeListPtr = findAttributeFieldEx( certInfoPtr->attributes,
												 CRYPT_CERTINFO_CERTPOLICYID );
		ENSURES( attributeListPtr != NULL );
		attributeListPtr->flags |= ATTR_FLAG_LOCKED;
		}
	return( status );
	}

/* Set certificate cursor info */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int setCertCursorInfo( INOUT CERT_INFO *certInfoPtr, 
							  IN_RANGE( CRYPT_CURSOR_LAST, \
										CRYPT_CURSOR_FIRST ) /* Values are -ve */
								const int cursorMoveType )
	{
	const BOOLEAN isCertChain = \
					( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN ) ? \
					TRUE : FALSE;
	const BOOLEAN isRTCS = \
					( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
					  certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE ) ? \
					TRUE : FALSE;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( cursorMoveType >= CRYPT_CURSOR_LAST && \
			  cursorMoveType <= CRYPT_CURSOR_FIRST );	/* Values are -ve */
	REQUIRES( isCertChain || \
			  certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			  certInfoPtr->type == CRYPT_CERTTYPE_CRL || isRTCS || \
			  certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
			  certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE );

	/* If it's a single certificate, there's nothing to do.  See the
	   CRYPT_CERTINFO_CURRENT_CERTIFICATE ACL comment for why we
	   (apparently) allow cursor movement movement in single certificates */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE )
		{
		REQUIRES( certInfoPtr->cCertCert->chainEnd <= 0 );

		return( ( cursorMoveType == CRYPT_CURSOR_FIRST || \
				  cursorMoveType == CRYPT_CURSOR_LAST ) ? \
				CRYPT_OK : CRYPT_ERROR_NOTFOUND );
		}

	switch( cursorMoveType )
		{
		case CRYPT_CURSOR_FIRST:
			if( isCertChain )
				{
				/* Set the chain position to -1 (= CRYPT_ERROR) to indicate 
				   that it's at the leaf certificate, which is logically at 
				   position -1 in the chain */
				certInfoPtr->cCertCert->chainPos = CRYPT_ERROR;
				break;
				}
			if( isRTCS )
				{
				CERT_VAL_INFO *certValInfo = certInfoPtr->cCertVal;

				certValInfo->currentValidity = certValInfo->validityInfo;
				if( certValInfo->currentValidity == NULL )
					return( CRYPT_ERROR_NOTFOUND );
				}
			else
				{
				CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;

				certRevInfo->currentRevocation = certRevInfo->revocations;
				if( certRevInfo->currentRevocation == NULL )
					return( CRYPT_ERROR_NOTFOUND );
				}
			break;

		case CRYPT_CURSOR_PREVIOUS:
			if( isCertChain )
				{
				/* Adjust the chain position.  Note that the value can go to
				   -1 (= CRYPT_ERROR) to indicate that it's at the leaf 
				   certificate, which is logically at position -1 in the 
				   chain */
				if( certInfoPtr->cCertCert->chainPos < 0 )
					return( CRYPT_ERROR_NOTFOUND );
				certInfoPtr->cCertCert->chainPos--;
				break;
				}
			if( isRTCS )
				{
				CERT_VAL_INFO *certValInfo = certInfoPtr->cCertVal;
				VALIDITY_INFO *valInfo = certValInfo->validityInfo;
				int iterationCount;

				if( valInfo == NULL || \
					certValInfo->currentValidity == NULL || \
					valInfo == certValInfo->currentValidity )
					{
					/* No validity info or we're already at the start of the 
					   list */
					return( CRYPT_ERROR_NOTFOUND );
					}

				/* Find the previous element in the list */
				for( iterationCount = 0;
					 valInfo != NULL && \
						valInfo->next != certValInfo->currentValidity && \
						iterationCount < FAILSAFE_ITERATIONS_LARGE;
					 valInfo = valInfo->next, iterationCount++ );
				ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
				certValInfo->currentValidity = valInfo;
				}
			else
				{
				CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;
				REVOCATION_INFO *revInfo = certRevInfo->revocations;
				int iterationCount;

				if( revInfo == NULL || \
					certRevInfo->currentRevocation == NULL || \
					revInfo == certRevInfo->currentRevocation )
					{
					/* No revocations or we're already at the start of the 
					   list */
					return( CRYPT_ERROR_NOTFOUND );
					}

				/* Find the previous element in the list.  We use 
				   FAILSAFE_ITERATIONS_MAX as the bound because CRLs can 
				   become enormous */
				for( iterationCount = 0;
					 revInfo != NULL && \
						revInfo->next != certRevInfo->currentRevocation && \
						iterationCount < FAILSAFE_ITERATIONS_MAX;
					 revInfo = revInfo->next, iterationCount++ );
				ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );
				certRevInfo->currentRevocation = revInfo;
				}
			break;

		case CRYPT_CURSOR_NEXT:
			if( isCertChain )
				{
				if( certInfoPtr->cCertCert->chainPos >= certInfoPtr->cCertCert->chainEnd - 1 )
					return( CRYPT_ERROR_NOTFOUND );
				certInfoPtr->cCertCert->chainPos++;
				break;
				}
			if( isRTCS )
				{
				CERT_VAL_INFO *certValInfo = certInfoPtr->cCertVal;

				if( certValInfo->currentValidity == NULL || \
					certValInfo->currentValidity->next == NULL )
					return( CRYPT_ERROR_NOTFOUND );
				certValInfo->currentValidity = certValInfo->currentValidity->next;
				}
			else
				{
				CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;

				if( certRevInfo->currentRevocation == NULL || \
					certRevInfo->currentRevocation->next == NULL )
					return( CRYPT_ERROR_NOTFOUND );
				certRevInfo->currentRevocation = certRevInfo->currentRevocation->next;
				}
			break;

		case CRYPT_CURSOR_LAST:
			if( isCertChain )
				{
				certInfoPtr->cCertCert->chainPos = certInfoPtr->cCertCert->chainEnd - 1;
				break;
				}
			if( isRTCS )
				{
				CERT_VAL_INFO *certValInfo = certInfoPtr->cCertVal;
				VALIDITY_INFO *valInfo = certValInfo->validityInfo;
				int iterationCount;

				if( valInfo == NULL )
					{
					/* No validity info present */
					return( CRYPT_ERROR_NOTFOUND );
					}

				/* Go to the end of the list */
				for( iterationCount = 0;
					 valInfo->next != NULL && \
						iterationCount < FAILSAFE_ITERATIONS_LARGE;
					 valInfo = valInfo->next, iterationCount++ );
				ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
				certValInfo->currentValidity = valInfo;
				}
			else
				{
				CERT_REV_INFO *certRevInfo = certInfoPtr->cCertRev;
				REVOCATION_INFO *revInfo = certRevInfo->revocations;
				int iterationCount;

				if( revInfo == NULL )
					{
					/* No revocations present */
					return( CRYPT_ERROR_NOTFOUND );
					}

				/* Go to the end of the list.  We use FAILSAFE_ITERATIONS_MAX 
				   as the bound because CRLs can become enormous */
				for( iterationCount = 0;
					 revInfo->next != NULL && \
						iterationCount < FAILSAFE_ITERATIONS_MAX;
					revInfo = revInfo->next, iterationCount++ );
				ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );
				certRevInfo->currentRevocation = revInfo;
				}
			break;

		default:
			return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

/* Set attribute cursor info */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int setCursorInfo( INOUT CERT_INFO *certInfoPtr,
						  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE certInfoType,
						  const int value )
	{
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( certInfoType == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
			  certInfoType == CRYPT_ATTRIBUTE_CURRENT || \
			  certInfoType == CRYPT_ATTRIBUTE_CURRENT_INSTANCE );
	REQUIRES( ( value <= CRYPT_CURSOR_FIRST && \
				value >= CRYPT_CURSOR_LAST ) || \
			  ( value >= CRYPT_CERTINFO_FIRST_EXTENSION && \
				value <= CRYPT_CERTINFO_LAST_EXTENSION ) );
			  /* See comment below for the odd CRYPT_CURSOR_xxx comparison */

	/* If the new position is specified relative to a previous position, try
	   and move to that position.  Note that the seemingly illogical
	   comparison is used because the cursor positioning codes are negative
	   values */
	if( value <= CRYPT_CURSOR_FIRST && value >= CRYPT_CURSOR_LAST )
		{
		ATTRIBUTE_LIST *attributeCursor;

		/* If we're moving to an extension field and there's a saved
		   GeneralName selection present we've tried to select a non-present
		   GeneralName so we can't move to a field in it */
		if( certInfoType != CRYPT_ATTRIBUTE_CURRENT_GROUP && \
			certInfoPtr->currentSelection.generalName != CRYPT_ATTRIBUTE_NONE )
			return( CRYPT_ERROR_NOTFOUND );

		/* If it's an absolute positioning code, pre-set the attribute
		   cursor if required */
		if( value == CRYPT_CURSOR_FIRST || value == CRYPT_CURSOR_LAST )
			{
			if( certInfoPtr->attributes == NULL )
				return( CRYPT_ERROR_NOTFOUND );

			/* It's an absolute attribute positioning code, reset the
			   attribute cursor to the start of the list before we try to
			   move it */
			if( certInfoType == CRYPT_ATTRIBUTE_CURRENT_GROUP )
				certInfoPtr->attributeCursor = certInfoPtr->attributes;
			else
				{
				/* It's a field or component positioning code, initialise the
				   attribute cursor if necessary */
				if( certInfoPtr->attributeCursor == NULL )
					certInfoPtr->attributeCursor = certInfoPtr->attributes;
				}

			/* If there are no attributes present return the appropriate
			   error code */
			if( certInfoPtr->attributeCursor == NULL )
				{
				return( ( value == CRYPT_CURSOR_FIRST || \
						  value == CRYPT_CURSOR_LAST ) ? \
						 CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_NOTINITED );
				}
			}
		else
			{
			/* It's a relative positioning code, return a not-inited error
			   rather than a not-found error if the cursor isn't set since
			   there may be attributes present but the cursor hasn't been
			   initialised yet by selecting the first or last absolute
			   attribute */
			if( certInfoPtr->attributeCursor == NULL )
				return( CRYPT_ERROR_NOTINITED );
			}

		/* Move the attribute cursor */
		attributeCursor = certMoveAttributeCursor( certInfoPtr->attributeCursor,
												   certInfoType, value );
		if( attributeCursor == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		certInfoPtr->attributeCursor = attributeCursor;
		syncSelection( certInfoPtr );

		return( CRYPT_OK );
		}

	/* It's a field in an extension, try and move to the start of the
	   extension that contains this field */
	if( certInfoType == CRYPT_ATTRIBUTE_CURRENT_GROUP )
		{
		ATTRIBUTE_LIST *attributeListPtr;

		attributeListPtr = findAttribute( certInfoPtr->attributes, value,
										  TRUE );
		if( attributeListPtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		certInfoPtr->attributeCursor = attributeListPtr;
		syncSelection( certInfoPtr );
		return( CRYPT_OK );
		}

	ENSURES( certInfoType == CRYPT_ATTRIBUTE_CURRENT || \
			 certInfoType == CRYPT_ATTRIBUTE_CURRENT_INSTANCE );
	ENSURES( value >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			 value <= CRYPT_CERTINFO_LAST_EXTENSION );

	/* If it's a GeneralName selection component, locate the attribute field
	   that it corresponds to */
	if( isGeneralNameSelectionComponent( value ) )
		return( selectGeneralName( certInfoPtr, value, MAY_BE_ABSENT ) );

	/* It's a standard attribute field, try and locate it */
	return( moveCursorToField( certInfoPtr, value ) );
	}

/****************************************************************************
*																			*
*									Add a Component							*
*																			*
****************************************************************************/

/* Add a certificate component */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int addCertComponent( INOUT CERT_INFO *certInfoPtr,
					  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  /*?*/ const void *certInfo, 
					  /*?*/ const int certInfoLength )
	{
	CRYPT_CERTIFICATE addedCert;
	CERT_INFO *addedCertInfoPtr;
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isAttribute( certInfoType ) || \
			  isInternalAttribute( certInfoType ) );

	/* If we're adding data to a certificate, clear the error information */
	if( !isPseudoInformation( certInfoType ) )
		clearErrorInfo( certInfoPtr );

	/* If it's a GeneralName or DN component, add it.  These are special-
	   case attribute values so they have to come before the attribute-
	   handling code */
	if( isGeneralNameSelectionComponent( certInfoType ) )
		{
		status = selectGeneralName( certInfoPtr, certInfoType,
									MAY_BE_ABSENT );
		if( cryptStatusError( status ) )
			return( status );
		return( selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
								   MUST_BE_PRESENT ) );
		}
	if( isGeneralNameComponent( certInfoType ) )
		{
		status = selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
									CREATE_IF_ABSENT );
		if( cryptStatusOK( status ) )
			{
			status = addAttributeField( &certInfoPtr->attributes,
					( certInfoPtr->attributeCursor != NULL ) ? \
						certInfoPtr->attributeCursor->fieldID : \
						certInfoPtr->currentSelection.generalName,
					certInfoType, certInfo, certInfoLength, ATTR_FLAG_NONE,
					&certInfoPtr->errorLocus, &certInfoPtr->errorType );
			}
		if( cryptStatusOK( status ) && \
			certInfoPtr->currentSelection.updateCursor )
			{
			/* If we couldn't update the cursor earlier on because the
			   attribute field in question hadn't been created yet, do it
			   now.  Since this is merely a side-effect of this operation, 
			   we ignore the return status and return the main result 
			   status */
			( void ) selectGeneralName( certInfoPtr,
										certInfoPtr->currentSelection.generalName,
										MAY_BE_ABSENT );
			}
		return( status );
		}
	if( isDNComponent( certInfoType ) )
		{
		/* Add the string component to the DN */
		status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
						   CREATE_IF_ABSENT );
		if( cryptStatusOK( status ) )
			status = insertDNComponent( certInfoPtr->currentSelection.dnPtr,
									certInfoType, certInfo, certInfoLength,
									&certInfoPtr->errorType );
		if( cryptStatusOK( status ) && \
			certInfoPtr->currentSelection.updateCursor )
			{
			/* If we couldn't update the cursor earlier on because the
			   attribute field in question hadn't been created yet, do it
			   now.  Since this is merely a side-effect of this operation, 
			   we ignore the return status and return the main result 
			   status */
			( void ) selectGeneralName( certInfoPtr,
										certInfoPtr->currentSelection.generalName,
										MAY_BE_ABSENT );
			}
		if( cryptStatusError( status ) && status != CRYPT_ERROR_MEMORY )
			certInfoPtr->errorLocus = certInfoType;
		return( status );
		}

	/* If it's standard certificate or CMS attribute, add it to the 
	   certificate */
	if( ( certInfoType >= CRYPT_CERTINFO_FIRST_EXTENSION && \
		  certInfoType <= CRYPT_CERTINFO_LAST_EXTENSION ) || \
		( certInfoType >= CRYPT_CERTINFO_FIRST_CMS && \
		  certInfoType <= CRYPT_CERTINFO_LAST_CMS ) )
		{
		int localCertInfoType = certInfoType;

		/* Revocation reason codes are actually a single range of values
		   spread across two different extensions so we adjust the
		   (internal) type based on the reason code value */
		if( certInfoType == CRYPT_CERTINFO_CRLREASON || \
			certInfoType == CRYPT_CERTINFO_CRLEXTREASON )
			{
			localCertInfoType = \
					( *( ( int * ) certInfo ) < CRYPT_CRLREASON_LAST ) ? \
					CRYPT_CERTINFO_CRLREASON : CRYPT_CERTINFO_CRLEXTREASON;
			}

		/* If it's a CRL, RTCS, or OCSP per-entry attribute, add the
		   attribute to the currently selected entry unless it's a
		   revocation request, in which case it goes in with the main
		   attributes */
		if( isRevocationEntryComponent( localCertInfoType ) && \
			certInfoPtr->type != CRYPT_CERTTYPE_REQUEST_REVOCATION )
			{
			if( certInfoPtr->type == CRYPT_CERTTYPE_RTCS_REQUEST || \
				certInfoPtr->type == CRYPT_CERTTYPE_RTCS_RESPONSE )
				{
				if( certInfoPtr->cCertVal->currentValidity == NULL )
					return( CRYPT_ERROR_NOTFOUND );
				return( addAttributeField( \
						&certInfoPtr->cCertVal->currentValidity->attributes,
						localCertInfoType, CRYPT_ATTRIBUTE_NONE,
						certInfo, certInfoLength, ATTR_FLAG_NONE,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType ) );
				}

			ENSURES( certInfoPtr->type == CRYPT_CERTTYPE_CRL || \
					 certInfoPtr->type == CRYPT_CERTTYPE_OCSP_REQUEST || \
					 certInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE );

			if( certInfoPtr->cCertRev->currentRevocation == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			return( addAttributeField( \
						&certInfoPtr->cCertRev->currentRevocation->attributes,
						localCertInfoType, CRYPT_ATTRIBUTE_NONE,
						certInfo, certInfoLength, ATTR_FLAG_NONE,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType ) );
			}

		return( addAttributeField( &certInfoPtr->attributes,
				localCertInfoType, CRYPT_ATTRIBUTE_NONE, certInfo, certInfoLength,
				ATTR_FLAG_NONE, &certInfoPtr->errorLocus, &certInfoPtr->errorType ) );
		}

	/* If it's anything else, handle it specially */
	switch( certInfoType )
		{
		case CRYPT_CERTINFO_SELFSIGNED:
			if( *( ( int * ) certInfo ) )
				certInfoPtr->flags |= CERT_FLAG_SELFSIGNED;
			else
				certInfoPtr->flags &= ~CERT_FLAG_SELFSIGNED;
			return( CRYPT_OK );

		case CRYPT_CERTINFO_XYZZY:
			return( setXyzzyInfo( certInfoPtr ) );

		case CRYPT_CERTINFO_CURRENT_CERTIFICATE:
			return( setCertCursorInfo( certInfoPtr,
									   *( ( int * ) certInfo ) ) );

		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ATTRIBUTE_CURRENT_INSTANCE:
			return( setCursorInfo( certInfoPtr, certInfoType,
								   *( ( int * ) certInfo ) ) );

		case CRYPT_CERTINFO_TRUSTED_USAGE:
			certInfoPtr->cCertCert->trustedUsage = *( ( int * ) certInfo );
			return( CRYPT_OK );

		case CRYPT_CERTINFO_TRUSTED_IMPLICIT:
			return( krnlSendMessage( certInfoPtr->ownerHandle,
									 IMESSAGE_USER_TRUSTMGMT,
									 &certInfoPtr->objectHandle,
									 *( ( int * ) certInfo ) ? \
										MESSAGE_TRUSTMGMT_ADD : \
										MESSAGE_TRUSTMGMT_DELETE ) );

		case CRYPT_CERTINFO_SIGNATURELEVEL:
			certInfoPtr->cCertRev->signatureLevel = *( ( int * ) certInfo );
			return( CRYPT_OK );

		case CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO:
			return( copyPublicKeyInfo( certInfoPtr,
									   *( ( CRYPT_HANDLE * ) certInfo ),
									   NULL ) );

		case CRYPT_CERTINFO_CERTIFICATE:
			/* If it's a certificate, copy across various components or
			   store the entire certificate where required */
			status = krnlSendMessage( *( ( CRYPT_HANDLE * ) certInfo ),
									  IMESSAGE_GETDEPENDENT, &addedCert,
									  OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );

			/* If it's a certificate chain then we're adding the complete 
			   certificate, just store it and exit */
			if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
				{
				int i;

				if( certInfoPtr->cCertCert->chainEnd >= MAX_CHAINLENGTH - 1 )
					return( CRYPT_ERROR_OVERFLOW );

				/* Perform a simple check to make sure that it hasn't been
				   added already */
				for( i = 0; i < certInfoPtr->cCertCert->chainEnd && \
							i < MAX_CHAINLENGTH; i++ )
					{
					if( cryptStatusOK( \
						krnlSendMessage( addedCert, IMESSAGE_COMPARE,
										 &certInfoPtr->cCertCert->chain[ i ],
										 MESSAGE_COMPARE_CERTOBJ ) ) )
						{
						setErrorInfo( certInfoPtr,
									  CRYPT_CERTINFO_CERTIFICATE,
									  CRYPT_ERRTYPE_ATTR_PRESENT );
						return( CRYPT_ERROR_INITED );
						}
					}
				ENSURES( i < MAX_CHAINLENGTH );

				/* Add the user certificate and increment its reference 
				   count */
				krnlSendNotifier( addedCert, IMESSAGE_INCREFCOUNT );
				certInfoPtr->cCertCert->chain[ certInfoPtr->cCertCert->chainEnd++ ] = addedCert;

				return( CRYPT_OK );
				}

			/* For the remaining operations we need access to the user 
			   certificate internals */
			status = krnlAcquireObject( addedCert, OBJECT_TYPE_CERTIFICATE,
										( void ** ) &addedCertInfoPtr,
										CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyUserCertInfo( certInfoPtr, addedCertInfoPtr,
									   *( ( CRYPT_HANDLE * ) certInfo ) );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_CERTINFO_CACERTIFICATE:
			/* We can't add another CA certificate if there's already one 
			   present, in theory this is valid but it's more likely to be 
			   an implementation problem than an attempt to query multiple 
			   CAs through a single responder */
			if( certInfoPtr->certHashSet )
				{
				setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CACERTIFICATE,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			ENSURES( certInfoPtr->version == 1 );

			/* Get the certificate handle and make sure that it really is a 
			   CA certificate */
			status = krnlSendMessage( *( ( CRYPT_HANDLE * ) certInfo ),
									  IMESSAGE_GETDEPENDENT, &addedCert,
									  OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );
			if( cryptStatusError( \
					krnlSendMessage( addedCert, IMESSAGE_CHECK, NULL,
									 MESSAGE_CHECK_CA ) ) )
				return( CRYPT_ARGERROR_NUM1 );
			status = krnlAcquireObject( addedCert, OBJECT_TYPE_CERTIFICATE,
										( void ** ) &addedCertInfoPtr,
										CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyCaCertInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_CERTINFO_SERIALNUMBER:
			ENSURES( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE );
			if( certInfoPtr->cCertCert->serialNumber != NULL )
				{
				setErrorInfo( certInfoPtr, CRYPT_CERTINFO_SERIALNUMBER,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			return( setSerialNumber( certInfoPtr, certInfo,
									 certInfoLength ) );

		case CRYPT_CERTINFO_SUBJECTNAME:
		case CRYPT_CERTINFO_ISSUERNAME:
			if( *( ( int * ) certInfo ) != CRYPT_UNUSED )
				return( CRYPT_ARGERROR_NUM1 );
			return( selectDN( certInfoPtr, certInfoType, MAY_BE_ABSENT ) );

		case CRYPT_CERTINFO_VALIDFROM:
		case CRYPT_CERTINFO_THISUPDATE:
			{
			time_t certTime = *( ( time_t * ) certInfo );

			if( certInfoPtr->startTime > 0 )
				{
				setErrorInfo( certInfoPtr, certInfoType,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			if( certInfoPtr->endTime > 0 && \
				certTime >= certInfoPtr->endTime )
				{
				setErrorInfo( certInfoPtr,
							  ( certInfoType == CRYPT_CERTINFO_VALIDFROM ) ? \
								CRYPT_CERTINFO_VALIDTO : CRYPT_CERTINFO_NEXTUPDATE,
							  CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ARGERROR_STR1 );
				}
			certInfoPtr->startTime = certTime;
			return( CRYPT_OK );
			}

		case CRYPT_CERTINFO_VALIDTO:
		case CRYPT_CERTINFO_NEXTUPDATE:
			{
			time_t certTime = *( ( time_t * ) certInfo );

			if( certInfoPtr->endTime > 0 )
				{
				setErrorInfo( certInfoPtr, certInfoType,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			if( certInfoPtr->startTime > 0 && \
				certTime <= certInfoPtr->startTime )
				{
				setErrorInfo( certInfoPtr,
							  ( certInfoType == CRYPT_CERTINFO_VALIDTO ) ? \
								CRYPT_CERTINFO_VALIDFROM : CRYPT_CERTINFO_THISUPDATE,
							  CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ARGERROR_STR1 );
				}
			certInfoPtr->endTime = certTime;
			return( CRYPT_OK );
			}

		case CRYPT_CERTINFO_CERTREQUEST:
			/* Make sure that we haven't already got a public key or DN
			   present */
			if( ( certInfoPtr->iPubkeyContext != CRYPT_ERROR || \
				  certInfoPtr->publicKeyInfo != NULL ) || \
				certInfoPtr->subjectName != NULL )
				{
				setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTREQUEST,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}

			status = krnlAcquireObject( *( ( CRYPT_CERTIFICATE * ) certInfo ),
										OBJECT_TYPE_CERTIFICATE,
										( void ** ) &addedCertInfoPtr,
										CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyCertReqInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_CERTINFO_REVOCATIONDATE:
			{
			time_t certTime = *( ( time_t * ) certInfo );
			time_t *revocationTimePtr = getRevocationTimePtr( certInfoPtr );

			if( *revocationTimePtr > 0 )
				{
				setErrorInfo( certInfoPtr, certInfoType,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INITED );
				}
			*revocationTimePtr = certTime;
			return( CRYPT_OK );
			}

		case CRYPT_CERTINFO_DN:
			return( getEncodedDn( certInfoPtr, certInfo, certInfoLength ) );

		case CRYPT_IATTRIBUTE_CRLENTRY:
			{
			STREAM stream;

			ENSURES( certInfoPtr->type == CRYPT_CERTTYPE_CRL );

			/* The revocation information is being provided to us in pre-
			   encoded form from a certificate store, decode it so that we 
			   can add it to the CRL */
			sMemConnect( &stream, certInfo, certInfoLength );
			status = readCRLentry( &stream,
								   &certInfoPtr->cCertRev->revocations,
								   &certInfoPtr->errorLocus,
								   &certInfoPtr->errorType );
			sMemDisconnect( &stream );
			return( status );
			}

		case CRYPT_IATTRIBUTE_CERTCOLLECTION:
			return( copyCertChain( certInfoPtr,
								   *( ( CRYPT_CERTIFICATE * ) certInfo ),
								   TRUE ) );

		case CRYPT_IATTRIBUTE_RTCSREQUEST:
			status = krnlAcquireObject( *( ( CRYPT_CERTIFICATE * ) certInfo ),
										OBJECT_TYPE_CERTIFICATE,
										( void ** ) &addedCertInfoPtr,
										CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyRtcsReqInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_IATTRIBUTE_OCSPREQUEST:
			status = krnlAcquireObject( *( ( CRYPT_CERTIFICATE * ) certInfo ),
										OBJECT_TYPE_CERTIFICATE,
										( void ** ) &addedCertInfoPtr,
										CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyOcspReqInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_IATTRIBUTE_REVREQUEST:
			status = krnlAcquireObject( *( ( CRYPT_CERTIFICATE * ) certInfo ),
										OBJECT_TYPE_CERTIFICATE,
										( void ** ) &addedCertInfoPtr,
										CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyRevReqInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_IATTRIBUTE_PKIUSERINFO:
			status = krnlAcquireObject( *( ( CRYPT_HANDLE * ) certInfo ),
										OBJECT_TYPE_CERTIFICATE,
										( void ** ) &addedCertInfoPtr,
										CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = copyPkiUserInfo( certInfoPtr, addedCertInfoPtr );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_IATTRIBUTE_BLOCKEDATTRS:
			status = krnlAcquireObject( *( ( CRYPT_HANDLE * ) certInfo ),
										OBJECT_TYPE_CERTIFICATE,
										( void ** ) &addedCertInfoPtr,
										CRYPT_ARGERROR_NUM1 );
			if( cryptStatusError( status ) )
				return( status );
			status = sanitiseCertAttributes( certInfoPtr,
											 addedCertInfoPtr->attributes );
			krnlReleaseObject( addedCertInfoPtr->objectHandle );
			return( status );

		case CRYPT_IATTRIBUTE_AUTHCERTID:
			ENSURES( certInfoLength == KEYID_SIZE );
			memcpy( certInfoPtr->cCertReq->authCertID, certInfo, KEYID_SIZE );
			return( CRYPT_OK );
		}

	retIntError();
	}
