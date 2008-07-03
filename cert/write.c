/****************************************************************************
*																			*
*							Certificate Write Routines						*
*						Copyright Peter Gutmann 1996-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* The X.509 version numbers */

enum { X509VERSION_1, X509VERSION_2, X509VERSION_3 };

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Add standard X.509v3 extensions to a certificate if they're not already 
   present.  This function simply adds the required extensions, it doesn't 
   check for consistency with existing extensions which is done later by 
   checkCert() */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int addStandardExtensions( INOUT CERT_INFO *certInfoPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	BOOLEAN isCA = FALSE;
	int keyUsage, extKeyUsage, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Get various pieces of information about the certificate.  We do this 
	   before we make any changes so that we can safely bail out if 
	   necessary.  First we get the implicit key usage flags (based on any 
	   extended key usage extensions present) and explicit key usage flags.  
	   Since these are required to be consistent we extend the keyUsage 
	   with extKeyUsage flags further on if necessary */
	status = getKeyUsageFromExtKeyUsage( certInfoPtr, &extKeyUsage,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   CRYPT_CERTINFO_KEYUSAGE,
										   CRYPT_ATTRIBUTE_NONE );
	keyUsage = ( attributeListPtr != NULL ) ? \
			   attributeListPtr->intValue : 0;

	/* If there's an explicit key usage present, make sure that it's
	   consistent with the implicit key usage flags derived from the 
	   extended key usage.  We mask out the nonRepudiation bit for reasons 
	   given in chk_cert.c.

	   This check is also performed by checkCert(), however we need to
	   explicitly perform it here as well since we need to add a key usage 
	   to match the extKeyUsage before calling checkCert() if one wasn't
	   explicitly set or checkCert() will reject the certificate because of 
	   the inconsistent keyUsage */
	if( keyUsage > 0 )
		{
		const int effectiveKeyUsage = \
						extKeyUsage & ~CRYPT_KEYUSAGE_NONREPUDIATION;

		if( ( keyUsage & effectiveKeyUsage ) != effectiveKeyUsage )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* Check whether this is a CA certificate */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   CRYPT_CERTINFO_CA,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		isCA = ( attributeListPtr->intValue > 0 ) ? TRUE : FALSE;

	/* If there's no basicConstraints present, add one and make it a non-CA
	   certificate */
	if( attributeListPtr == NULL )
		{
		static const int basicConstraints = 0;

		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_CA,
								   &basicConstraints, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If there's no explicit keyUsage information present, add it based on
	   various implicit information.  We also add key feature information
	   which is used to help automate key management, for example to inhibit
	   speculative reads of keys held in removable tokens, which can result
	   in spurious insert-token dialogs being presented to the user outside
	   the control of cryptlib if the token isn't present */
	if( keyUsage <= 0 )
		{
		/* If there's no implicit key usage present, set the key usage flags
		   based on the algorithm type.  Because no-one can figure out what
		   the nonRepudiation flag signifies we don't set this, if the user
		   wants it they have to specify it explicitly.  Similarly, we don't
		   try and set the keyAgreement encipher/decipher-only flags, which
		   were tacked on as variants of keyAgreement long after the basic
		   keyAgreement flag was defined */
		if( extKeyUsage <= 0 && !isCA )
			{
			if( isSigAlgo( certInfoPtr->publicKeyAlgo ) )
				keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE;
			if( isCryptAlgo( certInfoPtr->publicKeyAlgo ) )
				keyUsage |= CRYPT_KEYUSAGE_KEYENCIPHERMENT;
			if( isKeyxAlgo( certInfoPtr->publicKeyAlgo ) )
				keyUsage |= CRYPT_KEYUSAGE_KEYAGREEMENT;
			}
		else
			{
			/* Make the usage consistent with the extended usage */
			keyUsage = extKeyUsage;

			/* If it's a CA key, make sure that it's a signing key and
			   enable its use for certification-related purposes*/
			if( isCA )
				{
				if( !isSigAlgo( certInfoPtr->publicKeyAlgo ) )
					{
					setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CA,
								  CRYPT_ERRTYPE_CONSTRAINT );
					return( CRYPT_ERROR_INVALID );
					}
				keyUsage |= CRYPT_KEYUSAGE_KEYCERTSIGN | \
							CRYPT_KEYUSAGE_CRLSIGN;
				}
			}
		assert( keyUsage > 0 );
		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
								   &keyUsage, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( certInfoPtr->publicKeyFeatures > 0 )
		{
		/* This is a bitstring so we only add it if there are feature flags
		   present to avoid writing zero-length values */
		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_KEYFEATURES,
								   &certInfoPtr->publicKeyFeatures,
								   CRYPT_UNUSED );
		if( cryptStatusError( status ) && status != CRYPT_ERROR_INITED )
			return( status );
		}

	/* Add the subjectKeyIdentifier */
	return( addCertComponent( certInfoPtr, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
							  certInfoPtr->publicKeyID, KEYID_SIZE ) );
	}

/****************************************************************************
*																			*
*							Pre-encode Checking Functions					*
*																			*
****************************************************************************/

/* Check whether an empty DN is permitted in a certificate */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkEmptyDnOK( INOUT CERT_INFO *subjectCertInfoPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int complianceLevel;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	/* PKIX allows empty subject DNs if a subject altName is present, 
	   however creating certificates like this breaks every certificate-
	   using protocol supported by cryptlib so we only allow it at the 
	   highest compliance level */
	if( cryptStatusError( \
			krnlSendMessage( subjectCertInfoPtr->ownerHandle,
							 IMESSAGE_GETATTRIBUTE, &complianceLevel,
							 CRYPT_OPTION_CERT_COMPLIANCELEVEL ) ) || \
		complianceLevel < CRYPT_COMPLIANCELEVEL_PKIX_FULL )
		{
		/* We only allow this behaviour at the highest compliance level */
		return( FALSE );
		}
	   
	/* We also have to be very careful to ensure that the empty subject 
	   DN can't end up becoming an empty issuer DN, which can occur if it's 
	   a self-signed certificate */
	if( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED )
		{
		/* We can't have an empty issuer (== subject) DN */
		return( FALSE );
		}

	/* In addition if it's a CA certificate the subject DN can't be empty, 
	   for obvious reasons */
	attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && attributeListPtr->intValue > 0 )
		{
		/* It's a CA certificate then the subject DN can't be empty */
		return( FALSE );
		}

	/* Finally, if there's no subject DN present there has to be an altName
	   present to take its place */
	attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
										   CRYPT_CERTINFO_SUBJECTALTNAME,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr == NULL )
		{
		/* Either a subject DN or subject altName must be present */
		return( FALSE );
		}

	/* There's a subject altName present but no subject DN, mark the altName 
	   as critical */
	attributeListPtr->flags |= ATTR_FLAG_CRITICAL;

	return( TRUE );
	}

/* Before we encode a certificate object, we have to perform various final 
   setup actions and perform checks to ensure that the object is ready for
   encoding.  The following setup operations and checks can be requested by
   the caller:

	CHECK_DN: Full subject DN is present.

	CHECK_DN_PARTIAL: Partial subject DN is present.  This is a DN template,
		so the full DN doesn't have to be present since the CA can fill in
		the rest later.

	CHECK_ISSUERDN: Issuer DN is present.

	CHECK_ISSUERCERTDN: Issuer certificate's subject DN == subject 
		certificate's issuer DN.

	CHECK_NONSELFSIGNEDDN: Certificate's subject DN != certificate's issuer 
		DN, which would make it appear to be a self-signed certificate.

	CHECK_REVENTRIES: At least one revocation entry is present.

	CHECK_SERIALNO: Serial number is present.

	CHECK_SPKI: SubjectPublicKeyInfo is present.

	CHECK_VALENTRIES: At least one validity entry is present.

	SET_ISSUERATTR: Copy issuer attributes to subject.

	SET_ISSUERDN: Copy issuer DN to subject.

	SET_REVINFO: Set up revocation info.

	SET_STANDARDATTR: Set up standard extensions/attributes.

	SET_VALIDITYPERIOD: Constrain subject validity to issuer validity.

	SET_VALINFO: Set up validity info */

#define PRE_CHECK_NONE			0x0000	/* No check actions */
#define PRE_CHECK_SPKI			0x0001	/* SPKI present */
#define PRE_CHECK_DN			0x0002	/* Subject DN present */
#define PRE_CHECK_DN_PARTIAL	0x0004	/* Partial subject DN present */
#define PRE_CHECK_ISSUERDN		0x0008	/* Issuer DN present */
#define PRE_CHECK_ISSUERCERTDN	0x0010	/* Issuer cert DN == subj.issuer DN */
#define PRE_CHECK_NONSELFSIGNED_DN 0x0020	/* Issuer DN != subject DN */
#define PRE_CHECK_SERIALNO		0x0040	/* SerialNo present */
#define PRE_CHECK_VALENTRIES	0x0080	/* Validity entries present */
#define PRE_CHECK_REVENTRIES	0x0100	/* Revocation entries present */

#define PRE_CHECK_FLAG_NONE		0x0000	/* No check actions */
#define PRE_CHECK_FLAG_MAX		0x01FF	/* Maximum possible flag value */

#define PRE_SET_NONE			0x0000	/* No setup actions */
#define PRE_SET_STANDARDATTR	0x0001	/* Set up standard extensions */
#define PRE_SET_ISSUERATTR		0x0002	/* Copy issuer attr.to subject */
#define PRE_SET_ISSUERDN		0x0004	/* Copy issuer DN to subject */
#define PRE_SET_VALIDITYPERIOD	0x0008	/* Constrain subj.val.to issuer val.*/
#define PRE_SET_VALINFO			0x0010	/* Set up validity info */
#define PRE_SET_REVINFO			0x0020	/* Set up revocation info */

#define PRE_SET_FLAG_NONE		0x0000	/* No setup actions */
#define PRE_SET_FLAG_MAX		0x003F	/* Maximum possible flag value */

/* Additional flags that control the operations indicated above */

#define PRE_FLAG_NONE			0x0000	/* No special control options */
#define PRE_FLAG_DN_IN_ISSUERCERT 0x0001/* Issuer DN is in issuer cert */
#define PRE_FLAG_MAX			0x0001	/* Maximum possible flag value */

/* The checks for the different object types are:

				|  Cert	|  Attr	|  P10	|Cr.Req	|Rv.Req	
	------------+-------+-------+-------+-------+-------+
	STDATTR		|	X	|		|		|		|		|
	ISSUERATTR	|	X	|	X	|		|		|		|
	ISSUERDN	|	X	|	X	|		|		|		|
	VALPERIOD	|	X	|	X	|		|		|		|
	VALINFO		|		|		|		|		|		|
	REVINFO		|		|		|		|		|		|
	------------+-------+-------+-------+-------+-------+
	SPKI		|	X	|		|	X	|	X	|		|
	DN			|	X	|	X	|		|		|		|
	DN_PART		|		|		|	X	|	X	|		|
	ISSUERDN	|	X	|	X	|		|		|	X	|
	ISSUERCRTDN	|		|		|		|		|		|
	NON_SELFSD	|	X	|	X	|		|		|		|
	SERIALNO	|	X	|	X	|		|		|	X	|
	REVENTRIES	|		|		|		|		|		|
	------------+-------+-------+-------+-------+-------+

				|RTCS Rq|RTCS Rs|OCSP Rq|OCSP Rs|  CRL	|CRLentr|
	------------+-------+-------+-------+-------+-------+-------+
	STDATTR		|		|		|		|		|		|		|
	ISSUERATTR	|		|		|		|		|	X	|		|
	ISSUERDN	|		|		|		|		|	X	|		|
	VALPERIOD	|		|		|		|		|		|		|
	VALINFO		|	X	|		|		|		|		|		|
	REVINFO		|		|		|	X	|		|	X	|	X	|
	------------+-------+-------+-------+-------+-------+-------+
	SPKI		|		|		|		|		|		|		|
	DN			|		|		|		|	X	|		|		|
	DN_PART		|		|		|		|		|		|		|
	ISSUERDN	|		|		|		|		|	X	|		|
	ISSUERCRTDN	|		|		|		|		|	X	|		|
	NON_SELFSD	|		|		|		|		|		|		|
	SERIALNO	|		|		|		|		|		|		|
	VALENTRIES	|	X	|		|		|		|		|		|
	REVENTRIES	|		|		|	X	|	X	|		|		|
	------------+-------+-------+-------+-------+-------+-------+ */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int preEncodeCertificate( INOUT CERT_INFO *subjectCertInfoPtr,
								 IN_OPT const CERT_INFO *issuerCertInfoPtr,
								 IN_FLAGS( PRE_SET ) const int setActions, 
								 IN_FLAGS( PRE_CHECK ) const int checkActions, 
								 IN_FLAGS( PRE ) const int flags )
	{
	int status;

	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( ( issuerCertInfoPtr == NULL ) || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( setActions >= PRE_SET_NONE && \
			  setActions <= PRE_SET_FLAG_MAX );
	REQUIRES( checkActions >= PRE_CHECK_NONE && \
			  checkActions <= PRE_CHECK_FLAG_MAX );
	REQUIRES( flags == PRE_FLAG_NONE || \
			  flags == PRE_FLAG_DN_IN_ISSUERCERT );
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/* Correlate flags with pointers being null/nonnull */
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

	/* Make sure that everything is in order.  Some of the checks depend on 
	   data that isn't set up yet, so first perform all of the setup actions
	   that add default and issuer-contributed attributes, and then perform
	   all of the checks */
	if( setActions & PRE_SET_STANDARDATTR )
		{
		/* If it's a >= v3 certificate add the standard X.509v3 extensions 
		   if these aren't already present */
		if( subjectCertInfoPtr->version >= 3 )
			{
			status = addStandardExtensions( subjectCertInfoPtr );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	if( setActions & PRE_SET_ISSUERATTR )
		{
		/* Copy any required extensions from the issuer to the subject 
		   certificate if necessary */
		if( !( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) )
			{
			status = copyIssuerAttributes( &subjectCertInfoPtr->attributes,
										   issuerCertInfoPtr->attributes,
										   subjectCertInfoPtr->type,
										   &subjectCertInfoPtr->errorLocus,
										   &subjectCertInfoPtr->errorType );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	if( setActions & PRE_SET_ISSUERDN )
		{
		/* Copy the issuer DN if this isn't already present */
		if( subjectCertInfoPtr->issuerName == NULL )
			{
			status = copyDN( &subjectCertInfoPtr->issuerName,
							 issuerCertInfoPtr->subjectName );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	if( setActions & PRE_SET_VALIDITYPERIOD )
		{
		/* Constrain the subject validity period to be within the issuer
		   validity period */
		if( subjectCertInfoPtr->startTime < issuerCertInfoPtr->startTime )
			subjectCertInfoPtr->startTime = issuerCertInfoPtr->startTime;
		if( subjectCertInfoPtr->endTime > issuerCertInfoPtr->endTime )
			subjectCertInfoPtr->endTime = issuerCertInfoPtr->endTime;
		}
	if( setActions & PRE_SET_VALINFO )
		{
		/* If it's an RTCS response, prepare the certificate status list 
		   entries prior to encoding them */
		status = prepareValidityEntries( subjectCertInfoPtr->cCertVal->validityInfo,
										 &subjectCertInfoPtr->cCertVal->currentValidity,
										 &subjectCertInfoPtr->errorLocus,
										 &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( setActions & PRE_SET_REVINFO )
		{
		REVOCATION_INFO *revocationErrorEntry;
		const BOOLEAN isCrlEntry = checkActions ? FALSE : TRUE;

		/* If it's a CRL or OCSP response, prepare the revocation list
		   entries prior to encoding them */
		status = prepareRevocationEntries( subjectCertInfoPtr->cCertRev->revocations,
										   subjectCertInfoPtr->cCertRev->revocationTime,
										   &revocationErrorEntry, isCrlEntry,
										   &subjectCertInfoPtr->errorLocus,
										   &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			{
			/* If there was an error and we're processing an entire 
			   revocation list, select the entry that caused the problem */
			if( !isCrlEntry )
				{
				subjectCertInfoPtr->cCertRev->currentRevocation = \
													revocationErrorEntry;
				}
			return( status );
			}
		}

	/* Now that everything's set up, check that the object is reading for 
	   encoding */
	if( checkActions & PRE_CHECK_SPKI )
		{
		/* Make sure that there's public-key info present */
		if( subjectCertInfoPtr->publicKeyInfo == NULL )
			{
			setErrorInfo( subjectCertInfoPtr, 
						  CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}
	if( checkActions & PRE_CHECK_DN )
		{
		/* Make sure that there's a full DN present */
		status = checkDN( subjectCertInfoPtr->subjectName, TRUE, FALSE,
						  &subjectCertInfoPtr->errorLocus,
						  &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			{
			/* In some very special cases an empty DN is permitted, so we
			   only return an error if this really isn't allowed */
			if( status != CRYPT_ERROR_NOTINITED || \
				!checkEmptyDnOK( subjectCertInfoPtr ) )
				return( status );
			}
		}
	if( checkActions & PRE_CHECK_DN_PARTIAL )
		{
		/* Make sure that there's at least a partial DN present (some CA's 
		   will fill the remainder themselves) */
		status = checkDN( subjectCertInfoPtr->subjectName, TRUE, TRUE,
						  &subjectCertInfoPtr->errorLocus,
						  &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( checkActions & PRE_CHECK_ISSUERDN )
		{
		if( flags & PRE_FLAG_DN_IN_ISSUERCERT )
			{
			if( issuerCertInfoPtr == NULL || \
				issuerCertInfoPtr->subjectDNptr == NULL || \
				issuerCertInfoPtr->subjectDNsize < 1 )
				{
				setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			}
		else
			{
			/* The issuer DN can be present either in pre-encoded form (if
			   it was copied from an issuer certificate) or as a full DN (if 
			   it's a self-signed certificate), so we check for the presence 
			   of either */
			if( ( subjectCertInfoPtr->issuerName == NULL ) && 
				( subjectCertInfoPtr->issuerDNptr == NULL || \
				  subjectCertInfoPtr->issuerDNsize < 1 ) )
				{
				setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			}
		}
	if( checkActions & PRE_CHECK_ISSUERCERTDN )
		{
		/* If it's a CRL, compare the revoked certificate issuer DN and 
		   signer DN to make sure that we're not trying to revoke someone 
		   else's certificates, and prepare the revocation entries */
		if( !compareDN( subjectCertInfoPtr->issuerName,
						issuerCertInfoPtr->subjectName, FALSE ) )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ERROR_INVALID );
			}
		}
	if( checkActions & PRE_CHECK_NONSELFSIGNED_DN )
		{
		/* If we're creating a non-self-signed certificate check whether the
		   subject's DN is the same as the issuer's DN.  If this is the 
		   case then the resulting object would appear to be self-signed so 
		   we disallow it */
		if( compareDN( issuerCertInfoPtr->subjectName,
					   subjectCertInfoPtr->subjectName, FALSE ) )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SUBJECTNAME,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}
	if( checkActions & PRE_CHECK_SERIALNO )
		{
		if( subjectCertInfoPtr->type == CRYPT_CERTTYPE_REQUEST_REVOCATION )
			{
			if( subjectCertInfoPtr->cCertReq->serialNumberLength <= 0 )
				{
				setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SERIALNUMBER,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			}
		else
			{
			if( subjectCertInfoPtr->cCertCert->serialNumberLength <= 0 )
				{
				setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SERIALNUMBER,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			}
		}
	if( checkActions & PRE_CHECK_VALENTRIES )
		{
		if( subjectCertInfoPtr->cCertVal->validityInfo == NULL )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}
	if( checkActions & PRE_CHECK_REVENTRIES )
		{
		if( subjectCertInfoPtr->cCertRev->revocations == NULL )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}
		}

	/* Now that we've set up the attributes, perform the remainder of the
	   checks.  Because RTCS is a CMS standard rather than PKIX, the RTCS
	   attributes are CMS rather than certificate attributes */
	if( subjectCertInfoPtr->attributes != NULL )
		{
		status = checkAttributes( ( subjectCertInfoPtr->type == \
									CRYPT_CERTTYPE_RTCS_REQUEST ) ? \
								  ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE,
								  subjectCertInfoPtr->attributes,
								  &subjectCertInfoPtr->errorLocus,
								  &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = checkCert( subjectCertInfoPtr, issuerCertInfoPtr, FALSE,
						&subjectCertInfoPtr->errorLocus,
						&subjectCertInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a certificate or certificate chain remember that it's been 
	   checked at full compliance level.  This short-circuits the need to 
	   perform excessive levels of checking if the caller wants to re-check 
	   it after it's been signed */
	if( subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
		subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
		{
		subjectCertInfoPtr->cCertCert->maxCheckLevel = \
									CRYPT_COMPLIANCELEVEL_PKIX_FULL;
		}

	return( status );
	}

/****************************************************************************
*																			*
*							Write a Certificate Object						*
*																			*
****************************************************************************/

/* Write certificate information:

	CertificateInfo ::= SEQUENCE {
		version			  [ 0 ]	EXPLICIT INTEGER DEFAULT(0),
		serialNumber			INTEGER,
		signature				AlgorithmIdentifier,
		issuer					Name
		validity				Validity,
		subject					Name,
		subjectPublicKeyInfo	SubjectPublicKeyInfo,
		extensions		  [ 3 ]	Extensions OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeCertInfo( INOUT STREAM *stream, 
						  INOUT CERT_INFO *subjectCertInfoPtr,
						  const CERT_INFO *issuerCertInfoPtr,
						  IN_HANDLE const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_CERT_INFO *certCertInfo = subjectCertInfoPtr->cCertCert;
	const int algoIdInfoSize = \
			sizeofContextAlgoID( iIssuerCryptContext, certCertInfo->hashAlgo );
	int length, extensionSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );
	
	REQUIRES( isHandleRangeValid( iIssuerCryptContext ) );

	if( cryptStatusError( algoIdInfoSize ) )
		return( algoIdInfoSize  );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
						PRE_SET_STANDARDATTR | PRE_SET_ISSUERATTR | \
						PRE_SET_ISSUERDN | PRE_SET_VALIDITYPERIOD, 
						PRE_CHECK_SPKI | PRE_CHECK_DN | \
						PRE_CHECK_ISSUERDN | PRE_CHECK_SERIALNO | \
						( ( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) ? \
							0 : PRE_CHECK_NONSELFSIGNED_DN ),
						( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
							PRE_FLAG_DN_IN_ISSUERCERT : PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how the issuer name will be encoded */
	subjectCertInfoPtr->issuerDNsize = \
							( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
							issuerCertInfoPtr->subjectDNsize : \
							sizeofDN( subjectCertInfoPtr->issuerName );
	subjectCertInfoPtr->subjectDNsize = \
							sizeofDN( subjectCertInfoPtr->subjectName );

	/* Determine the size of the certificate information */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = sizeofInteger( certCertInfo->serialNumber,
							certCertInfo->serialNumberLength ) + \
			 algoIdInfoSize + \
			 subjectCertInfoPtr->issuerDNsize + \
			 sizeofObject( sizeofUTCTime() * 2 ) + \
			 subjectCertInfoPtr->subjectDNsize + \
			 subjectCertInfoPtr->publicKeyInfoSize;
	if( extensionSize > 0 )
		{
		length += sizeofObject( sizeofShortInteger( X509VERSION_3 ) ) + \
				  sizeofObject( sizeofObject( extensionSize ) );
		}

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If there are extensions present, mark this as a v3 certificate */
	if( extensionSize > 0 )
		{
		writeConstructed( stream, sizeofShortInteger( X509VERSION_3 ),
						  CTAG_CE_VERSION );
		writeShortInteger( stream, X509VERSION_3, DEFAULT_TAG );
		}

	/* Write the serial number and signature algorithm identifier */
	writeInteger( stream, certCertInfo->serialNumber,
				  certCertInfo->serialNumberLength, DEFAULT_TAG );
	status = writeContextAlgoID( stream, iIssuerCryptContext,
								 certCertInfo->hashAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the issuer name, validity period, subject name, and public key
	   information */
	if( issuerCertInfoPtr->subjectDNptr != NULL )
		status = swrite( stream, issuerCertInfoPtr->subjectDNptr,
						 issuerCertInfoPtr->subjectDNsize );
	else
		status = writeDN( stream, subjectCertInfoPtr->issuerName, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	writeSequence( stream, sizeofUTCTime() * 2 );
	writeUTCTime( stream, subjectCertInfoPtr->startTime, DEFAULT_TAG );
	writeUTCTime( stream, subjectCertInfoPtr->endTime, DEFAULT_TAG );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		status = swrite( stream, subjectCertInfoPtr->publicKeyInfo,
						 subjectCertInfoPtr->publicKeyInfoSize );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the extensions */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_CERTIFICATE, extensionSize ) );
	}

/* Write attribute certificate information:

	AttributeCertificateInfo ::= SEQUENCE {
		version					INTEGER DEFAULT(1),
		owner			  [ 1 ]	Name,
		issuer					Name,
		signature				AlgorithmIdentifier,
		serialNumber			INTEGER,
		validity				Validity,
		attributes				SEQUENCE OF Attribute,
		extensions				Extensions OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeAttributeCertInfo( INOUT STREAM *stream,
								   INOUT CERT_INFO *subjectCertInfoPtr,
								   const CERT_INFO *issuerCertInfoPtr,
								   IN_HANDLE const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_CERT_INFO *certCertInfo = subjectCertInfoPtr->cCertCert;
	const int algoIdInfoSize = \
			sizeofContextAlgoID( iIssuerCryptContext, certCertInfo->hashAlgo );
	int length, extensionSize, issuerNameSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iIssuerCryptContext ) );

	if( cryptStatusError( algoIdInfoSize ) )
		return( algoIdInfoSize  );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
						PRE_SET_ISSUERDN | PRE_SET_ISSUERATTR | \
						PRE_SET_VALIDITYPERIOD, 
						PRE_CHECK_DN | PRE_CHECK_ISSUERDN | \
						PRE_CHECK_SERIALNO | \
						( ( subjectCertInfoPtr->flags & CERT_FLAG_SELFSIGNED ) ? \
							0 : PRE_CHECK_NONSELFSIGNED_DN ),
						( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
							PRE_FLAG_DN_IN_ISSUERCERT : PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how the issuer name will be encoded */
	issuerNameSize = ( issuerCertInfoPtr->subjectDNptr != NULL ) ? \
					 issuerCertInfoPtr->subjectDNsize : \
					 sizeofDN( subjectCertInfoPtr->issuerName );

	/* Determine the size of the certificate information */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = ( int ) sizeofObject( sizeofDN( subjectCertInfoPtr->subjectName ) ) + \
			 issuerNameSize + \
			 algoIdInfoSize + \
			 sizeofInteger( certCertInfo->serialNumber,
							certCertInfo->serialNumberLength ) + \
			 sizeofObject( sizeofUTCTime() * 2 ) + \
			 sizeofObject( 0 ) + \
			 ( ( extensionSize > 0 ) ? \
				( int ) sizeofObject( extensionSize ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* Write the owner and issuer name */
	writeConstructed( stream, sizeofDN( subjectCertInfoPtr->subjectName ),
					  CTAG_AC_ENTITYNAME );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		if( issuerCertInfoPtr->subjectDNptr != NULL )
			status = swrite( stream, issuerCertInfoPtr->subjectDNptr,
							 issuerCertInfoPtr->subjectDNsize );
		else
			status = writeDN( stream, subjectCertInfoPtr->issuerName, DEFAULT_TAG );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the signature algorithm identifier, serial number and validity
	   period */
	writeContextAlgoID( stream, iIssuerCryptContext, certCertInfo->hashAlgo );
	writeInteger( stream, certCertInfo->serialNumber,
				  certCertInfo->serialNumberLength, DEFAULT_TAG );
	writeSequence( stream, sizeofUTCTime() * 2 );
	writeUTCTime( stream, subjectCertInfoPtr->startTime, DEFAULT_TAG );
	writeUTCTime( stream, subjectCertInfoPtr->endTime, DEFAULT_TAG );

	/* Write the attributes */
	status = writeSequence( stream, 0 );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the extensions */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_ATTRIBUTE_CERT, extensionSize ) );
	}

/* Write certificate request information:

	CertificationRequestInfo ::= SEQUENCE {
		version					INTEGER (0),
		subject					Name,
		subjectPublicKeyInfo	SubjectPublicKeyInfo,
		attributes		  [ 0 ]	SET OF Attribute
		}

   If extensions are present they are encoded as:

	SEQUENCE {							-- Attribute from X.501
		OBJECT IDENTIFIER {pkcs-9 14},	--   type
		SET OF {						--   values
			SEQUENCE OF {				-- ExtensionReq from CMMF draft
				<X.509v3 extensions>
				}
			}
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCertRequestInfo( INOUT STREAM *stream,
								 INOUT CERT_INFO *subjectCertInfoPtr,
								 STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
								 IN_HANDLE const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int length, extensionSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Make sure that everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL, PRE_SET_NONE, 
									   PRE_CHECK_SPKI | PRE_CHECK_DN_PARTIAL,
									   PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = sizeofShortInteger( 0 ) + \
			 sizeofDN( subjectCertInfoPtr->subjectName ) + \
			 subjectCertInfoPtr->publicKeyInfoSize;
	if( extensionSize > 0 )
		{
		length += sizeofObject( \
					sizeofObject( \
						sizeofOID( OID_PKCS9_EXTREQ ) + \
						sizeofObject( sizeofObject( extensionSize ) ) ) );
		}
	else
		length += ( int ) sizeofObject( 0 );

	/* Write the header, version number, DN, and public key info */
	writeSequence( stream, length );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		status = swrite( stream, subjectCertInfoPtr->publicKeyInfo,
						 subjectCertInfoPtr->publicKeyInfoSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the attributes.  If there are no attributes, we have to write
	   an (erroneous) zero-length field */
	if( extensionSize <= 0 )
		return( writeConstructed( stream, 0, CTAG_CR_ATTRIBUTES ) );
	writeConstructed( stream, ( int ) \
					  sizeofObject( \
						sizeofOID( OID_PKCS9_EXTREQ ) + \
						sizeofObject( sizeofObject( extensionSize ) ) ),
					  CTAG_CR_ATTRIBUTES );
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_CERTREQUEST, extensionSize ) );
	}

/* Write CRMF certificate request information:

	CertReq ::= SEQUENCE {
		certReqID				INTEGER (0),
		certTemplate			SEQUENCE {
			validity	  [ 4 ]	SEQUENCE {
				validFrom [ 0 ]	EXPLICIT GeneralizedTime OPTIONAL,
				validTo	  [ 1 ] EXPLICIT GeneralizedTime OPTIONAL
				} OPTIONAL,
			subject		  [ 5 ]	EXPLICIT Name OPTIONAL,
			publicKey	  [ 6 ]	SubjectPublicKeyInfo,
			extensions	  [ 9 ]	SET OF Attribute OPTIONAL
			}
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCrmfRequestInfo( INOUT STREAM *stream,
								 INOUT CERT_INFO *subjectCertInfoPtr,
								 STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
								 IN_HANDLE const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int payloadLength, extensionSize, subjectDNsize = 0, timeSize = 0;
	int status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Make sure that everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL, PRE_SET_NONE, 
							PRE_CHECK_SPKI | \
							( ( subjectCertInfoPtr->subjectName != NULL ) ? \
								PRE_CHECK_DN_PARTIAL : 0 ),
							PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	if( subjectCertInfoPtr->subjectName != NULL )
		subjectCertInfoPtr->subjectDNsize = subjectDNsize = \
								sizeofDN( subjectCertInfoPtr->subjectName );
	if( subjectCertInfoPtr->startTime > MIN_TIME_VALUE )
		timeSize = sizeofObject( sizeofGeneralizedTime() );
	if( subjectCertInfoPtr->endTime > MIN_TIME_VALUE )
		timeSize += sizeofObject( sizeofGeneralizedTime() );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	payloadLength = ( ( timeSize > 0 ) ? sizeofObject( timeSize ) : 0 ) + \
					( ( subjectDNsize > 0 ) ? sizeofObject( subjectDNsize ) : 0 ) + \
					subjectCertInfoPtr->publicKeyInfoSize;
	if( extensionSize )
		payloadLength += sizeofObject( extensionSize );

	/* Write the header, request ID, inner header, DN, and public key */
	writeSequence( stream, sizeofShortInteger( 0 ) + \
				   sizeofObject( payloadLength ) );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeSequence( stream, payloadLength );
	if( timeSize > 0 )
		{
		writeConstructed( stream, timeSize, CTAG_CF_VALIDITY );
		if( subjectCertInfoPtr->startTime > MIN_TIME_VALUE )
			{
			writeConstructed( stream, sizeofGeneralizedTime(), 0 );
			writeGeneralizedTime( stream, subjectCertInfoPtr->startTime,
								  DEFAULT_TAG );
			}
		if( subjectCertInfoPtr->endTime > MIN_TIME_VALUE )
			{
			writeConstructed( stream, sizeofGeneralizedTime(), 1 );
			writeGeneralizedTime( stream, subjectCertInfoPtr->endTime,
								  DEFAULT_TAG );
			}
		}
	if( subjectDNsize > 0 )
		{
		writeConstructed( stream, subjectCertInfoPtr->subjectDNsize,
						  CTAG_CF_SUBJECT );
		status = writeDN( stream, subjectCertInfoPtr->subjectName,
						  DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );
		}
	if( !sIsNullStream( stream ) )
		{
		/* Convert the SPKI SEQUENCE tag to the CRMF alternative */
		sputc( stream, MAKE_CTAG( CTAG_CF_PUBLICKEY ) );
		swrite( stream, ( BYTE * ) subjectCertInfoPtr->publicKeyInfo + 1,
				subjectCertInfoPtr->publicKeyInfoSize - 1 );
		}
	else
		{
		swrite( stream, subjectCertInfoPtr->publicKeyInfo,
				subjectCertInfoPtr->publicKeyInfoSize );
		}
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	writeConstructed( stream, extensionSize, CTAG_CF_EXTENSIONS );
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_REQUEST_CERT, extensionSize ) );
	}

/* Write CMP revocation request information:

	RevDetails ::= SEQUENCE {
		certTemplate			SEQUENCE {
			serialNumber  [ 1 ]	INTEGER,
			issuer		  [ 3 ]	EXPLICIT Name,
			},
		crlEntryDetails			SET OF Attribute
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRevRequestInfo( INOUT STREAM *stream, 
								INOUT CERT_INFO *subjectCertInfoPtr,
								STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
								STDC_UNUSED const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int payloadLength, extensionSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED );

	/* Make sure that everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL, PRE_SET_NONE, 
									   PRE_CHECK_ISSUERDN | PRE_CHECK_SERIALNO,
									   PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	payloadLength = sizeofInteger( subjectCertInfoPtr->cCertCert->serialNumber,
								   subjectCertInfoPtr->cCertCert->serialNumberLength ) + \
					sizeofObject( subjectCertInfoPtr->issuerDNsize ) + \
					( ( extensionSize > 0 ) ? \
						sizeofObject( extensionSize ) : 0 );

	/* Write the header, inner header, serial number and issuer DN */
	writeSequence( stream, sizeofObject( payloadLength ) );
	writeSequence( stream, payloadLength );
	writeInteger( stream, subjectCertInfoPtr->cCertCert->serialNumber,
				  subjectCertInfoPtr->cCertCert->serialNumberLength,
				  CTAG_CF_SERIALNUMBER );
	writeConstructed( stream, subjectCertInfoPtr->issuerDNsize,
					  CTAG_CF_ISSUER );
	status = swrite( stream, subjectCertInfoPtr->issuerDNptr,
					 subjectCertInfoPtr->issuerDNsize );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	writeConstructed( stream, extensionSize, CTAG_CF_EXTENSIONS );
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_REQUEST_REVOCATION, extensionSize ) );
	}

/* Write CRL information:

	CRLInfo ::= SEQUENCE {
		version					INTEGER DEFAULT(0),
		signature				AlgorithmIdentifier,
		issuer					Name,
		thisUpdate				UTCTime,
		nextUpdate				UTCTime OPTIONAL,
		revokedCertificates		SEQUENCE OF RevokedCerts,
		extensions		  [ 0 ]	Extensions OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCRLInfo( INOUT STREAM *stream, 
						 INOUT CERT_INFO *subjectCertInfoPtr,
						 IN_OPT const CERT_INFO *issuerCertInfoPtr,
						 IN_HANDLE_OPT const CRYPT_CONTEXT iIssuerCryptContext )
	{
	const CERT_REV_INFO *certRevInfo = subjectCertInfoPtr->cCertRev;
	REVOCATION_INFO *revocationInfo;
	const BOOLEAN isCrlEntry = ( issuerCertInfoPtr == NULL ) ? TRUE : FALSE;
	int length, algoIdInfoSize, extensionSize, revocationInfoLength = 0;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( ( issuerCertInfoPtr == NULL && \
			  iIssuerCryptContext == CRYPT_UNUSED ) || \
			( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) && \
			  isHandleRangeValid( iIssuerCryptContext ) ) );

	REQUIRES( ( issuerCertInfoPtr == NULL && \
				iIssuerCryptContext == CRYPT_UNUSED ) || \
			  ( issuerCertInfoPtr != NULL && \
				isHandleRangeValid( iIssuerCryptContext ) ) );

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		if( isCrlEntry )
			{
			status = preEncodeCertificate( subjectCertInfoPtr, NULL,
										   PRE_SET_REVINFO, 0,
										   PRE_FLAG_NONE );
			}
		else
			{
			status = preEncodeCertificate( subjectCertInfoPtr, 
										   issuerCertInfoPtr,
								PRE_SET_ISSUERDN | PRE_SET_ISSUERATTR | \
									PRE_SET_REVINFO, 
								PRE_CHECK_ISSUERCERTDN | PRE_CHECK_ISSUERDN,
								PRE_FLAG_DN_IN_ISSUERCERT );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process CRL entries and version information */
	subjectCertInfoPtr->version = \
					( subjectCertInfoPtr->attributes != NULL ) ? 2 : 1;
	for( revocationInfo = certRevInfo->revocations;
		 revocationInfo != NULL; revocationInfo = revocationInfo->next )
		{
		const int crlEntrySize = sizeofCRLentry( revocationInfo );

		if( cryptStatusError( crlEntrySize ) )
			return( crlEntrySize );
		revocationInfoLength += crlEntrySize;

		/* If there are per-entry extensions present it's a v2 CRL */
		if( revocationInfo->attributes != NULL )
			subjectCertInfoPtr->version = 2;
		}

	/* If we're being asked to write a single CRL entry, we don't try and go
	   any further since the remaining CRL fields (and issuer info) may not
	   be set up */
	if( isCrlEntry )
		return( writeCRLentry( stream, certRevInfo->currentRevocation ) );

	/* Determine how big the encoded CRL will be */
	algoIdInfoSize = sizeofContextAlgoID( iIssuerCryptContext, 
										  certRevInfo->hashAlgo );
	if( cryptStatusError( algoIdInfoSize ) )
		return( algoIdInfoSize  );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = algoIdInfoSize + \
			 issuerCertInfoPtr->subjectDNsize + sizeofUTCTime() + \
			 ( ( subjectCertInfoPtr->endTime > MIN_TIME_VALUE ) ? \
				sizeofUTCTime() : 0 ) + \
			 sizeofObject( revocationInfoLength );
	if( extensionSize > 0 )
		{
		length += sizeofShortInteger( X509VERSION_2 ) + \
			 	  sizeofObject( sizeofObject( extensionSize ) );
		}

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If there are extensions present, mark this as a v2 CRL */
	if( extensionSize > 0 )
		writeShortInteger( stream, X509VERSION_2, DEFAULT_TAG );

	/* Write the signature algorithm identifier, issuer name, and CRL time */
	status = writeContextAlgoID( stream, iIssuerCryptContext,
								 certRevInfo->hashAlgo );
	if( cryptStatusError( status ) )
		return( status );
	swrite( stream, issuerCertInfoPtr->subjectDNptr,
			issuerCertInfoPtr->subjectDNsize );
	writeUTCTime( stream, subjectCertInfoPtr->startTime, DEFAULT_TAG );
	if( subjectCertInfoPtr->endTime > MIN_TIME_VALUE )
		writeUTCTime( stream, subjectCertInfoPtr->endTime, DEFAULT_TAG );

	/* Write the SEQUENCE OF revoked certificates wrapper and the revoked
	   certificate information */
	status = writeSequence( stream, revocationInfoLength );
	for( revocationInfo = certRevInfo->revocations;
		 cryptStatusOK( status ) && revocationInfo != NULL;
		 revocationInfo = revocationInfo->next )
		status = writeCRLentry( stream, revocationInfo );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the extensions */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_CRL, extensionSize ) );
	}

/* Write CMS attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCmsAttributes( INOUT STREAM *stream, 
							   INOUT CERT_INFO *attributeInfoPtr,
							   STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
							   STDC_UNUSED const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int addDefaultAttributes, attributeSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED );
	REQUIRES( attributeInfoPtr->attributes != NULL );

	status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
							  IMESSAGE_GETATTRIBUTE, &addDefaultAttributes,
							  CRYPT_OPTION_CMS_DEFAULTATTRIBUTES );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that there's a hash and content type present */
	if( findAttributeField( attributeInfoPtr->attributes,
							CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
							CRYPT_ATTRIBUTE_NONE ) == NULL )
		{
		setErrorInfo( attributeInfoPtr, CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_INVALID );
		}
	if( !checkAttributePresent( attributeInfoPtr->attributes,
								CRYPT_CERTINFO_CMS_CONTENTTYPE ) )
		{
		const int value = CRYPT_CONTENT_DATA;

		/* If there's no content type and we're not adding it automatically,
		   complain */
		if( !addDefaultAttributes )
			{
			setErrorInfo( attributeInfoPtr, CRYPT_CERTINFO_CMS_CONTENTTYPE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_INVALID );
			}

		/* There's no content type present, treat it as straight data (which
		   means that this is signedData) */
		status = addCertComponent( attributeInfoPtr, CRYPT_CERTINFO_CMS_CONTENTTYPE,
								   &value, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If there's no signing time attribute present and we're adding the
	   default attributes, add it now.  This will usually already have been
	   added by the caller via getReliableTime(), if it hasn't then we
	   default to using the system time source because the signing object
	   isn't available at this point to provide a time source */
	if( addDefaultAttributes && \
		!checkAttributePresent( attributeInfoPtr->attributes,
								CRYPT_CERTINFO_CMS_SIGNINGTIME ) )
		{
		const time_t currentTime = getTime();

		/* If the time is screwed up we can't provide a signed indication
		   of the time */
		if( currentTime <= MIN_TIME_VALUE )
			{
			setErrorInfo( attributeInfoPtr, CRYPT_CERTINFO_VALIDFROM,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ERROR_NOTINITED );
			}

		status = addCertComponent( attributeInfoPtr, CRYPT_CERTINFO_CMS_SIGNINGTIME,
								   &currentTime, sizeof( time_t ) );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Check that the attributes are in order and determine how big the whole
	   mess will be */
	status = checkAttributes( ATTRIBUTE_CMS, attributeInfoPtr->attributes,
							  &attributeInfoPtr->errorLocus,
							  &attributeInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	attributeSize = sizeofAttributes( attributeInfoPtr->attributes );
	if( cryptStatusError( attributeSize ) || attributeSize <= 0 )
		return( attributeSize );

	/* Write the attributes */
	return( writeAttributes( stream, attributeInfoPtr->attributes,
							 CRYPT_CERTTYPE_CMS_ATTRIBUTES, attributeSize ) );
	}

/* Write an RTCS request:

	RTCSRequests ::= SEQUENCE {
		SEQUENCE OF SEQUENCE {
			certHash	OCTET STRING SIZE(20)
			},
		attributes		Attributes OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRtcsRequestInfo( INOUT STREAM *stream, 
								 INOUT CERT_INFO *subjectCertInfoPtr,
								 STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
								 STDC_UNUSED \
									const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_VAL_INFO *certValInfo = subjectCertInfoPtr->cCertVal;
	VALIDITY_INFO *validityInfo;
	int length, extensionSize, requestInfoLength = 0;
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED );

	/* Perform any necessary pre-encoding steps.  We should really update the
	   nonce when we write the data for real, but to do that we'd have to re-
	   calculate the extension information (via preEncodeCertifiate()) for
	   null-stream and real writes just because the one extension changes so
	   we calculate it when we do the dummy write instead.  This is safe
	   because the write process always performs a real write immediately
	   after the null-stream write */
	if( sIsNullStream( stream ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;
		MESSAGE_DATA msgData;

		/* To ensure freshness we always use a new nonce when we write an
		   RTCS request */
		attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
											   CRYPT_CERTINFO_CMS_NONCE,
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			setMessageData( &msgData, attributeListPtr->value, 16 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			attributeListPtr->valueLength = 16;
			}
		else
			{
			CRYPT_ATTRIBUTE_TYPE dummy1;
			CRYPT_ERRTYPE_TYPE dummy2;
			BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];

			setMessageData( &msgData, nonce, 16 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			if( cryptStatusOK( status ) )
				status = addAttributeField( &subjectCertInfoPtr->attributes,
											CRYPT_CERTINFO_CMS_NONCE,
											CRYPT_ATTRIBUTE_NONE, nonce, 16,
											ATTR_FLAG_NONE, &dummy1, &dummy2 );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* Perform the pre-encoding checks */
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
									   PRE_SET_NONE, PRE_CHECK_VALENTRIES, 
									   PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded RTCS request will be */
	for( validityInfo = certValInfo->validityInfo, iterationCount = 0;
		 validityInfo != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE; 
		 validityInfo = validityInfo->next, iterationCount++ )
		{
		const int requestEntrySize = sizeofRtcsRequestEntry( validityInfo );
		
		if( cryptStatusError( requestEntrySize ) )
			return( requestEntrySize );
		requestInfoLength += requestEntrySize;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = sizeofObject( requestInfoLength ) + \
			 ( ( extensionSize > 0 ) ? sizeofObject( extensionSize ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* Write the SEQUENCE OF request wrapper and the request information */
	status = writeSequence( stream, requestInfoLength );
	for( validityInfo = certValInfo->validityInfo, iterationCount = 0;
		 cryptStatusOK( status ) && validityInfo != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE; 
		 validityInfo = validityInfo->next, iterationCount++ )
		{
		status = writeRtcsRequestEntry( stream, validityInfo );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_RTCS_REQUEST, extensionSize ) );
	}

/* Write an RTCS response:

	RTCSResponse ::= SEQUENCE {
		SEQUENCE OF SEQUENCE {
			certHash	OCTET STRING SIZE(20),
			RESPONSEINFO
			}
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeRtcsResponseInfo( INOUT STREAM *stream,
								  INOUT CERT_INFO *subjectCertInfoPtr,
								  STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
								  STDC_UNUSED \
									const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_VAL_INFO *certValInfo = subjectCertInfoPtr->cCertVal;
	VALIDITY_INFO *validityInfo;
	int length = 0, extensionSize, validityInfoLength = 0;
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED );

	/* RTCS can legitimately return an empty response if there's a problem
	   with the responder so we don't require that any responses be present
	   as for CRLs/OCSP */

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, NULL,
									   PRE_SET_VALINFO, PRE_CHECK_NONE,
									   PRE_FLAG_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded RTCS response will be */
	for( validityInfo = certValInfo->validityInfo, iterationCount = 0;
		 validityInfo != NULL && iterationCount < FAILSAFE_ITERATIONS_LARGE; 
		 validityInfo = validityInfo->next, iterationCount++ )
		{
		const int responseEntrySize = \
			sizeofRtcsResponseEntry( validityInfo,
					certValInfo->responseType == RTCSRESPONSE_TYPE_EXTENDED );

		if( cryptStatusError( responseEntrySize ) )
			return( responseEntrySize );
		validityInfoLength += responseEntrySize;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length += sizeofObject( validityInfoLength ) + \
			  ( ( extensionSize > 0 ) ? sizeofObject( extensionSize ) : 0 );

	/* Write the SEQUENCE OF status information wrapper and the certificate 
	   status information */
	status = writeSequence( stream, validityInfoLength );
	for( validityInfo = certValInfo->validityInfo, iterationCount = 0;
		 cryptStatusOK( status ) && validityInfo != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE; 
		 validityInfo = validityInfo->next, iterationCount++ )
		{
		status = writeRtcsResponseEntry( stream, validityInfo,
					certValInfo->responseType == RTCSRESPONSE_TYPE_EXTENDED );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_RTCS_RESPONSE, extensionSize ) );
	}

/* Write an OCSP request:

	OCSPRequest ::= SEQUENCE {				-- Write, v1
		reqName		[1]	EXPLICIT [4] EXPLICIT DirectoryName OPTIONAL,
		reqList			SEQUENCE OF SEQUENCE {
						SEQUENCE {			-- certID
			hashAlgo	AlgorithmIdentifier,
			iNameHash	OCTET STRING,
			iKeyHash	OCTET STRING,
			serialNo	INTEGER
			} }
		}

	OCSPRequest ::= SEQUENCE {				-- Write, v2
		version		[0]	EXPLICIT INTEGER (1),
		reqName		[1]	EXPLICIT [4] EXPLICIT DirectoryName OPTIONAL,
		reqList			SEQUENCE OF SEQUENCE {
			certID	[2]	EXPLICIT OCTET STRING	-- Certificate hash
			}
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeOcspRequestInfo( INOUT STREAM *stream, 
								 INOUT CERT_INFO *subjectCertInfoPtr,
								 IN_OPT const CERT_INFO *issuerCertInfoPtr,
								 IN_HANDLE_OPT \
									const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_REV_INFO *certRevInfo = subjectCertInfoPtr->cCertRev;
	REVOCATION_INFO *revocationInfo;
	int length, extensionSize, revocationInfoLength = 0;
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( issuerCertInfoPtr == NULL || \
			isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED || \
			  isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Perform any necessary pre-encoding steps.  We should really update the
	   nonce when we write the data for real, but to do that we'd have to re-
	   calculate the extension information (via preEncodeCertifiate()) for
	   null-stream and real writes just because the one extension changes so
	   we calculate it when we do the dummy write instead.  This is safe
	   because the write process always performs a real write immediately
	   after the null-stream write */
	if( sIsNullStream( stream ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;
		MESSAGE_DATA msgData;

		/* To ensure freshness we always use a new nonce when we write an
		   OCSP request.  We don't check for problems (which in any case,
		   could only occur if there's an out-of-memory error) because
		   there's not much that we can meaningfully do if the add fails */
		attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
											   CRYPT_CERTINFO_OCSP_NONCE,
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL )
			{
			setMessageData( &msgData, attributeListPtr->value, 16 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			attributeListPtr->valueLength = 16;
			}
		else
			{
			CRYPT_ATTRIBUTE_TYPE dummy1;
			CRYPT_ERRTYPE_TYPE dummy2;
			BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];

			setMessageData( &msgData, nonce, 16 );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_GETATTRIBUTE_S, &msgData,
									  CRYPT_IATTRIBUTE_RANDOM_NONCE );
			if( cryptStatusOK( status ) )
				{
				status = addAttributeField( &subjectCertInfoPtr->attributes,
											CRYPT_CERTINFO_OCSP_NONCE,
											CRYPT_ATTRIBUTE_NONE, nonce, 16,
											ATTR_FLAG_NONE, &dummy1, &dummy2 );
				}
			attributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
												   CRYPT_CERTINFO_OCSP_NONCE,
												   CRYPT_ATTRIBUTE_NONE );
			}
		if( cryptStatusError( status ) )
			return( status );
		if( attributeListPtr != NULL )
			{
			BYTE *noncePtr = attributeListPtr->value;

			/* Because of OCSP's inexplicable use of integers to encode the
			   nonce octet string we have to tweak the first byte to ensure
			   that the integer encoding works as a standard OCTET STRING */
			noncePtr[ 0 ] &= 0x7F;
			if( noncePtr[ 0 ] == 0 )
				noncePtr[ 0 ]++;
			}

		/* Perform the pre-encoding checks */
		if( issuerCertInfoPtr != NULL )
			{
			/* It's a signed request, there has to be an issuer DN present */
			status = preEncodeCertificate( subjectCertInfoPtr, 
										   issuerCertInfoPtr, PRE_SET_REVINFO, 
										   PRE_CHECK_ISSUERDN | \
												PRE_CHECK_REVENTRIES,
										   PRE_FLAG_DN_IN_ISSUERCERT );
			}
		else
			{
			status = preEncodeCertificate( subjectCertInfoPtr, NULL,
										   PRE_SET_REVINFO,  
										   PRE_CHECK_REVENTRIES, 
										   PRE_FLAG_NONE );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded OCSP request will be */
	for( revocationInfo = certRevInfo->revocations, iterationCount = 0;
		 revocationInfo != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 revocationInfo = revocationInfo->next, iterationCount++ )
		{
		const int requestEntrySize = sizeofOcspRequestEntry( revocationInfo );

		if( cryptStatusError( requestEntrySize ) )
			return( requestEntrySize );
		revocationInfoLength += requestEntrySize;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = ( ( subjectCertInfoPtr->version == 2 ) ? \
				 sizeofObject( sizeofShortInteger( CTAG_OR_VERSION ) ) : 0 ) + \
			 ( ( issuerCertInfoPtr != NULL ) ? \
				 sizeofObject( sizeofObject( issuerCertInfoPtr->subjectDNsize ) ) : 0 ) + \
			 sizeofObject( revocationInfoLength ) + \
			 ( ( extensionSize > 0 ) ? \
			   sizeofObject( sizeofObject( extensionSize ) ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If we're using v2 identifiers, mark this as a v2 request */
	if( subjectCertInfoPtr->version == 2 )
		{
		writeConstructed( stream, sizeofShortInteger( 1 ), CTAG_OR_VERSION );
		writeShortInteger( stream, 1, DEFAULT_TAG );
		}

	/* If we're signing the request, write the issuer DN as a GeneralName */
	if( issuerCertInfoPtr != NULL )
		{
		writeConstructed( stream,
						  sizeofObject( issuerCertInfoPtr->subjectDNsize ), 1 );
		writeConstructed( stream, issuerCertInfoPtr->subjectDNsize, 4 );
		swrite( stream, issuerCertInfoPtr->subjectDNptr,
				issuerCertInfoPtr->subjectDNsize );
		}

	/* Write the SEQUENCE OF revocation information wrapper and the
	   revocation information */
	status = writeSequence( stream, revocationInfoLength );
	for( revocationInfo = certRevInfo->revocations, iterationCount = 0;
		 cryptStatusOK( status ) && revocationInfo != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 revocationInfo = revocationInfo->next, iterationCount++ )
		{
		status = writeOcspRequestEntry( stream, revocationInfo );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_OCSP_REQUEST, extensionSize ) );
	}

/* Write an OCSP response:

	OCSPResponse ::= SEQUENCE {
		version		[0]	EXPLICIT INTEGER (1),
		respID		[1]	EXPLICIT Name,
		producedAt		GeneralizedTime,
		responses		SEQUENCE OF Response
		exts		[1]	EXPLICIT Extensions OPTIONAL,
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeOcspResponseInfo( INOUT STREAM *stream,
								  INOUT CERT_INFO *subjectCertInfoPtr,
								  const CERT_INFO *issuerCertInfoPtr,
								  IN_HANDLE \
									const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_REV_INFO *certRevInfo = subjectCertInfoPtr->cCertRev;
	REVOCATION_INFO *revocationInfo;
	int length = 0, extensionSize, revocationInfoLength = 0;
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( subjectCertInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isReadPtr( issuerCertInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( iIssuerCryptContext ) );/* Not used here */

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   PRE_SET_NONE, 
									   PRE_CHECK_ISSUERDN | \
											PRE_CHECK_REVENTRIES,
									   PRE_FLAG_DN_IN_ISSUERCERT );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded OCSP response will be */
	for( revocationInfo = certRevInfo->revocations, iterationCount = 0;
		 revocationInfo != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE; 
		 revocationInfo = revocationInfo->next, iterationCount++ )
		{
		const int responseEntrySize = sizeofOcspResponseEntry( revocationInfo );

		if( cryptStatusError( responseEntrySize ) )
			return( responseEntrySize );
		revocationInfoLength += responseEntrySize;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	length = sizeofObject( sizeofShortInteger( CTAG_OP_VERSION ) ) + \
			 sizeofObject( issuerCertInfoPtr->subjectDNsize ) + \
			 sizeofGeneralizedTime() + \
			 sizeofObject( revocationInfoLength ) + \
			 ( ( extensionSize > 0 ) ? \
				sizeofObject( sizeofObject( extensionSize ) ) : 0 );

	/* Write the outer SEQUENCE wrapper, version, and issuer DN and 
	   producedAt time */
	writeSequence( stream, length );
	writeConstructed( stream, sizeofShortInteger( 1 ), CTAG_OP_VERSION );
	writeShortInteger( stream, 1, DEFAULT_TAG );
	writeConstructed( stream, issuerCertInfoPtr->subjectDNsize, 1 );
	swrite( stream, issuerCertInfoPtr->subjectDNptr,
			issuerCertInfoPtr->subjectDNsize );
	writeGeneralizedTime( stream, subjectCertInfoPtr->startTime,
						  DEFAULT_TAG );

	/* Write the SEQUENCE OF revocation information wrapper and the
	   revocation information */
	status = writeSequence( stream, revocationInfoLength );
	for( revocationInfo = certRevInfo->revocations, iterationCount = 0;
		 cryptStatusOK( status ) && revocationInfo != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE; 
		 revocationInfo = revocationInfo->next, iterationCount++ )
		{
		status = writeOcspResponseEntry( stream, revocationInfo,
										 subjectCertInfoPtr->startTime );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	if( cryptStatusError( status ) || extensionSize <= 0 )
		return( status );

	/* Write the attributes */
	return( writeAttributes( stream, subjectCertInfoPtr->attributes,
							 CRYPT_CERTTYPE_OCSP_RESPONSE, extensionSize ) );
	}

/* Write PKI user info:

	userData ::= SEQUENCE {
		name				Name,			-- Name for CMP
		encAlgo				AlgorithmIdentifier,-- Algo to encrypt passwords
		encPW				OCTET STRING,	-- Encrypted passwords
		attributes			Attributes
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5, 7 ) ) \
static int getPkiUserInfo( INOUT CERT_PKIUSER_INFO *certUserInfo,
						   OUT_BUFFER( maxUserInfoSize, *userInfoSize ) \
							BYTE *userInfo, 
						   IN_LENGTH_SHORT_MIN( 64 ) const int maxUserInfoSize, 
						   OUT_LENGTH_SHORT_Z int *userInfoSize, 
						   OUT_BUFFER( maxAlgoIdSize, *algoIdSize ) BYTE *algoID, 
						   IN_LENGTH_SHORT_MIN( 16 ) const int maxAlgoIdSize, 
						   OUT_LENGTH_SHORT_Z int *algoIdSize )
	{
	CRYPT_CONTEXT iCryptContext;
	static const CRYPT_MODE_TYPE mode = CRYPT_MODE_CFB;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	STREAM stream;
	int userInfoBufPos, i, status;

	assert( isWritePtr( certUserInfo, sizeof( CERT_PKIUSER_INFO ) ) );
	assert( isWritePtr( userInfo, maxUserInfoSize ) );
	assert( isWritePtr( userInfoSize, sizeof( int ) ) );
	assert( isWritePtr( algoID, maxAlgoIdSize ) );
	assert( isWritePtr( algoIdSize, sizeof( int ) ) );

	REQUIRES( maxUserInfoSize >= 64 && \
			  maxUserInfoSize < MAX_INTLENGTH_SHORT );
	REQUIRES( maxAlgoIdSize >= 16 && maxAlgoIdSize < MAX_INTLENGTH_SHORT );

	/* Clear return values */
	*userInfoSize = *algoIdSize = 0;

	/* Create a stream-cipher encryption context and use it to generate the 
	   user passwords.  These aren't encryption keys but just authenticators 
	   used for MACing so we don't go to the usual extremes to protect them.  
	   In addition we can't use the most obvious option for the stream 
	   cipher, RC4, because it may be disabled in some builds.  Instead we 
	   rely on 3DES, which is always available */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_3DES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iCryptContext = createInfo.cryptHandle;
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE,
							  ( void * ) &mode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		status = krnlSendNotifier( iCryptContext, IMESSAGE_CTX_GENKEY );
	if( cryptStatusOK( status ) )
		status = krnlSendNotifier( iCryptContext, IMESSAGE_CTX_GENIV );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Encode the user info so that it can be encrypted */
	sMemOpen( &stream, userInfo, maxUserInfoSize );
	writeSequence( &stream, 2 * sizeofObject( PKIUSER_AUTHENTICATOR_SIZE ) );
	memset( certUserInfo->pkiIssuePW, 0, PKIUSER_AUTHENTICATOR_SIZE );
	krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT,
					 certUserInfo->pkiIssuePW, PKIUSER_AUTHENTICATOR_SIZE );
	writeOctetString( &stream, certUserInfo->pkiIssuePW,
					  PKIUSER_AUTHENTICATOR_SIZE, DEFAULT_TAG );
	memset( certUserInfo->pkiRevPW, 0, PKIUSER_AUTHENTICATOR_SIZE );
	status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT,
							  certUserInfo->pkiRevPW,
							  PKIUSER_AUTHENTICATOR_SIZE );
	writeOctetString( &stream, certUserInfo->pkiRevPW,
					  PKIUSER_AUTHENTICATOR_SIZE, DEFAULT_TAG );
	userInfoBufPos = stell( &stream );
	krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Encrypt (or at least mask) the user information.  For forwards 
	   compatibility (and because the format requires the use of some for of 
	   encryption when encoding the data) we encrypt the user data, once 
	   user roles are fully implemented this can use the static data storage 
	   key associated with the CA user to perform the encryption instead of 
	   a fixed interop key.  This isn't a security issue because the CA 
	   database is assumed to be secure (or at least the CA is in serious 
	   trouble if it's database isn't secured), we encrypt because it's 
	   pretty much free and because it doesn't hurt either way.  Most CA 
	   guidelines merely require that the CA protect its user database via 
	   standard (physical/ACL) security measures, so this is no less secure 
	   than what's required by various CA guidelines.

	   When we do this for real we probably need an extra level of 
	   indirection to go from the CA secret to the database decryption key 
	   so that we can change the encryption algorithm and so that we don't 
	   have to directly apply the CA's static data storage key to the user 
	   database */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_3DES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	iCryptContext = createInfo.cryptHandle;
	setMessageData( &msgData, "interop interop interop ", 24 );
	status = krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_KEY );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Add PKCS #5 padding to the end of the user info and encrypt it */
	REQUIRES( userInfoBufPos + 2 == PKIUSER_ENCR_AUTHENTICATOR_SIZE );
	for( i = 0; i < 2; i++ )
		userInfo[ userInfoBufPos++ ] = 2;
	krnlSendNotifier( iCryptContext, IMESSAGE_CTX_GENIV );
	status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT, 
							  userInfo, userInfoBufPos );
	if( cryptStatusOK( status ) )
		{
		sMemOpen( &stream, algoID, maxAlgoIdSize );
		status = writeCryptContextAlgoID( &stream, iCryptContext );
		*algoIdSize = stell( &stream );
		sMemDisconnect( &stream );
		}
	krnlSendNotifier( iCryptContext, IMESSAGE_DECREFCOUNT );
	*userInfoSize = userInfoBufPos;

	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writePkiUserInfo( INOUT STREAM *stream, 
							 INOUT CERT_INFO *userInfoPtr,
							 STDC_UNUSED const CERT_INFO *issuerCertInfoPtr,
							 STDC_UNUSED const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CERT_PKIUSER_INFO *certUserInfo = userInfoPtr->cCertUser;
	BYTE userInfo[ 128 + 8 ], algoID[ 128 + 8 ];
	int extensionSize, userInfoSize, algoIdSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( userInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( issuerCertInfoPtr == NULL );
	REQUIRES( iIssuerCryptContext == CRYPT_UNUSED );

	if( sIsNullStream( stream ) )
		{
		CRYPT_ATTRIBUTE_TYPE dummy1;
		CRYPT_ERRTYPE_TYPE dummy2;
		MESSAGE_DATA msgData;
		BYTE keyID[ 16 + 8 ];
		int keyIDlength = DUMMY_INIT;

		/* Generate the key identifier.  Once it's in user-encoded form the
		   full identifier can't quite fit so we adjust the size to the
		   maximum amount that we can encode by creating the encoded form 
		   (which trims the input to fit) and then decoding it again.  This 
		   is necessary because it's also used to locate the user info in a 
		   key store, if we used the un-adjusted form for the key ID then we 
		   couldn't locate the stored user info using the adjusted form */
		setMessageData( &msgData, keyID, 16 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusOK( status ) )
			{
			char encodedKeyID[ 32 + 8 ];
			int encKeyIdSize;

			status = encodePKIUserValue( encodedKeyID, 32, &encKeyIdSize,
										 keyID, 16, 3 );
			if( cryptStatusOK( status ) )
				status = decodePKIUserValue( keyID, 16, &keyIDlength,
											 encodedKeyID, encKeyIdSize );
			}
		if( cryptStatusError( status ) )
			return( status );
		status = addAttributeField( &userInfoPtr->attributes,
									CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
									CRYPT_ATTRIBUTE_NONE, keyID, keyIDlength,
									ATTR_FLAG_NONE, &dummy1, &dummy2 );
		if( cryptStatusOK( status ) )
			{
			status = checkAttributes( ATTRIBUTE_CERTIFICATE,
									  userInfoPtr->attributes,
									  &userInfoPtr->errorLocus,
									  &userInfoPtr->errorType );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* We can't generate the user info yet since we're doing the pre-
		   encoding pass and writing to a null stream so we leave it for the
		   actual encoding pass and only provide a size estimate for now */
		userInfoSize = PKIUSER_ENCR_AUTHENTICATOR_SIZE;

		/* Since we can't use the fixed CA key yet we set the algo ID size
		   to the size of the info for the fixed 3DES key */
		algoIdSize = 22;
		}
	else
		{
		status = getPkiUserInfo( certUserInfo, userInfo, 128, &userInfoSize, 
								 algoID, 128, &algoIdSize );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine the size of the user information */
	userInfoPtr->subjectDNsize = sizeofDN( userInfoPtr->subjectName );
	extensionSize = sizeofAttributes( userInfoPtr->attributes );
	if( cryptStatusError( extensionSize ) )
		return( extensionSize );
	ENSURES( extensionSize > 0 && extensionSize < MAX_INTLENGTH_SHORT );

	/* Write the user DN, encrypted user info, and any supplementary
	   information */
	status = writeDN( stream, userInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	swrite( stream, algoID, algoIdSize );
	writeOctetString( stream, userInfo, userInfoSize, DEFAULT_TAG );
	return( writeAttributes( stream, userInfoPtr->attributes,
							 CRYPT_CERTTYPE_PKIUSER, extensionSize ) );
	}

/****************************************************************************
*																			*
*						Write Function Access Information					*
*																			*
****************************************************************************/

typedef struct {
	const CRYPT_CERTTYPE_TYPE type;
	const WRITECERT_FUNCTION function;
	} CERTWRITE_INFO;
static const CERTWRITE_INFO FAR_BSS certWriteTable[] = {
	{ CRYPT_CERTTYPE_CERTIFICATE, writeCertInfo },
	{ CRYPT_CERTTYPE_CERTCHAIN, writeCertInfo },
	{ CRYPT_CERTTYPE_ATTRIBUTE_CERT, writeAttributeCertInfo },
	{ CRYPT_CERTTYPE_CERTREQUEST, writeCertRequestInfo },
	{ CRYPT_CERTTYPE_REQUEST_CERT, writeCrmfRequestInfo },
	{ CRYPT_CERTTYPE_REQUEST_REVOCATION, writeRevRequestInfo },
	{ CRYPT_CERTTYPE_CRL, writeCRLInfo },
	{ CRYPT_CERTTYPE_CMS_ATTRIBUTES, writeCmsAttributes },
	{ CRYPT_CERTTYPE_RTCS_REQUEST, writeRtcsRequestInfo },
	{ CRYPT_CERTTYPE_RTCS_RESPONSE, writeRtcsResponseInfo },
	{ CRYPT_CERTTYPE_OCSP_REQUEST, writeOcspRequestInfo },
	{ CRYPT_CERTTYPE_OCSP_RESPONSE, writeOcspResponseInfo },
	{ CRYPT_CERTTYPE_PKIUSER, writePkiUserInfo },
	{ CRYPT_CERTTYPE_NONE, NULL }, { CRYPT_CERTTYPE_NONE, NULL }
	};

CHECK_RETVAL_PTR \
WRITECERT_FUNCTION getCertWriteFunction( IN_ENUM( CRYPT_CERTTYPE ) \
											const CRYPT_CERTTYPE_TYPE certType )
	{
	int i;

	REQUIRES_N( certType > CRYPT_CERTTYPE_NONE && certType < CRYPT_CERTTYPE_LAST );

	for( i = 0; 
		 certWriteTable[ i ].type != CRYPT_CERTTYPE_NONE && \
			i < FAILSAFE_ARRAYSIZE( certWriteTable, CERTWRITE_INFO ); 
		 i++ )
		{
		if( certWriteTable[ i ].type == certType )
			return( certWriteTable[ i ].function );
		}
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( certWriteTable, CERTWRITE_INFO ) );

	return( NULL );
	}
