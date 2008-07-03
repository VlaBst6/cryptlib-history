/****************************************************************************
*																			*
*						Certificate Revocation Routines						*
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

/* The maximum length of ID that can be stored in a REVOCATION_INFO entry.
   Larger IDs require external storage */

#define MAX_ID_SIZE		128

/* Usually when we add revocation information we perform various checks such
   as making sure we're not adding duplicate information, however when
   processing the mega-CRLs from some CAs this becomes prohibitively
   expensive.  To solve this problem we perform checking up to a certain
   number of entries and after that just drop in any further entries as is
   in order to provide same-day service.  The following value defines the
   CRL threshold size in bytes at which we stop performing checks when we
   add new entries */

#define CRL_SORT_LIMIT	8192

/* Context-specific tags for OCSP certificate identifier types */

enum { CTAG_OI_CERTIFICATE, CTAG_OI_CERTIDWITHSIG, CTAG_OI_RTCS };

/* OCSP certificate status values */

enum { OCSP_STATUS_NOTREVOKED, OCSP_STATUS_REVOKED, OCSP_STATUS_UNKNOWN };

/****************************************************************************
*																			*
*					Add/Delete/Check Revocation Information					*
*																			*
****************************************************************************/

/* Find an entry in a revocation list.  This is done using a linear search,
   which isn't very optimal but anyone trying to do anything useful with
   mega-CRLs (or with CRLs in general) is in more trouble than basic search
   algorithm choice.  In other words it doesn't really make much difference
   whether we have an optimal or suboptimal implementation of a
   fundamentally broken mechanism like CRLs.

   The value is either a serialNumber or a hash of some form (issuerID,
   certHash), we don't bother distinguishing the exact type since the
   chances of a hash collision are virtually nonexistant */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int findRevocationEntry( const REVOCATION_INFO *listPtr,
								OUT_OPT_PTR REVOCATION_INFO **insertPoint,
								IN_BUFFER( valueLength ) const void *value, 
								IN_LENGTH_SHORT const int valueLength,
								const BOOLEAN sortEntries )
	{
	const REVOCATION_INFO *prevElement = NULL;
	const int idCheck = checksumData( value, valueLength );
	int iterationCount;

	assert( isReadPtr( listPtr, sizeof( REVOCATION_INFO ) ) );
	assert( insertPoint == NULL || \
			isWritePtr( insertPoint, sizeof( REVOCATION_INFO * ) ) );
	assert( isReadPtr( value, valueLength ) );

	REQUIRES( valueLength > 0 && valueLength < MAX_INTLENGTH_SHORT );

	/* Clear the return value */
	if( insertPoint != NULL )
		*insertPoint = NULL;

	/* Find the correct place in the list to insert the new element and check
	   for duplicates.  If requested we sort the entries by serial number
	   (or more generally data value) for no adequately explored reason 
	   (some implementations can optimise the searching of CRLs based on
	   this but since there's no agreement on whether to do it or not you 
	   can't tell whether it's safe to rely on it).  In addition we bound 
	   the loop with FAILSAFE_ITERATIONS_MAX since CRLs can grow enormous */
	for( iterationCount = 0;
		 listPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MAX;
		 listPtr = listPtr->next, iterationCount++ )
		{
		if( ( sortEntries || idCheck == listPtr->idCheck ) && \
			listPtr->idLength == valueLength )
			{
			const int compareStatus = memcmp( listPtr->id,
											  value, valueLength );

			if( !compareStatus )
				{
				/* We found a matching entry, tell the caller which one it
				   is if required */
				if( insertPoint != NULL )
					*insertPoint = ( REVOCATION_INFO * ) listPtr;
				return( CRYPT_OK );
				}
			if( sortEntries && compareStatus > 0 )
				break;					/* Insert before this point */
			}
		else
			{
			if( sortEntries && listPtr->idLength > valueLength )
				break;					/* Insert before this point */
			}

		prevElement = listPtr;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );

	/* We can't find a matching entry, return the revocation entry after
	   which we should insert the new value */
	if( insertPoint != NULL )
		*insertPoint = ( REVOCATION_INFO * ) prevElement;
	return( CRYPT_ERROR_NOTFOUND );
	}

/* Check whether a certificate has been revoked */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkRevocation( const CERT_INFO *certInfoPtr, 
					 INOUT CERT_INFO *revocationInfoPtr )
	{
	CERT_REV_INFO *certRevInfo = revocationInfoPtr->cCertRev;
	REVOCATION_INFO *revocationEntry = DUMMY_INIT_PTR;
	int status;

	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( revocationInfoPtr, sizeof( CERT_INFO ) ) );

	/* If there's no revocation information present then the certificate 
	   can't have been revoked */
	if( certRevInfo->revocations == NULL )
		return( CRYPT_OK );

	/* Check whether the certificate is present in the revocation list */
	if( revocationInfoPtr->type == CRYPT_CERTTYPE_CRL )
		{
		/* If the issuers differ then the certificate can't be in this CRL */
		if( ( revocationInfoPtr->issuerDNsize != certInfoPtr->issuerDNsize || \
			memcmp( revocationInfoPtr->issuerDNptr, certInfoPtr->issuerDNptr,
					revocationInfoPtr->issuerDNsize ) ) )
			return( CRYPT_OK );

		/* Check whether there's an entry for this certificate in the list */
		status = findRevocationEntry( certRevInfo->revocations,
									  &revocationEntry,
									  certInfoPtr->cCertCert->serialNumber,
									  certInfoPtr->cCertCert->serialNumberLength,
									  FALSE );
		if( cryptStatusError( status ) )
			{
			/* No CRL entry, the certificate is OK */
			return( CRYPT_OK );
			}
		}
	else
		{
		BYTE certHash[ CRYPT_MAX_HASHSIZE + 8 ];
		int certHashLength;

		ENSURES( revocationInfoPtr->type == CRYPT_CERTTYPE_OCSP_RESPONSE );

		/* Get the certificate hash and use it to check whether there's an 
		   entry for this certificate in the list.  We read the certificate 
		   hash indirectly since it's computed on demand and may not have 
		   been evaluated yet */
		status = getCertComponent( ( CERT_INFO * ) certInfoPtr,
								   CRYPT_CERTINFO_FINGERPRINT_SHA,
								   certHash, CRYPT_MAX_HASHSIZE, 
								   &certHashLength );
		if( cryptStatusOK( status ) )
			{
			status = findRevocationEntry( certRevInfo->revocations,
										  &revocationEntry, certHash,
										  certHashLength, FALSE );
			}
		if( cryptStatusError( status ) )
			{
			/* No entry, either good or bad, we can't report anything about
			   the certificate */
			return( status );
			}
		}
	ENSURES( revocationEntry != NULL );

	/* Select the entry that contains the revocation information and return
	   the certificate's status.  For CRLs the presence of an entry means 
	   that the certificate is invalid, for OCSP the validity information is 
	   contained in the entry.  The unknown status is a bit difficult to 
	   report, the best that we can do is report notfound although the 
	   notfound occurred at the responder rather than here */
	certRevInfo->currentRevocation = revocationEntry;
	if( revocationInfoPtr->type == CRYPT_CERTTYPE_CRL )
		return( CRYPT_ERROR_INVALID );
	return( ( revocationEntry->status == CRYPT_OCSPSTATUS_NOTREVOKED ) ? \
				CRYPT_OK : \
			( revocationEntry->status == CRYPT_OCSPSTATUS_REVOKED ) ? \
				CRYPT_ERROR_INVALID : CRYPT_ERROR_NOTFOUND );
	}

/* Add an entry to a revocation list */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int addRevocationEntry( INOUT_PTR REVOCATION_INFO **listHeadPtrPtr,
						OUT_PTR REVOCATION_INFO **newEntryPosition,
						IN_KEYID const CRYPT_KEYID_TYPE valueType,
						IN_BUFFER( valueLength ) const void *value, 
						IN_LENGTH_SHORT const int valueLength,
						const BOOLEAN noCheck )
	{
	REVOCATION_INFO *newElement, *insertPoint;

	assert( isWritePtr( listHeadPtrPtr, sizeof( REVOCATION_INFO * ) ) );
	assert( isWritePtr( newEntryPosition, sizeof( REVOCATION_INFO * ) ) );
	assert( isReadPtr( value, valueLength ) );
	
	REQUIRES( valueType == CRYPT_KEYID_NONE || \
			  valueType == CRYPT_IKEYID_CERTID || \
			  valueType == CRYPT_IKEYID_ISSUERID || \
			  valueType == CRYPT_IKEYID_ISSUERANDSERIALNUMBER );
	REQUIRES( valueLength > 0 && valueLength < MAX_INTLENGTH_SHORT );

	/* Clear return value */
	*newEntryPosition = NULL;

	/* Find the insertion point for the new entry unless we're reading data
	   from a pre-encoded CRL, in which case we just drop it in at the start.
	   The absence of checking for data from an existing CRL is necessary in
	   order to provide same-day service for large CRLs */
	if( !noCheck && *listHeadPtrPtr != NULL && \
		cryptStatusOK( \
			findRevocationEntry( *listHeadPtrPtr, &insertPoint, value,
								  valueLength, TRUE ) ) )
		{
		/* If we get an OK status it means that we've found an existing
		   entry that matches the one being added, we can't add it again */
		return( CRYPT_ERROR_DUPLICATE );
		}
	else
		{
		/* It's an empty list, insert the new element at the start */
		insertPoint = NULL;
		}

	/* Allocate memory for the new element and copy the information across */
	if( ( newElement = ( REVOCATION_INFO * ) \
			clAlloc( "addRevocationEntry", sizeof( REVOCATION_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newElement, 0, sizeof( REVOCATION_INFO ) );
	if( valueLength > MAX_ID_SIZE )
		{
		if( ( newElement->idPtr = clDynAlloc( "addRevocationEntry",
											  valueLength ) ) == NULL )
			{
			clFree( "addRevocationEntry", newElement );
			return( CRYPT_ERROR_MEMORY );
			}
		}
	else
		newElement->idPtr = newElement->id;
	newElement->idType = valueType;
	memcpy( newElement->idPtr, value, valueLength );
	newElement->idLength = valueLength;
	newElement->idCheck = checksumData( value, valueLength );

	/* Insert the new element into the list */
	if( noCheck )
		{
		/* If we're adding data from an existing CRL drop it in at the
		   quickest insert point.  This is necessary for quick operation
		   when handling mega-CRLs */
		newElement->next = *listHeadPtrPtr;
		*listHeadPtrPtr = newElement;
		}
	else
		insertSingleListElement( listHeadPtrPtr, insertPoint, newElement );
	*newEntryPosition = newElement;
	return( CRYPT_OK );
	}

/* Delete a revocation list */

STDC_NONNULL_ARG( ( 1 ) ) \
void deleteRevocationEntries( INOUT_PTR REVOCATION_INFO **listHeadPtrPtr )
	{
	REVOCATION_INFO *entryListPtr = *listHeadPtrPtr;
	int iterationCount;

	assert( isWritePtr( listHeadPtrPtr, sizeof( REVOCATION_INFO * ) ) );

	*listHeadPtrPtr = NULL;

	/* Destroy any remaining list items */
	for( iterationCount = 0;
		 entryListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MAX;
		 iterationCount++ )
		{
		REVOCATION_INFO *itemToFree = entryListPtr;

		entryListPtr = entryListPtr->next;
		if( itemToFree->idPtr != itemToFree->id )
			{
			zeroise( itemToFree->idPtr, itemToFree->idLength );
			clFree( "deleteRevocationEntries", itemToFree->idPtr );
			}
		if( itemToFree->attributes != NULL )
			deleteAttributes( &itemToFree->attributes );
		zeroise( itemToFree, sizeof( REVOCATION_INFO ) );
		clFree( "deleteRevocationEntries", itemToFree );
		}
	}

/* Copy a revocation list */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int copyRevocationEntries( INOUT_PTR REVOCATION_INFO **destListHeadPtrPtr,
						   const REVOCATION_INFO *srcListPtr )
	{
	const REVOCATION_INFO *srcListCursor;
	REVOCATION_INFO *destListCursor = DUMMY_INIT_PTR;
	int iterationCount;

	assert( isWritePtr( destListHeadPtrPtr, sizeof( REVOCATION_INFO * ) ) );
	assert( *destListHeadPtrPtr == NULL );	/* Dest.should be empty */
	assert( isReadPtr( srcListPtr, sizeof( REVOCATION_INFO ) ) );

	/* Sanity check to make sure that the destination list doesn't already 
	   exist, which would cause the copy loop below to fail */
	REQUIRES( *destListHeadPtrPtr == NULL );

	/* Copy all revocation entries from source to destination */
	for( srcListCursor = srcListPtr, iterationCount = 0; 
		 srcListCursor != NULL && iterationCount < FAILSAFE_ITERATIONS_MAX;
		 srcListCursor = srcListCursor->next, iterationCount++ )
		{
		REVOCATION_INFO *newElement;

		/* Allocate the new entry and copy the data from the existing one
		   across.  We don't copy the attributes because there aren't any
		   that should be carried from request to response */
		if( ( newElement = ( REVOCATION_INFO * ) \
					clAlloc( "copyRevocationEntries",
							 sizeof( REVOCATION_INFO ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		memcpy( newElement, srcListCursor, sizeof( REVOCATION_INFO ) );
		if( srcListCursor->idLength > MAX_ID_SIZE )
			{
			/* If the ID information doesn't fit into the fixed buffer,
			   allocate a variable-length one and copy it across */
			if( ( newElement->idPtr = \
					clDynAlloc( "copyRevocationEntries",
								srcListCursor->idLength ) ) == NULL )
				{
				clFree( "copyRevocationEntries", newElement );
				return( CRYPT_ERROR_MEMORY );
				}
			memcpy( newElement->idPtr, srcListCursor->id,
					srcListCursor->idLength );
			}
		else
			newElement->idPtr = newElement->id;
		newElement->attributes = NULL;
		newElement->next = NULL;

		/* Set the status to 'unknown' by default, this means that any
		   entries that we can't do anything with automatically get the
		   correct status associated with them */
		newElement->status = CRYPT_OCSPSTATUS_UNKNOWN;

		/* Link the new element into the list */
		if( *destListHeadPtrPtr == NULL )
			*destListHeadPtrPtr = destListCursor = newElement;
		else
			{
			destListCursor->next = newElement;
			destListCursor = newElement;
			}
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );

	return( CRYPT_OK );
	}

/* Prepare the entries in a revocation list prior to encoding them */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 6 ) ) \
int prepareRevocationEntries( INOUT_OPT REVOCATION_INFO *listPtr, 
							  const time_t defaultTime,
							  OUT_PTR REVOCATION_INFO **errorEntry,
							  const BOOLEAN isSingleEntry,
							  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
								CRYPT_ATTRIBUTE_TYPE *errorLocus,
							  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType )
	{
	REVOCATION_INFO *revocationEntry;
	const time_t currentTime = ( defaultTime > MIN_TIME_VALUE ) ? \
							   defaultTime : getApproxTime();
	int iterationCount, status;

	assert( listPtr == NULL || \
			isReadPtr( listPtr, sizeof( REVOCATION_INFO ) ) );
	assert( isWritePtr( errorEntry, sizeof( REVOCATION_INFO * ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* Clear return value */
	*errorEntry = NULL;

	/* If the revocation list is empty there's nothing to do */
	if( listPtr == NULL )
		return( CRYPT_OK );

	/* Set the revocation time if this hasn't already been set.  If there's a
	   default time set we use that otherwise we use the current time */
	for( revocationEntry = listPtr, iterationCount = 0; 
		 revocationEntry != NULL && iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 revocationEntry = revocationEntry->next, iterationCount++ )
		{
		const ATTRIBUTE_LIST *attributeListPtr;

		if( revocationEntry->revocationTime <= MIN_TIME_VALUE )
			revocationEntry->revocationTime = currentTime;

		/* Check whether the certificate was revoked with a reason of 
		   neverValid, which requires special handling of dates because 
		   X.509 doesn't formally define a neverValid reason, assuming that 
		   all CAs are perfect and never issue certificates in error.  The 
		   general idea is to set the two to the same value with the 
		   invalidity date (which should be earlier than the revocation date, 
		   at least in a sanely-run CA) taking precedence.  A revocation 
		   with this reason code will in general only be issued by the 
		   cryptlib CA (where it's required to handle problems in the CMP 
		   protocol) and this always sets the invalidity date so in almost 
		   all cases we'll be setting the revocation date to the 
		   (CA-specified) invalidity date which is the date of issue of the 
		   certificate being revoked */
		attributeListPtr = findAttributeField( revocationEntry->attributes,
											   CRYPT_CERTINFO_CRLREASON,
											   CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL && \
			attributeListPtr->intValue == CRYPT_CRLREASON_NEVERVALID )
			{
			/* The certificate was revoked with the neverValid code, see if 
			   there's an invalidity date present */
			attributeListPtr = \
					findAttributeField( revocationEntry->attributes,
										CRYPT_CERTINFO_INVALIDITYDATE,
										CRYPT_ATTRIBUTE_NONE );
			if( attributeListPtr == NULL )
				{
				/* There's no invalidity date present, set it to the same as
				   the revocation date */
				status = addAttributeField( &revocationEntry->attributes,
											CRYPT_CERTINFO_INVALIDITYDATE,
											CRYPT_ATTRIBUTE_NONE,
											&revocationEntry->revocationTime,
											sizeof( time_t ), ATTR_FLAG_NONE,
											errorLocus, errorType );
				if( cryptStatusError( status ) )
					{
					/* Remember the entry that caused the problem */
					*errorEntry = revocationEntry;
					return( status );
					}
				}
			else
				{
				/* There's an invalidity date present, make sure the
				   revocation date is the same as the invalidity date */
				revocationEntry->revocationTime = \
						*( time_t * ) attributeListPtr->value;
				}
			}

		/* If we're only processing a single CRL entry rather than an 
		   entire revocation list we're done */
		if( isSingleEntry )
			break;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );

	/* Check the attributes for each entry in a revocation list */
	for( revocationEntry = listPtr, iterationCount = 0; 
		 revocationEntry != NULL && iterationCount < FAILSAFE_ITERATIONS_MAX; 
		 revocationEntry = revocationEntry->next, iterationCount++ )
		{
		if( revocationEntry->attributes != NULL )
			{
			status = checkAttributes( ATTRIBUTE_CERTIFICATE,
									  revocationEntry->attributes,
									  errorLocus, errorType );
			if( cryptStatusError( status ) )
				{
				/* Remember the entry that caused the problem */
				*errorEntry = revocationEntry;
				return( status );
				}
			}

		/* If we're only processing a single CRL entry rather than an 
		   entire revocation list we're done */
		if( isSingleEntry )
			break;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read/write CRL Information						*
*																			*
****************************************************************************/

/* Read/write CRL entries:

	RevokedCert ::= SEQUENCE {
			userCertificate		CertificalSerialNumber,
			revocationDate		UTCTime
			extensions			Extensions OPTIONAL,
			} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofCRLentry( INOUT REVOCATION_INFO *crlEntry )
	{
	assert( isWritePtr( crlEntry, sizeof( REVOCATION_INFO ) ) );

	/* Remember the encoded attribute size for later when we write the
	   attributes */
	crlEntry->attributeSize = sizeofAttributes( crlEntry->attributes );

	return( ( int ) sizeofObject( \
						sizeofInteger( crlEntry->id, crlEntry->idLength ) + \
						sizeofUTCTime() + \
						( ( crlEntry->attributeSize > 0 ) ? \
							( int ) sizeofObject( crlEntry->attributeSize ) : 0 ) ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readCRLentry( INOUT STREAM *stream, 
				  INOUT_PTR REVOCATION_INFO **listHeadPtrPtr,
				  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
					CRYPT_ATTRIBUTE_TYPE *errorLocus,
				  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
					CRYPT_ERRTYPE_TYPE *errorType )
	{
	REVOCATION_INFO *currentEntry;
	BYTE serialNumber[ MAX_SERIALNO_SIZE + 8 ];
	int serialNumberLength, endPos, length, status;
	time_t revocationTime;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( listHeadPtrPtr, sizeof( REVOCATION_INFO * ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* Determine the overall size of the entry */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;

	/* Read the integer component of the serial number (limited to a sane
	   length) and the revocation time */
	readInteger( stream, serialNumber, MAX_SERIALNO_SIZE,
				 &serialNumberLength );
	status = readUTCTime( stream, &revocationTime );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the entry to the revocation information list.  The ID type isn't
	   quite an issueAndSerialNumber but the checking code eventually
	   converts it into this form using the supplied issuer certificate DN */
	status = addRevocationEntry( listHeadPtrPtr, &currentEntry,
								 CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
								 serialNumber, serialNumberLength,
								 ( endPos > CRL_SORT_LIMIT ) ? TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );
	currentEntry->revocationTime = revocationTime;

	/* Read the extensions if there are any present.  Since these are per-
	   entry extensions we read the extensions themselves as
	   CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_CRL to make sure
	   that they're processed as required */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		{
		status = readAttributes( stream, &currentEntry->attributes,
								 CRYPT_CERTTYPE_NONE, length,
								 errorLocus, errorType );
		}

	return( status );
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCRLentry( INOUT STREAM *stream, 
				   const REVOCATION_INFO *crlEntry )
	{
	const int revocationLength = \
				sizeofInteger( crlEntry->id, crlEntry->idLength ) + \
				sizeofUTCTime() + \
				( ( crlEntry->attributeSize > 0 ) ? \
					( int ) sizeofObject( crlEntry->attributeSize ) : 0 );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( crlEntry, sizeof( REVOCATION_INFO ) ) );

	/* Write the CRL entry */
	writeSequence( stream, revocationLength );
	writeInteger( stream, crlEntry->id, crlEntry->idLength, DEFAULT_TAG );
	status = writeUTCTime( stream, crlEntry->revocationTime, DEFAULT_TAG );
	if( cryptStatusError( status ) || crlEntry->attributeSize <= 0 )
		return( status );

	/* Write the per-entry extensions.  Since these are per-entry extensions
	   we write them as CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_CRL to
	   make sure that they're processed as required  */
	return( writeAttributes( stream, crlEntry->attributes,
							 CRYPT_CERTTYPE_NONE, crlEntry->attributeSize ) );
	}

/****************************************************************************
*																			*
*							Read/write OCSP Information						*
*																			*
****************************************************************************/

/* Read/write an OCSP certificate ID:

	CertID ::=	CHOICE {
		certID			SEQUENCE {
			hashAlgo	AlgorithmIdentifier,
			iNameHash	OCTET STRING,	-- Hash of issuerName
			iKeyHash	OCTET STRING,	-- Hash of issuer SPKI w/o tag+len
			serialNo	INTEGER
				},
		certificate	[0]	EXPLICIT [0] EXPLICIT Certificate,
		certIdWithSignature
					[1]	EXPLICIT SEQUENCE {
			iAndS		IssuerAndSerialNumber,
			tbsCertHash	BIT STRING,
			certSig		SEQUENCE {
				sigAlgo	AlgorithmIdentifier,
				sigVal	BIT STRING
				}
			}
		} */

CHECK_RETVAL_RANGE( MAX_ERROR, 1024 ) STDC_NONNULL_ARG( ( 1 ) ) \
static int sizeofOcspID( const REVOCATION_INFO *ocspEntry )
	{
	assert( isReadPtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );
	
	REQUIRES( ocspEntry->idType == CRYPT_KEYID_NONE );

	/* For now we don't try and handle anything except the v1 ID since the
	   status of v2 is uncertain (it doesn't add anything to v1 except even
	   more broken IDs) */
	return( ocspEntry->idLength );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
static int readOcspID( INOUT STREAM *stream, 
					   OUT_ENUM_OPT( CRYPT_KEYID ) CRYPT_KEYID_TYPE *idType,
					   OUT_BUFFER( idMaxLen, *idLen ) BYTE *id, 
					   IN_LENGTH_SHORT_MIN( 16 ) const int idMaxLen,
					   OUT_LENGTH_SHORT_Z int *idLen )
	{
	HASHFUNCTION_ATOMIC hashFunctionAtomic;
	void *dataPtr = DUMMY_INIT_PTR;
	int length, tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( idType, sizeof( CRYPT_KEYID_TYPE ) ) );
	assert( isWritePtr( id, idMaxLen ) );
	assert( isWritePtr( idLen, sizeof( int ) ) );

	REQUIRES( idMaxLen >= 16 && idMaxLen < MAX_INTLENGTH_SHORT );

	getHashAtomicParameters( CRYPT_ALGO_SHA1, &hashFunctionAtomic, NULL );

	/* Clear return values */
	*idType = CRYPT_KEYID_NONE;
	memset( id, 0, min( 16, idMaxLen ) );
	*idLen = 0;

	/* Read the ID */
	tag = peekTag( stream );
	if( cryptStatusError( tag ) )
		return( tag );
	switch( tag )
		{
		case BER_SEQUENCE:
			/* We can't really do anything with v1 IDs since the one-way
			   hashing process destroys any chance of being able to work
			   with them and the fact that no useful certificate info is 
			   hashed means that we can't use them to identify a cert.  As 
			   a result the following ID type will always produce a result
			   of "unknown" */
			*idType = CRYPT_KEYID_NONE;
			status = getStreamObjectLength( stream, &length );
			if( cryptStatusError( status ) )
				return( status );
			if( length < 8 )
				return( CRYPT_ERROR_UNDERFLOW );
			if( length > idMaxLen )
				return( CRYPT_ERROR_OVERFLOW );
			*idLen = length;
			return( sread( stream, id, length ) );

		case MAKE_CTAG( CTAG_OI_CERTIFICATE ):
			/* Convert the certificate to a certID */
			*idType = CRYPT_IKEYID_CERTID;
			*idLen = KEYID_SIZE;
			readConstructed( stream, NULL, CTAG_OI_CERTIFICATE );
			status = readConstructed( stream, &length, 0 );
			if( cryptStatusOK( status ) )
				status = sMemGetDataBlock( stream, &dataPtr, length );
			if( cryptStatusError( status ) )
				return( status );
			hashFunctionAtomic( id, KEYID_SIZE, dataPtr, length );
			return( readUniversal( stream ) );

		case MAKE_CTAG( CTAG_OI_CERTIDWITHSIG ):
			/* A bizarro ID dreamed up by Denis Pinkas that manages to carry
			   over all the problems of the v1 ID without being compatible
			   with it.  It's almost as unworkable as the v1 original but we 
			   can convert the iAndS to an issuerID and use that */
			*idType = CRYPT_IKEYID_ISSUERID;
			*idLen = KEYID_SIZE;
			readConstructed( stream, NULL, CTAG_OI_CERTIDWITHSIG );
			readSequence( stream, NULL );
			status = getStreamObjectLength( stream, &length );
			if( cryptStatusOK( status ) )
				status = sMemGetDataBlock( stream, &dataPtr, length );
			if( cryptStatusError( status ) )
				return( status );
			hashFunctionAtomic( id, KEYID_SIZE, dataPtr, length );
			sSkip( stream, length );			/* issuerAndSerialNumber */
			readUniversal( stream );			/* tbsCertificateHash */
			return( readUniversal( stream ) );	/* certSignature */
		}

	return( CRYPT_ERROR_BADDATA );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeOcspID( INOUT STREAM *stream, 
						const REVOCATION_INFO *ocspEntry )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );
	
	return( swrite( stream, ocspEntry->id, ocspEntry->idLength ) );
	}

/* Read/write an OCSP request entry:

	Entry ::= SEQUENCE {				-- Request
		certID			CertID,
		extensions	[0]	EXPLICIT Extensions OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofOcspRequestEntry( INOUT REVOCATION_INFO *ocspEntry )
	{
	assert( isWritePtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );
	
	REQUIRES( ocspEntry->idType == CRYPT_KEYID_NONE );

	/* Remember the encoded attribute size for later when we write the
	   attributes */
	ocspEntry->attributeSize = sizeofAttributes( ocspEntry->attributes );

	return( ( int ) \
			sizeofObject( sizeofOcspID( ocspEntry ) + \
						  ( ( ocspEntry->attributeSize > 0 ) ? \
							( int ) \
							sizeofObject( \
								sizeofObject( ocspEntry->attributeSize ) ) : 0 ) ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readOcspRequestEntry( INOUT STREAM *stream, 
						  INOUT_PTR REVOCATION_INFO **listHeadPtrPtr,
						  INOUT CERT_INFO *certInfoPtr )
	{
	const ATTRIBUTE_LIST *attributeListPtr;
	REVOCATION_INFO *currentEntry;
	STREAM certIdStream;
	BYTE idBuffer[ MAX_ID_SIZE + 8 ];
	CRYPT_KEYID_TYPE idType;
	int endPos, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( listHeadPtrPtr, sizeof( REVOCATION_INFO * ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Determine the overall size of the entry */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;

	/* Read the ID information */
	status = readOcspID( stream, &idType, idBuffer, MAX_ID_SIZE, &length );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the entry to the revocation information list */
	status = addRevocationEntry( listHeadPtrPtr, &currentEntry, idType,
								 idBuffer, length, FALSE );
	if( cryptStatusError( status ) || \
		stell( stream ) > endPos - MIN_ATTRIBUTE_SIZE )
		return( status );

	/* Read the extensions.  Since these are per-entry extensions we read
	   the wrapper here and read the extensions themselves as
	   CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_OCSP to make sure that
	   they're processed as required.  Note that these are per-request-entry
	   extensions rather than overall per-request extensions so the tag
	   is CTAG_OR_SR_EXTENSIONS rather than CTAG_OR_EXTENSIONS */
	status = readConstructed( stream, &length, CTAG_OR_SR_EXTENSIONS );
	if( cryptStatusOK( status ) )
		{
		status = readAttributes( stream, &currentEntry->attributes,
								 CRYPT_CERTTYPE_NONE, length,
								 &certInfoPtr->errorLocus,
								 &certInfoPtr->errorType );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* OCSPv1 uses a braindamaged certificate identification method that 
	   breaks the certificate information up into bits and hashes some while 
	   leaving others intact, making it impossible to identify the 
	   certificate from it.  To try and fix this, if the request includes an 
	   ESSCertID we use that to make it look like there was a proper ID 
	   present */
	if( currentEntry->idType != CRYPT_KEYID_NONE )
		return( CRYPT_OK );		/* Proper ID present, we're done */
	attributeListPtr = findAttribute( currentEntry->attributes, 
									  CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID, 
									  TRUE );
	if( attributeListPtr == NULL )
		return( CRYPT_OK );		/* No ESSCertID present, can't continue */

	/* Extract the ID information from the ESSCertID and save it alongside
	   the OCSP ID which we need to retain for use in the response */
	sMemConnect( &certIdStream, attributeListPtr->value, 
				 attributeListPtr->valueLength );
	readSequence( &certIdStream, NULL );
	status = readOctetString( &certIdStream, idBuffer, &length, KEYID_SIZE, 
							  KEYID_SIZE );
	if( cryptStatusOK( status ) )
		{
		currentEntry->altIdType = CRYPT_IKEYID_CERTID;
		memcpy( currentEntry->altID, idBuffer, length );
		}
	sMemDisconnect( &certIdStream );
	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeOcspRequestEntry( INOUT STREAM *stream, 
						   const REVOCATION_INFO *ocspEntry )
	{
	const int attributeSize = ( ocspEntry->attributeSize > 0 ) ? \
					( int ) sizeofObject( \
								sizeofObject( ocspEntry->attributeSize ) ) : 0;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );

	/* Write the header and ID information */
	writeSequence( stream, sizeofOcspID( ocspEntry ) + attributeSize );
	status = writeOcspID( stream, ocspEntry );
	if( cryptStatusError( status ) || ocspEntry->attributeSize <= 0 )
		return( status );

	/* Write the per-entry extensions.  Since these are per-entry extensions
	   we write them as CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_OCSP
	   to make sure that they're processed as required.  Note that these are 
	   per-request-entry extensions rather than overall per-request 
	   extensions so the tag is CTAG_OR_SR_EXTENSIONS rather than 
	   CTAG_OR_EXTENSIONS */
	writeConstructed( stream, sizeofObject( ocspEntry->attributeSize ), 
					  CTAG_OR_SR_EXTENSIONS );
	return( writeAttributes( stream, ocspEntry->attributes,
							 CRYPT_CERTTYPE_NONE, ocspEntry->attributeSize ) );
	}

/* Read/write an OCSP response entry:

	Entry ::= SEQUENCE {
		certID			CertID,
		certStatus		CHOICE {
			notRevd	[0]	IMPLICIT NULL,
			revd	[1]	SEQUENCE {
				revTime	GeneralizedTime,
				revReas	[0] EXPLICIT CRLReason Optional
							},
			unknown	[2] IMPLICIT NULL
						},
		thisUpdate		GeneralizedTime,
		extensions	[1]	EXPLICIT Extensions OPTIONAL
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofOcspResponseEntry( INOUT REVOCATION_INFO *ocspEntry )
	{
	int certStatusSize = 0;

	assert( isWritePtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );

	/* Remember the encoded attribute size for later when we write the
	   attributes */
	ocspEntry->attributeSize = sizeofAttributes( ocspEntry->attributes );

	/* Determine the size of the certificate status field */
	certStatusSize = ( ocspEntry->status != CRYPT_OCSPSTATUS_REVOKED ) ? \
					 sizeofNull() : ( int ) sizeofObject( sizeofGeneralizedTime() );

	return( ( int ) \
			sizeofObject( sizeofOcspID( ocspEntry ) + \
						  certStatusSize + sizeofGeneralizedTime() ) + \
						  ( ( ocspEntry->attributeSize > 0 ) ? \
							( int ) sizeofObject( ocspEntry->attributeSize ) : 0 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readOcspResponseEntry( INOUT STREAM *stream, 
						   INOUT_PTR REVOCATION_INFO **listHeadPtrPtr,
						   INOUT CERT_INFO *certInfoPtr )
	{
	REVOCATION_INFO *currentEntry;
	BYTE idBuffer[ MAX_ID_SIZE + 8 ];
	CRYPT_KEYID_TYPE idType;
	int endPos, length, crlReason = 0, tag, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( listHeadPtrPtr, sizeof( REVOCATION_INFO * ) ) );
	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Determine the overall size of the entry */
	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;

	/* Read the ID information */
	status = readOcspID( stream, &idType, idBuffer, MAX_ID_SIZE, &length );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the entry to the revocation information list */
	status = addRevocationEntry( listHeadPtrPtr, &currentEntry, idType,
								 idBuffer, length, FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the status information */
	status = tag = peekTag( stream );
	if( cryptStatusError( status ) )
		return( status );
	switch( tag )
		{
		case MAKE_CTAG_PRIMITIVE( OCSP_STATUS_NOTREVOKED ):
			currentEntry->status = CRYPT_OCSPSTATUS_NOTREVOKED;
			status = readUniversal( stream );
			break;

		case MAKE_CTAG( OCSP_STATUS_REVOKED ):
			currentEntry->status = CRYPT_OCSPSTATUS_REVOKED;
			readConstructed( stream, NULL, OCSP_STATUS_REVOKED );
			status = readGeneralizedTime( stream, 
										  &currentEntry->revocationTime );
			if( cryptStatusOK( status ) && \
				peekTag( stream ) == MAKE_CTAG( 0 ) )
				{
				/* Remember the crlReason for later */
				readConstructed( stream, NULL, 0 );
				status = readEnumerated( stream, &crlReason );
				}
			break;

		case MAKE_CTAG_PRIMITIVE( OCSP_STATUS_UNKNOWN ):
			currentEntry->status = CRYPT_OCSPSTATUS_UNKNOWN;
			status = readUniversal( stream );
			break;

		default:
			return( CRYPT_ERROR_BADDATA );
		}
	if( cryptStatusError( status ) )
		return( status );
	status = readGeneralizedTime( stream, &certInfoPtr->startTime );
	if( cryptStatusOK( status ) && peekTag( stream ) == MAKE_CTAG( 0 ) )
		{
		readConstructed( stream, NULL, 0 );
		status = readGeneralizedTime( stream, &certInfoPtr->endTime );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the extensions if there are any present.  Since these are per-
	   entry extensions we read the wrapper here and read the extensions
	   themselves as CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_OCSP to
	   make sure that they're processed as required */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		{
		status = readConstructed( stream, &length, CTAG_OP_EXTENSIONS );
		if( cryptStatusOK( status ) )
			{
			status = readAttributes( stream, &currentEntry->attributes,
						CRYPT_CERTTYPE_NONE, length,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If there's a crlReason present in the response and none as an
	   extension add it as an extension (OCSP allows the same information
	   to be specified in two different places, to make it easier we always
	   return it as a crlReason extension, however some implementations
	   return it in both places so we have to make sure that we don't try and
	   add it a second time) */
	if( findAttributeField( currentEntry->attributes,
							CRYPT_CERTINFO_CRLREASON,
							CRYPT_ATTRIBUTE_NONE ) == NULL )
		{
		status = addAttributeField( &currentEntry->attributes,
						CRYPT_CERTINFO_CRLREASON, CRYPT_ATTRIBUTE_NONE,
						&crlReason, CRYPT_UNUSED, ATTR_FLAG_NONE,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		}

	return( status );
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeOcspResponseEntry( INOUT STREAM *stream, 
							const REVOCATION_INFO *ocspEntry,
							const time_t entryTime )
	{
	int certStatusSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( ocspEntry, sizeof( REVOCATION_INFO ) ) );

	/* Determine the size of the certificate status field */
	certStatusSize = ( ocspEntry->status != CRYPT_OCSPSTATUS_REVOKED ) ? \
					 sizeofNull() : ( int ) sizeofObject( sizeofGeneralizedTime() );

	/* Write the header and ID information */
	writeSequence( stream, sizeofOcspID( ocspEntry ) + \
				   certStatusSize + sizeofGeneralizedTime() + \
				   ( ( ocspEntry->attributeSize > 0 ) ? \
						( int ) sizeofObject( ocspEntry->attributeSize ) : 0 ) );
	writeOcspID( stream, ocspEntry );

	/* Write the certificate status */
	if( ocspEntry->status == CRYPT_OCSPSTATUS_REVOKED )
		{
		writeConstructed( stream, sizeofGeneralizedTime(),
						  CRYPT_OCSPSTATUS_REVOKED );
		writeGeneralizedTime( stream, ocspEntry->revocationTime,
							  DEFAULT_TAG );
		}
	else
		{
		/* An other-than-revoked status is communicated as a tagged NULL
		   value.  For no known reason this portion of OCSP uses implicit
		   tagging, since it's the one part of the PDU in which an
		   explicit tag would actually make sense */
		writeNull( stream, ocspEntry->status );
		}

	/* Write the current update time, which should be the current time.
	   Since new status information is always available we don't write a
	   nextUpdate time (in fact there is some disagreement over whether these
	   times are based on CRL info, responder info, the response dispatch
	   time, or a mixture of the above, implementations can be found that
	   return all manner of peculiar values here) */
	status = writeGeneralizedTime( stream, entryTime, DEFAULT_TAG );
	if( cryptStatusError( status ) || ocspEntry->attributeSize <= 0 )
		return( status );

	/* Write the per-entry extensions.  Since these are per-entry extensions
	   we write them as CRYPT_CERTTYPE_NONE rather than CRYPT_CERTTYPE_OCSP
	   to make sure that they're processed as required */
	return( writeAttributes( stream, ocspEntry->attributes,
							 CRYPT_CERTTYPE_NONE, ocspEntry->attributeSize ) );
	}
