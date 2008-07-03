/****************************************************************************
*																			*
*						Certificate Attribute Copy Routines					*
*						Copyright Peter Gutmann 1996-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "certattr.h"
  #include "asn1.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1.h"		/* For sizeofOID() */
#endif /* Compiler-specific includes */

/* When replicating attributes from one type of certificate object to 
   another (for example from an issuer certificate to a subject certificate 
   when issuing a new certificate) we may have to adjust the attribute info 
   based on the source and destination object roles.  The following values 
   denote the different copy types that we have to handle.  Usually this is 
   a direct copy, however if we're copying from subject to issuer we have to 
   adjust attribute IDs such as the altName (subjectAltName -> issuerAltName), 
   if we're copying from issuer to subject we have to adjust path 
   length-based contraints since the new subject is one further down the 
   chain */

typedef enum {
	COPY_NONE,				/* No copy type */
	COPY_DIRECT,			/* Direct attribute copy */
	COPY_SUBJECT_TO_ISSUER,	/* Copy of subject attributes to issuer cert */
	COPY_ISSUER_TO_SUBJECT,	/* Copy of issuer attributes to subject cert */
	COPY_LAST				/* Last valid copy type */
	} COPY_TYPE;

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Copy an attribute field */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyAttributeField( OUT_PTR ATTRIBUTE_LIST **destAttributeField,
							   const ATTRIBUTE_LIST *srcAttributeField )
	{
	ATTRIBUTE_LIST *newElement;
	int status = CRYPT_OK;

	assert( isWritePtr( destAttributeField, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( srcAttributeField, sizeof( ATTRIBUTE_LIST ) ) );

	/* Allocate memory for the new element and copy the information across */
	*destAttributeField = NULL;
	if( ( newElement = ( ATTRIBUTE_LIST * ) \
					   clAlloc( "copyAttributeField", \
								sizeofVarStruct( srcAttributeField, \
												 ATTRIBUTE_LIST ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	copyVarStruct( newElement, srcAttributeField, ATTRIBUTE_LIST );
	if( srcAttributeField->fieldType == FIELDTYPE_DN )
		{
		/* If the field contains a DN, copy the DN across */
		status = copyDN( ( void ** ) &newElement->value,
						 srcAttributeField->value );
		if( cryptStatusError( status ) )
			{
			endVarStruct( newElement, ATTRIBUTE_LIST );
			clFree( "copyAttributeField", newElement );
			return( status );
			}
		}
	newElement->next = newElement->prev = NULL;
	*destAttributeField = newElement;

	return( CRYPT_OK );
	}

/* Copy an attribute from one attribute list to another.  This is an all-or-
   nothing copy in that it either copies a complete attribute or nothing at
   all */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyAttribute( OUT_PTR ATTRIBUTE_LIST **destListHeadPtr,
						  const ATTRIBUTE_LIST *srcListPtr,
						  IN_ENUM( COPY ) const COPY_TYPE copyType )
	{
	const CRYPT_ATTRIBUTE_TYPE attributeID = srcListPtr->attributeID;
	CRYPT_ATTRIBUTE_TYPE newAttributeID = attributeID;
	ATTRIBUTE_LIST *newAttributeListHead = NULL;
	ATTRIBUTE_LIST *newAttributeListTail = DUMMY_INIT_PTR;
	ATTRIBUTE_LIST *insertPoint, *prevElement = NULL;
	int iterationCount;

	assert( isWritePtr( destListHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( srcListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	
	REQUIRES( copyType > COPY_NONE && copyType < COPY_LAST );

	/* If we're re-mapping the destination attribute ID (see the comment
	   further down) we have to insert it at a point corresponding to the 
	   re-mapped ID, not the original ID, to maintain the list's sorted
	   property */
	if( copyType == COPY_SUBJECT_TO_ISSUER )
		{
		if( attributeID == CRYPT_CERTINFO_SUBJECTALTNAME )
			newAttributeID = CRYPT_CERTINFO_ISSUERALTNAME;
		if( attributeID == CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER )
			newAttributeID = CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER;
		}

	/* Find the location at which to insert this attribute (this assumes 
	   that the fieldIDs are defined in sorted order) */
	for( insertPoint = *destListHeadPtr;
		 insertPoint != NULL && \
			insertPoint->attributeID < newAttributeID && \
			insertPoint->fieldID != CRYPT_ATTRIBUTE_NONE;
		 insertPoint = insertPoint->next )
		{
		prevElement = insertPoint;
		}
	insertPoint = prevElement;

	/* Build a new attribute list containing the attribute fields */
	for( iterationCount = 0;
		 srcListPtr != NULL && srcListPtr->attributeID == attributeID && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		ATTRIBUTE_LIST *newAttributeField;
		int status;

		/* Copy the field across */
		status = copyAttributeField( &newAttributeField, srcListPtr );
		if( cryptStatusError( status ) )
			{
			deleteAttributes( &newAttributeListHead );
			return( status );
			}

		/* If we're copying from an issuer to a subject attribute list and 
		   the field is an altName or keyIdentifier, change the field type 
		   from issuer.subjectAltName to subject.issuerAltName or
		   issuer.subjectKeyIdentifier to subject.authorityKeyIdentifier */
		if( copyType == COPY_SUBJECT_TO_ISSUER )
			{
			if( attributeID == CRYPT_CERTINFO_SUBJECTALTNAME )
				newAttributeField->attributeID = \
					newAttributeField->fieldID = \
						CRYPT_CERTINFO_ISSUERALTNAME;
			if( attributeID == CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER )
				{
				newAttributeField->attributeID = \
						CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER;
				newAttributeField->fieldID = \
						CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER;
				}
			}

		/* If we're copying from a subject to an issuer attribute list and
		   it's a path length-based constraint, adjust the constraint value
		   by one since we're now one further down the chain */
		if( copyType == COPY_ISSUER_TO_SUBJECT && \
			( newAttributeField->fieldID == \
							CRYPT_CERTINFO_PATHLENCONSTRAINT || \
			  newAttributeField->fieldID == \
							CRYPT_CERTINFO_REQUIREEXPLICITPOLICY || \
			  newAttributeField->fieldID == \
							CRYPT_CERTINFO_INHIBITPOLICYMAPPING ) )
			{
			/* If we're already at a path length of zero we can't reduce it
			   any further the best that we can do is to not copy the
			   attribute */
			if( newAttributeField->intValue <= 0 )
				{
				deleteAttributeField( &newAttributeField, NULL, 
									  newAttributeField, NULL );
				}
			else
				newAttributeField->intValue--;
			}

		/* Append the new field to the new attribute list.  We can't use 
		   insertDoubleListElement() for this because we're appending the 
		   element to the list rather than inserting it at a given 
		   position */
		if( newAttributeListHead == NULL )
			newAttributeListHead = newAttributeListTail = newAttributeField;
		else
			{
			newAttributeListTail->next = newAttributeField;
			newAttributeField->prev = newAttributeListTail;
			newAttributeListTail = newAttributeField;
			}

		/* Move on to the next field */
		srcListPtr = srcListPtr->next;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	ENSURES( newAttributeListHead != NULL );

	/* Link the new list into the existing list at the appropriate position */
	insertDoubleListElements( destListHeadPtr, insertPoint, 
							  newAttributeListHead, newAttributeListTail );

	return( CRYPT_OK );
	}

/* Copy a length constraint, adjusting the value by one */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int copyLengthConstraint( /*?*/ ATTRIBUTE_LIST **destListHeadPtr,
								 const ATTRIBUTE_LIST *srcListPtr,
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	ATTRIBUTE_LIST *destListPtr;

	assert( isWritePtr( destListHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( srcListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	
	REQUIRES( fieldID > CRYPT_ATTRIBUTE_NONE && \
			  fieldID < CRYPT_ATTRIBUTE_LAST );

	/* If there's nothing to copy, we're done */
	srcListPtr = findAttributeField( srcListPtr, fieldID, 
									 CRYPT_ATTRIBUTE_NONE );
	if( srcListPtr == NULL )
		return( CRYPT_OK );

	/* There's something to copy, if it's not already present in the 
	   destination, just copy it across */
	destListPtr = findAttributeField( *destListHeadPtr, fieldID, 
									  CRYPT_ATTRIBUTE_NONE );
	if( destListPtr == NULL )
		return( copyAttributeField( destListHeadPtr, srcListPtr ) );

	/* The same constraint exists in source and destination, set the result
	   value to the lesser of the two */
	if( srcListPtr->intValue < destListPtr->intValue )
		destListPtr->intValue = srcListPtr->intValue;

	return( CRYPT_OK );
	}					

/****************************************************************************
*																			*
*							Copy a Complete Attribute List					*
*																			*
****************************************************************************/

/* Copy a complete attribute list */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int copyAttributes( INOUT ATTRIBUTE_LIST **destListHeadPtr,
					const ATTRIBUTE_LIST *srcListPtr,
					OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						CRYPT_ATTRIBUTE_TYPE *errorLocus,
					OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
						CRYPT_ERRTYPE_TYPE *errorType )
	{
	int iterationCount;

	assert( isWritePtr( destListHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( srcListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* If there are destination attributes present make a first pass down 
	   the list checking that the attribute to copy isn't already in the
	   destination attributes, first for recognised attributes and then for
	   unrecognised ones.  We have to do this separately since once we begin
	   the copy process it's rather hard to undo it.  There are two special 
	   cases that we could in theory allow:

		1. Some composite attributes could have non-overlapping fields in 
		   the source and destination.

		2. Some attributes can have multiple instances of a field present.

	   This means that we could allow them to appear in both the source and 
	   destination lists, however if this occurs it's more likely to be an 
	   error than a desire to merge two disparate collections of fields or
	   attributes */
	if( *destListHeadPtr != NULL )
		{
		const ATTRIBUTE_LIST *attributeListCursor;

		for( attributeListCursor = srcListPtr, iterationCount = 0;
			 attributeListCursor != NULL && \
				!isBlobAttribute( attributeListCursor ) && \
				iterationCount < FAILSAFE_ITERATIONS_MAX; 
			 attributeListCursor = attributeListCursor->next, iterationCount++ )
			{
			ENSURES( attributeListCursor->next == NULL || \
					 !isValidAttributeField( attributeListCursor->next ) || \
					 attributeListCursor->attributeID <= \
							attributeListCursor->next->attributeID );
			if( findAttributeField( *destListHeadPtr,
									attributeListCursor->fieldID, 
									CRYPT_ATTRIBUTE_NONE ) != NULL )
				{
				*errorLocus = attributeListCursor->fieldID;
				*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
				return( CRYPT_ERROR_DUPLICATE );
				}
			}
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );
		for( ; attributeListCursor != NULL && \
			   iterationCount < FAILSAFE_ITERATIONS_MAX;
			 attributeListCursor = attributeListCursor->next, iterationCount++ )
			{
			ENSURES( isBlobAttribute( attributeListCursor ) );
			if( findAttributeByOID( *destListHeadPtr, 
									attributeListCursor->oid,
									sizeofOID( attributeListCursor->oid ) ) != NULL )
				{
				/* We can't set the locus for blob-type attributes since 
				   it's not a known attribute */
				*errorLocus = CRYPT_ATTRIBUTE_NONE;
				*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
				return( CRYPT_ERROR_DUPLICATE );
				}
			}
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );
		}

	/* Make a second pass copying everything across */
	for( iterationCount = 0;
		 srcListPtr != NULL && !isBlobAttribute( srcListPtr ) && \
			iterationCount < FAILSAFE_ITERATIONS_MAX;
		 iterationCount++ )
		{
		CRYPT_ATTRIBUTE_TYPE attributeID = srcListPtr->attributeID;
		const ATTRIBUTE_INFO *attributeInfoPtr = \
				( srcListPtr->attributeInfoPtr != NULL ) ? \
				srcListPtr->attributeInfoPtr : \
				fieldIDToAttribute( ( attributeID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
										ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE,
									attributeID, CRYPT_ATTRIBUTE_NONE, NULL );
		int status;

		assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

		/* Copy the complete attribute across unless it's one that we 
		   explicitly don't propagate from source to destination */
		if( !( attributeInfoPtr->flags & FL_NOCOPY ) )
			{
			status = copyAttribute( destListHeadPtr, srcListPtr, 
									COPY_DIRECT );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Move on to the next attribute */
		while( srcListPtr != NULL && \
			   srcListPtr->attributeID == attributeID && \
			   iterationCount++ < FAILSAFE_ITERATIONS_MAX )
			srcListPtr = srcListPtr->next;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );

	/* If there are blob-type attributes left at the end of the list, copy
	   them across last */
	if( srcListPtr != NULL )
		{
		ATTRIBUTE_LIST *insertPoint;

		/* Find the end of the destination list */
		for( insertPoint = *destListHeadPtr, iterationCount = 0;
			 insertPoint != NULL && insertPoint->next != NULL && \
				iterationCount < FAILSAFE_ITERATIONS_MAX;
			 insertPoint = insertPoint->next, iterationCount++ );
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );

		/* Copy all remaining attributes across */
		for( ; srcListPtr != NULL && \
			   iterationCount < FAILSAFE_ITERATIONS_MAX;
			srcListPtr = srcListPtr->next, iterationCount++ )
			{
			ATTRIBUTE_LIST *newAttribute;
			int status;

			status = copyAttributeField( &newAttribute, srcListPtr );
			if( cryptStatusError( status ) )
				return( status );
			insertDoubleListElement( destListHeadPtr, insertPoint, 
									 newAttribute );
			
			}
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Copy Specific Attributes						*
*																			*
****************************************************************************/

/* Copy attributes that are propagated down certificate chains from an 
   issuer to a subject certificate, changing the field types from subject 
   to issuer and adjust constraint values at the same time if required */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
int copyIssuerAttributes( INOUT ATTRIBUTE_LIST **destListHeadPtr,
						  const ATTRIBUTE_LIST *srcListPtr,
						  const CRYPT_CERTTYPE_TYPE type,
						  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
							CRYPT_ATTRIBUTE_TYPE *errorLocus,
						  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
							CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int status = CRYPT_OK;

	assert( isWritePtr( destListHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( srcListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( type > CRYPT_CERTTYPE_NONE && type < CRYPT_CERTTYPE_LAST );

	/* If the destination is a CA certificate and the source has constraint 
	   extensions, copy them over to the destination.  The reason why we
	   copy the constraints even though they're already present in the
	   source is to ensure that they're still present in a certificate chain 
	   even if the parent isn't available.  This can occur for example when 
	   a chain-internal certificate is marked as implicitly trusted and the 
	   chain is only available up to the implicitly-trusted certificate with 
	   the contraint-imposing parent not present */
	attributeListPtr = findAttributeField( *destListHeadPtr, 
										   CRYPT_CERTINFO_CA, 
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && attributeListPtr->intValue > 0 )
		{
		ATTRIBUTE_LIST *srcPermittedSubtrees, *srcExcludedSubtrees;

		srcPermittedSubtrees = findAttributeField( srcListPtr,
												   CRYPT_CERTINFO_PERMITTEDSUBTREES,
												   CRYPT_ATTRIBUTE_NONE );
		srcExcludedSubtrees = findAttributeField( srcListPtr,
												  CRYPT_CERTINFO_EXCLUDEDSUBTREES,
												  CRYPT_ATTRIBUTE_NONE );

		/* If we're copying permitted or excluded subtrees they can't 
		   already be present.  We check the two separately rather than just 
		   checking for the overall presence of name constraints since in 
		   theory it's possible to merge permitted and excluded constraints,
		   so that permitted constraints in the destination don't clash with
		   excluded constraints in the source (yet another one of X.509's 
		   semantic holes) */
		if( srcPermittedSubtrees != NULL && \
			findAttributeField( *destListHeadPtr, \
								CRYPT_CERTINFO_PERMITTEDSUBTREES,
								CRYPT_ATTRIBUTE_NONE ) != NULL )
			{
			*errorLocus = CRYPT_CERTINFO_PERMITTEDSUBTREES;
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_DUPLICATE );
			}
		if( srcExcludedSubtrees != NULL && \
			findAttributeField( *destListHeadPtr, \
								CRYPT_CERTINFO_EXCLUDEDSUBTREES,
								CRYPT_ATTRIBUTE_NONE ) != NULL )
			{
			*errorLocus = CRYPT_CERTINFO_EXCLUDEDSUBTREES;
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_DUPLICATE );
			}

		/* Copy the fields across */
		if( srcPermittedSubtrees != NULL )
			{
			status = copyAttribute( destListHeadPtr, srcPermittedSubtrees, 
									COPY_SUBJECT_TO_ISSUER );
			if( cryptStatusError( status ) )
				return( status );
			}
		if( srcExcludedSubtrees != NULL )
			{
			status = copyAttribute( destListHeadPtr, srcExcludedSubtrees, 
									COPY_SUBJECT_TO_ISSUER );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* The path-length constraints are a bit easier to handle, if 
		   they're already present we just use the smaller of the two */
		if( srcPermittedSubtrees != NULL )
			{
			status = copyLengthConstraint( destListHeadPtr, srcPermittedSubtrees, 
										   CRYPT_CERTINFO_PATHLENCONSTRAINT );
			if( cryptStatusOK( status ) )
				status = copyLengthConstraint( destListHeadPtr, srcPermittedSubtrees, 
											   CRYPT_CERTINFO_REQUIREEXPLICITPOLICY );
			if( cryptStatusOK( status ) )
				status = copyLengthConstraint( destListHeadPtr, srcPermittedSubtrees, 
											   CRYPT_CERTINFO_INHIBITPOLICYMAPPING );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* If it's an attribute certificate, that's all that we can copy */
	if( type == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		return( CRYPT_OK );

	/* Copy the altName and keyIdentifier if these are present.  We don't
	   have to check for their presence in the destination certificate since 
	   they're read-only fields and can't be added by the user */
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_SUBJECTALTNAME, 
									  TRUE );
	if( attributeListPtr != NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, 
								COPY_SUBJECT_TO_ISSUER );
		if( cryptStatusError( status ) )
			return( status );
		}
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER, 
									  TRUE );
	if( attributeListPtr != NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, 
								COPY_SUBJECT_TO_ISSUER );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Copy the authorityInfoAccess if it's present.  This one is a bit 
	   tricky both because it's a multi-valued attribute and some values 
	   may already be present in the destination certificate and because 
	   it's not certain that the issuer certificate's AIA should be the same 
	   as the subject certificate's AIA.  At the moment with monolithic CAs 
	   (i.e. ones that control all the certificates down to the EE) this is 
	   always the case and if it isn't it's assumed that the CA will set the 
	   EE's AIA to the appropriate value before trying to sign the 
	   certificate.  Because of this we copy the issuer AIA if there's no 
	   subject AIA present, otherwise we assume that the CA has set the 
	   subject AIA to its own choice of value and don't try and copy 
	   anything */
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_AUTHORITYINFOACCESS, FALSE );
	if( attributeListPtr != NULL && \
		findAttribute( *destListHeadPtr, 
					   CRYPT_CERTINFO_AUTHORITYINFOACCESS, FALSE ) == NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, 
								COPY_SUBJECT_TO_ISSUER );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Copy attributes that are propagated from a CRMF certificate request 
   template to the issued certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int copyCRMFRequestAttributes( INOUT ATTRIBUTE_LIST **destListHeadPtr,
							   const ATTRIBUTE_LIST *srcListPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int status;

	assert( isWritePtr( destListHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( srcListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	/* Copy the altName across.  This is needed because it contains 
	   additional identification information (in fact probably the only 
	   identification information of any value) like the email address and 
	   server URL */
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_SUBJECTALTNAME, 
									  TRUE );
	if( attributeListPtr != NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, 
								COPY_DIRECT );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Copy attributes that are propagated from an OCSP request to a response */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int copyOCSPRequestAttributes( INOUT ATTRIBUTE_LIST **destListHeadPtr,
							   const ATTRIBUTE_LIST *srcListPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	assert( isWritePtr( destListHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( srcListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	/* If the nonce attribute is already present in the destination, delete
	   it */
	attributeListPtr = findAttributeField( *destListHeadPtr,
							CRYPT_CERTINFO_OCSP_NONCE, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		deleteAttributeField( destListHeadPtr, NULL, attributeListPtr, NULL );

	/* Copy the nonce attribute from the source to the destination.  We don't
	   copy anything else (i.e. we default to deny-all) to prevent the 
	   requester from being able to insert arbitrary attributes into the 
	   response */
	attributeListPtr = findAttributeField( srcListPtr,
							CRYPT_CERTINFO_OCSP_NONCE, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		return( copyAttribute( destListHeadPtr, attributeListPtr, 
							   COPY_DIRECT ) );
		}

	return( CRYPT_OK );
	}

/* Copy attributes that are propagated from a revocation request to a CRL */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int copyRevocationAttributes( INOUT ATTRIBUTE_LIST **destListHeadPtr,
							  const ATTRIBUTE_LIST *srcListPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int status;

	assert( isWritePtr( destListHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( srcListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	/* Copy the CRL reason and invalidity date attributes from the source to 
	   the destination.  We don't copy anything else (i.e. we default to 
	   deny-all) to prevent the requester from being able to insert arbitrary 
	   attributes into the CRL */
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_CRLREASON, FALSE );
	if( attributeListPtr != NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, 
								COPY_DIRECT );
		if( cryptStatusError( status ) )
			return( status );
		}
	attributeListPtr = findAttribute( srcListPtr,
									  CRYPT_CERTINFO_INVALIDITYDATE, FALSE );
	if( attributeListPtr != NULL )
		{
		return( copyAttribute( destListHeadPtr, attributeListPtr, 
								COPY_DIRECT ) );
		}

	return( CRYPT_OK );
	}
