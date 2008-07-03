/****************************************************************************
*																			*
*					Certificate Attribute Management Routines				*
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
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Callback function used to provide external access to attribute list-
   internal fields */

CHECK_RETVAL_PTR \
static const void *getAttrFunction( IN_OPT TYPECAST( ATTRIBUTE_LIST * ) \
										const void *attributePtr, 
									OUT_OPT_ATTRIBUTE_Z \
										CRYPT_ATTRIBUTE_TYPE *groupID, 
									OUT_OPT_ATTRIBUTE_Z \
										CRYPT_ATTRIBUTE_TYPE *attributeID, 
									OUT_OPT_ATTRIBUTE_Z \
										CRYPT_ATTRIBUTE_TYPE *instanceID,
									IN_ENUM( ATTR ) const ATTR_TYPE attrGetType )
	{
	const ATTRIBUTE_LIST *attributeListPtr = attributePtr;

	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
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

	/* Move to the next or previous attribute if required */
	if( attributeListPtr == NULL || \
		!isValidAttributeField( attributeListPtr ) )
		return( NULL );
	if( attrGetType == ATTR_PREV )
		attributeListPtr = attributeListPtr->prev;
	else
		{
		if( attrGetType == ATTR_NEXT )
			attributeListPtr = attributeListPtr->next;
		}
	if( attributeListPtr == NULL || \
		!isValidAttributeField( attributeListPtr ) )
		return( NULL );

	/* Return ID information to the caller */
	if( groupID != NULL )
		*groupID = attributeListPtr->attributeID;
	if( attributeID != NULL )
		*attributeID = attributeListPtr->fieldID;
	if( instanceID != NULL )
		*instanceID = attributeListPtr->subFieldID;
	return( attributeListPtr );
	}

/****************************************************************************
*																			*
*								Attribute Type Mapping						*
*																			*
****************************************************************************/

/* Get the attribute information for a given OID */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
const ATTRIBUTE_INFO *oidToAttribute( IN_ENUM( ATTRIBUTE ) \
										const ATTRIBUTE_TYPE attributeType,
									  IN_BUFFER( oidLength ) const BYTE *oid, 
									  IN_RANGE( MIN_OID_SIZE, MAX_OID_SIZE ) \
										const int oidLength )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr;
	const int attributeInfoSize = sizeofAttributeInfo( attributeType );
	int iterationCount;

	assert( isReadPtr( selectAttributeInfo( attributeType ), 
					   sizeof( ATTRIBUTE_INFO ) ) );
	assert( isReadPtr( oid, oidLength ) );
	
	REQUIRES_N( attributeType == ATTRIBUTE_CERTIFICATE || \
				attributeType == ATTRIBUTE_CMS );
	REQUIRES_N( oidLength >= MIN_OID_SIZE && oidLength <= MAX_OID_SIZE && \
				oidLength == sizeofOID( oid ) );
	REQUIRES_N( selectAttributeInfo( attributeType ) != NULL );

	for( attributeInfoPtr = selectAttributeInfo( attributeType ), \
			iterationCount = 0;
		 attributeInfoPtr->fieldID != CRYPT_ERROR && \
			iterationCount < attributeInfoSize; \
		 attributeInfoPtr++, iterationCount++ )
		{
		assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

		if( attributeInfoPtr->oid != NULL && \
			sizeofOID( attributeInfoPtr->oid ) == oidLength && \
			!memcmp( attributeInfoPtr->oid, oid, oidLength ) )
			return( attributeInfoPtr );
		}
	ENSURES_N( iterationCount < attributeInfoSize );

	/* It's an unknown attribute */
	return( NULL );
	}

/* Get the attribute and attributeID for a field ID */

CHECK_RETVAL \
const ATTRIBUTE_INFO *fieldIDToAttribute( IN_ENUM( ATTRIBUTE ) \
											const ATTRIBUTE_TYPE attributeType,
										  IN_ATTRIBUTE \
											const CRYPT_ATTRIBUTE_TYPE fieldID, 
										  IN_ATTRIBUTE_OPT \
											const CRYPT_ATTRIBUTE_TYPE subFieldID,
										  OUT_OPT_ATTRIBUTE_Z \
											CRYPT_ATTRIBUTE_TYPE *attributeID )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr = \
							selectAttributeInfo( attributeType );
	const int attributeInfoSize = sizeofAttributeInfo( attributeType );
	int i;

	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( attributeID == NULL || \
			isWritePtr( attributeID, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );

	REQUIRES_N( attributeType == ATTRIBUTE_CERTIFICATE || \
				attributeType == ATTRIBUTE_CMS );
	REQUIRES_N( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
				fieldID <= CRYPT_CERTINFO_LAST );
	REQUIRES_N( subFieldID == CRYPT_ATTRIBUTE_NONE || \
				( subFieldID >= CRYPT_CERTINFO_FIRST_NAME && \
				  subFieldID <= CRYPT_CERTINFO_LAST_GENERALNAME ) );
	REQUIRES_N( attributeInfoPtr != NULL );

	/* Clear the return value */
	if( attributeID != NULL )
		*attributeID = CRYPT_ATTRIBUTE_NONE;

	/* Find the information on this attribute field */
	for( i = 0; attributeInfoPtr[ i ].fieldID != CRYPT_ERROR && \
				i < attributeInfoSize; i++ )
		{
		assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

		/* If we're looking for an attribute ID and the previous entry 
		   doesn't have more data following it then the current entry is the 
		   start of a complete attribute and therefore contains the 
		   attribute ID */
		if( attributeID != NULL && \
			( i == 0 || !( attributeInfoPtr[ i - 1 ].flags & FL_MORE ) ) )
			{
			int offset;

			/* Usually the attribute ID is the fieldID for the first entry,
			   however in some cases the attributeID is the same as the
			   fieldID and isn't specified until later on.  For example when
			   the attribute consists of a SEQUENCE OF field the first
			   entry is the SEQUENCE and the fieldID isn't given until the
			   second entry.  This case is denoted by the fieldID being 
			   FIELDID_FOLLOWS, if this happens we have to look ahead to 
			   find the fieldID */
			for( offset = 0; 
				 attributeInfoPtr[ i + offset ].fieldID == FIELDID_FOLLOWS && \
					i + offset < attributeInfoSize; offset++ );
			ENSURES_N( i + offset < attributeInfoSize );
			*attributeID = attributeInfoPtr[ i + offset ].fieldID;
			}

		/* Check whether the field ID for this entry matches the one that we 
		   want */
		if( attributeInfoPtr[ i ].fieldID == fieldID )
			{
			/* If we're after a subfield match as well, try and match the
			   subfield */
			if( subFieldID != CRYPT_ATTRIBUTE_NONE && \
				attributeInfoPtr[ i ].extraData != NULL )
				{
				const ATTRIBUTE_INFO *altEncodingTable = \
											attributeInfoPtr[ i ].extraData;

				/* Unfortunately we can't use the attributeInfoSize bounds 
				   check limit here because we don't know the size of the 
				   alternative encoding table so we have to use a generic
				   large value */
				for( i = 0; altEncodingTable[ i ].fieldID != CRYPT_ERROR && \
							i < FAILSAFE_ITERATIONS_LARGE; i++ )
					{
					if( altEncodingTable[ i ].fieldID == subFieldID )
						return( &altEncodingTable[ i ] );
					}

				/* If we reach this point for any reason it's an error so we 
				   don't have to perform an explicit iteration-count check */
				retIntError_Null();
				}

			return( &attributeInfoPtr[ i ] );
			}
		}

	/* If we reach this point for any reason it's an error so we don't have
	   to perform an explicit iteration-count check */
	retIntError_Null();
	}

/****************************************************************************
*																			*
*					Attribute Location/Cursor Movement Routines				*
*																			*
****************************************************************************/

/* Find the start of an attribute from a field within the attribute */

CHECK_RETVAL_PTR \
ATTRIBUTE_LIST *findAttributeStart( IN_OPT const ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	return( attributeFindStart( attributeListPtr, getAttrFunction ) );
	}

/* Find an attribute in a list of certificate attributes by object identifier
   (for blob-type attributes) or by field and subfield ID (for known
   attributes) with extended handling for fields with default values */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 2 ) ) \
ATTRIBUTE_LIST *findAttributeByOID( const ATTRIBUTE_LIST *attributeListPtr,
									IN_BUFFER( oidLength ) const BYTE *oid, 
									IN_RANGE( MIN_OID_SIZE, MAX_OID_SIZE ) \
										const int oidLength )
	{
	int iterationCount;

	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isReadPtr( oid, oidLength ) );
	
	REQUIRES_N( oidLength >= MIN_OID_SIZE && oidLength <= MAX_OID_SIZE && \
				oidLength == sizeofOID( oid ) );

	/* Find the position of this component in the list */
	for( iterationCount = 0;
		 attributeListPtr != NULL && \
			( !isBlobAttribute( attributeListPtr ) || \
			  sizeofOID( attributeListPtr->oid ) != oidLength || \
			  memcmp( attributeListPtr->oid, oid, oidLength ) ) && \
			iterationCount < FAILSAFE_ITERATIONS_MAX;
		 attributeListPtr = attributeListPtr->next, iterationCount++ );
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_MAX );

	return( ( ATTRIBUTE_LIST * ) attributeListPtr );
	}

CHECK_RETVAL_PTR \
ATTRIBUTE_LIST *findAttributeField( IN_OPT const ATTRIBUTE_LIST *attributeListPtr,
									IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID,
									IN_ATTRIBUTE_OPT \
										const CRYPT_ATTRIBUTE_TYPE subFieldID )
	{
	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	REQUIRES_N( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
				fieldID <= CRYPT_CERTINFO_LAST );
	REQUIRES_N( subFieldID == CRYPT_ATTRIBUTE_NONE || \
				( subFieldID >= CRYPT_CERTINFO_FIRST_NAME && \
				  subFieldID <= CRYPT_CERTINFO_LAST_GENERALNAME ) );

	return( attributeFind( attributeListPtr, getAttrFunction,
						   fieldID, subFieldID ) );
	}

CHECK_RETVAL_PTR \
ATTRIBUTE_LIST *findAttributeFieldEx( IN_OPT const ATTRIBUTE_LIST *attributeListPtr,
									  IN_ATTRIBUTE \
										const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	static const ATTRIBUTE_LIST defaultField = DEFAULTFIELD_VALUE;
	static const ATTRIBUTE_LIST completeAttribute = COMPLETEATTRIBUTE_VALUE;
	const ATTRIBUTE_LIST *attributeListCursor;
	const ATTRIBUTE_INFO *attributeInfoPtr;
	const ATTRIBUTE_TYPE attributeType = \
							( fieldID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
							ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	CRYPT_ATTRIBUTE_TYPE attributeID;
	int iterationCount;

	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	REQUIRES_N( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
				fieldID <= CRYPT_CERTINFO_LAST );

	if( attributeListPtr == NULL )
		return( NULL );

	/* Find the position of this component in the list */
	attributeListCursor = attributeFind( attributeListPtr, 
										 getAttrFunction, fieldID, 
										 CRYPT_ATTRIBUTE_NONE );
	if( attributeListCursor != NULL )
		return( ( ATTRIBUTE_LIST * ) attributeListCursor );

	/* The field isn't present in the list of attributes, check whether
	   the attribute itself is present and whether this field has a default
	   value */
	attributeInfoPtr = fieldIDToAttribute( attributeType, fieldID, 
										   CRYPT_ATTRIBUTE_NONE, &attributeID );
	if( attributeInfoPtr == NULL )
		{
		/* There's no attribute containing this field, exit */
		return( NULL );
		}

	/* Check whether any part of the attribute that contains the given 
	   field is present in the list of attribute fields */
	for( attributeListCursor = attributeListPtr, iterationCount = 0;
		 attributeListCursor != NULL && \
			isValidAttributeField( attributeListCursor ) && \
			attributeListCursor->attributeID != attributeID && \
			iterationCount < FAILSAFE_ITERATIONS_MAX; 
		 attributeListCursor = attributeListCursor->next, iterationCount++ );
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_MAX );
	if( attributeListCursor == NULL || \
		!isValidAttributeField( attributeListCursor ) )
		return( NULL );

	/* Some other part of the attribute containing the given field is 
	   present in the list.  If this field wasn't found it could either be a 
	   default value (in which case we return an entry that denotes that 
	   this field is absent but has a default setting) or a field that 
	   denotes an entire constructed attribute (in which case we return an 
	   entry that denotes this) */
	if( attributeInfoPtr->flags & FL_DEFAULT )
		return( ( ATTRIBUTE_LIST * ) &defaultField );
	if( attributeInfoPtr->fieldType == BER_SEQUENCE )
		return( ( ATTRIBUTE_LIST * ) &completeAttribute );

	return( NULL );
	}

/* Find the next instance of an attribute field in an attribute.  This is 
   used to step through multiple instances of a field, for example where the
   attribute is defined as containing a SEQUENCE OF <field> */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
ATTRIBUTE_LIST *findNextFieldInstance( const ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	return( attributeFindNextInstance( attributeListPtr, 
									   getAttrFunction ) );
	}

/* Find an overall attribute in a list of attributes.  This is almost always
   used as a check for the presence of an overall attribute so we provide a 
   separate function to make this explicit */

CHECK_RETVAL_PTR \
ATTRIBUTE_LIST *findAttribute( IN_OPT const ATTRIBUTE_LIST *attributeListPtr,
							   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attributeID,
							   const BOOLEAN isFieldID )
	{
	CRYPT_ATTRIBUTE_TYPE localAttributeID = attributeID;
	int iterationCount;

	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	REQUIRES_N( attributeID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
				attributeID <= CRYPT_CERTINFO_LAST );
	
	if( attributeListPtr == NULL )
		return( NULL );

	/* If this is a (potential) fieldID rather than an attributeID, find the
	   attributeID for the attribute containing this field */
	if( isFieldID )
		{
		if( fieldIDToAttribute( ( attributeID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
									ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE, 
								attributeID, CRYPT_ATTRIBUTE_NONE, 
								&localAttributeID ) == NULL )
			{
			/* There's no attribute containing this field, exit */
			return( NULL );
			}
		}
	else
		{
		/* Make sure that we're searching on an attribute ID rather than a 
		   field ID */
		ENSURES_N( \
			fieldIDToAttribute( ( attributeID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
									ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE, 
								attributeID, CRYPT_ATTRIBUTE_NONE, 
								&localAttributeID ) != NULL && \
			attributeID == localAttributeID );
		}

	/* Check whether this attribute is present in the list of attribute 
	   fields */
	for( iterationCount = 0;
		 attributeListPtr != NULL && \
			isValidAttributeField( attributeListPtr ) && \
			iterationCount < FAILSAFE_ITERATIONS_MAX;
		 attributeListPtr = attributeListPtr->next, iterationCount++ )
		{
		if( attributeListPtr->attributeID == localAttributeID )
			return( ( ATTRIBUTE_LIST * ) attributeListPtr );
		}
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_MAX );

	return( NULL );
	}

CHECK_RETVAL_BOOL \
BOOLEAN checkAttributePresent( IN_OPT const ATTRIBUTE_LIST *attributeListPtr,
							   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	REQUIRES_B( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
				fieldID <= CRYPT_CERTINFO_LAST );

	return( findAttribute( attributeListPtr, fieldID, FALSE ) != NULL ? \
			TRUE : FALSE );
	}

/* Move the attribute cursor relative to the current cursor position */

CHECK_RETVAL_PTR \
ATTRIBUTE_LIST *certMoveAttributeCursor( IN_OPT const ATTRIBUTE_LIST *currentCursor,
										 IN_ATTRIBUTE \
											const CRYPT_ATTRIBUTE_TYPE certInfoType,
										 IN_RANGE( CRYPT_CURSOR_FIRST, \
												   CRYPT_CURSOR_LAST ) \
											const int position )
	{
	assert( currentCursor == NULL || \
			isReadPtr( currentCursor, sizeof( ATTRIBUTE_LIST ) ) );

	REQUIRES_N( certInfoType == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
				certInfoType == CRYPT_ATTRIBUTE_CURRENT || \
				certInfoType == CRYPT_ATTRIBUTE_CURRENT_INSTANCE );
	REQUIRES_N( position <= CRYPT_CURSOR_FIRST && \
				position >= CRYPT_CURSOR_LAST );

	return( ( ATTRIBUTE_LIST * ) \
			attributeMoveCursor( currentCursor, getAttrFunction,
								 certInfoType, position ) );
	}

/****************************************************************************
*																			*
*						Miscellaneous Attribute Routines					*
*																			*
****************************************************************************/

/* Get the default value for an optional field of an attribute */

CHECK_RETVAL \
int getDefaultFieldValue( IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr;

	REQUIRES( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			  fieldID <= CRYPT_CERTINFO_LAST );

	attributeInfoPtr = \
		fieldIDToAttribute( ( fieldID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
							ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE, fieldID, 
							CRYPT_ATTRIBUTE_NONE, NULL );
	ENSURES( attributeInfoPtr != NULL );

	return( ( int ) attributeInfoPtr->defaultValue );
	}

/* Fix up certificate attributes, mapping from incorrect values to standards-
   compliant ones */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int fixAttributes( INOUT CERT_INFO *certInfoPtr )
	{
	int complianceLevel, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	/* Try and locate email addresses wherever they might be stashed and move
	   them to the certificate altNames */
	status = convertEmail( certInfoPtr, &certInfoPtr->subjectName,
						   CRYPT_CERTINFO_SUBJECTALTNAME );
	if( cryptStatusOK( status ) )
		status = convertEmail( certInfoPtr, &certInfoPtr->issuerName,
							   CRYPT_CERTINFO_ISSUERALTNAME );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're running at a compliance level of 
	   CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL or above don't try and compensate
	   for dubious attributes */
	status = krnlSendMessage( certInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE, &complianceLevel, 
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );
	if( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		return( CRYPT_OK );

	/* If the only key usage info present is the Netscape one, convert it 
	   into the X.509 equivalent */
	if( !checkAttributePresent( certInfoPtr->attributes, 
								CRYPT_CERTINFO_KEYUSAGE ) && \
		findAttributeField( certInfoPtr->attributes, 
							CRYPT_CERTINFO_NS_CERTTYPE, 
							CRYPT_ATTRIBUTE_NONE ) != NULL )
		{
		int keyUsage;

		status = getKeyUsageFromExtKeyUsage( certInfoPtr, &keyUsage,
											 &certInfoPtr->errorLocus, 
											 &certInfoPtr->errorType );
		if( cryptStatusOK( status ) )
			{
			status = addAttributeField( &certInfoPtr->attributes,
							CRYPT_CERTINFO_KEYUSAGE, CRYPT_ATTRIBUTE_NONE,
							&keyUsage, CRYPT_UNUSED, ATTR_FLAG_NONE, 
							&certInfoPtr->errorLocus, &certInfoPtr->errorType );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}
