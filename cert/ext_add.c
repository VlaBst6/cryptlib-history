/****************************************************************************
*																			*
*					Certificate Attribute Add/Delete Routines				*
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

/* Check the validity of an attribute field */

typedef enum { 
	CHECKATTR_INFO_NONE,		/* No special return info */
	CHECKATTR_INFO_ZEROLENGTH,	/* Zero-length data, e.g.int, bool, DN placeholder */
	CHECKATTR_INFO_NEWLENGTH,	/* Data length change, value in newDataLength */
	CHECKATTR_INFO_LAST			/* Last possible return info type */
	} CHECKATTR_INFO_TYPE;

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 2, 8, 9, 10 ) ) \
static int checkAttributeField( IN_OPT const ATTRIBUTE_LIST *attributeListPtr,
								const ATTRIBUTE_INFO *attributeInfoPtr,
								IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID,
								IN_ATTRIBUTE_OPT \
									const CRYPT_ATTRIBUTE_TYPE subFieldID,
								/*?*/ const void *data, 
								/*?*/ const int dataLength,
								IN_FLAGS( ATTR ) const int flags, 
								OUT_ENUM_OPT( CHECKATTR_INFO ) \
									CHECKATTR_INFO_TYPE *infoType, 
								OUT_LENGTH_SHORT_Z int *newDataLength, 
								OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	int status;

	assert( attributeListPtr == NULL || \
			isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( dataLength == CRYPT_UNUSED || isReadPtr( data, dataLength ) );
	assert( isWritePtr( infoType, sizeof( CHECKATTR_INFO_TYPE ) ) );
	assert( isWritePtr( newDataLength, sizeof( int ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			  fieldID <= CRYPT_CERTINFO_LAST );
	REQUIRES( subFieldID == CRYPT_ATTRIBUTE_NONE || \
			  ( subFieldID >= CRYPT_CERTINFO_FIRST_NAME && \
				subFieldID <= CRYPT_CERTINFO_LAST_GENERALNAME ) );
	REQUIRES( dataLength == CRYPT_UNUSED || \
			  ( data != NULL && \
				dataLength > 0 && dataLength <= MAX_ATTRIBUTE_SIZE ) );
assert( ( flags & ~( ATTR_FLAG_NONE | ATTR_FLAG_BLOB_PAYLOAD | ATTR_FLAG_CRITICAL | ATTR_FLAG_MULTIVALUED ) ) == 0 );
	REQUIRES( flags >= ATTR_FLAG_NONE && flags <= ATTR_FLAG_MAX );
	REQUIRES( !( flags & ATTR_FLAG_INVALID ) );

	/* Clear return values */
	*infoType = CHECKATTR_INFO_NONE;
	*newDataLength = 0;

	/* Make sure that a valid field has been specified and that this field
	   isn't already present as a non-default entry unless it's a field for
	   which multiple values are allowed */
	if( attributeInfoPtr == NULL )
		return( CRYPT_ARGERROR_VALUE );
	if( attributeListPtr != NULL && \
		findAttributeField( attributeListPtr, fieldID, subFieldID ) != NULL )
		{
		/* If it's not multivalued, we can't have any duplicate fields */
		if( !( ( attributeInfoPtr->flags & FL_MULTIVALUED ) || \
			   ( flags & ATTR_FLAG_MULTIVALUED ) ) )
			{
			if( errorType != NULL )
				*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_INITED );
			}
		}

	/* If it's a blob field, don't do any type checking.  This is a special
	   case that differs from FIELDTYPE_BLOB in that it corresponds to an
	   ASN.1 value that's mis-encoded by one or more implementations, so we
	   have to accept absolutely anything at this point */
	if( flags & ATTR_FLAG_BLOB )
		return( CRYPT_OK );

	switch( attributeInfoPtr->fieldType )
		{
		case FIELDTYPE_IDENTIFIER:
			/* It's an identifier, make sure that all parameters are correct */
			ENSURES( dataLength == CRYPT_UNUSED );
			if( *( ( int * ) data ) != CRYPT_UNUSED )
				return( CRYPT_ARGERROR_NUM1 );

			/* Tell the caller that this is a special-case entry with 
			   zero-length data */
			*infoType = CHECKATTR_INFO_ZEROLENGTH;
			return( CRYPT_OK );

		case FIELDTYPE_DN:
			/* When creating a new certificate this is a special-case field 
			   that's used as a placeholder to indicate that a DN structure 
			   is being instantiated.  When reading an encoded certificate 
			   this is the decoded DN structure */
			ENSURES( dataLength == CRYPT_UNUSED );

			/* Tell the caller that this is a special-case entry with 
			   zero-length data */
			*infoType = CHECKATTR_INFO_ZEROLENGTH;
			return( CRYPT_OK );

		case BER_OBJECT_IDENTIFIER:
			{
			const BYTE *oidPtr = data;
			BYTE binaryOID[ MAX_OID_SIZE + 8 ];

			/* If it's a BER/DER-encoded OID, make sure that it's valid 
			   ASN.1 */
			if( oidPtr[ 0 ] == BER_OBJECT_IDENTIFIER )
				{
				if( dataLength >= 3 && sizeofOID( oidPtr ) == dataLength )
					return( CRYPT_OK );
				}
			else
				{
				int length;

				/* It's a text OID, check the syntax and make sure that the 
				   length is valid */
				status = textToOID( data, dataLength, binaryOID, 
									MAX_OID_SIZE, &length );
				if( cryptStatusOK( status ) )
					{
					/* The binary form of the OID differs in length from the 
					   string form, tell the caller that the data length has
					   changed */
					*infoType = CHECKATTR_INFO_NEWLENGTH;
					*newDataLength = length;
					return( CRYPT_OK );
					}
				}

			if( errorType != NULL )
				*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			return( CRYPT_ARGERROR_STR1 );
			}

		case BER_BOOLEAN:
			ENSURES( dataLength == CRYPT_UNUSED );

			/* BOOLEAN data is accepted as zero/nonzero so it's always 
			   valid, however we let the caller know that this is non-string 
			   data with no storage requirements */
			*infoType = CHECKATTR_INFO_ZEROLENGTH;
			return( CRYPT_OK );

		case BER_INTEGER:
		case BER_ENUMERATED:
		case BER_BITSTRING:
		case BER_NULL:
		case FIELDTYPE_CHOICE:
			{
			int value = *( ( int * ) data );

			/* Check that the range is valid */
			if( value < attributeInfoPtr->lowRange || \
				value > attributeInfoPtr->highRange )
				{
				if( errorType != NULL )
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( CRYPT_ARGERROR_NUM1 );
				}

			/* Let the caller know that this is non-string data with no 
			   storage requirements */
			*infoType = CHECKATTR_INFO_ZEROLENGTH;
			return( CRYPT_OK );
			}

		}

	/* It's some sort of string value, perform a general data size check */
	if( dataLength < attributeInfoPtr->lowRange || \
		dataLength > attributeInfoPtr->highRange )
		{
		if( errorType != NULL )
			*errorType = CRYPT_ERRTYPE_ATTR_SIZE;
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* If we're not checking the payload in order to handle CAs who stuff 
	   any old rubbish into the fields exit now unless it's a blob field, 
	   for which we need to find at least valid ASN.1 data */
	if( ( flags & ATTR_FLAG_BLOB_PAYLOAD ) && \
		( attributeInfoPtr->fieldType != FIELDTYPE_BLOB ) )
		return( CRYPT_OK );

	switch( attributeInfoPtr->fieldType )
		{
		case FIELDTYPE_BLOB:
			/* It's a blob field, make sure that it's a valid ASN.1 object */
			status = checkObjectEncoding( data, dataLength );
			if( cryptStatusError( status ) )
				{
				if( errorType != NULL )
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( CRYPT_ARGERROR_STR1 );
				}
			return( CRYPT_OK );

		case BER_STRING_NUMERIC:
			{
			const char *dataPtr = data;
			int i;

			/* Make sure that it's a numeric string */
			for( i = 0; i < dataLength; i++ )
				{
				if( !isDigit( dataPtr[ i ] ) )
					{
					if( errorType != NULL )
						*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
					return( CRYPT_ARGERROR_STR1 );
					}
				}
			return( CRYPT_OK );
			}

		case BER_STRING_IA5:
		case BER_STRING_ISO646:
		case BER_STRING_PRINTABLE:
			/* Make sure that it's an ASCII string of the correct type */
			if( !checkTextStringData( data, dataLength, 
					( attributeInfoPtr->fieldType == BER_STRING_PRINTABLE ) ? \
					TRUE : FALSE ) )
				{
				if( errorType != NULL )
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( CRYPT_ARGERROR_STR1 );
				}
			return( CRYPT_OK );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Add Attribute Data							*
*																			*
****************************************************************************/

/* Add a blob-type attribute to a list of attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 6 ) ) \
int addAttribute( IN_ENUM( ATTRIBUTE ) const ATTRIBUTE_TYPE attributeType,
				  /*?*/ ATTRIBUTE_LIST **listHeadPtr, 
				  IN_BUFFER( oidLength ) const BYTE *oid, 
				  IN_RANGE( MIN_OID_SIZE, MAX_OID_SIZE ) const int oidLength,
				  const BOOLEAN critical, 
				  IN_BUFFER( dataLength ) const void *data, 
				  IN_LENGTH_SHORT const int dataLength, 
				  IN_FLAGS_Z( ATTR ) const int flags )
	{
	ATTRIBUTE_LIST *newElement, *insertPoint = NULL;

	assert( isWritePtr( listHeadPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( oid, oidLength ) );
	assert( isReadPtr( data, dataLength ) );
	assert( ( flags & ( ATTR_FLAG_IGNORED | ATTR_FLAG_BLOB ) ) || \
			!cryptStatusError( checkObjectEncoding( data, dataLength ) ) );

	REQUIRES( attributeType == ATTRIBUTE_CERTIFICATE || \
			  attributeType == ATTRIBUTE_CMS );
	REQUIRES( oidLength >= MIN_OID_SIZE && oidLength <= MAX_OID_SIZE && \
			  oidLength == sizeofOID( oid ) );
	REQUIRES( data != NULL && \
			  dataLength > 0 && dataLength <= MAX_ATTRIBUTE_SIZE );
assert( ( flags & ~( ATTR_FLAG_NONE | ATTR_FLAG_IGNORED | ATTR_FLAG_BLOB | ATTR_FLAG_MULTIVALUED ) ) == 0 );
	REQUIRES( flags == ATTR_FLAG_NONE || flags == ATTR_FLAG_BLOB || \
			  flags == ( ATTR_FLAG_BLOB | ATTR_FLAG_IGNORED ) );

	/* If this attribute type is already handled as a non-blob attribute,
	   don't allow it to be added as a blob as well.  This avoids problems
	   with the same attribute being added twice, once as a blob and once as
	   a non-blob.  In addition it forces the caller to use the (recommended)
	   normal attribute handling mechanism, which allows for proper type
	   checking */
	if( !( flags & ATTR_FLAG_BLOB ) && \
		oidToAttribute( attributeType, oid, oidLength ) != NULL )
		return( CRYPT_ERROR_PERMISSION );

	/* Find the correct place in the list to insert the new element */
	if( *listHeadPtr != NULL )
		{
		ATTRIBUTE_LIST *prevElement = NULL;

		for( insertPoint = *listHeadPtr; insertPoint != NULL;
			 insertPoint = insertPoint->next )
			{
			/* Make sure that this blob attribute isn't already present */
			if( isBlobAttribute( insertPoint ) && \
				sizeofOID( insertPoint->oid ) == oidLength && \
				!memcmp( insertPoint->oid, oid, oidLength ) )
				return( CRYPT_ERROR_INITED );

			prevElement = insertPoint;
			}
		insertPoint = prevElement;
		}

	/* Allocate memory for the new element and copy the information across.  
	   The data is stored in storage ... storage + dataLength, the OID in
	   storage + dataLength ... storage + dataLength + oidLength */
	if( ( newElement = ( ATTRIBUTE_LIST * ) \
					   clAlloc( "addAttribute", sizeof( ATTRIBUTE_LIST ) + \
												dataLength + oidLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	initVarStruct( newElement, ATTRIBUTE_LIST, dataLength + oidLength );
	newElement->oid = newElement->storage + dataLength;
	memcpy( newElement->oid, oid, oidLength );
	newElement->flags = ( flags & ATTR_FLAG_IGNORED ) | \
						( critical ? ATTR_FLAG_CRITICAL : ATTR_FLAG_NONE );
	memcpy( newElement->value, data, dataLength );
	newElement->valueLength = dataLength;
	insertDoubleListElements( listHeadPtr, insertPoint, newElement, newElement );

	return( CRYPT_OK );
	}

/* Add an attribute field to a list of attributes at the appropriate 
   location */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 7, 8 ) ) \
int addAttributeField( /*?*/ ATTRIBUTE_LIST **attributeListPtr,
					   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID,
					   IN_ATTRIBUTE_OPT const CRYPT_ATTRIBUTE_TYPE subFieldID,
					   /*?*/ const void *data, 
					   /*?*/ const int dataLength,
					   IN_FLAGS_Z( ATTR ) const int flags, 
					   OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
							CRYPT_ATTRIBUTE_TYPE *errorLocus,
					   OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
							CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_TYPE attributeType = \
							( fieldID >= CRYPT_CERTINFO_FIRST_CMS ) ? \
							ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	CRYPT_ATTRIBUTE_TYPE attributeID;
	const ATTRIBUTE_INFO *attributeInfoPtr = fieldIDToAttribute( attributeType,
										fieldID, subFieldID, &attributeID );
	ATTRIBUTE_LIST *newElement, *insertPoint, *prevElement = NULL;
	CHECKATTR_INFO_TYPE infoType;
	int storageSize, newDataLength, iterationCount, status;

	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( dataLength == CRYPT_UNUSED || isReadPtr( data, dataLength ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES( fieldID >= CRYPT_CERTINFO_FIRST_EXTENSION && \
			  fieldID <= CRYPT_CERTINFO_LAST );
	REQUIRES( subFieldID == CRYPT_ATTRIBUTE_NONE || \
			  ( subFieldID >= CRYPT_CERTINFO_FIRST_NAME && \
				subFieldID <= CRYPT_CERTINFO_LAST_GENERALNAME ) );
	REQUIRES( dataLength == CRYPT_UNUSED || \
			  ( data != NULL && \
			    dataLength > 0 && dataLength <= MAX_ATTRIBUTE_SIZE ) );
assert( ( flags & ~( ATTR_FLAG_BLOB_PAYLOAD | ATTR_FLAG_CRITICAL | ATTR_FLAG_MULTIVALUED | ATTR_FLAG_BLOB_PAYLOAD ) ) == 0 );
	REQUIRES( flags >= ATTR_FLAG_NONE && flags <= ATTR_FLAG_MAX );
	REQUIRES( !( flags & ATTR_FLAG_INVALID ) );

	/* Sanity-check the state */
	ENSURES( attributeInfoPtr != NULL );

	/* Check the field's validity */
	status = checkAttributeField( *attributeListPtr, attributeInfoPtr, 
								  fieldID, subFieldID, data, dataLength, 
								  flags, &infoType, &newDataLength, 
								  errorType );
	if( cryptStatusError( status ) )
		{
		if( errorType != NULL && *errorType != CRYPT_ERRTYPE_NONE )
			{
			/* If we encountered an error that sets the error type, record 
			   the locus */
			*errorLocus = fieldID;
			}
		return( status );
		}
	ENSURES( infoType == CHECKATTR_INFO_ZEROLENGTH || \
			 ( dataLength > 0 && dataLength < MAX_ATTRIBUTE_SIZE ) );

	/* Find the location at which to insert this attribute field (this 
	   assumes that the fieldIDs are defined in sorted order) */
	for( insertPoint = *attributeListPtr, iterationCount = 0;
		 insertPoint != NULL && \
			insertPoint->fieldID != CRYPT_ATTRIBUTE_NONE && \
			insertPoint->fieldID <= fieldID && \
			iterationCount < FAILSAFE_ITERATIONS_MAX;
		 iterationCount++ )
		{
		ENSURES( insertPoint->next == NULL || \
				 !isValidAttributeField( insertPoint->next ) || \
				 insertPoint->attributeID <= insertPoint->next->attributeID );

		/* If it's a composite field that can have multiple fields with the 
		   same field ID (e.g. a GeneralName), exit if the overall field ID 
		   is greater (the component belongs to a different field entirely) 
		   or if the field ID is the same and the subfield ID is greater (if 
		   the component belongs to the same field) */
		if( subFieldID != CRYPT_ATTRIBUTE_NONE && \
			insertPoint->fieldID == fieldID && \
			insertPoint->subFieldID > subFieldID )
			break;

		prevElement = insertPoint;
		insertPoint = insertPoint->next;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );
	insertPoint = prevElement;

	/* Allocate memory for the new element and copy the information across.
	   If it's a simple type we can assign it to the simple value in the
	   element itself, otherwise we copy it into the storage in the element.  
	   Something that encodes to NULL isn't really a numeric type but we 
	   class it as such so that any attempt to read it returns CRYPT_UNUSED 
	   as the value */
	switch( infoType )
		{
		case CHECKATTR_INFO_NONE:
			/* No special-case length handling */
			storageSize = dataLength;
			break;

		case CHECKATTR_INFO_ZEROLENGTH:
			/* Zero-length data, e.g. integer, boolean, DN placeholder */
			storageSize = 0;
			break;

		case CHECKATTR_INFO_NEWLENGTH:
			/* The length has changed due to data en/decoding, use the 
			   en/decoded length for the storage size */
			storageSize = newDataLength;
			break;

		default:
			retIntError();
		}
	if( ( newElement = ( ATTRIBUTE_LIST * ) \
					   clAlloc( "addAttributeField", sizeof( ATTRIBUTE_LIST ) + \
													 storageSize ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	initVarStruct( newElement, ATTRIBUTE_LIST, storageSize );
	newElement->attributeID = attributeID;
	newElement->fieldID = fieldID;
	newElement->subFieldID = subFieldID;
	newElement->flags = flags;
	newElement->fieldType = attributeInfoPtr->fieldType;
	switch( attributeInfoPtr->fieldType )
		{
		case BER_INTEGER:
		case BER_ENUMERATED:
		case BER_BITSTRING:
		case BER_BOOLEAN:
		case BER_NULL:
		case FIELDTYPE_CHOICE:
			newElement->intValue = *( ( int * ) data );
			if( attributeInfoPtr->fieldType == BER_BOOLEAN )
				{
				/* Force it to the correct type if it's a boolean */
				newElement->intValue = ( newElement->intValue ) ? TRUE : FALSE;
				}
			if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
				{
				/* For encoding purposes the subfield ID is set to the ID of 
				   the CHOICE selection */
				newElement->subFieldID = newElement->intValue;
				}
			break;

		case BER_OBJECT_IDENTIFIER:
			/* If it's a BER/DER-encoded OID copy it in as is, otherwise 
			   convert it from the text form.  In the latter case the 
			   amount of storage allocated is the space required by the
			   text form which is more than the BER/DER-encoded form but
			   we can't tell in advance how much we actually need to 
			   allocate until we've performed the decoding */
			if( ( ( BYTE * ) data )[ 0 ] == BER_OBJECT_IDENTIFIER )
				{
				memcpy( newElement->value, data, dataLength );
				newElement->valueLength = dataLength;
				}
			else
				{
				status = textToOID( data, dataLength, newElement->value, 
									storageSize, &newElement->valueLength );
				ENSURES( cryptStatusOK( status ) );
				}
			break;

		case FIELDTYPE_DN:
			/* When creating a new certificate this is a placeholder to 
			   indicate that a DN structure is being instantiated.  When 
			   reading an encoded certificate this is the decoded DN 
			   structure */
			newElement->value = ( *( ( int * ) data ) == CRYPT_UNUSED ) ? \
								NULL : ( void * ) data;
			break;

		case FIELDTYPE_IDENTIFIER:
			/* This is a placeholder entry with no explicit value */
			newElement->intValue = CRYPT_UNUSED;
			break;

		default:
			ENSURES( dataLength > 0 && dataLength < MAX_ATTRIBUTE_SIZE );
			memcpy( newElement->value, data, dataLength );
			newElement->valueLength = dataLength;
			break;
		}
	insertDoubleListElement( attributeListPtr, insertPoint, newElement );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Delete Attribute Data						*
*																			*
****************************************************************************/

/* Delete an attribute/attribute field from a list of attributes, updating
   the list cursor at the same time.  This is a somewhat ugly kludge, it's
   not really possible to do this cleanly since deleting attributes affects
   the attribute cursor */

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int deleteAttributeField( INOUT ATTRIBUTE_LIST **attributeListPtr,
						  INOUT_OPT ATTRIBUTE_LIST **listCursorPtr,
						  INOUT ATTRIBUTE_LIST *listItem,
						  IN_OPT const void *dnCursor )
	{
	ATTRIBUTE_LIST *listPrevPtr = listItem->prev;
	ATTRIBUTE_LIST *listNextPtr = listItem->next;
	BOOLEAN deletedDN = FALSE;

	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( *attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( listCursorPtr == NULL || \
			isWritePtr( listCursorPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( listItem, sizeof( ATTRIBUTE_LIST ) ) );

	/* If we're about to delete the field that's pointed to by the attribute 
	   cursor, advance the cursor to the next field.  If there's no next 
	   field, move it to the previous field.  This behaviour is the most
	   logically consistent, it means that we can do things like deleting an
	   entire attribute list by repeatedly deleting a field */
	if( listCursorPtr != NULL && *listCursorPtr == listItem )
		*listCursorPtr = ( listNextPtr != NULL ) ? listNextPtr : listPrevPtr;

	/* Remove the item from the list */
	deleteDoubleListElement( attributeListPtr, listItem );

	/* Clear all data in the item and free the memory */
	if( listItem->fieldType == FIELDTYPE_DN )
		{
		/* If we've deleted the DN at the current cursor position, remember
		   this so that we can warn the caller */
		if( dnCursor != NULL && dnCursor == &listItem->value )
			deletedDN = TRUE;
		deleteDN( ( void ** ) &listItem->value );
		}
	endVarStruct( listItem, ATTRIBUTE_LIST );
	clFree( "deleteAttributeField", listItem );

	/* If we deleted the DN at the current cursor position return a 
	   special-case code to let the caller know */
	return( deletedDN ? OK_SPECIAL : CRYPT_OK );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int deleteAttribute( INOUT ATTRIBUTE_LIST **attributeListPtr,
					 INOUT_OPT ATTRIBUTE_LIST **listCursorPtr,
					 INOUT ATTRIBUTE_LIST *listItem,
					 IN_OPT const void *dnCursor )
	{
	CRYPT_ATTRIBUTE_TYPE attributeID;
	ATTRIBUTE_LIST *attributeListCursor;
	int iterationCount, status = CRYPT_OK;

	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( *attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( listCursorPtr == NULL || \
			isWritePtr( listCursorPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( listItem, sizeof( ATTRIBUTE_LIST ) ) );

	/* If it's a blob-type attribute, everything is contained in this one
	   list item so we only need to destroy that */
	if( isBlobAttribute( listItem ) )
		{
		return( deleteAttributeField( attributeListPtr, listCursorPtr, 
									  listItem, NULL ) );
		}

	/* If it's a field that denotes an entire (constructed) attribute it
	   won't have an entry in the list so we find the first field of the
	   constructed attribute that's present in the list and start deleting
	   from that point */
	if( isCompleteAttribute( listItem ) )
		{
		for( attributeListCursor = *attributeListPtr; 
			 attributeListCursor != NULL && \
				attributeListCursor->attributeID != listItem->intValue;
			 attributeListCursor = attributeListCursor->next );
		}
	else
		{
		/* The list item is a field in the attribute, find the start of the
		   fields in this attribute */
		attributeListCursor = findAttributeStart( listItem );
		}
	assert( isWritePtr( attributeListCursor, sizeof( ATTRIBUTE_LIST ) ) );
	ENSURES( attributeListCursor != NULL );
	attributeID = attributeListCursor->attributeID;

	/* It's an item with multiple fields, destroy each field separately */
	for( iterationCount = 0;
		 attributeListCursor != NULL && \
			attributeListCursor->attributeID == attributeID && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		ATTRIBUTE_LIST *itemToFree = attributeListCursor;
		int localStatus;

		attributeListCursor = attributeListCursor->next;
		localStatus = deleteAttributeField( attributeListPtr, listCursorPtr, 
											itemToFree, dnCursor );
		if( cryptStatusError( localStatus ) && status != OK_SPECIAL )
			{
			/* Remember the error code, giving priority to DN cursor-
			   modification notifications */
			status = localStatus;
			}
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );

	return( status );
	}

/* Delete a complete set of attributes */

STDC_NONNULL_ARG( ( 1 ) ) \
void deleteAttributes( INOUT ATTRIBUTE_LIST **attributeListPtr )
	{
	ATTRIBUTE_LIST *attributeListCursor = *attributeListPtr;
	int iterationCount;

	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST * ) ) );

	/* If the list was empty, return now */
	if( attributeListCursor == NULL )
		return;

	/* Destroy any remaining list items */
	for( iterationCount = 0;
		 attributeListCursor != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_MAX;
		 iterationCount++ )
		{
		ATTRIBUTE_LIST *itemToFree = attributeListCursor;

		attributeListCursor = attributeListCursor->next;
		deleteAttributeField( attributeListPtr, NULL, itemToFree, NULL );
		}
	ENSURES_V( iterationCount < FAILSAFE_ITERATIONS_MAX );
	ENSURES_V( *attributeListPtr == NULL );
	}
