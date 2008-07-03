/****************************************************************************
*																			*
*						Certificate Attribute Write Routines				*
*						 Copyright Peter Gutmann 1996-2007					*
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

/* When we write the attributes as a SET OF Attribute (as CMS does) we have
   to sort them by encoded value.  This is an incredible nuisance since it
   requires that each value be encoded and stored in encoded form, then the
   encoded forms sorted and emitted in that order.  To avoid this hassle we
   keep a record of the current lowest encoded form and then find the next
   one by encoding enough information (the SEQUENCE and OID, CMS attributes
   don't have critical flags) on the fly to distinguish them.  This is
   actually less overhead than storing the encoded form because there are
   only a small total number of attributes (usually 3) and we don't have to
   malloc() storage for each one and manage the stored form if we do things
   on the fly */

#define ATTR_ENCODED_SIZE	( 16 + MAX_OID_SIZE )

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 2 ) ) \
static ATTRIBUTE_LIST *getNextEncodedAttribute( IN const ATTRIBUTE_LIST *attributeListPtr,
												OUT_BUFFER_FIXED( prevEncodedFormLength ) \
													BYTE *prevEncodedForm,
												IN_LENGTH_FIXED( ATTR_ENCODED_SIZE ) \
													const int prevEncodedFormLength )
	{
	const ATTRIBUTE_LIST *currentAttributeListPtr = NULL;
	STREAM stream;
	BYTE currentEncodedForm[ ATTR_ENCODED_SIZE + 8 ];
	BYTE buffer[ ATTR_ENCODED_SIZE + 8 ];
	int iterationCount;

	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isWritePtr( prevEncodedForm, prevEncodedFormLength ) );

	REQUIRES_N( prevEncodedFormLength == ATTR_ENCODED_SIZE );

	/* Give the current encoded form the maximum possible value */
	memset( buffer, 0, ATTR_ENCODED_SIZE );
	memset( currentEncodedForm, 0xFF, ATTR_ENCODED_SIZE );

	sMemOpen( &stream, buffer, ATTR_ENCODED_SIZE );

	/* Write the known attributes until we reach either the end of the list
	   or the first blob-type attribute */
	for( iterationCount = 0;
		 attributeListPtr != NULL && \
			!isBlobAttribute( attributeListPtr ) && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE; 
		 iterationCount++ )
		{
		const BOOLEAN isConstructed = ( attributeListPtr->fifoEnd ) ? TRUE : FALSE;
		const ATTRIBUTE_INFO *attributeInfoPtr = ( isConstructed ) ? \
			attributeListPtr->encodingFifo[ attributeListPtr->fifoEnd - 1 ] : \
			attributeListPtr->attributeInfoPtr;
		CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
		int attributeDataSize;

		/* Determine the size of the attribute payload */
		if( isConstructed && attributeInfoPtr->fieldType != FIELDTYPE_CHOICE )
			{
			attributeDataSize = ( int ) sizeofObject( \
				attributeListPtr->sizeFifo[ attributeListPtr->fifoEnd - 1 ] );
			}
		else
			attributeDataSize = attributeListPtr->encodedSize;

		/* Write the header and OID */
		sseek( &stream, 0 );
		writeSequence( &stream, sizeofOID( attributeInfoPtr->oid ) + \
					   ( int ) sizeofObject( attributeDataSize ) );
		swrite( &stream, attributeInfoPtr->oid,
				sizeofOID( attributeInfoPtr->oid ) );

		/* Check to see whether this is larger than the previous value but
		   smaller than any other one we've seen.  If it is, remember it.  A
		   full-length memcmp() is safe here because no encoded form can be a
		   prefix of another form so we always exit before we get into the 
		   leftover data from previous encodings */
		if( memcmp( prevEncodedForm, buffer, ATTR_ENCODED_SIZE ) < 0 && \
			memcmp( buffer, currentEncodedForm, ATTR_ENCODED_SIZE ) < 0 )
			{
			memcpy( currentEncodedForm, buffer, ATTR_ENCODED_SIZE );
			currentAttributeListPtr = attributeListPtr;
			}

		/* Move on to the next attribute */
		while( attributeListPtr != NULL && \
				attributeListPtr->attributeID == attributeID && \
				iterationCount++ < FAILSAFE_ITERATIONS_LARGE )
			attributeListPtr = attributeListPtr->next;
		}
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_LARGE );

	/* Write the blob-type attributes */
	for( ; attributeListPtr != NULL && \
		   iterationCount < FAILSAFE_ITERATIONS_LARGE; 
		attributeListPtr = attributeListPtr->next, iterationCount++ )
		{
		ENSURES_N( isBlobAttribute( attributeListPtr ) );

		/* Write the header and OID */
		sseek( &stream, 0 );
		writeSequence( &stream, sizeofOID( attributeListPtr->oid ) + \
					   ( int ) sizeofObject( attributeListPtr->valueLength ) );
		swrite( &stream, attributeListPtr->oid,
				sizeofOID( attributeListPtr->oid ) );

		/* Check to see whether this is larger than the previous value but
		   smaller than any other one we've seen.  If it is, remember it */
		if( memcmp( prevEncodedForm, buffer, ATTR_ENCODED_SIZE ) < 0 && \
			memcmp( buffer, currentEncodedForm, ATTR_ENCODED_SIZE ) < 0 )
			{
			memcpy( currentEncodedForm, buffer, ATTR_ENCODED_SIZE );
			currentAttributeListPtr = attributeListPtr;
			}
		}
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_LARGE );

	sMemDisconnect( &stream );

	/* Remember the encoded form of the attribute and return a pointer to
	   it */
	memcpy( prevEncodedForm, currentEncodedForm, ATTR_ENCODED_SIZE );
	return( ( ATTRIBUTE_LIST * ) currentAttributeListPtr );
	}

/* Determine the size of a set of attributes and validate and preprocess the
   attribute information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofAttributes( const ATTRIBUTE_LIST *attributeListPtr )
	{
	int signUnrecognised, attributeSize = 0, iterationCount;

	/* If there's nothing to write, return now */
	if( attributeListPtr == NULL )
		return( 0 );

	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	/* Determine the size of the recognised attributes */
	for( iterationCount = 0;
		 attributeListPtr != NULL && \
			!isBlobAttribute( attributeListPtr ) && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		const BOOLEAN isConstructed = ( attributeListPtr->fifoEnd ) ? TRUE : FALSE;
		const ATTRIBUTE_INFO *attributeInfoPtr = ( isConstructed ) ? \
			attributeListPtr->encodingFifo[ attributeListPtr->fifoEnd - 1 ] : \
			attributeListPtr->attributeInfoPtr;
		const CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
		int length;

		/* Determine the size of the encapsulated attribute payload data */
		if( isConstructed && attributeInfoPtr->fieldType != FIELDTYPE_CHOICE )
			{
			length = ( int ) sizeofObject( \
				attributeListPtr->sizeFifo[ attributeListPtr->fifoEnd - 1 ] );
			}
		else
			length = attributeListPtr->encodedSize;
		length = ( int ) sizeofObject( length );

		/* Determine the overall attribute size */
		length += sizeofOID( attributeInfoPtr->oid );
		if( ( attributeInfoPtr->flags & FL_CRITICAL ) || \
			( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) )
			length += sizeofBoolean();
		attributeSize += ( int ) sizeofObject( length );

		/* Skip everything else in the current attribute */
		while( attributeListPtr != NULL && \
				attributeListPtr->attributeID == attributeID && \
				iterationCount++ < FAILSAFE_ITERATIONS_LARGE )
			attributeListPtr = attributeListPtr->next;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );

	/* If we're not going to be signing the blob-type attributes, return */
	krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE, 
					 &signUnrecognised, 
					 CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES );
	if( !signUnrecognised )
		return( attributeSize );

	/* Determine the size of the blob-type attributes */
	for( ; attributeListPtr != NULL && \
		   iterationCount < FAILSAFE_ITERATIONS_LARGE; 
		attributeListPtr = attributeListPtr->next, iterationCount++ )
		{
		ENSURES( isBlobAttribute( attributeListPtr ) );

		attributeSize += ( int ) \
						 sizeofObject( sizeofOID( attributeListPtr->oid ) + \
						 sizeofObject( attributeListPtr->valueLength ) );
		if( attributeListPtr->flags & ATTR_FLAG_CRITICAL )
			attributeSize += sizeofBoolean();
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );

	return( attributeSize );
	}

/****************************************************************************
*																			*
*					Attribute/Attribute Field Write Routines				*
*																			*
****************************************************************************/

/* Calculate the size of an attribute field */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int calculateSpecialFieldSize( const ATTRIBUTE_LIST *attributeListPtr,
									  const ATTRIBUTE_INFO *attributeInfoPtr,
									  OUT_LENGTH_SHORT_Z int *payloadSize, 
									  const int fieldType )
	{
	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( payloadSize, sizeof( int ) ) );

	REQUIRES( fieldType == FIELDTYPE_BLOB || \
			  fieldType == FIELDTYPE_IDENTIFIER || \
			  ( fieldType > 0 && fieldType < MAX_TAG ) );

	/* Determine the size of the data payload */
	*payloadSize = attributeListPtr->sizeFifo[ attributeListPtr->fifoPos ];

	/* It's a special-case field, the data size is taken from somewhere 
	   other than the user-supplied data */
	switch( fieldType )
		{
		case FIELDTYPE_BLOB:
			/* Fixed-value blob (as opposed to user-supplied one) */
			return( ( int ) attributeInfoPtr->defaultValue );

		case FIELDTYPE_IDENTIFIER:
			return( sizeofOID( attributeInfoPtr->oid ) );

		case BER_INTEGER:
			return( sizeofShortInteger( attributeInfoPtr->defaultValue ) );

		case BER_SEQUENCE:
		case BER_SET:
			return( ( int ) sizeofObject( *payloadSize ) );
		}

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int calculateFieldSize( const ATTRIBUTE_LIST *attributeListPtr,
							   const ATTRIBUTE_INFO *attributeInfoPtr,
							   const int fieldType )
	{
	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES( fieldType >= FIELDTYPE_DISPLAYSTRING && fieldType < MAX_TAG );
			  /* The default handler at the end can include fields up to 
			     FIELDTYPE_DISPLAYSTRING */

	switch( fieldType )
		{
		case FIELDTYPE_BLOB:
		case BER_OBJECT_IDENTIFIER:
			return( attributeListPtr->valueLength );

		case FIELDTYPE_DN:
			return( sizeofDN( attributeListPtr->value ) );

		case FIELDTYPE_IDENTIFIER:
			return( sizeofOID( attributeInfoPtr->oid ) );

		case BER_BITSTRING:
			return( sizeofBitString( attributeListPtr->intValue ) );

		case BER_BOOLEAN:
			return( sizeofBoolean() );

		case BER_ENUMERATED:
			return( sizeofEnumerated( attributeListPtr->intValue ) );

		case BER_INTEGER:
			return( sizeofShortInteger( attributeListPtr->intValue ) );

		case BER_NULL:
			/* This is stored as a pseudo-numeric value CRYPT_UNUSED so we 
			   can't fall through to the default handler */
			return( sizeofNull() );

		case BER_OCTETSTRING:
			/* If it's an integer equivalent to an OCTET STRING hole, we 
			   need to make sure we encode it correctly if the high bit is 
			   set */
			if( attributeInfoPtr->flags & FL_ALIAS )
				{
				ENSURES( attributeInfoPtr->fieldEncodedType == BER_INTEGER );

				return( sizeofInteger( attributeListPtr->value, 
									   attributeListPtr->valueLength ) );
				}
			return( ( int ) sizeofObject( attributeListPtr->valueLength ) );

		case BER_TIME_GENERALIZED:
			return( sizeofGeneralizedTime() );

		case BER_TIME_UTC:
			return( sizeofUTCTime() );
		}

	return( ( int ) sizeofObject( attributeListPtr->valueLength ) );
	}

/* Write an attribute field */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
int writeAttributeField( INOUT_OPT STREAM *stream, 
						 INOUT ATTRIBUTE_LIST *attributeListPtr,
						 IN_RANGE( 0, 4 ) const int complianceLevel )
	{
	const BOOLEAN isSpecial = ( attributeListPtr->fifoPos > 0 ) ? TRUE : FALSE;
	const ATTRIBUTE_INFO *attributeInfoPtr = ( isSpecial ) ? \
		attributeListPtr->encodingFifo[ --attributeListPtr->fifoPos ] : \
		attributeListPtr->attributeInfoPtr;
	const void *dataPtr = attributeListPtr->value;
	const int fieldType = attributeInfoPtr->fieldType;
	int tag, size, payloadSize = DUMMY_INIT;

	assert( stream == NULL || isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	REQUIRES( complianceLevel >= CRYPT_COMPLIANCELEVEL_OBLIVIOUS && \
			  complianceLevel < CRYPT_COMPLIANCELEVEL_LAST );

	/* If this is just a marker for a series of CHOICE alternatives, return
	   without doing anything */
	if( fieldType == FIELDTYPE_CHOICE )
		return( CRYPT_OK );

	/* Calculate the size of the encoded data */
	if( isSpecial )
		{
		size = calculateSpecialFieldSize( attributeListPtr, attributeInfoPtr, 
										  &payloadSize, fieldType );
		}
	else
		{
		size = calculateFieldSize( attributeListPtr, attributeInfoPtr, 
								   fieldType );
		}
	if( cryptStatusError( size ) )
		return( size );

	/* If we're just calculating the attribute size, don't write any data */
	if( stream == NULL )
		{
		return( ( attributeInfoPtr->flags & FL_EXPLICIT ) ? \
				( int ) sizeofObject( size ) : size );
		}

	/* If the field is explicitly tagged, add another layer of wrapping */
	if( attributeInfoPtr->flags & FL_EXPLICIT )
		writeConstructed( stream, size, attributeInfoPtr->fieldEncodedType );

	/* If the encoded field type differs from the actual field type (because
	   if implicit tagging) and we're not specifically using explicit
	   tagging and it's not a DN in a GeneralName (which is a tagged IMPLICIT
	   SEQUENCE overridden to make it EXPLICIT because of the tagged CHOICE
	   encoding rules) set the tag to the encoded field type rather than the
	   actual field type */
	if( attributeInfoPtr->fieldEncodedType >= 0 && \
		!( attributeInfoPtr->flags & FL_EXPLICIT ) && \
		attributeInfoPtr->fieldType != FIELDTYPE_DN )
		tag = attributeInfoPtr->fieldEncodedType;
	else
		tag = DEFAULT_TAG;

	/* Write the data as appropriate */
	if( isSpecial )
		{
		/* If it's a special-case field, the data is taken from somewhere
		   other than the user-supplied data */
		switch( fieldType )
			{
			case FIELDTYPE_BLOB:
				/* Fixed-value blob (as opposed to user-supplied one) */
				return( swrite( stream, attributeInfoPtr->extraData, size ) );

			case FIELDTYPE_IDENTIFIER:
				return( swrite( stream, attributeInfoPtr->oid, size ) );

			case BER_INTEGER:
				return( writeShortInteger( stream, attributeInfoPtr->defaultValue, 
										   tag ) );

			case BER_SEQUENCE:
			case BER_SET:
				if( tag != DEFAULT_TAG )
					return( writeConstructed( stream, payloadSize, tag ) );
				return( ( fieldType == BER_SET ) ? \
						writeSet( stream, payloadSize ) : \
						writeSequence( stream, payloadSize ) );
			}
		
		retIntError();
		}

	/* It's a standard object, take the data from the user-supplied data */
	switch( fieldType )
		{
		case FIELDTYPE_BLOB:
			if( tag != DEFAULT_TAG )
				{
				/* This gets a bit messy because the blob is stored in 
				   encoded form in the attribute, to write it as a tagged 
				   value we have to write a different first byte */
				sputc( stream, getFieldEncodedTag( attributeInfoPtr ) );
				return( swrite( stream, ( ( BYTE * ) dataPtr ) + 1,
								attributeListPtr->valueLength - 1 ) );
				}
			return( swrite( stream, dataPtr, attributeListPtr->valueLength ) );

		case FIELDTYPE_DN:
			return( writeDN( stream, attributeListPtr->value, tag ) );

		case FIELDTYPE_IDENTIFIER:
			ENSURES( tag == DEFAULT_TAG );
			return( swrite( stream, attributeInfoPtr->oid, size ) );

		case FIELDTYPE_DISPLAYSTRING:
			if( tag == DEFAULT_TAG )
				{
				tag = ( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL ) ? \
					  BER_STRING_UTF8 : BER_STRING_ISO646;
				}
			return( writeCharacterString( stream, dataPtr, 
										  attributeListPtr->valueLength, 
										  tag ) );

		case BER_BITSTRING:
			return( writeBitString( stream, ( int ) \
									attributeListPtr->intValue, tag ) );

		case BER_BOOLEAN:
			return( writeBoolean( stream, ( BOOLEAN ) \
								  attributeListPtr->intValue, tag ) );

		case BER_ENUMERATED:
			return( writeEnumerated( stream, ( int ) \
									 attributeListPtr->intValue, tag ) );

		case BER_INTEGER:
			return( writeShortInteger( stream, attributeListPtr->intValue, 
									   tag ) );

		case BER_NULL:
			return( writeNull( stream, tag ) );

		case BER_OBJECT_IDENTIFIER:
			if( tag != DEFAULT_TAG )
				{
				/* This gets a bit messy because the OID is stored in 
				   encoded form in the attribute, to write it as a tagged 
				   value we have to write a different first byte */
				sputc( stream, getFieldEncodedTag( attributeInfoPtr ) );
				return( swrite( stream, ( ( BYTE * ) dataPtr ) + 1,
								attributeListPtr->valueLength - 1 ) );
				}
			return( swrite( stream, dataPtr, 
							attributeListPtr->valueLength ) );

		case BER_OCTETSTRING:
			/* If it's an integer equivalent to an OCTET STRING hole we need 
			   to use the INTEGER encoding rules rather than the OCTET 
			   STRING ones */
			if( attributeInfoPtr->flags & FL_ALIAS )
				{
				ENSURES( attributeInfoPtr->fieldEncodedType == BER_INTEGER );

				return( writeInteger( stream, dataPtr, 
									  attributeListPtr->valueLength, 
									  DEFAULT_TAG ) );
				}
			return( writeOctetString( stream, dataPtr, 
									  attributeListPtr->valueLength, 
									  tag ) );

		case BER_STRING_BMP:
		case BER_STRING_IA5:
		case BER_STRING_ISO646:
		case BER_STRING_NUMERIC:
		case BER_STRING_PRINTABLE:
		case BER_STRING_UTF8:
			return( writeCharacterString( stream, dataPtr, 
										  attributeListPtr->valueLength,
										  ( tag == DEFAULT_TAG ) ? \
											fieldType : \
											MAKE_CTAG_PRIMITIVE( tag ) ) );

		case BER_TIME_GENERALIZED:
			return( writeGeneralizedTime( stream, *( time_t * ) dataPtr, 
										  tag ) );

		case BER_TIME_UTC:
			return( writeUTCTime( stream, *( time_t * ) dataPtr, tag ) );
		}

	retIntError();
	}

/* Write an attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeAttribute( INOUT STREAM *stream, 
						   INOUT ATTRIBUTE_LIST **attributeListPtrPtr,
						   const BOOLEAN wrapperTagSet, 
						   IN_RANGE( 0, 4 ) const int complianceLevel )
	{
	ATTRIBUTE_LIST *attributeListPtr = *attributeListPtrPtr;
	int flagSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeListPtrPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( *attributeListPtrPtr, sizeof( ATTRIBUTE_LIST ) ) );

	REQUIRES( complianceLevel >= CRYPT_COMPLIANCELEVEL_OBLIVIOUS && \
			  complianceLevel < CRYPT_COMPLIANCELEVEL_LAST );

	/* If it's a non-blob attribute, write it field by field */
	if( !isBlobAttribute( attributeListPtr ) )
		{
		const BOOLEAN isConstructed = ( attributeListPtr->fifoEnd ) ? \
									  TRUE : FALSE;
		const ATTRIBUTE_INFO *attributeInfoPtr = ( isConstructed ) ? \
			attributeListPtr->encodingFifo[ attributeListPtr->fifoEnd - 1 ] : \
			attributeListPtr->attributeInfoPtr;
		const CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
		int dataLength, length = sizeofOID( attributeInfoPtr->oid );
		int iterationCount;

		assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

		/* Determine the size of the attribute payload */
		flagSize = ( ( attributeInfoPtr->flags & FL_CRITICAL ) || \
					 ( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) ) ? \
				   sizeofBoolean() : 0;
		if( isConstructed && attributeInfoPtr->fieldType != FIELDTYPE_CHOICE )
			{
			dataLength = ( int ) sizeofObject( \
				attributeListPtr->sizeFifo[ attributeListPtr->fifoEnd - 1 ] );
			}
		else
			dataLength = attributeListPtr->encodedSize;

		/* Write the outer SEQUENCE, OID, critical flag (if it's set) and
		   appropriate wrapper for the attribute payload */
		writeSequence( stream, length + flagSize + \
					   ( int ) sizeofObject( dataLength ) );
		swrite( stream, attributeInfoPtr->oid,
				sizeofOID( attributeInfoPtr->oid ) );
		if( flagSize > 0 )
			writeBoolean( stream, TRUE, DEFAULT_TAG );
		if( wrapperTagSet )
			status = writeSet( stream, dataLength );
		else
			status = writeOctetStringHole( stream, dataLength, DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );

		/* Write the current attribute */
		for( iterationCount = 0;
			 attributeListPtr != NULL && \
				attributeListPtr->attributeID == attributeID && \
				iterationCount < FAILSAFE_ITERATIONS_MED;
			 attributeListPtr = attributeListPtr->next, iterationCount++ )
			{
			int innerIterationCount;
			
			/* Write any encapsulating SEQUENCEs if necessary, followed by
			   the field itself.  In some rare instances we may have a zero-
			   length SEQUENCE (if all the member(s) of the sequence have
			   default values) so we only try to write the member if there's
			   encoding information for it present */
			for( attributeListPtr->fifoPos = attributeListPtr->fifoEnd, \
					innerIterationCount = 0;
				 cryptStatusOK( status ) && \
					attributeListPtr->fifoPos > 0 && \
					innerIterationCount < ENCODING_FIFO_SIZE;
				 innerIterationCount++ )
				{
				status = writeAttributeField( stream, 
									( ATTRIBUTE_LIST * ) attributeListPtr,
									complianceLevel );
				}
			ENSURES( innerIterationCount < ENCODING_FIFO_SIZE );
			if( cryptStatusOK( status ) && \
				attributeListPtr->attributeInfoPtr != NULL )
				{
				status = writeAttributeField( stream, 
									( ATTRIBUTE_LIST * ) attributeListPtr,
									complianceLevel );
				}
			if( cryptStatusError( status ) )
				return( status );
			}
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

		*attributeListPtrPtr = attributeListPtr;
		return( CRYPT_OK );
		}

	/* It's a blob attribute, write the header, OID, critical flag (if 
	   present), and payload wrapped up as appropriate */
	flagSize = ( attributeListPtr->flags & ATTR_FLAG_CRITICAL ) ? \
			   sizeofBoolean() : 0;
	writeSequence( stream, sizeofOID( attributeListPtr->oid ) + flagSize + \
				   ( int ) sizeofObject( attributeListPtr->valueLength ) );
	swrite( stream, attributeListPtr->oid,
			sizeofOID( attributeListPtr->oid ) );
	if( flagSize > 0 )
		writeBoolean( stream, TRUE, DEFAULT_TAG );
	if( wrapperTagSet )
		writeSet( stream, attributeListPtr->valueLength );
	else
		{
		writeOctetStringHole( stream, attributeListPtr->valueLength, 
							  DEFAULT_TAG );
		}
	status = swrite( stream, attributeListPtr->value,
					 attributeListPtr->valueLength );
	if( cryptStatusOK( status ) )
		*attributeListPtrPtr = attributeListPtr->next;
	return( status );
	}

/****************************************************************************
*																			*
*						Attribute Collection Write Routines					*
*																			*
****************************************************************************/

/* Write a set of attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeAttributes( INOUT STREAM *stream, 
					 INOUT ATTRIBUTE_LIST *attributeListPtr,
					 IN_ENUM_OPT( CRYPT_CERTTYPE ) const CRYPT_CERTTYPE_TYPE type,
					 IN_LENGTH const int attributeSize )
	{
	int signUnrecognised = DUMMY_INIT, complianceLevel, iterationCount;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	REQUIRES( type >= CRYPT_CERTTYPE_NONE && type < CRYPT_CERTTYPE_LAST );
			  /* Single CRL entries have the special-case type 
			     CRYPT_CERTTYPE_NONE */
	REQUIRES( attributeSize > 0 && attributeSize < MAX_INTLENGTH );

	/* Some attributes have odd encoding/handling requirements that can cause
	   problems for other software so we only enforce peculiarities required
	   by the standard at higher compliance levels.  In addition we only sign
	   unrecognised attributes if we're explicitly asked to do so by the 
	   user */
	status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE, &complianceLevel,
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE, &signUnrecognised,
								  CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* CMS attributes work somewhat differently from normal attributes in 
	   that, since they're encoded as a SET OF Attribute, they have to be 
	   sorted according to their encoded form before being written.  For 
	   this reason we don't write them sorted by OID as with the other 
	   attributes but keep writing the next-lowest attribute until they've 
	   all been written */
	if( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES || \
		type == CRYPT_CERTTYPE_RTCS_REQUEST || \
		type == CRYPT_CERTTYPE_RTCS_RESPONSE )
		{
		ATTRIBUTE_LIST *currentAttributePtr;
		BYTE currentEncodedForm[ ATTR_ENCODED_SIZE + 8 ];

		/* Write the wrapper, depending on the object type */
		if( type == CRYPT_CERTTYPE_RTCS_REQUEST )
			writeSet( stream, attributeSize );
		else
			{
			writeConstructed( stream, attributeSize, 
							  ( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
								CTAG_SI_AUTHENTICATEDATTRIBUTES : \
								CTAG_RP_EXTENSIONS );
			}

		/* Write the attributes in sorted form */
		memset( currentEncodedForm, 0, ATTR_ENCODED_SIZE );	/* Set lowest encoded form */
		for( currentAttributePtr = getNextEncodedAttribute( attributeListPtr, \
															currentEncodedForm,
															ATTR_ENCODED_SIZE ),
				iterationCount = 0;
			 currentAttributePtr != NULL && cryptStatusOK( status ) && \
				iterationCount < FAILSAFE_ITERATIONS_LARGE;
			currentAttributePtr = getNextEncodedAttribute( attributeListPtr,
														   currentEncodedForm,
														   ATTR_ENCODED_SIZE ),
				iterationCount++ )
			{
			status = writeAttribute( stream, &currentAttributePtr, TRUE,
									 complianceLevel );
			}
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
		return( status );
		}

	/* Write the appropriate extensions tag for the certificate object and 
	   determine how far we can read.  CRLs and OCSP requests/responses have 
	   two extension types that have different tagging, per-entry extensions 
	   and entire-CRL/request extensions.  To differentiate between the two 
	   we write per-entry extensions with a type of CRYPT_CERTTYPE_NONE */
	switch( type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
		case CRYPT_CERTTYPE_CRL:
			writeConstructed( stream, ( int ) sizeofObject( attributeSize ),
							  ( type == CRYPT_CERTTYPE_CERTIFICATE ) ? \
							  CTAG_CE_EXTENSIONS : CTAG_CL_EXTENSIONS );
			status = writeSequence( stream, attributeSize );
			break;

		case CRYPT_CERTTYPE_CERTREQUEST:
			writeSequence( stream, sizeofOID( OID_PKCS9_EXTREQ ) + \
						   ( int ) sizeofObject( sizeofObject( attributeSize ) ) );
			swrite( stream, OID_PKCS9_EXTREQ, sizeofOID( OID_PKCS9_EXTREQ ) );
			writeSet( stream, ( int ) sizeofObject( attributeSize ) );
			status = writeSequence( stream, attributeSize );
			break;

		case CRYPT_CERTTYPE_REQUEST_CERT:
		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* No wrapper, extensions are written directly */
			break;

		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
		case CRYPT_CERTTYPE_PKIUSER:
		case CRYPT_CERTTYPE_NONE:
			status = writeSequence( stream, attributeSize );
			break;

		case CRYPT_CERTTYPE_OCSP_REQUEST:
			writeConstructed( stream, ( int ) sizeofObject( attributeSize ), 
							  CTAG_OR_EXTENSIONS );
			status = writeSequence( stream, attributeSize );
			break;

		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			writeConstructed( stream, ( int ) sizeofObject( attributeSize ), 
							  CTAG_OP_EXTENSIONS );
			status = writeSequence( stream, attributeSize );
			break;

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the known attributes until we reach either the end of the list
	   or the first blob-type attribute */
	for( iterationCount = 0;
		 cryptStatusOK( status ) && attributeListPtr != NULL && \
			!isBlobAttribute( attributeListPtr ) && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		status = writeAttribute( stream, &attributeListPtr, FALSE, 
								 complianceLevel );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	if( cryptStatusError( status ) || !signUnrecognised  )
		return( status );

	/* Write the blob-type attributes */
	for( iterationCount = 0;
		 attributeListPtr != NULL && cryptStatusOK( status ) && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		status = writeAttribute( stream, &attributeListPtr, FALSE, 
								 complianceLevel );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	return( status );
	}
