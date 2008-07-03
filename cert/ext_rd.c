/****************************************************************************
*																			*
*						Certificate Attribute Read Routines					*
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

/* Define the following to print a trace of the certificate fields being 
   parsed, useful for debugging broken certificates */

#if !defined( NDEBUG ) && 0
  #define TRACE_FIELDTYPE( attributeInfoPtr, stackPos ) \
		  { \
		  int i; \
		  \
		  for( i = 0; i < stackPos; i++ ) \
			  printf( "  " ); \
		  if( ( attributeInfoPtr ) != NULL && \
			  ( attributeInfoPtr )->description != NULL ) \
			  puts( ( attributeInfoPtr )->description ); \
		  }
  #define TRACE_DEBUG( message, status ) \
		  printf( message, status );
#else
  #define TRACE_FIELDTYPE( attributeInfoPtr, stackPos )
  #define TRACE_DEBUG( message, status )
#endif /* NDEBUG */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Get the tag for a field from the attribute field definition */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int getFieldTag( INOUT STREAM *stream, 
						const ATTRIBUTE_INFO *attributeInfoPtr,
						int *tag )
	{
	int status, value;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( tag, sizeof( int ) ) );

	/* Clear return value.  This is actually a bit difficult to do because 
	   the output can have both positive values (tags) and negative values 
	   (field codes), setting the output to -1000 is invalid for both 
	   types */
	*tag = -1000;

	/* Check whether the field is tagged */
	status = value = getFieldEncodedTag( attributeInfoPtr );
	if( cryptStatusError( status ) )
		{
		/* If there's no tagging (i.e. the tag is the same as the field 
		   type) we'll get an OK_SPECIAL return value, this isn't an 
		   error */
		if( status != OK_SPECIAL )
			return( status );
		}
	else
		{
		/* It's a tagged field, return the encoded form */
		*tag = value;

		return( CRYPT_OK );
		}
	ENSURES( status == OK_SPECIAL );

	/* It's a non-tagged field, the tag is the same as the field type */
	value = attributeInfoPtr->fieldType;
	if( value == FIELDTYPE_DISPLAYSTRING )
		{
		/* This is a variable-tag field that can have one of a number of 
		   tags.  To handle this we peek ahead into the stream to see if an 
		   acceptable tag is present and if not set the value to a non-
		   matching tag value */
		status = value = peekTag( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( ( value != BER_STRING_IA5 ) && \
			( value != BER_STRING_ISO646 ) && \
			( value != BER_STRING_BMP ) && ( value != BER_STRING_UTF8 ) )
			value++;	/* Make sure that it doesn't match */
		}

	ENSURES( ( ( value == FIELDTYPE_BLOB || value == FIELDTYPE_DN ) && \
			   !( attributeInfoPtr->flags & FL_OPTIONAL ) ) || \
			 ( value > 0 && value < 0xF0 ) );
	*tag = value;

	return( CRYPT_OK );
	}

/* Find the end of an item (either primitive or constructed) in the attribute
   table.  Sometimes we may have already entered a constructed object (for
   example when an attribute has a version number so we don't know until we've
   started processing it that we can't do anything with it), if this is the
   case then the depth parameter indicates how many nesting levels we have to 
   undo */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int findItemEnd( const ATTRIBUTE_INFO **attributeInfoPtrPtr,
						IN_RANGE( 0, 3 ) const int depth )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr = *attributeInfoPtrPtr;
	BOOLEAN attributeContinues;
	int currentDepth = depth, iterationCount = 0;

	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES( depth >= 0 && depth < 3 );

	/* Skip to the end of the (potentially) constructed item by recording the
	   nesting level and continuing until either it reaches zero or we reach
	   the end of the item */
	do
		{
		/* If it's a sequence/set, increment the depth; if it's an end-of-
		   constructed-item marker, decrement it by the appropriate amount */
		if( attributeInfoPtr->fieldType == BER_SEQUENCE || \
			attributeInfoPtr->fieldType == BER_SET )
			currentDepth++;
		currentDepth -= decodeNestingLevel( attributeInfoPtr->flags );

		/* Move to the next entry */
		attributeContinues = ( attributeInfoPtr->flags & FL_MORE ) ? TRUE : FALSE;
		attributeInfoPtr++;
		}
	while( currentDepth > 0 && attributeContinues && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED );
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	/* We return the previous entry, since we're going to move on to the 
	   next entry once we return */
	*attributeInfoPtrPtr = attributeInfoPtr - 1;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							SET/SEQUENCE Management Routines				*
*																			*
****************************************************************************/

/* When we're processing SETs/SEQUENCEs (generically referred to as a SET
   OF) we need to maintain a stack of state information to handle a nested 
   SET OF.  The following code implements the state stack */

#define SETOF_STATE_STACKSIZE	16

#define SETOF_FLAG_NONE			0x00	/* No flag value */
#define SETOF_FLAG_SUBTYPED		0x01	/* SET ends on a subtyped value */
#define SETOF_FLAG_RESTARTPOINT	0x02	/* SET OF rather than SET */
#define SETOF_FLAG_ISEMPTY		0x04	/* Cleared if SET OF contains at least one entry */

typedef struct {
	/* SET OF state information */
	const ATTRIBUTE_INFO *infoStart;	/* Start of SET OF attribute info */
	int startPos, endPos;	/* Start and end position of SET OF */
	int flags;				/* SET OF flags */

	/* Subtype information */
	CRYPT_ATTRIBUTE_TYPE subtypeParent;	/* Parent type if this is subtyped */
	int inheritedFlags;		/* Flags inherited from parent if subtyped */
	} SETOF_STATE_INFO;

typedef struct {
	ARRAY( SETOF_STATE_STACKSIZE, stackPos ) \
	SETOF_STATE_INFO stateInfo[ SETOF_STATE_STACKSIZE + 8 ];
	int stackPos;			/* Current position in stack */
	} SETOF_STACK;

STDC_NONNULL_ARG( ( 1 ) ) \
static void setofStackInit( OUT SETOF_STACK *setofStack )
	{
	assert( isWritePtr( setofStack, sizeof( SETOF_STACK ) ) );

	memset( setofStack, 0, sizeof( SETOF_STACK ) );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN setofStackPush( INOUT SETOF_STACK *setofStack )
	{
	const int newPos = setofStack->stackPos + 1;

	assert( isWritePtr( setofStack, sizeof( SETOF_STACK ) ) );

	/* Increment the stack pointer and make sure that we don't overflow */
	ENSURES_B( newPos >= 1 && newPos < SETOF_STATE_STACKSIZE );
	setofStack->stackPos = newPos;

	/* Initialise the new entry */
	memset( &setofStack->stateInfo[ newPos ], 0, \
			sizeof( SETOF_STATE_INFO ) );

	return( TRUE );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN setofStackPop( INOUT SETOF_STACK *setofStack )
	{
	const int newPos = setofStack->stackPos - 1;

	assert( isWritePtr( setofStack, sizeof( SETOF_STACK ) ) );

	/* Decrement the stack pointer and make sure that we don't underflow */
	ENSURES_B( newPos >= 0 && newPos < SETOF_STATE_STACKSIZE - 1 );
	setofStack->stackPos = newPos;

	return( TRUE );
	}

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
static SETOF_STATE_INFO *setofTOS( const SETOF_STACK *setofStack )
	{
	assert( isReadPtr( setofStack, sizeof( SETOF_STACK ) ) );

	return( ( SETOF_STATE_INFO * ) \
			&setofStack->stateInfo[ setofStack->stackPos ] );
	}

/* Process the start of a SET/SET OF/SEQUENCE/SEQUENCE OF */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int beginSetof( INOUT STREAM *stream, 
					   INOUT SETOF_STACK *setofStack,
					   const ATTRIBUTE_INFO *attributeInfoPtr )
	{
	SETOF_STATE_INFO *setofInfoPtr = setofTOS( setofStack );
	CRYPT_ATTRIBUTE_TYPE oldSubtypeParent;
	int oldInheritedFlags, setofLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( setofStack, sizeof( SETOF_STACK ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	
	REQUIRES( !( attributeInfoPtr->flags & FL_EXPLICIT ) );

	/* Determine the length and start position of the SET OF items */
	if( attributeInfoPtr->fieldEncodedType >= 0 )
		{
		status = readConstructed( stream, &setofLength,
								  attributeInfoPtr->fieldEncodedType );
		}
	else
		{
		if( attributeInfoPtr->fieldType == BER_SET )
			status = readSet( stream, &setofLength );
		else
			status = readSequence( stream, &setofLength );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* When processing a SET/SEQUENCE with default values for the elements 
	   the result may be a zero-length object, in which case we don't take 
	   any action */
	if( setofLength <= 0 )
		return( CRYPT_OK );

	/* Remember assorted info such as where the SET/SEQUENCE ends.  In 
	   addition if this is a SET OF/SEQUENCE OF, remember this as a restart 
	   point for when we're parsing the next item in the SET/SEQUENCE OF */
	oldSubtypeParent = setofInfoPtr->subtypeParent;
	oldInheritedFlags = setofInfoPtr->inheritedFlags;
	if( !setofStackPush( setofStack ) )
		{
		/* Stack overflow, there's a problem with the certificate */
		return( CRYPT_ERROR_OVERFLOW );
		}
	setofInfoPtr = setofTOS( setofStack );
	setofInfoPtr->infoStart = attributeInfoPtr;
	if( attributeInfoPtr->flags & FL_SETOF )
		setofInfoPtr->flags |= SETOF_FLAG_RESTARTPOINT;
	if( attributeInfoPtr->flags & FL_NONEMPTY )
		setofInfoPtr->flags |= SETOF_FLAG_ISEMPTY;
	setofInfoPtr->subtypeParent = oldSubtypeParent;
	setofInfoPtr->inheritedFlags = oldInheritedFlags;
	setofInfoPtr->startPos = stell( stream );
	setofInfoPtr->endPos = setofInfoPtr->startPos + setofLength;

	return( CRYPT_OK );
	}

/* Check whether we've reached the end of a SET/SEQUENCE.  Returns OK_SPECIAL
   if the end has been reached */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int checkSetofEnd( const STREAM *stream, 
						  INOUT SETOF_STACK *setofStack,
						  const ATTRIBUTE_INFO **attributeInfoPtrPtr )
	{
	const SETOF_STATE_INFO *setofInfoPtr = setofTOS( setofStack );
	const ATTRIBUTE_INFO *oldAttributeInfoPtr = *attributeInfoPtrPtr;
	const ATTRIBUTE_INFO *attributeInfoPtr = *attributeInfoPtrPtr;
	const int currentPos = stell( stream );
	int iterationCount;

	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( setofStack, sizeof( SETOF_STACK ) ) );
	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );

	/* If we're still within the SET/SEQUENCE, we're done */
	if( setofStack->stackPos <= 0 || currentPos < setofInfoPtr->endPos )
		return( CRYPT_OK );

	/* We've reached the end of or or more layers of SET/SEQUENCE, keep 
	   popping SET/SEQUENCE state info until we can continue */
	for( iterationCount = 0;
		 setofStack->stackPos > 0 && \
			currentPos >= setofInfoPtr->endPos && \
			iterationCount < SETOF_STATE_STACKSIZE;
		 iterationCount++ )
		{
		const int flags = setofInfoPtr->flags;

		/* Pop one level of parse state */
		if( !setofStackPop( setofStack ) )
			{
			/* Stack underflow, there's a problem with the certificate */
			return( CRYPT_ERROR_UNDERFLOW );
			}
		setofInfoPtr = setofTOS( setofStack );
		attributeInfoPtr = setofInfoPtr->infoStart;
		ENSURES( setofInfoPtr->endPos > 0 && \
				 setofInfoPtr->endPos < MAX_INTLENGTH_SHORT );

		/* If it's a pure SET/SEQUENCE (not a SET OF/SEQUENCE OF) and there 
		   are no more elements present, go to the end of the SET/SEQUENCE 
		   info in the decoding table */
		if( !( flags & SETOF_FLAG_RESTARTPOINT ) && \
			currentPos >= setofInfoPtr->endPos )
			{
			int status;

			status = findItemEnd( &attributeInfoPtr, 0 );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	ENSURES( iterationCount < SETOF_STATE_STACKSIZE );

	*attributeInfoPtrPtr = attributeInfoPtr;
	return( ( attributeInfoPtr != oldAttributeInfoPtr ) ? \
			OK_SPECIAL : CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Identified Item Management Routines					*
*																			*
****************************************************************************/

/* Given a pointer to a set of SEQUENCE { type, value } entries, return a
   pointer to the { value } entry appropriate for the data in the stream.  
   If the entry contains user data in the { value } portion then the 
   returned pointer points to this, if it contains a fixed value or isn't 
   present at all then the returned pointer points to the { type } portion */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 2 ) ) \
static const ATTRIBUTE_INFO *findIdentifiedItem( INOUT STREAM *stream,
									const ATTRIBUTE_INFO *attributeInfoPtr )
	{
	BYTE oid[ MAX_OID_SIZE + 8 ];
	int oidLength, sequenceLength, iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES_N( attributeInfoPtr->flags & FL_IDENTIFIER );

	/* Skip the header and read the OID.  We only check for a sane total
	   length in the debug version since this isn't a fatal error */
	readSequence( stream, &sequenceLength );
	status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
							 BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( NULL );
	sequenceLength -= oidLength;
	assert( sequenceLength >= 0 );

	/* Walk down the list of entries trying to match it to an allowed value.
	   Unfortunately we can't use the attributeInfoSize bounds check limit 
	   here because we don't know how far through the attribute table we 
	   already are, so we have to use a generic large value */
	for( iterationCount = 0;
		 ( attributeInfoPtr->flags & FL_IDENTIFIER ) && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		const BYTE *oidPtr;

		/* Skip the SEQUENCE and OID */
		attributeInfoPtr++;
		oidPtr = attributeInfoPtr->oid;
		if( !( attributeInfoPtr->flags & FL_NONENCODING ) )
			attributeInfoPtr++;
		else
			{
			/* If this is a blob field we've hit a don't-care value (usually 
			   the last in a series of type-and-value pairs) which ensures 
			   that { type }s added after the encoding table was defined 
			   don't get processed as errors, skip the field and continue */
			if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB )
				{
				/* If there's a { value } attached to the type, skip it */
				if( sequenceLength > 0 )
					sSkip( stream, sequenceLength );
				return( attributeInfoPtr );
				}
			}

		/* In case there's an error in the encoding table, make sure that we
		   don't die during parsing */
		ENSURES_N( oidPtr != NULL );

		/* If the OID matches, return a pointer to the value entry */
		if( oidLength == sizeofOID( oidPtr ) && \
			!memcmp( oidPtr, oid, sizeofOID( oidPtr ) ) )
			{
			/* If this is a fixed field and there's a value attached, skip
			   it */
			if( ( attributeInfoPtr->flags & FL_NONENCODING ) && \
				sequenceLength > 0 )
				sSkip( stream, sequenceLength );

			return( attributeInfoPtr );
			}

		/* The OID doesn't match, skip the { value } entry and continue.  We 
		   set the current nesting depth parameter to 1 since we've already
		   entered the SEQUENCE above */
		status = findItemEnd( &attributeInfoPtr, 1 );
		if( cryptStatusError( status ) )
			return( NULL );
		attributeInfoPtr++;		/* Move to start of next item */
		}
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_LARGE );

	/* We reached the end of the set of entries without matching the OID */
	return( NULL );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5, 6, 7 ) ) \
static int processIdentifiedItem( INOUT STREAM *stream, 
								  /*?*/ ATTRIBUTE_LIST **attributeListPtrPtr,
								  IN_FLAGS( ATTR ) const int flags, 
								  const SETOF_STACK *setofStack,
								  const ATTRIBUTE_INFO **attributeInfoPtrPtr,
								  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus,
								  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	static const int dummy = CRYPT_UNUSED;
	const SETOF_STATE_INFO *setofInfoPtr = setofTOS( setofStack );
	const ATTRIBUTE_INFO *attributeInfoPtr = *attributeInfoPtrPtr;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeListPtrPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( setofStack, sizeof( SETOF_STACK ) ) );
	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

assert( ( flags & ~( ATTR_FLAG_CRITICAL ) ) == 0 );
	REQUIRES( flags >= ATTR_FLAG_NONE && flags <= ATTR_FLAG_MAX );
	REQUIRES( !( flags & ATTR_FLAG_INVALID ) );

	/* Search for the identified item from the start of the set of items.  
	   The 0-th value is the SET OF/SEQUENCE OF so we start the search at 
	   the next entry which is the first FL_IDENTIFIER */
	ENSURES( setofInfoPtr->infoStart->flags & FL_SETOF );
	attributeInfoPtr = findIdentifiedItem( stream, 
										   setofInfoPtr->infoStart + 1 );
	if( attributeInfoPtr == NULL )
		return( CRYPT_ERROR_BADDATA );
	*attributeInfoPtrPtr = attributeInfoPtr;

	/* If it's a subtyped field, continue from a new encoding table */
	if( attributeInfoPtr->fieldType == FIELDTYPE_SUBTYPED )
		return( OK_SPECIAL );

	/* If it's not a special-case, non-encoding field, we're done */
	if( !( attributeInfoPtr->flags & FL_NONENCODING ) )
		return( CRYPT_OK );

	/* If the { type, value } pair has a fixed value then the information 
	   being conveyed is its presence, not its contents, so we add an 
	   attribute corresponding to its ID and continue.  The addition of the 
	   attribute is a bit tricky, some of the fixed type-and-value pairs can 
	   have multiple entries denoting things like { algorithm, weak key }, 
	   { algorithm, average key }, { algorithm, strong key }, however all 
	   that we're interested in is the strong key so we ignore the value and 
	   only use the type (in his ordo est ordinem non servare).  Since the 
	   same type can be present multiple times (with different { value }s) 
	   we ignore data duplicate errors and continue.  If we're processing a 
	   blob field type, we've ended up at a generic catch-any value and 
	   can't do much with it */
	if( attributeInfoPtr->fieldType != FIELDTYPE_BLOB )
		{
		int status;

		/* Add the field type, discarding warnings about dups */
		TRACE_FIELDTYPE( attributeInfoPtr, 0 );
		status = addAttributeField( attributeListPtrPtr,
							attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
							&dummy, CRYPT_UNUSED, flags, errorLocus,
							errorType );
		if( status == CRYPT_ERROR_INITED )
			status = CRYPT_OK;
		else
			{
			if( cryptStatusError( status ) )
				return( CRYPT_ERROR_BADDATA );
			}
		}

	/* Reset the attribute info position in preparation for the next value 
	   and continue */
	attributeInfoPtr = setofInfoPtr->infoStart + 1;
	return( OK_SPECIAL );
	}

/* Read a sequence of identifier fields of the form { oid, value OPTIONAL }.
   This is used to read both SEQUENCE OF and CHOICE, with SEQUENCE OF 
   allowing multiple entries and CHOICE allowing only a single entry */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 6, 7 ) ) \
static int readIdentifierFields( INOUT STREAM *stream, 
								 /*?*/ ATTRIBUTE_LIST **attributeListPtrPtr,
								 const ATTRIBUTE_INFO **attributeInfoPtrPtr, 
								 IN_FLAGS( ATTR ) const int flags,
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID, 
								 OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus,
								 OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	const BOOLEAN isChoice = ( fieldID != CRYPT_ATTRIBUTE_NONE );
	int count = 0, iterationCount;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeListPtrPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO * ) ) );
	assert( isReadPtr( *attributeInfoPtrPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

assert( flags == ATTR_FLAG_NONE );
	REQUIRES( flags >= ATTR_FLAG_NONE && flags <= ATTR_FLAG_MAX );
	REQUIRES( !( flags & ATTR_FLAG_INVALID ) );

	for( iterationCount = 0;
		 peekTag( stream ) == BER_OBJECT_IDENTIFIER && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		const ATTRIBUTE_INFO *attributeInfoPtr = *attributeInfoPtrPtr;
		BYTE oid[ MAX_OID_SIZE + 8 ];
		BOOLEAN addField = TRUE;
		static const int dummy = CRYPT_UNUSED;
		int oidLength, innerIterationCount, status;

		/* Make sure that we don't die during parsing if there's an error in
		   the encoding table */
		ENSURES( attributeInfoPtr->oid != NULL );

		/* Read the OID and walk down the list of possible OIDs up to the end
		   of the group of alternatives trying to match it to an allowed
		   value */
		status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
								 BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			return( status );
		for( innerIterationCount = 0;
			 ( oidLength != sizeofOID( attributeInfoPtr->oid ) || \
			   memcmp( attributeInfoPtr->oid, oid, oidLength ) ) && \
			   innerIterationCount < FAILSAFE_ITERATIONS_MED;
			 innerIterationCount++ )
			{
			/* If we've reached the end of the list and the OID wasn't
			   matched, exit */
			if( ( attributeInfoPtr->flags & FL_SEQEND_MASK ) || \
				!( attributeInfoPtr->flags & FL_MORE ) )
				return( CRYPT_ERROR_BADDATA );

			attributeInfoPtr++;

			/* If this is a blob field we've hit a don't-care value which 
			   ensures that { type }s added after the encoding table was 
			   defined don't get processed as errors, skip the field and 
			   continue */
			if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB )
				{
				addField = FALSE;
				break;
				}

			/* Make sure that we don't die during parsing if there's an error
			   in the encoding table */
			ENSURES( attributeInfoPtr->oid != NULL );
			}
		ENSURES( innerIterationCount < FAILSAFE_ITERATIONS_MED );
		TRACE_FIELDTYPE( attributeInfoPtr, 0 );
		if( addField )
			{
			/* The OID matches, add this field as an identifier field.  This
			   will catch duplicate OIDs, since we can't add the same 
			   identifier field twice */
			if( isChoice )
				{
				/* If there's a field value present then this is a CHOICE of
				   attributes whose value is the field value so we add it with
				   this value */
				status = addAttributeField( attributeListPtrPtr,
									fieldID, CRYPT_ATTRIBUTE_NONE,
									&attributeInfoPtr->fieldID, CRYPT_UNUSED,
									flags, errorLocus, errorType );
				}
			else
				{
				/* It's a standard field */
				status = addAttributeField( attributeListPtrPtr,
							attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
							&dummy, CRYPT_UNUSED, 
							flags, errorLocus, errorType );
				}
			if( cryptStatusError( status ) )
				return( status );
			}
		count++;

		/* If there's more than one OID present in a CHOICE, it's an error */
		if( isChoice && count > 1 )
			{
			*errorLocus = attributeInfoPtr->fieldID,
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_BADDATA );
			}
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );

	/* We've processed the non-data field(s), move on to the next field.
	   We move to the last valid non-data field rather than the start of the
	   field following it since the caller needs to be able to check whether
	   there are more fields to follow using the current field's flags.
	   Unfortunately we can't use the attributeInfoSize bounds check limit 
	   here because we don't know how far through the attribute table we 
	   already are, so we have to use a generic large value */
	iterationCount = 0;
	while( !( ( *attributeInfoPtrPtr )->flags & FL_SEQEND_MASK ) && \
			( ( *attributeInfoPtrPtr )->flags & FL_MORE ) && \
			iterationCount++ < FAILSAFE_ITERATIONS_LARGE )
		( *attributeInfoPtrPtr )++;
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Attribute/Attribute Field Read Routines				*
*																			*
****************************************************************************/

/* Generic error-handler that sets extended error codes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int fieldErrorReturn( OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
								CRYPT_ATTRIBUTE_TYPE *errorLocus,
							 OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType, 
							 IN_ERROR const int status,
							 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( cryptStatusError( status ) );
	REQUIRES( fieldID > CRYPT_ATTRIBUTE_NONE && \
			  fieldID < CRYPT_IATTRIBUTE_LAST );

	/* Since some fields are internal-use only (e.g. meaningless blob data,
	   version numbers, and other paraphernalia) we only set the locus if
	   it has a meaningful value */
	*errorLocus = ( fieldID > CRYPT_CERTINFO_FIRST && \
					fieldID < CRYPT_CERTINFO_LAST ) ? \
				  fieldID : CRYPT_ATTRIBUTE_NONE;
	*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
	return( status );
	}

/* Switch from the main encoding table to a subtype encoding table */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 2 ) ) \
static ATTRIBUTE_INFO *switchToSubtype( const ATTRIBUTE_INFO *attributeInfoPtr,
										INOUT SETOF_STATE_INFO *setofInfoPtr )
	{
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isReadPtr( attributeInfoPtr->extraData, 
					   sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( setofInfoPtr, sizeof( SETOF_STATE_INFO ) ) );

	REQUIRES_N( attributeInfoPtr->extraData != NULL );

	/* Record the subtype parent information */
	setofInfoPtr->subtypeParent = attributeInfoPtr->fieldID;
	setofInfoPtr->inheritedFlags = \
							( attributeInfoPtr->flags & FL_MULTIVALUED ) ? \
								ATTR_FLAG_MULTIVALUED : ATTR_FLAG_NONE;

	/* If the subtype is being used to process a list of { ... OPTIONAL, 
	   ... OPTIONAL } and at least one entry must be present, remember 
	   that we haven't seen any entries yet */
	if( attributeInfoPtr->flags & FL_NONEMPTY )
		setofInfoPtr->flags |= SETOF_FLAG_ISEMPTY;

	/* If the subtype ends once the current SET/SEQUENCE ends, remember this 
	   so that we return to the main type when appropriate */
	if( ( attributeInfoPtr->flags & FL_SEQEND_MASK ) || \
		!( attributeInfoPtr->flags & FL_MORE ) )
		setofInfoPtr->flags |= SETOF_FLAG_SUBTYPED;

	/* Switch to the subtype encoding table */
	return( ( ATTRIBUTE_INFO * ) attributeInfoPtr->extraData );
	}

/* Read the contents of an attribute field.  This uses the readXXXData() 
   variants of the read functions because the field that we're reading may 
   be tagged so we process the tag at a higher level and only read the 
   contents here */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 6, 7 ) ) \
static int readAttributeField( INOUT STREAM *stream, 
							   /*?*/ ATTRIBUTE_LIST **attributeListPtrPtr,
							   const ATTRIBUTE_INFO *attributeInfoPtr,
							   IN_ATTRIBUTE_OPT \
									const CRYPT_ATTRIBUTE_TYPE subtypeParent, 
							   IN_FLAGS( ATTR ) const int flags, 
							   OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus,
							   OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	CRYPT_ATTRIBUTE_TYPE fieldID, subFieldID;
	const int fieldType = attributeInfoPtr->fieldType;
	int length, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeListPtrPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( subtypeParent >= CRYPT_ATTRIBUTE_NONE && \
			  subtypeParent < CRYPT_ATTRIBUTE_LAST );
assert( ( flags & ~( ATTR_FLAG_NONE | ATTR_FLAG_CRITICAL | ATTR_FLAG_MULTIVALUED ) ) == 0 );
	REQUIRES( flags >= ATTR_FLAG_NONE && flags <= ATTR_FLAG_MAX );
	REQUIRES( !( flags & ATTR_FLAG_INVALID ) );

	/* Set up the field identifiers depending on whether it's a normal field
	   or a subfield of a parent field */
	if( subtypeParent == CRYPT_ATTRIBUTE_NONE )
		{
		fieldID = attributeInfoPtr->fieldID;
		subFieldID = CRYPT_ATTRIBUTE_NONE;
		}
	else
		{
		fieldID = subtypeParent;
		subFieldID = attributeInfoPtr->fieldID;
		}

	/* Read the field as appropriate */
	switch( fieldType )
		{
		case BER_INTEGER:
		case BER_ENUMERATED:
		case BER_BITSTRING:
		case BER_BOOLEAN:
		case BER_NULL:
			{
			BOOLEAN boolean;
			long longValue;
			int value;

			/* Read the data as appropriate */
			switch( fieldType )
				{
				case BER_BITSTRING:
					status = readBitStringData( stream, &value );
					break;

				case BER_BOOLEAN:
					status = readBooleanData( stream, &boolean );
					value = boolean;
					break;

				case BER_ENUMERATED:
					status = readEnumeratedData( stream, &value );
					break;

				case BER_INTEGER:
					status = readShortIntegerData( stream, &longValue );
					value = ( int ) longValue;
					break;

				case BER_NULL:
					/* NULL values have no associated data so we explicitly 
					   set the value to CRYPT_UNUSED to ensure that this is 
					   returned on any attempt to read it */
					value = CRYPT_UNUSED;
					break;

				default:
					retIntError();
				}
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType, status,
										  attributeInfoPtr->fieldID ) );

			/* Add the data for this attribute field */
			return( addAttributeField( attributeListPtrPtr, fieldID, 
									   subFieldID, &value, CRYPT_UNUSED, 
									   flags, errorLocus, errorType ) );
			}

		case BER_TIME_GENERALIZED:
		case BER_TIME_UTC:
			{
			time_t timeVal;

			if( fieldType == BER_TIME_GENERALIZED )
				status = readGeneralizedTimeData( stream, &timeVal );
			else
				status = readUTCTimeData( stream, &timeVal );
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType, status,
										  attributeInfoPtr->fieldID ) );

			/* Add the data for this attribute field */
			return( addAttributeField( attributeListPtrPtr, fieldID, 
									   subFieldID, &timeVal, sizeof( time_t ), 
									   flags, errorLocus, errorType ) );
			}

		case BER_STRING_BMP:
		case BER_STRING_IA5:
		case BER_STRING_ISO646:
		case BER_STRING_NUMERIC:
		case BER_STRING_PRINTABLE:
		case BER_STRING_T61:
		case BER_STRING_UTF8:
		case BER_OCTETSTRING:
		case FIELDTYPE_BLOB:
		case FIELDTYPE_DISPLAYSTRING:
			{
			/* If it's a string type or a blob read it in as a blob (the 
			   only difference being that for a true blob we read the tag + 
			   length as well) */
			BYTE buffer[ 256 + 8 ];

			/* Read in the string to a maximum length of 256 bytes */
			if( fieldType == FIELDTYPE_BLOB )
				{
				const int tag = peekTag( stream );
				if( cryptStatusError( tag ) )
					{
					return( fieldErrorReturn( errorLocus, errorType, tag,
											  attributeInfoPtr->fieldID ) );
					}

				/* Reading in blob fields is somewhat difficult since these
				   are typically used to read SET/SEQUENCE OF kitchensink
				   values and so won't have a consistent tag that we can pass
				   to readRawObject().  To get around this we peek ahead into
				   the stream to get the tag and then pass that down to 
				   readRawObject().  Note that this requires that the blob 
				   have an internal structure (with its own { tag, length }
				   data) since the caller has already stripped off the tag
				   and length */
				status = readRawObject( stream, buffer, 256, &length, tag );
				}
			else
				{
				status = readOctetStringData( stream, buffer, &length, \
											  1, 256 );
				}
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType, status,
										  attributeInfoPtr->fieldID ) );

			/* There are enough broken certificates out there with 
			   enormously long disclaimers in the certificate policy 
			   explicit text field that we have to specifically check for 
			   them here and truncate the text at a valid length in order to 
			   get it past the extension validity checking code */
			if( fieldID == CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT && \
				length > 200 )
				length = 200;

			/* Add the data for this attribute field, setting the payload-
			   blob flag to disable type-checking of the payload data so 
			   users can cram any old rubbish into the strings */
			return( addAttributeField( attributeListPtrPtr, fieldID, 
									   subFieldID, buffer, length, 
									   flags | ATTR_FLAG_BLOB_PAYLOAD,
									   errorLocus, errorType ) );
			}

		case BER_OBJECT_IDENTIFIER:
			{
			BYTE oid[ MAX_OID_SIZE + 8 ];

			/* If it's an OID, we need to reassemble the entire OID since 
			   this is the form expected by addAttributeField() */
			oid[ 0 ] = BER_OBJECT_IDENTIFIER;	/* Add skipped tag */
			status = readEncodedOID( stream, oid  + 1, MAX_OID_SIZE - 1, 
									 &length, NO_TAG );
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType, status,
										  attributeInfoPtr->fieldID ) );
			return( addAttributeField( attributeListPtrPtr, fieldID, 
									   subFieldID, oid, length + 1, flags, 
									   errorLocus, errorType ) );
			}

		case FIELDTYPE_DN:
			{
			void *dnPtr = NULL;

			/* Read the DN */
			status = readDN( stream, &dnPtr );
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType, status,
										  attributeInfoPtr->fieldID ) );

			/* Some buggy certificates can include zero-length DNs, which we 
			   skip */
			if( dnPtr == NULL )
				return( CRYPT_OK );

			/* We're being asked to instantiate the field containing the DN,
			   create the attribute field and fill in the DN value */
			status = addAttributeField( attributeListPtrPtr, fieldID, 
										subFieldID, dnPtr, CRYPT_UNUSED, 
										flags, errorLocus, errorType );
			if( cryptStatusError( status ) )
				deleteDN( &dnPtr );
			return( status );
			}
		}

	retIntError();
	}

/* Read an attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 6, 7 ) ) \
static int readAttribute( INOUT STREAM *stream, 
						  /*?*/ ATTRIBUTE_LIST **attributeListPtrPtr,
						  const ATTRIBUTE_INFO *attributeInfoPtr, 
						  IN_LENGTH_Z const int attributeLength, 
						  const BOOLEAN criticalFlag, 
						  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
							CRYPT_ATTRIBUTE_TYPE *errorLocus,
						  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
							CRYPT_ERRTYPE_TYPE *errorType )
	{
	SETOF_STACK setofStack;
	SETOF_STATE_INFO *setofInfoPtr;
	const int endPos = stell( stream ) + attributeLength;
	BOOLEAN attributeContinues = TRUE;
	int flags = criticalFlag ? ATTR_FLAG_CRITICAL : ATTR_FLAG_NONE;
	int attributeFieldsProcessed = 0, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeListPtrPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );
	
	REQUIRES( attributeLength >= 0 && attributeLength < MAX_INTLENGTH );

	/* Initialise the SET OF state stack */
	setofStackInit( &setofStack );
	setofInfoPtr = setofTOS( &setofStack );

	/* Process each field in the attribute.  This is a simple FSM driven by
	   the encoding table and the data that we encounter.  The various 
	   states and associated actions are indicated by the comment tags */
	do
		{
		int tag;

		/* Inside a SET/SET OF/SEQUENCE/SEQUENCE OF: Check for the end of the
		   item/collection of items.  This must be the first action taken
		   since reaching the end of a SET/SEQUENCE pre-empts all other
		   parsing actions */
		if( setofInfoPtr->endPos > 0 )
			{
			/* If we've reached the end of the collection of items, exit */
			status = checkSetofEnd( stream, &setofStack, &attributeInfoPtr );
			if( cryptStatusError( status ) && status != OK_SPECIAL )
				return( status );
			setofInfoPtr = setofTOS( &setofStack );
			if( status == OK_SPECIAL )
				goto continueDecoding;

			/* If we're looking for a new item find the table entry that it
			   corresponds to.  This takes a pointer to the start of a set of
			   SEQUENCE { type, value } entries and returns a pointer to the
			   appropriate value entry.

			   The test for the start of a new item is a bit complex since we
			   could be at the end of the previous item (i.e. on the next item
			   flagged as an identifier) or at the end of the attribute (i.e.
			   on the start of the next attribute) */
			if( !( attributeInfoPtr[ -1 ].flags & FL_MORE ) || \
				( attributeInfoPtr->flags & FL_IDENTIFIER ) )
				{
				status = processIdentifiedItem( stream, attributeListPtrPtr,
												flags, &setofStack, 
												&attributeInfoPtr, 
												errorLocus, errorType );
				if( cryptStatusError( status ) )
					{
					if( status == OK_SPECIAL )
						{
						/* We've switched to a new encoding table, continue
						   from there */
						status = CRYPT_OK;
						continue;
						}
					return( fieldErrorReturn( errorLocus, errorType, 
											  CRYPT_ERROR_BADDATA,
											  attributeInfoPtr->fieldID ) );
					}
				}
			}

		/* Subtyped field: Switch to the new encoding table */
		if( attributeInfoPtr->fieldType == FIELDTYPE_SUBTYPED )
			{
			attributeInfoPtr = switchToSubtype( attributeInfoPtr, 
												setofInfoPtr );
			ENSURES( attributeInfoPtr != NULL );
			}

		/* CHOICE (of object identifiers): Read a single OID from a
		   selection.
		   Identifier field: Read a sequence of one or more { oid, value }
		   fields and continue */
		if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE || \
			attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER )
			{
			if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
				{
				const ATTRIBUTE_INFO *extraDataPtr = \
											attributeInfoPtr->extraData;
						/* Needed because ->extraData is read-only */

				status = readIdentifierFields( stream, attributeListPtrPtr,
							&extraDataPtr, flags, attributeInfoPtr->fieldID,
							errorLocus, errorType );
				}
			else
				{
				status = readIdentifierFields( stream, attributeListPtrPtr,
							&attributeInfoPtr, flags, CRYPT_ATTRIBUTE_NONE, 
							errorLocus, errorType );
				}
			if( cryptStatusError( status ) )
				{
				return( fieldErrorReturn( errorLocus, errorType,
										  CRYPT_ERROR_BADDATA,
										  attributeInfoPtr->fieldID ) );
				}
			if( setofInfoPtr->endPos > 0 )
				{
				/* Remember that we've seen an entry in the SET/SEQUENCE */
				setofInfoPtr->flags &= ~SETOF_FLAG_ISEMPTY;
				}
			goto continueDecoding;
			}

		/* Non-encoding field: Skip it and continue */
		if( attributeInfoPtr->flags & FL_NONENCODING )
			{
			/* Read the data and continue.  We don't check its value or set
			   specific error information for reasons given under the SET-OF
			   handling code above (value check) and optional field code below
			   (error locus set) */
			TRACE_FIELDTYPE( attributeInfoPtr, setofStack.stackPos );
			status = readUniversal( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( setofInfoPtr->endPos > 0 )
				{
				/* Remember that we've seen an entry in the SET/SEQUENCE */
				setofInfoPtr->flags &= ~SETOF_FLAG_ISEMPTY;
				}
			goto continueDecoding;
			}

		/* Get the tag for the field */
		status = getFieldTag( stream, attributeInfoPtr, &tag );
		if( cryptStatusError( status ) )
			return( status );

		/* Optional field: Check whether it's present and if it isn't, move
		   on to the next field */
		if( ( attributeInfoPtr->flags & FL_OPTIONAL ) && \
			peekTag( stream ) != tag )
			{
			/* If it's a field with a default value, add that value.  This
			   isn't needed for cryptlib's own use since it knows the default
			   values for fields but can cause confusion for the caller if 
			   all fields in an attribute have default values because the
			   attribute will appear to disappear when it's read in as no
			   fields are ever added */
			if( attributeInfoPtr->flags & FL_DEFAULT )
				{
				CRYPT_ATTRIBUTE_TYPE dummy1;
				CRYPT_ERRTYPE_TYPE dummy2;
				const int value = ( int ) attributeInfoPtr->defaultValue;

				status = addAttributeField( attributeListPtrPtr,
							attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
							&value, CRYPT_UNUSED, flags, &dummy1, &dummy2 );
				if( cryptStatusError( status ) )
					{
					/* This is a field contributed from internal data so we
					   don't try and get an error locus or value for it
					   since this would only confuse the caller */
					return( CRYPT_ERROR_BADDATA );
					}
				}

			/* Skip to the end of the item and continue */
			status = findItemEnd( &attributeInfoPtr, 0 );
			if( cryptStatusError( status ) )
				return( status );
			goto continueDecoding;
			}

		/* Print a trace of what we're processing.  Everything before this
		   point does its own special-case tracing if required so we don't
		   trace before we get here to avoid displaying duplicate/
		   misleading information */
		TRACE_FIELDTYPE( attributeInfoPtr, setofStack.stackPos );

		/* Explicitly tagged field: Read the explicit wrapper and make sure
		   that it matches what we're expecting */
		if( attributeInfoPtr->flags & FL_EXPLICIT )
			{
			ENSURES( attributeInfoPtr->fieldEncodedType >= 0 && \
					 attributeInfoPtr->fieldEncodedType < MAX_TAG );
			ENSURES( tag == MAKE_CTAG( attributeInfoPtr->fieldEncodedType ) ); 
					 /* Always constructed */

			status = readConstructed( stream, NULL, 
									  attributeInfoPtr->fieldEncodedType );
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType, status,
										  attributeInfoPtr->fieldID ) );

			/* We've processed the explicit wrappper, we're now on the actual
			   tag */
			tag = attributeInfoPtr->fieldType;
			}

		/* Blob field or DN: We don't try and interpret blobs in any way, 
		   and DNs are a composite structure read as a complete unit by the 
		   lower-level code */
		if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB || \
			attributeInfoPtr->fieldType == FIELDTYPE_DN )
			{
			status = readAttributeField( stream, attributeListPtrPtr,
										 attributeInfoPtr,
										 setofInfoPtr->subtypeParent,
										 flags | setofInfoPtr->inheritedFlags,
										 errorLocus, errorType );
			if( cryptStatusError( status ) )
				{
				/* Adding complex attributes such as DNs can return detailed
				   error codes that report the exact parameter that was wrong,
				   we don't need this much detail so we convert a parameter
				   error into a more general bad data status */
				return( fieldErrorReturn( errorLocus, errorType,
										  cryptArgError( status ) ? \
											CRYPT_ERROR_BADDATA : status,
										  attributeInfoPtr->fieldID ) );
				}
			if( setofInfoPtr->endPos > 0 )
				{
				/* Remember that we've seen an entry in the SET/SEQUENCE */
				setofInfoPtr->flags &= ~SETOF_FLAG_ISEMPTY;
				}
			goto continueDecoding;
			}

		/* Standard field: Read the tag for the field and make sure that it
		   matches what we're expecting */
		if( peekTag( stream ) != tag )
			{
			return( fieldErrorReturn( errorLocus, errorType,
									  CRYPT_ERROR_BADDATA,
									  attributeInfoPtr->fieldID ) );
			}
		if( setofInfoPtr->endPos > 0 )
			{
			/* Remember that we've seen an entry in the SET/SEQUENCE */
			setofInfoPtr->flags &= ~SETOF_FLAG_ISEMPTY;
			}

		/* SET/SET OF/SEQUENCE/SEQUENCE OF start: Record its end position,
		   stack the current processing state, and continue */
		if( attributeInfoPtr->fieldType == BER_SEQUENCE || \
			attributeInfoPtr->fieldType == BER_SET )
			{
			status = beginSetof( stream, &setofStack, attributeInfoPtr );
			if( cryptStatusError( status ) )
				return( fieldErrorReturn( errorLocus, errorType, status,
										  attributeInfoPtr->fieldID ) );
			setofInfoPtr = setofTOS( &setofStack );
			goto continueDecoding;
			}
		ENSURES( !( attributeInfoPtr->flags & FL_SETOF ) );

		/* We've checked the tag, skip it.  We do this at this level rather
		   than in readAttributeField() because it doesn't know about 
		   context-specific tagging requirements */
		status = readTag( stream );
		if( cryptStatusError( status ) )
			return( status );

		/* Standard field, read the field data */
		status = readAttributeField( stream, attributeListPtrPtr,
									 attributeInfoPtr,
									 setofInfoPtr->subtypeParent,
									 flags | setofInfoPtr->inheritedFlags,
									 errorLocus, errorType );
		if( cryptStatusError( status ) )
			{
			/* Adding invalid attribute data can return detailed error codes
			   that report the exact parameter that was wrong, we don't
			   need this much detail so we convert a parameter error into a
			   more general bad data status */
			return( cryptArgError( status ) ? CRYPT_ERROR_BADDATA : status );
			}

		/* Move on to the next field */
continueDecoding:
		attributeContinues = ( attributeInfoPtr->flags & FL_MORE ) ? TRUE : FALSE;
		attributeInfoPtr++;

		/* If this is the end of the attribute encoding info but we're
		   inside a SET OF/SEQUENCE OF and there's more attribute data 
		   present, go back to the restart point and try again */
		if( !attributeContinues && setofInfoPtr->endPos > 0 && \
			stell( stream ) < setofInfoPtr->endPos )
			{
			/* If we require at least one entry in the SET OF/SEQUENCE OF 
			   but we haven't found one, this is an error */
			if( setofInfoPtr->flags & SETOF_FLAG_ISEMPTY )
				return( CRYPT_ERROR_BADDATA );

			/* If we haven't made any progress in processing the SET OF/
			   SEQUENCE OF then further iterations through the loop won't
			   make any difference, there's a bug in the decoder */
			ENSURES( stell( stream ) > setofInfoPtr->startPos );

			/* Retry from the restart point */
			ENSURES( ( setofInfoPtr->flags & SETOF_FLAG_RESTARTPOINT ) || \
					 setofInfoPtr->infoStart[ 1 ].fieldType == FIELDTYPE_IDENTIFIER );
			attributeInfoPtr = setofInfoPtr->infoStart + 1;
			attributeContinues = TRUE;
			}
		}
	while( ( attributeContinues || setofStack.stackPos > 1 ) && \
		   stell( stream ) < endPos && \
		   attributeFieldsProcessed++ < 256 );

	/* If we got stuck in a loop trying to decode an attribute, complain and 
	   exit.  This can happen in cases where there's a series of nested 
	   sequences of optional attributes, where we have to keep backtracking 
	   and trying again to try and find a match.  In this case it's possible
	   to construct certificate data that matches the first part of the 
	   optional data, but since the rest doesn't match we keep having to 
	   restart (imagine an LL(1) parser trying to handle a non-LL(1) 
	   grammar).
	   
	   At this point we could have encountered either a certificate-parsing 
	   error or a CRYPT_ERROR_INTERNAL internal error, since we can't tell 
	   without human intervention we treat it as a certificate error rather 
	   than throwing a retIntError() exception */
	if( attributeFieldsProcessed >= 256 )
		{
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Handle the special case of (a) the encoded data ending but fields with
	   default values being present or (b) the encoded data continuing but no 
	   more decoding information being present */
	if( attributeContinues )
		{
		/* If there are default fields to follow, add the default value - see
		   the comment on the handling of default fields above.  For now we
		   only add the first field since the only attributes where this
		   case can occur have a single default value as the next possible
		   entry, burrowing down further causes complications due to default
		   values present in optional sequences.  As usual we don't set any
		   specific error information for the default fields */
		if( attributeInfoPtr->flags & FL_DEFAULT )
			{
			CRYPT_ATTRIBUTE_TYPE dummy1;
			CRYPT_ERRTYPE_TYPE dummy2;
			const int value = ( int ) attributeInfoPtr->defaultValue;

			status = addAttributeField( attributeListPtrPtr,
						attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
						&value, CRYPT_UNUSED, flags, &dummy1, &dummy2 );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	else
		{
		int iterationCount;
		
		/* Some attributes have a SEQUENCE OF fields of no great use (e.g.
		   Microsoft's extensive crlDistributionPoints lists providing
		   redundant pointers to the same inaccessible site-internal
		   servers, although these are already handled above), if there's
		   any extraneous data left we just skip it */
		for( iterationCount = 0;
			 stell( stream ) < endPos && cryptStatusOK( status ) && \
				iterationCount < FAILSAFE_ITERATIONS_LARGE;
			 iterationCount++ )
			{
			assert( DEBUG_WARN );
			status = readUniversal( stream );
			}
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
		}
	return( status );
	}

/****************************************************************************
*																			*
*						Attribute Collection Read Routines					*
*																			*
****************************************************************************/

/* Read the certificate object-specific wrapper for a set of attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readAttributeWrapper( INOUT STREAM *stream, 
								 OUT_LENGTH_Z int *lengthPtr, 
								 IN_ENUM_OPT( CRYPT_CERTTYPE ) \
									const CRYPT_CERTTYPE_TYPE type,
								 IN_LENGTH const int attributeLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( lengthPtr, sizeof( int ) ) );

	REQUIRES( type >= CRYPT_CERTTYPE_NONE && type < CRYPT_CERTTYPE_LAST );
			  /* Single CRL entries have the special-case type 
			     CRYPT_CERTTYPE_NONE */
	REQUIRES( attributeLength >= 0 && attributeLength < MAX_INTLENGTH );

	/* Clear return value */
	*lengthPtr = 0;

	/* Read the appropriate extensions tag for the certificate object and
	   determine how far we can read.  CRLs and OCSP requests/responses have
	   two extension types that have different tagging, per-entry extensions
	   and entire-CRL/request extensions.  To differentiate between the two
	   we read per-entry extensions with a type of CRYPT_CERTTYPE_NONE */
	switch( type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
			readConstructed( stream, NULL, CTAG_CE_EXTENSIONS );
			return( readSequence( stream, lengthPtr ) );

		case CRYPT_CERTTYPE_CRL:
			readConstructed( stream, NULL, CTAG_CL_EXTENSIONS );
			return( readSequence( stream, lengthPtr ) );

		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
		case CRYPT_CERTTYPE_PKIUSER:
		case CRYPT_CERTTYPE_NONE:
			/* Any outer wrapper for per-entry CRL/OCSP extensions has
			   already been read by the caller so there's only the inner
			   SEQUENCE left to read */
			return( readSequence( stream, lengthPtr ) );

		case CRYPT_CERTTYPE_CMS_ATTRIBUTES:
			return( readConstructed( stream, lengthPtr,
									 CTAG_SI_AUTHENTICATEDATTRIBUTES ) );

		case CRYPT_CERTTYPE_REQUEST_CERT:
		case CRYPT_CERTTYPE_REQUEST_REVOCATION:
			/* CRMF/CMP attributes don't contain any wrapper so there's
			   nothing to read */
			*lengthPtr = attributeLength;
			return( CRYPT_OK );

		case CRYPT_CERTTYPE_RTCS_REQUEST:
			return( readSet( stream, lengthPtr ) );

		case CRYPT_CERTTYPE_RTCS_RESPONSE:
			return( readConstructed( stream, lengthPtr, CTAG_RP_EXTENSIONS ) );

		case CRYPT_CERTTYPE_OCSP_REQUEST:
			readConstructed( stream, NULL, CTAG_OR_EXTENSIONS );
			return( readSequence( stream, lengthPtr ) );

		case CRYPT_CERTTYPE_OCSP_RESPONSE:
			readConstructed( stream, NULL, CTAG_OP_EXTENSIONS );
			return( readSequence( stream, lengthPtr ) );
		}

	retIntError();
	}

/* Read a certificate-request wrapper for a set of attributes.  This isn't 
   as simple as it should be because alongside their incompatible request 
   extension OID Microsoft also invented other values containing God knows 
   what sort of data (long Unicode strings describing the Windows module 
   that created it (as if you'd need that to know where it came from), the 
   scripts from "Gilligan's Island", every "Brady Bunch" episode ever made,
   dust from under somebody's bed from the 1930s, etc).  Because of this, 
   the following code skips over unknown garbage until it finds a valid 
   extension.

   Unfortunately this simple solution is complicated by the fact that SET 
   also defines non-CMMF-style attributes, however unlike MS's stuff these 
   are documented and stable so if we find SET-style attributes (or more 
   generally any attributes that we know about) we process them normally.  
   Finally, since all attributes may be either skipped or processed at this
   stage we include provisions for bailing out if we exhaust the available 
   attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5, 6 ) ) \
static int readCertReqWrapper( INOUT STREAM *stream, 
							   /*?*/ ATTRIBUTE_LIST **attributeListPtrPtr,
							   OUT_LENGTH_Z int *lengthPtr, 
							   IN_LENGTH const int attributeLength,
							   OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus,
							   OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType )
	{
	const int endPos = stell( stream ) + attributeLength;
	int status, attributesProcessed = 0;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeListPtrPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( lengthPtr, sizeof( int ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( attributeLength >= 0 && attributeLength < MAX_INTLENGTH );

	/* Clear return value */
	*lengthPtr = 0;
			
	do
		{
		const ATTRIBUTE_INFO *attributeInfoPtr;
		BYTE oid[ MAX_OID_SIZE + 8 ];
		int oidLength;

		/* If we've run out of attributes without finding anything useful, 
		   exit */
		if( stell( stream ) > endPos - MIN_ATTRIBUTE_SIZE )
			return( CRYPT_OK );

		/* Read the wrapper SEQUENCE and OID */
		readSequence( stream, NULL );
		status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
								 BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			return( status );

		/* Check for a known attribute, which can happen with SET 
		   certificate requests.  If it's a known attribute, process it */
		attributeInfoPtr = oidToAttribute( ATTRIBUTE_CERTIFICATE, 
										   oid, oidLength );
		if( attributeInfoPtr != NULL )
			{
			status = readSet( stream, lengthPtr );
			if( cryptStatusOK( status ) )
				{
				status = readAttribute( stream, attributeListPtrPtr,
										attributeInfoPtr, *lengthPtr, FALSE, 
										errorLocus, errorType );
				}
			}
		else
			{
			/* It's not a known attribute, check whether it's a CMMF or MS 
			   wrapper attribute */
			if( !memcmp( oid, OID_PKCS9_EXTREQ, oidLength ) || \
				!memcmp( oid, OID_MS_EXTREQ, oidLength ) )
				{
				/* Skip the wrapper to reveal the encapsulated attributes */
				readSet( stream, NULL );
				return( readSequence( stream, lengthPtr ) );
				}
			else
				{
				/* It's unknown MS garbage, skip it */
				status = readUniversal( stream );
				}
			}
		}
	while( cryptStatusOK( status ) && attributesProcessed++ < 16 );
	if( attributesProcessed >= 16 )
		{
		/* As with the check in readAttribute() above this could be either a 
		   certificate-parsing error or a CRYPT_ERROR_INTERNAL internal 
		   error, since we can't tell without human intervention we treat it 
		   as a certificate error rather than throwing a retIntError() 
		   exception */
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_BADDATA );
		}

	return( status );
	}

/* Read a set of attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5, 6 ) ) \
int readAttributes( INOUT STREAM *stream, 
					/*?*/ ATTRIBUTE_LIST **attributeListPtrPtr,
					IN_ENUM_OPT( CRYPT_CERTTYPE ) const CRYPT_CERTTYPE_TYPE type, 
					IN_LENGTH_Z const int attributeLength,
					OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						CRYPT_ATTRIBUTE_TYPE *errorLocus,
					OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
						CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_TYPE attributeType = ( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES || \
										   type == CRYPT_CERTTYPE_RTCS_REQUEST || \
										   type == CRYPT_CERTTYPE_RTCS_RESPONSE ) ? \
										 ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	const BOOLEAN wrapperTagSet = ( attributeType == ATTRIBUTE_CMS ) ? \
								  TRUE : FALSE;
	int length, endPos, complianceLevel, iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( attributeListPtrPtr, sizeof( ATTRIBUTE_LIST * ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( type >= CRYPT_CERTTYPE_NONE && type < CRYPT_CERTTYPE_LAST );
			  /* Single CRL entries have the special-case type 
			     CRYPT_CERTTYPE_NONE */
	REQUIRES( ( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
				attributeLength == 0 ) || \
			  ( type != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
				attributeLength >= 0 && attributeLength < MAX_INTLENGTH ) );
			  /* CMS attributes are pure attribute data with no 
			     encapsulation to indicate the length so the length is 
				 implicitly "everything that's present" */

	status = krnlSendMessage( DEFAULTUSER_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE, &complianceLevel,
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the wrapper for the certificate object's attributes and 
	   determine how far we can read */
	if( type == CRYPT_CERTTYPE_CERTREQUEST )
		{
		status = readCertReqWrapper( stream, attributeListPtrPtr, &length, 
									 attributeLength, errorLocus, errorType );
		}
	else
		status = readAttributeWrapper( stream, &length, type, attributeLength );
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;

	/* Read the collection of attributes.  We allow for a bit of slop for
	   software that gets the length encoding wrong by a few bytes */
	for( iterationCount = 0;
		 stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		const ATTRIBUTE_INFO *attributeInfoPtr;
		BYTE oid[ MAX_OID_SIZE + 8 ];
		BOOLEAN criticalFlag = FALSE, ignoreAttribute = FALSE;
		void *attributeDataPtr;
		int oidLength, attributeDataLength;

		/* Read the outer wrapper and determine the attribute type based on
		   the OID */
		readSequence( stream, NULL );
		status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
								 BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			{
			TRACE_DEBUG( "Couldn't read attribute OID, status %d.\n", 
						 status );
			return( status );
			}
		attributeInfoPtr = oidToAttribute( attributeType, oid, oidLength );
		if( attributeInfoPtr != NULL && \
			complianceLevel < decodeComplianceLevel( attributeInfoPtr->flags ) )
			{
			/* If we're running at a lower compliance level than that
			   required for the attribute, ignore it by treating it as a
			   blob-type attribute */
			attributeInfoPtr = NULL;
			ignoreAttribute = TRUE;
			}

		/* Read the optional critical flag if it's a certificate.  If the
		   extension is marked critical and we don't recognise it we don't 
		   reject it at this point because that'd make it impossible to 
		   examine the contents of the certificate or display it to the 
		   user.  Instead we reject the certificate when we try and check 
		   it */
		if( attributeType != ATTRIBUTE_CMS && \
			peekTag( stream ) == BER_BOOLEAN )
			{
			status = readBoolean( stream, &criticalFlag );
			if( cryptStatusError( status ) )
				{
				*errorLocus = ( attributeInfoPtr != NULL ) ? \
							  attributeInfoPtr->fieldID : CRYPT_ATTRIBUTE_NONE;
				*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( status );
				}
			}

		/* Read the wrapper around the attribute payload */
		if( wrapperTagSet )
			status = readSet( stream, &attributeDataLength );
		else
			status = readOctetStringHole( stream, &attributeDataLength, 2,
										  DEFAULT_TAG );
		if( cryptStatusError( status ) )
			{
			*errorLocus = ( attributeInfoPtr != NULL ) ? \
						  attributeInfoPtr->fieldID : CRYPT_ATTRIBUTE_NONE;
			*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			TRACE_DEBUG( "Couldn't read attribute wrapper, status %d.\n", 
						 status );
			return( status );
			}

		/* If it's a known attribute, parse the payload */
		if( attributeInfoPtr != NULL )
			{
			status = readAttribute( stream, attributeListPtrPtr,
									attributeInfoPtr, attributeDataLength,
									criticalFlag, errorLocus, errorType );
			if( cryptStatusError( status ) )
				{
				TRACE_DEBUG( "Error %d reading attribute.\n", status );
				return( status );
				}
			continue;
			}

		/* If it's a zero-length unrecognised attribute, don't add anything.
		   A zero length indicates that the attribute contains all default
		   values, however since we don't recognise the attribute we can't
		   fill these in so the attribute is in effect not present */
		if( attributeDataLength <= 0 )
			continue;

		/* It's an unrecognised or ignored attribute type, add the raw data
		   to the list of attributes */
		status = sMemGetDataBlock( stream, &attributeDataPtr, 
								   attributeDataLength );
		if( cryptStatusOK( status ) )
			{
			status = addAttribute( attributeType, attributeListPtrPtr, 
								   oid, oidLength, criticalFlag, 
								   attributeDataPtr, attributeDataLength, 
								   ignoreAttribute ? \
										ATTR_FLAG_BLOB | ATTR_FLAG_IGNORED : \
										ATTR_FLAG_NONE );
			}
		if( cryptStatusError( status ) )
			{
			if( status == CRYPT_ERROR_INITED )
				{
				/* If there's a duplicate attribute present, set error
				   information for it and flag it as a bad data error.  We
				   can't set an error locus since it's an unknown blob */
				*errorLocus = CRYPT_ATTRIBUTE_NONE;
				*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
				status = CRYPT_ERROR_BADDATA;
				}
			TRACE_DEBUG( "Error %d adding attribute data.\n", status );
			return( status );
			}
		sSkip( stream, attributeDataLength );	/* Skip the attribute data */
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );

	return( CRYPT_OK );
	}
