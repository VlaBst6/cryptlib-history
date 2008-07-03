/****************************************************************************
*																			*
*							cryptlib Internal API							*
*						Copyright Peter Gutmann 1992-2007					*
*																			*
****************************************************************************/

/* A generic module that implements a rug under which all problems not
   solved elsewhere are swept */

#if defined( INC_ALL )
  #include "crypt.h"
  #include "stream.h"
#else
  #include "crypt.h"
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/* Perform the FIPS-140 statistical checks that are feasible on a byte
   string.  The full suite of tests assumes that an infinite source of
   values (and time) is available, the following is a scaled-down version
   used to sanity-check keys and other short random data blocks.  Note that
   this check requires at least 64 bits of data in order to produce useful
   results */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkEntropy( IN_BUFFER( dataLength ) const BYTE *data, 
					  IN_LENGTH_SHORT_MIN( MIN_KEYSIZE ) const int dataLength )
	{
	const int delta = ( dataLength < 16 ) ? 1 : 0;
	int bitCount[ 4 + 8 ] = { 0 }, noOnes, i;

	assert( isReadPtr( data, dataLength ) );
	
	REQUIRES_B( dataLength >= MIN_KEYSIZE && dataLength < MAX_INTLENGTH_SHORT );

	for( i = 0; i < dataLength; i++ )
		{
		const int value = data[ i ];

		bitCount[ value & 3 ]++;
		bitCount[ ( value >> 2 ) & 3 ]++;
		bitCount[ ( value >> 4 ) & 3 ]++;
		bitCount[ ( value >> 6 ) & 3 ]++;
		}

	/* Monobit test: Make sure that at least 1/4 of the bits are ones and 1/4
	   are zeroes */
	noOnes = bitCount[ 1 ] + bitCount[ 2 ] + ( 2 * bitCount[ 3 ] );
	if( noOnes < dataLength * 2 || noOnes > dataLength * 6 )
		return( FALSE );

	/* Poker test (almost): Make sure that each bit pair is present at least
	   1/16 of the time.  The FIPS 140 version uses 4-bit values but the
	   numer of samples available from the keys is far too small for this so
	   we can only use 2-bit values.

	   This isn't precisely 1/16, for short samples (< 128 bits) we adjust
	   the count by one because of the small sample size and for odd-length
	   data we're getting four more samples so the actual figure is slightly
	   less than 1/16 */
	if( ( bitCount[ 0 ] + delta < dataLength / 2 ) || \
		( bitCount[ 1 ] + delta < dataLength / 2 ) || \
		( bitCount[ 2 ] + delta < dataLength / 2 ) || \
		( bitCount[ 3 ] + delta < dataLength / 2 ) )
		return( FALSE );

	return( TRUE );
	}

/* Copy a string attribute to external storage, with various range checks
   to follow the cryptlib semantics (these will already have been done by
   the caller, this is just a backup check).  There are two forms for this
   function, one that takes a MESSAGE_DATA parameter containing all of the 
   result parameters in one place and the other that takes distinct result
   parameters, typically because they've been passed down through several
   levels of function call beyond the point where they were in a 
   MESSAGE_DATA */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 4 ) ) \
int attributeCopyParams( OUT_BUFFER_OPT( destMaxLength, \
										 *destLength ) void *dest, 
						 IN_LENGTH_SHORT_Z const int destMaxLength, 
						 OUT_LENGTH_SHORT_Z int *destLength, 
						 IN_BUFFER( sourceLength ) const void *source, 
						 IN_LENGTH_SHORT_Z const int sourceLength )
	{
	assert( ( dest == NULL && destMaxLength == 0 ) || \
			( isWritePtr( dest, destMaxLength ) ) );
	assert( isWritePtr( destLength, sizeof( int ) ) );
	assert( ( source == NULL && sourceLength == 0 ) || \
			isReadPtr( source, sourceLength ) );

	REQUIRES( ( dest == NULL && destMaxLength == 0 ) || \
			  ( dest != NULL && \
				destMaxLength > 0 && \
				destMaxLength < MAX_INTLENGTH_SHORT ) );
	REQUIRES( ( source == NULL && sourceLength == 0 ) || \
			  ( source != NULL && \
			    sourceLength > 0 && \
				sourceLength < MAX_INTLENGTH_SHORT ) );

	/* Clear return value */
	*destLength = 0;

	if( sourceLength <= 0 )
		return( CRYPT_ERROR_NOTFOUND );
	if( dest != NULL )
		{
		assert( isReadPtr( source, sourceLength ) );

		if( sourceLength > destMaxLength || \
			!isWritePtr( dest, sourceLength ) )
			return( CRYPT_ERROR_OVERFLOW );
		memcpy( dest, source, sourceLength );
		}
	*destLength = sourceLength;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int attributeCopy( INOUT MESSAGE_DATA *msgData, 
				   IN_BUFFER( attributeLength ) const void *attribute, 
				   IN_LENGTH_SHORT_Z const int attributeLength )
	{
	assert( isWritePtr( msgData, sizeof( MESSAGE_DATA ) ) );
	assert( attributeLength == 0 || \
			isReadPtr( attribute, attributeLength ) );

	REQUIRES( attributeLength >= 0 && \
			  attributeLength < MAX_INTLENGTH_SHORT );

	return( attributeCopyParams( msgData->data, msgData->length, 
								 &msgData->length, attribute, 
								 attributeLength ) );
	}

/* Check whether a given algorithm is available */

CHECK_RETVAL_BOOL \
BOOLEAN algoAvailable( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_QUERY_INFO queryInfo;

	REQUIRES_B( cryptAlgo > CRYPT_ALGO_NONE && \
				cryptAlgo < CRYPT_ALGO_LAST );

	return( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									IMESSAGE_DEV_QUERYCAPABILITY, &queryInfo,
									cryptAlgo ) ) ? TRUE : FALSE );
	}

/* For a given algorithm pair, check whether the first is stronger than the
   second.  For hashes the order is:

	SHA2 > RIPEMD160 > SHA-1 > all others */

CHECK_RETVAL_BOOL \
BOOLEAN isStrongerHash( IN_ALGO const CRYPT_ALGO_TYPE algorithm1,
						IN_ALGO const CRYPT_ALGO_TYPE algorithm2 )
	{
	static const CRYPT_ALGO_TYPE algoPrecedence[] = {
		CRYPT_ALGO_SHA2, CRYPT_ALGO_RIPEMD160, CRYPT_ALGO_SHA1,
		CRYPT_ALGO_NONE, CRYPT_ALGO_NONE };
	int algo1index, algo2index;

	REQUIRES_B( algorithm1 >= CRYPT_ALGO_FIRST_HASH && \
				algorithm1 <= CRYPT_ALGO_LAST_HASH );
	REQUIRES_B( algorithm2 >= CRYPT_ALGO_FIRST_HASH && \
				algorithm2 <= CRYPT_ALGO_LAST_HASH );

	/* Find the relative positions on the scale of the two algorithms */
	for( algo1index = 0; 
		 algoPrecedence[ algo1index ] != algorithm1 && \
			algo1index < FAILSAFE_ARRAYSIZE( algoPrecedence, CRYPT_ALGO_TYPE );
		 algo1index++ )
		{
		/* If we've reached an unrated algorithm, it can't be stronger than 
		   the other one */
		if( algoPrecedence[ algo1index ] == CRYPT_ALGO_NONE )
			return( FALSE );
		}
	ENSURES_B( algo1index < FAILSAFE_ARRAYSIZE( algoPrecedence, \
												CRYPT_ALGO_TYPE ) );
	for( algo2index = 0; 
		 algoPrecedence[ algo2index ] != algorithm2 && \
			algo2index < FAILSAFE_ARRAYSIZE( algoPrecedence, CRYPT_ALGO_TYPE );
		 algo2index++ )
		{
		/* If we've reached an unrated algorithm, it's weaker than the other 
		   one */
		if( algoPrecedence[ algo2index ] == CRYPT_ALGO_NONE )
			return( TRUE );
		}
	ENSURES_B( algo2index < FAILSAFE_ARRAYSIZE( algoPrecedence, \
												CRYPT_ALGO_TYPE ) );

	/* If the first algorithm has a smaller index than the second, it's a
	   stronger algorithm */
	return( ( algo1index < algo2index ) ? TRUE : FALSE );
	}

/* Map one value to another, used to map values from one representation 
   (e.g. PGP algorithms or HMAC algorithms) to another (cryptlib algorithms
   or the underlying hash used for the HMAC algorithm) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int mapValue( IN_INT_SHORT_Z const int srcValue,
			  OUT_INT_SHORT_Z int *destValue,
			  IN_ARRAY( mapTblSize ) const MAP_TABLE *mapTbl,
			  IN_LENGTH_SHORT const int mapTblSize )
	{
	int i;

	assert( isWritePtr( destValue, sizeof( int ) ) );
	assert( isReadPtr( mapTbl, mapTblSize * sizeof( MAP_TABLE ) ) );

	REQUIRES( srcValue >= 0 && srcValue < MAX_INTLENGTH_SHORT );
	REQUIRES( mapTblSize > 0 && mapTblSize < 100 );

	/* Clear return value */
	*destValue = 0;

	/* Convert the hash algorithm into the equivalent HMAC algorithm */
	for( i = 0; mapTbl[ i ].source != CRYPT_ERROR && i < mapTblSize; i++ )
		{
		if( mapTbl[ i ].source == srcValue )
			{
			*destValue = mapTbl[ i ].destination;

			return( CRYPT_OK );
			}
		}
	ENSURES( i < mapTblSize );

	return( CRYPT_ERROR_NOTAVAIL );
	}

/****************************************************************************
*																			*
*							Checksum/Hash Functions							*
*																			*
****************************************************************************/

/* Calculate a 16-bit Fletcher-like checksum of a block of data.  This isn't
   quite a pure Fletcher checksum because we don't bother keeping the
   accumulators at 8 bits and also don't need to set the initial value to
   nonzero since we'll never see a sequence of zero bytes.  This isn't a big
   deal since all we need is consistent results for identical data, the 
   value itself is never communicated externally.  In addition we don't 
   bother with masking to 16 bits during the calculation process (although 
   we mask at the end to avoid potential problems with sign bits) since it's 
   not being used as a true checksum */

RETVAL_RANGE( MAX_ERROR, 0xFFFF ) STDC_NONNULL_ARG( ( 1 ) ) \
int checksumData( IN_BUFFER( dataLength ) const void *data, 
				  IN_LENGTH const int dataLength )
	{
	const BYTE *dataPtr = data;
	int sum1 = 0, sum2 = 0, i;

	assert( isReadPtr( data, dataLength ) );

	REQUIRES( data != NULL );
	REQUIRES( dataLength > 0 && dataLength < MAX_INTLENGTH )

	for( i = 0; i < dataLength; i++ )
		{
		sum1 += dataPtr[ i ];
		sum2 += sum1;
		}

	return( sum2 & 0xFFFF );
	}

/* Calculate the hash of a block of data.  We use SHA-1 because it's the 
   built-in default, but any algorithm will do since we're only using it
   to transform a variable-length value to a fixed-length one for easy
   comparison purposes */

STDC_NONNULL_ARG( ( 1, 3 ) ) \
void hashData( OUT_BUFFER_FIXED( hashMaxLength ) BYTE *hash, 
			   IN_LENGTH_HASH const int hashMaxLength, 
			   IN_BUFFER( dataLength ) const void *data, 
			   IN_LENGTH const int dataLength )
	{
	static HASHFUNCTION_ATOMIC hashFunctionAtomic = NULL;
	static int hashSize;
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE + 8 ];

	assert( isWritePtr( hash, hashMaxLength ) );
	assert( hashMaxLength >= 16 && \
			hashMaxLength <= CRYPT_MAX_HASHSIZE );
	assert( isReadPtr( data, dataLength ) );
	assert( dataLength > 0 && dataLength < MAX_INTLENGTH );

	/* Get the hash algorithm information if necessary */
	if( hashFunctionAtomic == NULL )
		getHashAtomicParameters( CRYPT_ALGO_SHA1, &hashFunctionAtomic, 
								 &hashSize );

	/* Error handling: If there's a problem, return a zero hash.  We use 
	   this strategy since this is a void function and so the usual 
	   REQUIRES() predicate won't be effective.  Note that this can lead to 
	   a false-positive match if we're called multiple times with invalid 
	   input, in theory we could fill the return buffer with nonce data to 
	   ensure that we never get a false-positive match but since this is a 
	   should-never-occur condition anyway it's not certain whether forcing 
	   a match or forcing a non-match is the preferred behaviour */
	if( data == NULL || dataLength <= 0 || dataLength >= MAX_INTLENGTH || \
		hashMaxLength < 16 || hashMaxLength > hashSize || \
		hashMaxLength > CRYPT_MAX_HASHSIZE || hashFunctionAtomic == NULL )
		{
		memset( hash, 0, hashMaxLength );
		retIntError_Void();
		}

	/* Hash the data and copy as many bytes as the caller has requested to
	   the output.  Typically they'll require only a subset of the full 
	   amount since all that we're doing is transforming a variable-length
	   value to a fixed-length value for easy comparison purposes */
	hashFunctionAtomic( hashBuffer, 20, data, dataLength );
	memcpy( hash, hashBuffer, hashMaxLength );
	zeroise( hashBuffer, 20 );
	}

/****************************************************************************
*																			*
*							Stream Export/Import Routines					*
*																			*
****************************************************************************/

/* Export attribute or certificate data to a stream.  In theory we would
   have to export this via a dynbuf and then write it to the stream but we 
   can save some overhead by writing it directly to the stream's buffer.
   
   Some attributes have a user-defined size (e.g. 
   CRYPT_IATTRIBUTE_RANDOM_NONCE) so we allow the caller to specify an 
   optional length parameter indicating how much of the attribute should be 
   exported */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exportAttr( INOUT STREAM *stream, 
					   IN_HANDLE const CRYPT_HANDLE cryptHandle,
					   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attributeType,
					   IN_LENGTH_INDEF const int length )
							/* Declared as LENGTH_INDEF because SHORT_INDEF
							   doesn't make sense */
	{
	MESSAGE_DATA msgData;
	void *dataPtr = NULL;
	int attrLength = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );

	REQUIRES( cryptHandle == SYSTEM_OBJECT_HANDLE || \
			  isHandleRangeValid( cryptHandle ) );
	REQUIRES( isAttribute( attributeType ) || \
			  isInternalAttribute( attributeType ) );
	REQUIRES( ( length == CRYPT_UNUSED ) || \
			  ( length >= 8 && length < MAX_INTLENGTH_SHORT ) );

	/* Get access to the stream buffer if required */
	if( !sIsNullStream( stream ) )
		{
		if( length != CRYPT_UNUSED )
			{
			/* It's an explicit-length attribute, make sure that there's 
			   enough room left in the stream for it */
			attrLength = length;
			status = sMemGetDataBlock( stream, &dataPtr, length );
			}
		else
			{
			/* It's an implicit-length attribute whose maximum length is 
			   defined by the stream size */
			status = sMemGetDataBlockRemaining( stream, &dataPtr, 
												&attrLength );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Export the attribute directly into the stream buffer */
	setMessageData( &msgData, dataPtr, attrLength );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, attributeType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int exportAttributeToStream( INOUT TYPECAST( STREAM * ) void *streamPtr, 
							 IN_HANDLE const CRYPT_HANDLE cryptHandle,
							 IN_ATTRIBUTE \
								const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );

	REQUIRES( isHandleRangeValid( cryptHandle ) );
	REQUIRES( isAttribute( attributeType ) || \
			  isInternalAttribute( attributeType ) );

	return( exportAttr( streamPtr, cryptHandle, attributeType, \
						CRYPT_UNUSED ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int exportVarsizeAttributeToStream( INOUT TYPECAST( STREAM * ) void *streamPtr,
									IN_HANDLE const CRYPT_HANDLE cryptHandle,
									IN_LENGTH_FIXED( CRYPT_IATTRIBUTE_RANDOM_NONCE ) \
										const CRYPT_ATTRIBUTE_TYPE attributeType,
									IN_RANGE( 8, 1024 ) \
										const int attributeDataLength )
	{
	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );

	REQUIRES( cryptHandle == SYSTEM_OBJECT_HANDLE );
	REQUIRES( attributeType == CRYPT_IATTRIBUTE_RANDOM_NONCE );
	REQUIRES( attributeDataLength >= 8 && attributeDataLength <= 1024 );

	return( exportAttr( streamPtr, cryptHandle, attributeType, 
						attributeDataLength ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int exportCertToStream( INOUT TYPECAST( STREAM * ) void *streamPtr,
						IN_HANDLE const CRYPT_CERTIFICATE cryptCertificate,
						IN_ENUM( CRYPT_CERTFORMAT ) \
							const CRYPT_CERTFORMAT_TYPE certFormatType )
	{
	MESSAGE_DATA msgData;
	STREAM *stream = streamPtr;
	void *dataPtr = NULL;
	int length = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );

	REQUIRES( isHandleRangeValid( cryptCertificate ) );
	REQUIRES( certFormatType > CRYPT_CERTFORMAT_NONE && \
			  certFormatType < CRYPT_CERTFORMAT_LAST );

	/* Get access to the stream buffer if required */
	if( !sIsNullStream( stream ) )
		{
		status = sMemGetDataBlockRemaining( stream, &dataPtr, &length );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Export the cert directly into the stream buffer */
	setMessageData( &msgData, dataPtr, length );
	status = krnlSendMessage( cryptCertificate, IMESSAGE_CRT_EXPORT,
							  &msgData, certFormatType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int importCertFromStream( INOUT void *streamPtr,
						  OUT_HANDLE_OPT CRYPT_CERTIFICATE *cryptCertificate,
						  IN_ENUM( CRYPT_CERTTYPE ) \
							const CRYPT_CERTTYPE_TYPE certType, 
						  IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
							const int certDataLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM *stream = streamPtr;
	void *dataPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( isWritePtr( cryptCertificate, sizeof( CRYPT_CERTIFICATE ) ) );

	REQUIRES( certType > CRYPT_CERTTYPE_NONE && \
			  certType < CRYPT_CERTTYPE_LAST );
	REQUIRES( certDataLength >= MIN_CRYPT_OBJECTSIZE && \
			  certDataLength < MAX_INTLENGTH_SHORT );

	/* Clear return value */
	*cryptCertificate = CRYPT_ERROR;

	/* Get access to the stream buffer and skip over the certificate data */
	status = sMemGetDataBlock( stream, &dataPtr, certDataLength );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, certDataLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the cert directly from the stream buffer */
	setMessageCreateObjectIndirectInfo( &createInfo, dataPtr, 
										certDataLength, certType );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	*cryptCertificate = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Safe Text-line Read Functions					*
*																			*
****************************************************************************/

/* Read a line of text data ending in an EOL.  If we get more data than will 
   fit into the read buffer we discard it until we find an EOL.  As a 
   secondary concern we want to strip leading, trailing, and repeated 
   whitespace.  Leading whitespace is handled by setting the seen-whitespace 
   flag to true initially, this treats any whitespace at the start of the 
   line as superfluous and strips it.  Stripping of repeated whitespace is 
   also handled by the seenWhitespace flag, and stripping of trailing 
   whitespace is handled by walking back through any final whitespace once we 
   see the EOL. 
   
   We also handle continued lines denoted by the MIME convention of a 
   semicolon as the last non-whitespace character by setting the 
   seenContinuation flag if we see a semicolon as the last non-whitespace 
   character.

   Finally, we also need to handle generic DoS attacks.  If we see more than
   MAX_LINE_LENGTH chars in a line we bail out */

#define MAX_LINE_LENGTH		4096

/* The extra level of indirection provided by this function is necessary 
   because the the extended error information isn't accessible from outside 
   the stream code so we can't set it in readTextLine() in the usual manner 
   via a retExt().  Instead we use a retExt() in the dummy function
   formatTextLineError() and then pass it down to the stream layer via an 
   ioctl */

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int formatTextLineError( OUT ERROR_INFO *errorInfo,
								FORMAT_STRING const char *format, 
								const int value1, const int value2 )
	{
	assert( isWritePtr( errorInfo, sizeof( ERROR_INFO ) ) );
	assert( isReadPtr( format, 4 ) );

	retExt( CRYPT_ERROR_BADDATA, 
			( CRYPT_ERROR_BADDATA, errorInfo, 
			  format, value1, value2 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readTextLine( READCHARFUNCTION readCharFunction, 
				  INOUT void *streamPtr,
				  OUT_BUFFER( lineBufferMaxLen, \
							  lineBufferSize ) char *lineBuffer, 
				  IN_LENGTH_SHORT_MIN( 16 ) const int lineBufferMaxLen, 
				  OUT_LENGTH_SHORT_Z int *lineBufferSize, 
				  OUT_OPT_BOOL BOOLEAN *localError )
	{
	BOOLEAN seenWhitespace, seenContinuation = FALSE;
	int totalChars, bufPos = 0;

	assert( readCharFunction != NULL );
	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );
	assert( isWritePtr( lineBuffer, lineBufferMaxLen ) );
	assert( isWritePtr( lineBufferSize, sizeof( int ) ) );
	assert( localError == NULL || \
			isWritePtr( localError, sizeof( BOOLEAN ) ) );

	REQUIRES( lineBufferMaxLen >= 16 && \
			  lineBufferMaxLen < MAX_INTLENGTH_SHORT );

	/* Clear return values */
	memset( lineBuffer, 0, min( 16, lineBufferMaxLen ) );
	*lineBufferSize = 0;
	if( localError != NULL )
		*localError = FALSE;

	/* Set the seen-whitespace flag initially to strip leading whitespace */
	seenWhitespace = TRUE;

	/* Read up to MAX_LINE_LENGTH chars.  Anything longer than this is 
	   probably a DoS */
	for( totalChars = 0; totalChars < MAX_LINE_LENGTH; totalChars++ )
		{
		int ch;

		/* Get the next input character */
		ch = readCharFunction( streamPtr );
		if( cryptStatusError( ch ) )
			return( ch );

		/* Process EOL */
		if( ch == '\n' )
			{
			/* Strip trailing whitespace.  At this point it's all been
			   canonicalised so we don't need to check for anything other 
			   than spaces */
			while( bufPos > 0 && lineBuffer[ bufPos - 1 ] == ' ' )
				bufPos--;

			/* If we've seen a continuation marker as the last non-
			   whitespace char, the line continues on the next one.  This
			   can theoretically result in stripping a space at the end of
			   a line but since continuations are only placed at MIME
			   keyword separators the space is superfluous and can be 
			   safely removed */
			if( seenContinuation )
				{
				seenContinuation = FALSE;
				continue;
				}

			/* We're done */
			break;
			}

		/* Ignore any additional decoration that may accompany EOLs */
		if( ch == '\r' )
			continue;

		/* If we're over the maximum buffer size discard any further input
		   until we either hit EOL or exceed the DoS threshold at
		   MAX_LINE_LENGTH */
		if( bufPos > lineBufferMaxLen - 8 )
			{
			/* If we've run off into the weeds (for example we're reading 
			   binary data following the text header), bail out */
			if( ch <= 0 || ch > 0x7F || !isPrint( ch ) )
				{
				ERROR_INFO errorInfo;

				if( localError != NULL )
					*localError = TRUE;
				formatTextLineError( &errorInfo, "Invalid character 0x%02X "
									 "at position %d", ch, totalChars );
				sioctl( streamPtr, STREAM_IOCTL_ERRORINFO, &errorInfo, 0 );
				return( CRYPT_ERROR_BADDATA );
				}
			continue;
			}

		/* Process whitespace.  We can't use isspace() for this because it
		   includes all sorts of extra control characters that we don't want
		   to allow */
		if( ch == ' ' || ch == '\t' )
			{
			if( seenWhitespace )
				{
				/* Ignore leading and repeated whitespace */
				continue;
				}
			ch = ' ';	/* Canonicalise whitespace */
			}

		/* Process any remaining chars */
		if( ch <= 0 || ch > 0x7F || !isPrint( ch ) )
			{
			ERROR_INFO errorInfo;

			if( localError != NULL )
				*localError = TRUE;
			formatTextLineError( streamPtr, "Invalid character 0x%02X at "
								 "position %d", ch, totalChars );
			sioctl( streamPtr, STREAM_IOCTL_ERRORINFO, &errorInfo, 0 );
			return( CRYPT_ERROR_BADDATA );
			}
		lineBuffer[ bufPos++ ] = ch;
		ENSURES( bufPos > 0 && bufPos <= totalChars + 1 );
				 /* The 'totalChars + 1' is because totalChars is the loop
				    iterator and won't have been incremented yet at this 
					point */

		/* Update the state variables.  If the character that we've just 
		   processed was whitespace or if we've seen a continuation 
		   character or we're processing whitespace after having seen a 
		   continuation character (which makes it effectively leading 
		   whitespace to be stripped), remember this */
		seenWhitespace = ( ch == ' ' ) ? TRUE : FALSE;
		seenContinuation = ( ch == ';' || \
						     ( seenContinuation && seenWhitespace ) ) ? \
						   TRUE : FALSE;
		}
	if( totalChars >= MAX_LINE_LENGTH )
		{
		ERROR_INFO errorInfo;

		if( localError != NULL )
			*localError = TRUE;
		formatTextLineError( streamPtr, "Text line too long", 0, 0 );
		sioctl( streamPtr, STREAM_IOCTL_ERRORINFO, &errorInfo, 0 );
		return( CRYPT_ERROR_OVERFLOW );
		}
	*lineBufferSize = bufPos;

	return( CRYPT_OK );
	}
