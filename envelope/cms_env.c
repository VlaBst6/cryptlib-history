/****************************************************************************
*																			*
*						cryptlib CMS Enveloping Routines					*
*					    Copyright Peter Gutmann 1996-2008					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "envelope.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "envelope/envelope.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

#ifdef USE_ENVELOPES

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the envelope state */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheck( const ENVELOPE_INFO *envelopeInfoPtr )
	{
	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Make sure that general envelope state is in order */
	if( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE )
		return( FALSE );
	if( envelopeInfoPtr->envState < ENVSTATE_NONE || \
		envelopeInfoPtr->envState >= ENVSTATE_LAST )
		return( FALSE );

	/* Make sure that the buffer position is within bounds */
	if( envelopeInfoPtr->buffer == NULL || \
		envelopeInfoPtr->bufPos < 0 || \
		envelopeInfoPtr->bufPos > envelopeInfoPtr->bufSize || \
		envelopeInfoPtr->bufSize < MIN_BUFFER_SIZE || \
		envelopeInfoPtr->bufSize >= MAX_INTLENGTH )
		return( FALSE );

	/* If the auxBuffer isn't being used, make sure that all values related 
	   to it are clear */
	if( envelopeInfoPtr->auxBuffer == NULL )
		{
		if( envelopeInfoPtr->auxBufPos != 0 || \
			envelopeInfoPtr->auxBufSize != 0 )
			return( FALSE );

		return( TRUE );
		}

	/* Make sure that the auxBuffer position is within bounds */
	if( envelopeInfoPtr->auxBufPos < 0 || \
		envelopeInfoPtr->auxBufPos > envelopeInfoPtr->auxBufSize || \
		envelopeInfoPtr->auxBufSize < 0 || \
		envelopeInfoPtr->auxBufSize >= MAX_INTLENGTH )
		return( FALSE );

	return( TRUE );
	}

/* Check that a requested algorithm type is valid with enveloped data */

CHECK_RETVAL_BOOL \
BOOLEAN cmsCheckAlgo( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					  IN_MODE_OPT const CRYPT_MODE_TYPE cryptMode )
	{
	REQUIRES_B( cryptAlgo > CRYPT_ALGO_NONE && \
				cryptAlgo < CRYPT_ALGO_LAST );
	REQUIRES_B( ( cryptMode == CRYPT_MODE_NONE ) || \
				( cryptMode > CRYPT_MODE_NONE && \
				  cryptMode < CRYPT_MODE_LAST ) );

	return( checkAlgoID( cryptAlgo, cryptMode ) );
	}

/* Get the OID for a CMS content type.  If no type is explicitly given, we
   assume raw data */

static const OID_INFO FAR_BSS contentOIDs[] = {
	{ OID_CMS_DATA, CRYPT_CONTENT_DATA },
	{ OID_CMS_SIGNEDDATA, CRYPT_CONTENT_SIGNEDDATA },
	{ OID_CMS_ENVELOPEDDATA, CRYPT_CONTENT_ENVELOPEDDATA },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x04" ), CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA },
	{ OID_CMS_DIGESTEDDATA, CRYPT_CONTENT_DIGESTEDDATA },
	{ OID_CMS_ENCRYPTEDDATA, CRYPT_CONTENT_ENCRYPTEDDATA },
	{ OID_CMS_COMPRESSEDDATA, CRYPT_CONTENT_COMPRESSEDDATA },
	{ OID_CMS_AUTHDATA, CRYPT_CONTENT_AUTHDATA },
	{ OID_CMS_AUTHENVDATA, CRYPT_CONTENT_AUTHENVDATA },
	{ OID_CMS_TSTOKEN, CRYPT_CONTENT_TSTINFO },
	{ OID_MS_SPCINDIRECTDATACONTEXT, CRYPT_CONTENT_SPCINDIRECTDATACONTEXT },
	{ OID_CRYPTLIB_RTCSREQ, CRYPT_CONTENT_RTCSREQUEST },
	{ OID_CRYPTLIB_RTCSRESP, CRYPT_CONTENT_RTCSRESPONSE },
	{ OID_CRYPTLIB_RTCSRESP_EXT, CRYPT_CONTENT_RTCSRESPONSE_EXT },
	{ MKOID( "\x06\x06\x67\x81\x08\x01\x01\x01" ), CRYPT_CONTENT_MRTD },
	{ NULL, 0 }, { NULL, 0 }
	};

CHECK_RETVAL_PTR \
static const BYTE *getContentOID( IN_ENUM( CRYPT_CONTENT ) \
								  const CRYPT_CONTENT_TYPE contentType )
	{
	int i;

	REQUIRES_N( contentType > CRYPT_CONTENT_NONE && \
				contentType < CRYPT_CONTENT_LAST );

	for( i = 0; contentOIDs[ i ].oid != NULL && \
				i < FAILSAFE_ARRAYSIZE( contentOIDs, OID_INFO ); i++ )
		{
		if( contentOIDs[ i ].selectionID == contentType )
			return( contentOIDs[ i ].oid );
		}

	retIntError_Null();
	}

/* Copy as much post-data state information (i.e. signatures) from the
   auxiliary buffer to the main buffer as possible */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int copyFromAuxBuffer( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	int bytesCopied, dataLeft;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Copy as much of the signature data as we can across */
	bytesCopied = min( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos,
					   envelopeInfoPtr->auxBufPos );
	REQUIRES( bytesCopied > 0 && \
			  envelopeInfoPtr->bufPos + \
				bytesCopied <= envelopeInfoPtr->bufSize );
	memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
			envelopeInfoPtr->auxBuffer, bytesCopied );
	envelopeInfoPtr->bufPos += bytesCopied;

	/* Since we're in the post-data state any necessary payload data
	   segmentation has been completed, however, the caller can't copy out 
	   any post-payload data because it's past the end-of-segment position.
	   In order to allow the buffer to be emptied to make room for new data
	   from the auxBuffer we set the end-of-segment position to the end of
	   the new data */
	envelopeInfoPtr->segmentDataEnd = envelopeInfoPtr->bufPos;

	/* If there's anything left move it down in the buffer */
	dataLeft = envelopeInfoPtr->auxBufPos - bytesCopied;
	if( dataLeft > 0 )
		{
		REQUIRES( rangeCheck( bytesCopied, dataLeft, \
							  envelopeInfoPtr->auxBufPos ) );
		memmove( envelopeInfoPtr->auxBuffer, \
				 envelopeInfoPtr->auxBuffer + bytesCopied, dataLeft );
		}
	envelopeInfoPtr->auxBufPos = dataLeft;
	
	ENSURES( dataLeft >= 0 );

	return( ( dataLeft > 0 ) ? CRYPT_ERROR_OVERFLOW : CRYPT_OK );
	}

/* Write one or more indefinite-length end-of-contents indicators */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeEOCs( INOUT ENVELOPE_INFO *envelopeInfoPtr, const int count )
	{
	static const BYTE indefEOC[ 16 ] = \
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const int dataLeft = envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos;
	const int eocLength = count * 2;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( eocLength >= 2 && eocLength <= 16 );	/* Count = 1...8 */

	if( dataLeft < eocLength )
		return( CRYPT_ERROR_OVERFLOW );
	memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos, indefEOC,
			eocLength );
	envelopeInfoPtr->bufPos += eocLength;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Emit Content-Specific Headers						*
*																			*
****************************************************************************/

/* Write the header fields that encapsulate any enveloped data:

   SignedData/DigestedData */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeSignedDataHeader( INOUT STREAM *stream,
								  const ENVELOPE_INFO *envelopeInfoPtr,
								  const BOOLEAN isSignedData )
	{
	const BYTE *contentOID = getContentOID( envelopeInfoPtr->contentType );
	ACTION_LIST *actionListPtr;
	long dataSize;
	int hashActionSize = 0, iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES_S( contentOID != NULL );

	/* Determine the size of the hash actions */
	for( actionListPtr = envelopeInfoPtr->actionList, iterationCount = 0;
		 actionListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED;
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		const int actionSize = \
						sizeofContextAlgoID( actionListPtr->iCryptHandle, 
											 CRYPT_ALGO_NONE );
		if( cryptStatusError( actionSize ) )
			return( actionSize );
		hashActionSize += actionSize;
		}
	ENSURES_S( iterationCount < FAILSAFE_ITERATIONS_MED );
	
	/* Determine the size of the SignedData/DigestedData */
	if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED || \
		( envelopeInfoPtr->dataFlags & ENVDATA_HASINDEFTRAILER ) )
		dataSize = CRYPT_UNUSED;
	else
		{
		/* Determine the size of the content OID + content */
		dataSize = ( envelopeInfoPtr->payloadSize > 0 ) ? \
			sizeofObject( sizeofObject( envelopeInfoPtr->payloadSize ) ) : 0;
		dataSize = sizeofObject( sizeofOID( contentOID ) + dataSize );

		/* Determine the size of the version, hash algoID, content, 
		   certificate chain, and signatures */
		dataSize = sizeofShortInteger( 1 ) + sizeofObject( hashActionSize ) + \
				   dataSize + envelopeInfoPtr->extraDataSize + \
				   sizeofObject( envelopeInfoPtr->signActionSize );
		}
	ENSURES_S( dataSize == CRYPT_UNUSED || \
			   ( dataSize >= MIN_CRYPT_OBJECTSIZE && \
				 dataSize < MAX_INTLENGTH ) );

	/* Write the SignedData/DigestedData header, version number, and SET OF
	   DigestInfo */
	if( isSignedData )
		{
		status = writeCMSheader( stream, OID_CMS_SIGNEDDATA, 
								 sizeofOID( OID_CMS_SIGNEDDATA ), 
								 dataSize, FALSE );
		}
	else
		{
		status = writeCMSheader( stream, OID_CMS_DIGESTEDDATA, 
								 sizeofOID( OID_CMS_DIGESTEDDATA ), 
								 dataSize, FALSE );
		}
	if( cryptStatusError( status ) )
		return( status );
	writeShortInteger( stream, 1, DEFAULT_TAG );
	writeSet( stream, hashActionSize );
	for( actionListPtr = envelopeInfoPtr->actionList, iterationCount = 0;
		 actionListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED;
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		status = writeContextAlgoID( stream, actionListPtr->iCryptHandle, 
									 CRYPT_ALGO_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES_S( iterationCount < FAILSAFE_ITERATIONS_MED );

	/* Write the inner Data header */
	return( writeCMSheader( stream, contentOID, sizeofOID( contentOID ), 
							envelopeInfoPtr->payloadSize, TRUE ) );
	}

/* EncryptedContentInfo contained within EnvelopedData.  This may also be 
   Authenticated or AuthEnc data so the encryption context can be 
   CRYPT_UNUSED */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int getBlockedPayloadSize( IN_LENGTH_INDEF const long payloadSize, 
								  IN_LENGTH_IV const int blockSize,
								  OUT_LENGTH_INDEF long *blockedPayloadSize )
	{
	assert( isWritePtr( blockedPayloadSize, sizeof( long ) ) );

	REQUIRES( payloadSize == CRYPT_UNUSED || \
			  ( payloadSize > 0 && payloadSize < MAX_INTLENGTH ) );
	REQUIRES( blockSize >= 1 && blockSize <= CRYPT_MAX_IVSIZE );

	/* Clear return value */
	*blockedPayloadSize = 0;

	/* If it's an indefinite length payload the blocked size is also of 
	   indefinite length */
	if( payloadSize == CRYPT_UNUSED )
		{
		*blockedPayloadSize = CRYPT_UNUSED;
		return( CRYPT_OK );
		}

	/* If it's a stream cipher there's no encryption blocking */
	if( blockSize <= 1 )
		{
		*blockedPayloadSize = payloadSize;
		return( CRYPT_OK );
		}

	/* Calculate the size of the payload after PKCS #5 block padding.  This 
	   isn't just the size rounded up to the nearest multiple of the block 
	   size since if the size is already a multiple of the block size it 
	   expands by another block, so we make the payload look one byte longer 
	   before rounding to the block size to ensure the one-block expansion */
	*blockedPayloadSize = roundUp( payloadSize + 1, blockSize );

	ENSURES( *blockedPayloadSize >= 8 && \
			 *blockedPayloadSize <= payloadSize + CRYPT_MAX_IVSIZE );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeEncryptedContentHeader( INOUT STREAM *stream,
							IN_BUFFER( contentOIDlength ) const BYTE *contentOID, 
							IN_LENGTH_OID const int contentOIDlength,
							IN_HANDLE const CRYPT_CONTEXT iCryptContext,
							IN_LENGTH_INDEF const long payloadSize, 
							IN_LENGTH_IV const long blockSize )
	{
	long blockedPayloadSize;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contentOID, contentOIDlength ) );
	
	REQUIRES( isHandleRangeValid( iCryptContext ) || \
			  iCryptContext == CRYPT_UNUSED );
	REQUIRES( payloadSize == CRYPT_UNUSED || \
			  ( payloadSize > 0 && payloadSize < MAX_INTLENGTH ) );
	REQUIRES( blockSize > 1 && blockSize <= CRYPT_MAX_IVSIZE );

	status = getBlockedPayloadSize( payloadSize, blockSize, 
									&blockedPayloadSize );
	if( cryptStatusError( status ) )
		return( status );
	return( writeCMSencrHeader( stream, contentOID, contentOIDlength,
								blockedPayloadSize, iCryptContext ) );
	}

/* EncryptedData, EnvelopedData */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
static int getEncrypedContentSize( const ENVELOPE_INFO *envelopeInfoPtr,
								   IN_BUFFER( contentOIDlength ) const BYTE *contentOID, 
								   IN_LENGTH_OID const int contentOIDlength,
								   OUT_LENGTH_INDEF long *blockedPayloadSize,
								   OUT_LENGTH_Z long *encrContentInfoSize )
	{
	long length;
	int status;

	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	assert( isReadPtr( contentOID, contentOIDlength ) );
	assert( isWritePtr( blockedPayloadSize, sizeof( long ) ) );
	assert( isWritePtr( encrContentInfoSize, sizeof( long ) ) );

	REQUIRES( contentOIDlength >= MIN_OID_SIZE && \
			  contentOIDlength <= MAX_OID_SIZE );

	/* Clear return values */
	*blockedPayloadSize = *encrContentInfoSize = 0;

	/* Calculate the size of the payload after encryption blocking */
	status = getBlockedPayloadSize( envelopeInfoPtr->payloadSize, 
									envelopeInfoPtr->blockSize,
									blockedPayloadSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Calculate the size of the CMS ContentInfo header */
	length = sizeofCMSencrHeader( contentOID, contentOIDlength, 
								  *blockedPayloadSize, 
								  envelopeInfoPtr->iCryptContext );
	if( cryptStatusError( length ) )
		return( ( int ) length );
	*encrContentInfoSize = length;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeEncryptionHeader( INOUT STREAM *stream, 
								  IN_BUFFER( oidLength ) const BYTE *oid, 
								  IN_LENGTH_OID const int oidLength, 
								  IN_RANGE( 0, 2 ) const int version, 
								  IN_LENGTH_INDEF const long blockedPayloadSize,
								  IN_LENGTH_INDEF const long extraSize )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( oid, oidLength ) );

	REQUIRES_S( oidLength >= MIN_OID_SIZE && oidLength <= MAX_OID_SIZE );
	REQUIRES_S( version >= 0 && version <= 2 );
	REQUIRES_S( ( oidLength == sizeofOID( OID_CMS_AUTHDATA ) && \
				  !memcmp( oid, OID_CMS_AUTHDATA, \
						   sizeofOID( OID_CMS_AUTHDATA ) ) ) || \
				blockedPayloadSize == CRYPT_UNUSED || \
				( blockedPayloadSize >= 8 && \
				  blockedPayloadSize < MAX_INTLENGTH ) );
	REQUIRES_S( extraSize == CRYPT_UNUSED || \
				( extraSize > 0 && extraSize < MAX_INTLENGTH ) );

	status = writeCMSheader( stream, oid, oidLength,
							 ( blockedPayloadSize == CRYPT_UNUSED || \
							   extraSize == CRYPT_UNUSED ) ? \
								CRYPT_UNUSED : \
								sizeofShortInteger( 0 ) + extraSize + \
								blockedPayloadSize,
							  FALSE );
	if( cryptStatusError( status ) )
		return( status );
	return( writeShortInteger( stream, version, DEFAULT_TAG ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeEncryptedDataHeader( INOUT STREAM *stream,
									 const ENVELOPE_INFO *envelopeInfoPtr )
	{
	const BYTE *contentOID = getContentOID( envelopeInfoPtr->contentType );
	long blockedPayloadSize, encrContentInfoSize;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES_S( contentOID != NULL );

	/* Calculate the size of the payload due to blocking and the ContentInfo
	   header */
	status = getEncrypedContentSize( envelopeInfoPtr, contentOID,
									 sizeofOID( contentOID ), 
									 &blockedPayloadSize, 
									 &encrContentInfoSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the EncryptedData header, version number, and
	   EncryptedContentInfo header */
	status = writeEncryptionHeader( stream, OID_CMS_ENCRYPTEDDATA, 
									sizeofOID( OID_CMS_ENCRYPTEDDATA ), 0,
									blockedPayloadSize, encrContentInfoSize );
	if( cryptStatusError( status ) )
		return( status );
	return( writeEncryptedContentHeader( stream, contentOID, 
				sizeofOID( contentOID ), envelopeInfoPtr->iCryptContext, 
				envelopeInfoPtr->payloadSize, envelopeInfoPtr->blockSize ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeEnvelopedDataHeader( INOUT STREAM *stream,
									 const ENVELOPE_INFO *envelopeInfoPtr )
	{
	const BYTE *contentOID = getContentOID( envelopeInfoPtr->contentType );
	long blockedPayloadSize, encrContentInfoSize;
#ifdef USE_KEA
	const int originatorInfoSize = ( envelopeInfoPtr->extraDataSize > 0 ) ? \
			( int ) sizeofObject( envelopeInfoPtr->extraDataSize ) : 0;
#endif /* USE_KEA */
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES_S( contentOID != NULL );

	/* Calculate the size of the payload due to blocking and the ContentInfo
	   header */
	status = getEncrypedContentSize( envelopeInfoPtr, contentOID,
									 sizeofOID( contentOID ), 
									 &blockedPayloadSize, 
									 &encrContentInfoSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the EnvelopedData header and version number and start of the 
	   SET OF RecipientInfo/EncryptionKeyInfo */
#ifndef USE_KEA
	status = writeEncryptionHeader( stream, OID_CMS_ENVELOPEDDATA, 
						sizeofOID( OID_CMS_ENVELOPEDDATA ), 0, 
						blockedPayloadSize,
						( envelopeInfoPtr->cryptActionSize == CRYPT_UNUSED ) ? \
							CRYPT_UNUSED : \
							sizeofObject( envelopeInfoPtr->cryptActionSize ) + \
								encrContentInfoSize );
	if( cryptStatusError( status ) )
		return( status );
#else
	status = writeEncryptionHeader( stream, OID_CMS_ENVELOPEDDATA, 
						sizeofOID( OID_CMS_ENVELOPEDDATA ),
						( originatorInfoSize > 0 ) ? 2 : 0, 
						blockedPayloadSize,
						( envelopeInfoPtr->cryptActionSize == CRYPT_UNUSED ) ? \
							CRYPT_UNUSED : \
							sizeofObject( envelopeInfoPtr->cryptActionSize ) + \
								originatorInfoSize + encrContentInfoSize );
	if( cryptStatusError( status ) )
		return( status );
	if( originatorInfoSize > 0 )
		{
		int status;

		/* Write the wrapper for the originator info and the originator info
		   itself */
		writeConstructed( stream, envelopeInfoPtr->extraDataSize, 0 );

		/* Export the originator certificate chain either directly into the 
		   main buffer or into the auxBuffer if there's not enough room */
		if( originatorInfoSize >= sMemDataLeft( stream ) )
			{
			/* The originator chain is too big for the main buffer so we 
			   have to write everything from this point on into the 
			   auxBuffer.  This is then flushed into the main buffer in the 
			   calling code before anything else is written */
			stream = ( STREAM * ) &envelopeInfoPtr->auxStream;
			}
		status = exportCertToStream( stream, envelopeInfoPtr->iExtraCertChain,
									 CRYPT_ICERTFORMAT_CERTSET );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_KEA */

	return( ( envelopeInfoPtr->cryptActionSize == CRYPT_UNUSED ) ? \
			writeSetIndef( stream ) : \
			writeSet( stream, envelopeInfoPtr->cryptActionSize ) );
	}

/* AuthenticatedData */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeAuthenticatedDataHeader( INOUT STREAM *stream,
							const ENVELOPE_INFO *envelopeInfoPtr )
	{
	const BYTE *contentOID = getContentOID( envelopeInfoPtr->contentType );
	const int macActionSize = \
				sizeofContextAlgoID( envelopeInfoPtr->actionList->iCryptHandle,
									 CRYPT_ALGO_NONE );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES_S( contentOID != NULL );

	if( cryptStatusError( macActionSize ) )
		return( macActionSize );

	/* Write the AuthenticatedData header and version number and start of 
	   the SET OF RecipientInfo.  Technically this isn't an encryption 
	   header but it uses the same format */
 	if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED )
		{
		status = writeEncryptionHeader( stream, OID_CMS_AUTHDATA, 
										sizeofOID( OID_CMS_AUTHDATA ), 0, 1, 
										CRYPT_UNUSED );
		}
	else
		{
		int macSize, contentInfoSize;

		/* Determine the size of the MAC and the encapsulated content 
		   header */
		status = krnlSendMessage( envelopeInfoPtr->actionList->iCryptHandle, 
								  IMESSAGE_GETATTRIBUTE, &macSize, 
								  CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusError( status ) )
			return( status );
		contentInfoSize = sizeofObject( \
							sizeofObject( envelopeInfoPtr->payloadSize ) );
		contentInfoSize = sizeofObject( sizeofOID( contentOID ) + \
										contentInfoSize ) - \
						  envelopeInfoPtr->payloadSize;
		REQUIRES_S( contentInfoSize >= 16 && \
					contentInfoSize < MAX_INTLENGTH );

		/* Write the data header */
		status = writeEncryptionHeader( stream, OID_CMS_AUTHDATA, 
					sizeofOID( OID_CMS_AUTHDATA ), 0, 
					envelopeInfoPtr->payloadSize,
					( envelopeInfoPtr->cryptActionSize == CRYPT_UNUSED ) ? \
						CRYPT_UNUSED : \
						sizeofObject( envelopeInfoPtr->cryptActionSize ) + \
							macActionSize + contentInfoSize + \
							sizeofObject( macSize ) );
		}
	if( cryptStatusError( status ) )
		return( status );

	return( ( envelopeInfoPtr->cryptActionSize == CRYPT_UNUSED ) ? \
			writeSetIndef( stream ) : \
			writeSet( stream, envelopeInfoPtr->cryptActionSize ) );
	}

/* CompressedData */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCompressedDataHeader( INOUT STREAM *stream,
									  INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	const BYTE *contentOID = getContentOID( envelopeInfoPtr->contentType );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES_S( contentOID != NULL );

	/* Since compressing the data changes its length we have to use the
	   indefinite-length encoding even if we know how big the payload is */
	envelopeInfoPtr->payloadSize = CRYPT_UNUSED;

	/* Write the CompressedData header, version number, and Zlib algoID */
	status = writeCMSheader( stream, OID_CMS_COMPRESSEDDATA, 
							 sizeofOID( OID_CMS_COMPRESSEDDATA ), 
							 CRYPT_UNUSED, FALSE );
	if( cryptStatusError( status ) )
		return( status );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeGenericAlgoID( stream, OID_ZLIB, sizeofOID( OID_ZLIB ) );

	/* Write the inner Data header */
	return( writeCMSheader( stream, contentOID, sizeofOID( contentOID ), 
							CRYPT_UNUSED, TRUE ) );
	}

/****************************************************************************
*																			*
*							Header Processing Routines						*
*																			*
****************************************************************************/

/* Write the envelope header */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeEnvelopeHeader( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	STREAM stream;
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* If we're encrypting, set up the encryption-related information */
	if( envelopeInfoPtr->usage == ACTION_CRYPT )
		{
		REQUIRES( envelopeInfoPtr->actionList != NULL );
		status = initEnvelopeEncryption( envelopeInfoPtr,
								envelopeInfoPtr->actionList->iCryptHandle,
								CRYPT_ALGO_NONE, CRYPT_MODE_NONE, NULL, 0,
								FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the appropriate CMS header based on the envelope usage.  The
	   DigestedData/ACTION_HASH action is never taken since the higher-level 
	   code assumes that the presence of hash actions indicates the desire 
	   to create signed data and returns an error if no signature actions are 
	   present */
	sMemOpen( &stream, envelopeInfoPtr->buffer, envelopeInfoPtr->bufSize );
	switch( envelopeInfoPtr->usage )
		{
		case ACTION_CRYPT:
			if( envelopeInfoPtr->preActionList == NULL )
				status = writeEncryptedDataHeader( &stream,
												   envelopeInfoPtr );
			else
				status = writeEnvelopedDataHeader( &stream,
												   envelopeInfoPtr );
			break;

		case ACTION_SIGN:
			status = writeSignedDataHeader( &stream, envelopeInfoPtr, TRUE );
			break;

		case ACTION_HASH:
			status = writeSignedDataHeader( &stream, envelopeInfoPtr, FALSE );
			break;

		case ACTION_COMPRESS:
			status = writeCompressedDataHeader( &stream, envelopeInfoPtr );
			break;

		case ACTION_NONE:
			{
			const BYTE *contentOID = \
							getContentOID( envelopeInfoPtr->contentType );

			REQUIRES( contentOID != NULL );

			status = writeCMSheader( &stream, contentOID, 
									 sizeofOID( contentOID ),
									 envelopeInfoPtr->payloadSize, FALSE );
			break;
			}

		case ACTION_MAC:
			status = writeAuthenticatedDataHeader( &stream, envelopeInfoPtr );
			break;

		default:
			retIntError();
		}
	if( cryptStatusOK( status ) )
		envelopeInfoPtr->bufPos = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're not encrypting with key exchange actions, we're done */
	if( ( envelopeInfoPtr->usage != ACTION_CRYPT && \
		  envelopeInfoPtr->usage != ACTION_MAC ) || \
		envelopeInfoPtr->preActionList == NULL )
		{
		/* Set the block size mask to all ones if we're not encrypting since 
		   we can begin and end data segments on arbitrary boundaries and 
		   inform the caller that we're done */
		if( envelopeInfoPtr->usage != ACTION_CRYPT )
			envelopeInfoPtr->blockSizeMask = -1;
		envelopeInfoPtr->lastAction = NULL;
		return( OK_SPECIAL );
		}

	/* Start emitting the key exchange actions */
	envelopeInfoPtr->lastAction = findAction( envelopeInfoPtr->preActionList,
											  ACTION_KEYEXCHANGE_PKC );
	if( envelopeInfoPtr->lastAction == NULL )
		envelopeInfoPtr->lastAction = findAction( envelopeInfoPtr->preActionList,
												  ACTION_KEYEXCHANGE );
	ENSURES( envelopeInfoPtr->lastAction != NULL );

	return( CRYPT_OK );
	}

/* Write key exchange actions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeKeyex( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	const CRYPT_CONTEXT iCryptContext = \
							( envelopeInfoPtr->usage == ACTION_CRYPT ) ? \
							envelopeInfoPtr->iCryptContext : \
							envelopeInfoPtr->actionList->iCryptHandle;
	ACTION_LIST *actionListPtr;
	int iterationCount, status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Export the session key/MAC using each of the PKC or conventional 
	   keys.  If it's a conventional key exchange we force the use of the 
	   CMS format since there's no reason to use the cryptlib format */
	for( actionListPtr = envelopeInfoPtr->lastAction, iterationCount = 0;
		 actionListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED;
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		const CRYPT_FORMAT_TYPE formatType = \
						( actionListPtr->action == ACTION_KEYEXCHANGE ) ? \
						CRYPT_FORMAT_CMS : envelopeInfoPtr->type;
		const int dataLeft = min( envelopeInfoPtr->bufSize - \
								  envelopeInfoPtr->bufPos, 
								  MAX_INTLENGTH_SHORT - 1 );
		int keyexSize;

		ENSURES( dataLeft >= 0 && dataLeft < MAX_INTLENGTH_SHORT );

		/* Make sure that there's enough room to emit this key exchange 
		   action */
		if( actionListPtr->encodedSize + 128 > dataLeft )
			{
			status = CRYPT_ERROR_OVERFLOW;
			break;
			}

		/* Emit the key exchange action */
		status = iCryptExportKey( envelopeInfoPtr->buffer + \
								  envelopeInfoPtr->bufPos, dataLeft, 
								  &keyexSize, formatType, iCryptContext,
								  actionListPtr->iCryptHandle );
		if( cryptStatusError( status ) )
			break;
		envelopeInfoPtr->bufPos += keyexSize;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );
	envelopeInfoPtr->lastAction = actionListPtr;
	if( cryptStatusError( status ) )
		return( status );

	/* If it's an indefinite-length header close off the set of key 
	   exchange actions */
	if( envelopeInfoPtr->cryptActionSize == CRYPT_UNUSED )
		return( writeEOCs( envelopeInfoPtr, 1 ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Trailer Processing Routines						*
*																			*
****************************************************************************/

/* Write the signing certificate chain.  This can grow arbitrarily large and 
   in particular can become larger than the main envelope buffer if multiple 
   signatures with long chains and a small envelope buffer are used, so we 
   emit the certificate chain into a dynamically-allocated auxiliary buffer 
   if there isn't enough room to emit it into the main buffer  */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeCertchainTrailer( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	STREAM stream;
	void *certChainBufPtr;
	const int dataLeft = min( envelopeInfoPtr->bufSize - \
							  envelopeInfoPtr->bufPos, 
							  MAX_INTLENGTH_SHORT - 1 );
	const int eocSize = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
						( 3 * 2 ) : 0;
	int certChainBufSize, certChainSize = DUMMY_INIT, status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	ENSURES( dataLeft >= 0 && dataLeft < MAX_INTLENGTH_SHORT );

	/* Check whether there's enough room left in the buffer to emit the 
	   signing certificate chain directly into it */
	if( envelopeInfoPtr->extraDataSize + 64 < dataLeft )
		{
		/* The certificate chain will fit into the envelope buffer */
		certChainBufPtr = envelopeInfoPtr->buffer + \
						  envelopeInfoPtr->bufPos + eocSize;
		certChainBufSize = dataLeft - eocSize;
		}
	else
		{
		/* If there's almost no room left in the buffer anyway tell the 
		   caller that they have to pop some data before they can continue.  
		   Hopefully this will create enough room to emit the certificates 
		   directly into the buffer */
		if( dataLeft < 1024 )
			return( CRYPT_ERROR_OVERFLOW );

		/* We can't emit the certificates directly into the envelope buffer, 
		   allocate an auxiliary buffer for them and from there copy them 
		   into the main buffer */
		REQUIRES( envelopeInfoPtr->auxBuffer == NULL );
		if( ( envelopeInfoPtr->auxBuffer = \
				clDynAlloc( "emitPostamble",
							envelopeInfoPtr->extraDataSize + 64 ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		certChainBufPtr = envelopeInfoPtr->auxBuffer;
		certChainBufSize = envelopeInfoPtr->auxBufSize = \
									envelopeInfoPtr->extraDataSize + 64;
		}

	/* Write the end-of-contents octets for the Data OCTET STRING, [0], and 
	   SEQUENCE if necessary */
	if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED )
		{
		status = writeEOCs( envelopeInfoPtr, 3 );
		if( cryptStatusError( status ) )
			return( status );
		}
	envelopeInfoPtr->lastAction = envelopeInfoPtr->postActionList;

	/* Write the signing certificate chain if it's a CMS signature and 
	   they're not explicitly excluded, followed by the SET OF SignerInfo 
	   header */
	sMemOpen( &stream, certChainBufPtr, certChainBufSize );
	if( ( envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
		  envelopeInfoPtr->type == CRYPT_FORMAT_SMIME ) && \
		!( envelopeInfoPtr->flags & ENVELOPE_NOSIGNINGCERTS ) )
		{
		status = exportCertToStream( &stream,
							( envelopeInfoPtr->iExtraCertChain != CRYPT_ERROR ) ? \
							  envelopeInfoPtr->iExtraCertChain : \
							  envelopeInfoPtr->lastAction->iCryptHandle,
							CRYPT_ICERTFORMAT_CERTSET );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		}
	if( envelopeInfoPtr->dataFlags & ENVDATA_HASINDEFTRAILER )
		status = writeSetIndef( &stream );
	else
		status = writeSet( &stream, envelopeInfoPtr->signActionSize );
	if( cryptStatusOK( status ) )
		certChainSize = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're copying data via the auxBuffer flush as much as we can into 
	   the main buffer.  If we can't copy it all in, resulting in an overflow
	   error, we use the OK_SPECIAL status to tell the caller that although
	   an overflow occurred it was due to the auxBuffer copy and not the
	   certificate chain write and it's OK to move on to the next state */
	if( envelopeInfoPtr->auxBufSize > 0 )
		{
		envelopeInfoPtr->auxBufPos = certChainSize;
		status = copyFromAuxBuffer( envelopeInfoPtr );
		return( ( status == CRYPT_ERROR_OVERFLOW ) ? OK_SPECIAL : status );
		}

	/* Since we're in the post-data state any necessary payload data 
	   segmentation has been completed, however the caller can't copy out 
	   any post-payload data because it's past the end-of-segment position.  
	   In order to allow the buffer to be emptied to make room for signature 
	   data we set the end-of-segment position to the end of the new data */
	envelopeInfoPtr->bufPos += certChainSize;
	envelopeInfoPtr->segmentDataEnd = envelopeInfoPtr->bufPos;

	return( CRYPT_OK );
	}

/* Write signatures */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeSignatures( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr;
	int iterationCount, status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Sign each hash using the associated signature key */
	for( actionListPtr = envelopeInfoPtr->lastAction, iterationCount = 0;
		 actionListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED; 
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		SIGPARAMS sigParams;
		const int sigBufSize = min( envelopeInfoPtr->bufSize - \
									envelopeInfoPtr->bufPos, \
									MAX_INTLENGTH_SHORT - 1 );
		int sigSize;

		REQUIRES( actionListPtr->action == ACTION_SIGN );
		ENSURES( sigBufSize >= 0 && sigBufSize < MAX_INTLENGTH_SHORT );

		/* Check whether there's enough room left in the buffer to emit the
		   signature directly into it.  Since signatures are fairly small (a
		   few hundred bytes) we always require enough room in the buffer
		   and don't bother with any overflow handling via the auxBuffer */
		if( actionListPtr->encodedSize + 64 > sigBufSize )
			{
			status = CRYPT_ERROR_OVERFLOW;
			break;
			}

		/* Set up any necessary signature parameters such as signature 
		   attributes and timestamps if necessary */
		status = cmsInitSigParams( actionListPtr, envelopeInfoPtr->type, 
								   envelopeInfoPtr->ownerHandle, 
								   &sigParams );
		if( cryptStatusError( status ) )
			break;

		/* Sign the data */
		REQUIRES( actionListPtr->associatedAction != NULL );
		status = iCryptCreateSignature( envelopeInfoPtr->buffer + \
										envelopeInfoPtr->bufPos, sigBufSize, 
							&sigSize, envelopeInfoPtr->type,
							actionListPtr->iCryptHandle,
							actionListPtr->associatedAction->iCryptHandle,
							( envelopeInfoPtr->type == CRYPT_FORMAT_CRYPTLIB ) ? \
								NULL : &sigParams );
		if( cryptStatusError( status ) )
			break;
		envelopeInfoPtr->bufPos += sigSize;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );
	envelopeInfoPtr->lastAction = actionListPtr;

	return( status );
	}

/* Write MAC value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeMAC( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	STREAM stream;
	MESSAGE_DATA msgData;
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ];
	const int eocSize = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
						( 3 * 2 ) : 0;
	const int dataLeft = min( envelopeInfoPtr->bufSize - \
							  envelopeInfoPtr->bufPos, 512 );
	int length = DUMMY_INIT, status;

	/* Make sure that there's room for the MAC data in the buffer */
	if( dataLeft < eocSize + sizeofObject( CRYPT_MAX_HASHSIZE ) )
		return( CRYPT_ERROR_OVERFLOW );

	/* Write the end-of-contents octets for the Data OCTET STRING, [0], and 
	   SEQUENCE if necessary */
	if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED )
		{
		status = writeEOCs( envelopeInfoPtr, 3 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Get the MAC value and write it to the buffer */
	setMessageData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( envelopeInfoPtr->actionList->iCryptHandle,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	sMemOpen( &stream, envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos, 
			  dataLeft );
	status = writeOctetString( &stream, hash, msgData.length, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	envelopeInfoPtr->bufPos += length;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Emit Envelope Preamble/Postamble				*
*																			*
****************************************************************************/

/* Output as much of the preamble as possible into the envelope buffer */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int emitPreamble( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	int status = CRYPT_OK;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( sanityCheck( envelopeInfoPtr ) );

	/* If we've finished processing the header information, don't do
	   anything */
	if( envelopeInfoPtr->envState == ENVSTATE_DONE )
		return( CRYPT_OK );

	/* If we haven't started doing anything yet perform various final
	   initialisations */
	if( envelopeInfoPtr->envState == ENVSTATE_NONE )
		{
		/* If there's no nested content type set default to plain data */
		if( envelopeInfoPtr->contentType == CRYPT_CONTENT_NONE )
			envelopeInfoPtr->contentType = CRYPT_CONTENT_DATA;

		/* If there's an absolute data length set, remember it for when we
		   copy in data */
		if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
			envelopeInfoPtr->segmentSize = envelopeInfoPtr->payloadSize;

		/* Perform any remaining initialisation.  MAC'd data is a special-
		   case form of encrypted data so we treat them as the same thing
		   at the key exchange level */
		if( envelopeInfoPtr->usage == ACTION_CRYPT || \
			envelopeInfoPtr->usage == ACTION_MAC )
			status = cmsPreEnvelopeEncrypt( envelopeInfoPtr );
		else
			{
			if( envelopeInfoPtr->usage == ACTION_SIGN )
				status = cmsPreEnvelopeSign( envelopeInfoPtr );
			}
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Couldn't perform final %s initialisation prior to "
					  "enveloping data", 
					  ( envelopeInfoPtr->usage == ACTION_SIGN ) ? \
						"signing" : "encryption" ) );
			}

		/* Delete any orphaned actions such as automatically-added hash
		   actions that were overridden with user-supplied alternate
		   actions */
		deleteUnusedActions( envelopeInfoPtr );

		/* Make sure that we start a new segment when we add the first lot
		   of payload data after we've emitted the header info */
		envelopeInfoPtr->dataFlags |= ENVDATA_SEGMENTCOMPLETE;

		/* We're ready to go, prepare to emit the outer header */
		envelopeInfoPtr->envState = ENVSTATE_HEADER;
		
		ENSURES( checkActions( envelopeInfoPtr ) );
		}

	/* Emit the outer header.  This always follows directly from the final
	   initialisation step but we keep the two logically distinct to 
	   emphasise the fact that the former is merely finalising enveloping 
	   actions without performing any header processing while the latter is 
	   the first stage that actually emits header data */
	if( envelopeInfoPtr->envState == ENVSTATE_HEADER )
		{
		status = writeEnvelopeHeader( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			{
			/* If there's nothing else to emit, we're done */
			if( status == OK_SPECIAL )
				{
				envelopeInfoPtr->envState = ENVSTATE_DONE;
				ENSURES( sanityCheck( envelopeInfoPtr ) );

				return( CRYPT_OK );
				}

			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Couldn't create envelope header" ) );
			}

		/* Move on to the next state */
		envelopeInfoPtr->envState = ENVSTATE_KEYINFO;
		}

	/* Handle key export actions */
	if( envelopeInfoPtr->envState == ENVSTATE_KEYINFO )
		{
		status = writeKeyex( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Couldn't emit key exchange actions to envelope "
					  "header" ) );
			}

		/* Move on to the next state */
		envelopeInfoPtr->envState = ENVSTATE_ENCRINFO;
		}

	/* Handle encrypted content information */
	if( envelopeInfoPtr->envState == ENVSTATE_ENCRINFO )
		{
		STREAM stream;
		const BYTE *contentOID = getContentOID( envelopeInfoPtr->contentType );
		const int dataLeft = min( envelopeInfoPtr->bufSize - \
								  envelopeInfoPtr->bufPos, \
								  MAX_INTLENGTH_SHORT - 1 );

		REQUIRES( contentOID != NULL );
		ENSURES( dataLeft >= dataLeft && dataLeft < MAX_INTLENGTH_SHORT );

		/* Make sure that there's enough room to emit the data header.  The
		   value used is only approximate, if there's not enough room left
		   the write will also return an overflow error */
		if( dataLeft < 256 )
			return( CRYPT_ERROR_OVERFLOW );

		/* Write the encrypted content header */
		sMemOpen( &stream, envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
				  dataLeft );
		if( envelopeInfoPtr->usage == ACTION_MAC )
			{
			/* If it's authenticated data, there's a MAC algorithm ID 
			   preceding standard EncapContent */
			status = writeContextAlgoID( &stream, 
										 envelopeInfoPtr->actionList->iCryptHandle,
										 CRYPT_ALGO_NONE );
			if( cryptStatusOK ( status ) )
				{
				status = writeCMSheader( &stream, contentOID, 
										 sizeofOID( contentOID ),
										 envelopeInfoPtr->payloadSize, 
										 TRUE );
				}
			}
		else
			{
			/* It's encrypted data, it's EncrContent */
			status = writeEncryptedContentHeader( &stream, contentOID,
										sizeofOID( contentOID ),
										envelopeInfoPtr->iCryptContext, 
										envelopeInfoPtr->payloadSize, 
										envelopeInfoPtr->blockSize );
			}
		if( cryptStatusOK( status ) )
			envelopeInfoPtr->bufPos += stell( &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Couldn't emit encrypted content header to envelope "
					  "header" ) );
			}

#if 0	/* ?/?/08 Commented out between 3.3.1 and 3.3.2 although there's no 
		   indication why */
		/* Make sure that we start a new segment if we try to add any data */
		envelopeInfoPtr->dataFlags |= ENVDATA_SEGMENTCOMPLETE;
#endif /* 0 */

		/* We're done */
		envelopeInfoPtr->envState = ENVSTATE_DONE;
		}

	ENSURES( sanityCheck( envelopeInfoPtr ) );

	return( CRYPT_OK );
	}

/* Output as much of the postamble as possible into the envelope buffer */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int emitPostamble( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	REQUIRES( sanityCheck( envelopeInfoPtr ) );

	/* Before we can emit the trailer we need to flush any remaining data
	   from internal buffers */
	if( envelopeInfoPtr->envState == ENVSTATE_NONE )
		{
		status = envelopeInfoPtr->copyToEnvelopeFunction( envelopeInfoPtr,
													( BYTE * ) "", 0 );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Couldn't flush remaining data into envelope "
					  "buffer" ) );
			}
		envelopeInfoPtr->envState = \
					( envelopeInfoPtr->usage == ACTION_SIGN ) ? \
					ENVSTATE_FLUSHED : ENVSTATE_SIGNATURE;
		}

	/* The only message type that has a trailer is signed or authenticated 
	   data so if we're not signing/authenticating data we can exit now */
	if( envelopeInfoPtr->usage != ACTION_SIGN && \
		envelopeInfoPtr->usage != ACTION_MAC )
		{
		/* Emit the various end-of-contents octets if necessary */
		if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED || \
			( envelopeInfoPtr->usage == ACTION_CRYPT &&
			  envelopeInfoPtr->cryptActionSize == CRYPT_UNUSED ) )
			{
			/* Write the end-of-contents octets for the encapsulated data if
			   necessary.  Normally we have two EOCs, however compressed 
			   data requires an extra one due to the explicit tagging */
			if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED && \
				( envelopeInfoPtr->usage == ACTION_CRYPT || \
				  envelopeInfoPtr->usage == ACTION_COMPRESS ) )
				{
				status = writeEOCs( envelopeInfoPtr, 3 + \
									( ( envelopeInfoPtr->usage == \
										ACTION_COMPRESS ) ? \
									  3 : 2 ) );
				}
			else
				{
				/* Write the remaining end-of-contents octets for the OCTET
				   STRING/SEQUENCE, [0], and SEQUENCE */
				status = writeEOCs( envelopeInfoPtr, 3 );
				}
			if( cryptStatusError( status ) )
				{
				retExt( status,
						( status, ENVELOPE_ERRINFO,
						  "Couldn't emit final EOC octets" ) );
				}
			}

		/* Now that we've written the final end-of-contents octets, set the end-
		   of-segment-data pointer to the end of the data in the buffer so that
		   copyFromEnvelope() can copy out the remaining data */
		envelopeInfoPtr->segmentDataEnd = envelopeInfoPtr->bufPos;
		envelopeInfoPtr->envState = ENVSTATE_DONE;

		ENSURES( sanityCheck( envelopeInfoPtr ) );

		return( CRYPT_OK );
		}

	/* If there's any signature data left in the auxiliary buffer try and 
	   empty that first */
	if( envelopeInfoPtr->auxBufPos > 0 )
		{
		status = copyFromAuxBuffer( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Couldn't flush remaining signature data into "
					  "envelope buffer" ) );
			}
		}

	/* Handle signing certificate chain */
	if( envelopeInfoPtr->envState == ENVSTATE_FLUSHED )
		{
		status = writeCertchainTrailer( envelopeInfoPtr );
		if( cryptStatusError( status ) && status != OK_SPECIAL )
			{
			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Couldn't emit certificate chain to envelope "
					  "trailer" ) );
			}

		/* Move on to the next state */
		envelopeInfoPtr->envState = ENVSTATE_SIGNATURE;

		/* If we were writing the certificate chain using the auxBuffer as 
		   an intermediate stage because there wasn't enough room to 
		   assemble the complete chain in the main buffer and we then got an
		   overflow error moving the data out into the main buffer we have 
		   to resume later in the signature state */
		if( status == OK_SPECIAL )
			return( CRYPT_ERROR_OVERFLOW );
		}

	/* Handle signing actions */
	REQUIRES( envelopeInfoPtr->envState == ENVSTATE_SIGNATURE );

	/* Write the signatures/MACs */
	if( envelopeInfoPtr->usage == ACTION_SIGN )
		status = writeSignatures( envelopeInfoPtr );
	else
		status = writeMAC( envelopeInfoPtr );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, ENVELOPE_ERRINFO,
				  "Couldn't emit %s to envelope trailer", 
				  ( envelopeInfoPtr->usage == ACTION_SIGN ) ? \
					"signatures" : "MAC" ) );
		}

	/* Write the end-of-contents octets for the OCTET STRING/SEQUENCE, [0],
	   and SEQUENCE if necessary.  If the trailer has an indefinite length
	   then we need to add an EOC for the trailer as well */
	if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED || \
		( envelopeInfoPtr->dataFlags & ENVDATA_HASINDEFTRAILER ) )
		{
		status = writeEOCs( envelopeInfoPtr,
							3 + ( ( envelopeInfoPtr->dataFlags & \
									ENVDATA_HASINDEFTRAILER ) ? \
								  1 : 0 ) );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, ENVELOPE_ERRINFO,
					  "Couldn't emit final EOC octets" ) );
			}
		}

	/* Now that we've written the final end-of-contents octets set the end-
	   of-segment-data pointer to the end of the data in the buffer so that
	   copyFromEnvelope() can copy out the remaining data */
	envelopeInfoPtr->segmentDataEnd = envelopeInfoPtr->bufPos;
	envelopeInfoPtr->envState = ENVSTATE_DONE;

	ENSURES( sanityCheck( envelopeInfoPtr ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Envelope Access Routines						*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initCMSEnveloping( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	int status;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );
	
	REQUIRES_V( !( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) );

	/* Set the access method pointers */
	envelopeInfoPtr->processPreambleFunction = emitPreamble;
	envelopeInfoPtr->processPostambleFunction = emitPostamble;
	envelopeInfoPtr->checkAlgo = cmsCheckAlgo;

	/* Set up the processing state information */
	envelopeInfoPtr->envState = ENVSTATE_NONE;

	/* Remember the current default settings for use with the envelope.
	   We force the use of the CBC encryption mode because this is the
	   safest and most efficient encryption mode, and the only mode defined
	   for many CMS algorithms.  Since the CMS algorithms represent only a
	   subset of what's available we have to drop back to fixed values if
	   the caller has selected something exotic */
	status = krnlSendMessage( envelopeInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE,
							  &envelopeInfoPtr->defaultHash, 
							  CRYPT_OPTION_ENCR_HASH );
	if( cryptStatusError( status ) || \
		!checkAlgoID( envelopeInfoPtr->defaultHash, CRYPT_MODE_NONE ) )
		envelopeInfoPtr->defaultHash = CRYPT_ALGO_SHA1;
	status = krnlSendMessage( envelopeInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE,
							  &envelopeInfoPtr->defaultAlgo, 
							  CRYPT_OPTION_ENCR_ALGO );
	if( cryptStatusError( status ) || \
		!checkAlgoID( envelopeInfoPtr->defaultAlgo,
					  ( envelopeInfoPtr->defaultAlgo == CRYPT_ALGO_RC4 ) ? \
					  CRYPT_MODE_OFB : CRYPT_MODE_CBC ) )
		envelopeInfoPtr->defaultAlgo = CRYPT_ALGO_3DES;
	status = krnlSendMessage( envelopeInfoPtr->ownerHandle, 
							  IMESSAGE_GETATTRIBUTE,
							  &envelopeInfoPtr->defaultMAC, 
							  CRYPT_OPTION_ENCR_MAC );
	if( cryptStatusError( status ) || \
		!checkAlgoID( envelopeInfoPtr->defaultMAC, CRYPT_MODE_NONE ) )
		envelopeInfoPtr->defaultMAC = CRYPT_ALGO_HMAC_SHA;
	}
#endif /* USE_ENVELOPES */
