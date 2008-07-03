/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Crypto Routines						*
*					 Copyright Peter Gutmann 1998-2008						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssl.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/ssl.h"
#endif /* Compiler-specific includes */

/* Proto-HMAC padding data */

#define PROTOHMAC_PAD1_VALUE	0x36
#define PROTOHMAC_PAD2_VALUE	0x5C
#define PROTOHMAC_PAD1			"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36"
#define PROTOHMAC_PAD2			"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C"

#ifdef USE_SSL

/****************************************************************************
*																			*
*							Encrypt/Decrypt Functions						*
*																			*
****************************************************************************/

/* Encrypt/decrypt a data block */

int encryptData( const SESSION_INFO *sessionInfoPtr, BYTE *data,
				 const int dataMaxLength, int *dataLength,
				 const int payloadLength )
	{
	int length = payloadLength, status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( payloadLength > 0 && \
			payloadLength <= MAX_PACKET_SIZE + 20 && \
			payloadLength < sessionInfoPtr->sendBufSize && \
			payloadLength < dataMaxLength );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	/* Sanity-check the state */
	if( payloadLength <= 0 || \
		payloadLength > MAX_PACKET_SIZE + 20 || \
		payloadLength >= sessionInfoPtr->sendBufSize || \
		payloadLength >= dataMaxLength )
		retIntError();

	/* Clear return value */
	*dataLength = 0;

	/* If it's a block cipher, we need to add end-of-block padding */
	if( sessionInfoPtr->cryptBlocksize > 1 )
		{
		BYTE *dataPadPtr = data + payloadLength;
		const int padSize = ( sessionInfoPtr->cryptBlocksize - 1 ) - \
						    ( payloadLength & ( sessionInfoPtr->cryptBlocksize - 1 ) );
		int i;

		/* Make sure that there's room to add the padding */
		if( padSize < 0 || length + padSize + 1 > dataMaxLength ) 
			retIntError();

		/* Add the PKCS #5-style padding (PKCS #5 uses n, TLS uses n-1) */
		for( i = 0; i < padSize + 1; i++ )
			*dataPadPtr++ = padSize;
		length += padSize + 1;
		}

	/* Encrypt the data and optional padding */
	status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_CTX_ENCRYPT, data, length );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = length;

	return( CRYPT_OK );
	}

int decryptData( SESSION_INFO *sessionInfoPtr, BYTE *data,
				 const int dataLength, int *processedDataLength )
	{
	int length = dataLength, padSize, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( dataLength > 0 && dataLength <= sessionInfoPtr->receiveBufEnd );
	assert( isWritePtr( data, dataLength ) );
	assert( isWritePtr( processedDataLength, sizeof( int ) ) );

	/* Sanity-check the state */
	if( dataLength <= 0 || dataLength > sessionInfoPtr->receiveBufEnd )
		retIntError();

	/* Clear return value */
	*processedDataLength = 0;

	/* Decrypt the data */
	status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
							  IMESSAGE_CTX_DECRYPT, data, length );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Packet decryption failed" ) );
		}

	/* If it's a stream cipher there's no padding present */
	if( sessionInfoPtr->cryptBlocksize <= 1 )
		{
		*processedDataLength = length;

		return( CRYPT_OK );
		}

	/* If it's a block cipher, we need to remove end-of-block padding.  Up
	   until TLS 1.1 the spec was silent about any requirement to check the
	   padding (and for SSLv3 it didn't specify the padding format at all)
	   so it's not really safe to reject an SSL message if we don't find the
	   correct padding because many SSL implementations didn't process the
	   padded space in any way, leaving it containing whatever was there
	   before (which can include old plaintext (!!)).  Almost all TLS
	   implementations get it right (even though in TLS 1.0 there was only a
	   requirement to generate, but not to check, the PKCS #5-style padding).
	   Because of this we only check the padding bytes if we're talking
	   TLS.

	   First we make sure that the padding info looks OK.  TLS allows up to 
	   256 bytes of padding (only GnuTLS actually seems to use this 
	   capability though) so we can't check for a sensible (small) padding 
	   length, however we can check this for SSL, which is good because for 
	   that we can't check the padding itself */
	padSize = data[ dataLength - 1 ];
	if( padSize < 0 || \
		( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL && \
		  padSize > sessionInfoPtr->cryptBlocksize - 1 ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid encryption padding value 0x%02X", padSize ) );
		}
	length -= padSize + 1;
	if( length < 0 )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Encryption padding adjustment value %d is greater "
				  "than packet length %d", padSize, dataLength ) );
		}

	/* Check for PKCS #5-type padding (PKCS #5 uses n, TLS uses n-1) if 
	   necessary */
	if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS )
		{
		int i;

		for( i = 0; i < padSize; i++ )
			{
			if( data[ length + i ] != padSize )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid encryption padding byte 0x%02X at "
						  "position %d, should be 0x%02X",
						  data[ length + i ], length + i, padSize ) );
				}
			}
		}
	*processedDataLength = length;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								SSL MAC Functions							*
*																			*
****************************************************************************/

/* Perform an SSL MAC of a data block.  We have to provide special-case 
   handling of zero-length blocks since some versions of OpenSSL send these 
   as a kludge in SSL/TLS 1.0 to work around chosen-IV attacks */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 6 ) ) \
static int macDataSSL( const CRYPT_CONTEXT iHashContext, 
					   const CRYPT_ALGO_TYPE hashAlgo,
					   IN_BUFFER( macSecretLength ) \
					   const void *macSecret, const int macSecretLength,
					   const long seqNo, 
					   IN_BUFFER( dataLength ) \
					   const void *data, const int dataLength, 
					   const int type )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE buffer[ 128 + 8 ];
	const int padSize = ( hashAlgo == CRYPT_ALGO_MD5 ) ? 48 : 40;
	int length = DUMMY_INIT, status;

	assert( isHandleRangeValid( iHashContext ) );
	assert( isReadPtr( macSecret, macSecretLength ) );
	assert( seqNo >= 0 );
	assert( isReadPtr( data, dataLength ) );
	assert( dataLength >= 0 && dataLength <= MAX_PACKET_SIZE );

	/* Set up the sequence number and length data */
	memset( buffer, PROTOHMAC_PAD1_VALUE, padSize );
	sMemOpen( &stream, buffer + padSize, 128 - padSize );
	writeUint64( &stream, seqNo );
	sputc( &stream, type );
	status = writeUint16( &stream, dataLength );
	if( cryptStatusOK( status ) )
		length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Reset the hash context and generate the inner portion of the MAC:

		hash( MAC_secret || pad1 || seq_num || type || length || data ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) macSecret,
					 macSecretLength );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer,
					 padSize + length );
	if( dataLength > 0 )
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) data,
						 dataLength );
	status = krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* Extract the inner hash value */
	memset( buffer, PROTOHMAC_PAD2_VALUE, padSize );
	setMessageData( &msgData, buffer + padSize, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iHashContext, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the outer portion of the handshake message's MAC:

		hash( MAC_secret || pad2 || inner_hash ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) macSecret,
					 macSecretLength );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer,
					 padSize + msgData.length );
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 ) );
	}

int createMacSSL( SESSION_INFO *sessionInfoPtr, void *data,
				  const int dataMaxLength, int *dataLength,
				  const int payloadLength, const int type )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );
	assert( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE && \
			payloadLength + sessionInfoPtr->authBlocksize <= dataMaxLength );

	/* Sanity-check the state */
	if( payloadLength < 0 || payloadLength > MAX_PACKET_SIZE || \
		payloadLength + sessionInfoPtr->authBlocksize > dataMaxLength )
		retIntError();

	/* Clear return value */
	*dataLength = 0;

	/* MAC the payload */
	status = macDataSSL( sessionInfoPtr->iAuthOutContext, 
						 sessionInfoPtr->integrityAlgo,
						 sslInfo->macWriteSecret, 
						 sessionInfoPtr->authBlocksize, sslInfo->writeSeqNo,
						 data, payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	sslInfo->writeSeqNo++;

	/* Set the MAC value at the end of the packet */
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthOutContext, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = payloadLength + msgData.length;

	return( CRYPT_OK );
	}

int checkMacSSL( SESSION_INFO *sessionInfoPtr, const void *data,
				 const int dataLength, const int payloadLength,
				 const int type, const BOOLEAN noReportError )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, dataLength ) );
	assert( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE && \
			payloadLength + sessionInfoPtr->authBlocksize <= dataLength );

	/* Sanity-check the state */
	if( payloadLength < 0 || payloadLength > MAX_PACKET_SIZE || \
		payloadLength + sessionInfoPtr->authBlocksize > dataLength )
		retIntError();

	/* MAC the payload */
	status = macDataSSL( sessionInfoPtr->iAuthInContext, 
						 sessionInfoPtr->integrityAlgo,
						 sslInfo->macReadSecret, 
						 sessionInfoPtr->authBlocksize, sslInfo->readSeqNo,
						 data, payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	sslInfo->readSeqNo++;

	/* Compare the calculated MAC to the MAC present at the end of the 
	   data */
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
							  IMESSAGE_COMPARE, &msgData, 
							  MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		{
		/* If the error message has already been set at a higher level, 
		   don't update the error info */
		if( noReportError )
			return( CRYPT_ERROR_SIGNATURE );

		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad message MAC for packet type %d, length %d",
				  type, dataLength ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								TLS MAC Functions							*
*																			*
****************************************************************************/

/* Perform a TLS MAC of a data block.  We have to provide special-case 
   handling of zero-length blocks since some versions of OpenSSL send these 
   as a kludge in SSL/TLS 1.0 to work around chosen-IV attacks */

CHECK_RETVAL STDC_NONNULL_ARG( ( 4 ) ) \
static int macDataTLS( const CRYPT_CONTEXT iHashContext, const long seqNo, 
					   const int version,
					   IN_BUFFER( dataLength ) \
					   const void *data, const int dataLength, 
					   const int type )
	{
	STREAM stream;
	BYTE buffer[ 64 + 8 ];
	int length = DUMMY_INIT, status;

	assert( isHandleRangeValid( iHashContext ) );
	assert( seqNo >= 0 );
	assert( version >= 1 );
	assert( isReadPtr( data, dataLength ) );
	assert( dataLength >= 0 && dataLength <= MAX_PACKET_SIZE );

	/* Set up the sequence number, type, version, and length data */
	sMemOpen( &stream, buffer, 64 );
	writeUint64( &stream, seqNo );
	sputc( &stream, type );
	sputc( &stream, SSL_MAJOR_VERSION );
	sputc( &stream, version );
	status = writeUint16( &stream, dataLength );
	if( cryptStatusOK( status ) )
		length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Reset the hash context and generate the MAC:

		HMAC( seq_num || type || version || length || data ) */
	krnlSendMessage( iHashContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer, length );
	if( dataLength > 0 )
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, ( void * ) data,
						 dataLength );
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 ) );
	}

int createMacTLS( SESSION_INFO *sessionInfoPtr, void *data,
				  const int dataMaxLength, int *dataLength,
				  const int payloadLength, const int type )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );
	assert( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE && \
			payloadLength + sessionInfoPtr->authBlocksize <= dataMaxLength );

	/* Sanity-check the state */
	if( payloadLength < 0 || payloadLength > MAX_PACKET_SIZE || \
		payloadLength + sessionInfoPtr->authBlocksize > dataMaxLength )
		retIntError();

	/* Clear return value */
	*dataLength = 0;

	/* MAC the payload */
	status = macDataTLS( sessionInfoPtr->iAuthOutContext, sslInfo->writeSeqNo,
						 sessionInfoPtr->version, data, payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	sslInfo->writeSeqNo++;

	/* Set the MAC value at the end of the packet */
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthOutContext, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = payloadLength + msgData.length;

	return( CRYPT_OK );
	}

int checkMacTLS( SESSION_INFO *sessionInfoPtr, const void *data,
				 const int dataLength, const int payloadLength,
				 const int type, const BOOLEAN noReportError )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, dataLength ) );
	assert( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE && \
			payloadLength + sessionInfoPtr->authBlocksize <= dataLength );

	/* Sanity-check the state */
	if( payloadLength < 0 || payloadLength > MAX_PACKET_SIZE || \
		payloadLength + sessionInfoPtr->authBlocksize > dataLength )
		retIntError();

	/* MAC the payload */
	status = macDataTLS( sessionInfoPtr->iAuthInContext, sslInfo->readSeqNo,
						 sessionInfoPtr->version, data, payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	sslInfo->readSeqNo++;

	/* Compare the calculated MAC to the MAC present at the end of the 
	   data */
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
							  IMESSAGE_COMPARE, &msgData, 
							  MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		{
		/* If the error message has already been set at a higher level, 
		   don't update the error info */
		if( noReportError )
			return( CRYPT_ERROR_SIGNATURE );

		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad message MAC for packet type %d, length %d",
				  type, dataLength ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Dual-MAC Functions							*
*																			*
****************************************************************************/

/* Perform a dual MAC of a data block */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int dualMacData( const SSL_HANDSHAKE_INFO *handshakeInfo,
						IN_BUFFER( dataLength ) \
						const void *data, const int dataLength )
	{
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( data, dataLength ) );

	status = krnlSendMessage( handshakeInfo->clientMD5context,
							  IMESSAGE_CTX_HASH, ( void * ) data,
							  dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->clientSHA1context,
								  IMESSAGE_CTX_HASH, ( void * ) data,
								  dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->serverMD5context,
								  IMESSAGE_CTX_HASH, ( void * ) data,
								  dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->serverSHA1context,
								  IMESSAGE_CTX_HASH, ( void * ) data,
								  dataLength );
	return( status );
	}

int dualMacDataRead( const SSL_HANDSHAKE_INFO *handshakeInfo,
					 STREAM *stream )
	{
	const int dataLength = sMemDataLeft( stream );
	void *data;
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( dataLength > 0 );

	/* On a read we've just processed the packet header and everything 
	   that's left in the stream is the data to be MACd */
	status = sMemGetDataBlock( stream, &data, dataLength );
	if( cryptStatusOK( status ) )
		status = dualMacData( handshakeInfo, data, dataLength );
	return( status );
	}

int dualMacDataWrite( const SSL_HANDSHAKE_INFO *handshakeInfo,
					  STREAM *stream )
	{
	const int dataLength = stell( stream ) - SSL_HEADER_SIZE;
	void *data;
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( stream, sizeof( STREAM ) ) );
	assert( dataLength > 0 );

	/* On a write we've just finished writing the packet and everything but
	   the header needs to be MACd */
	status = sMemGetDataBlockAbs( stream, SSL_HEADER_SIZE, &data, 
								  dataLength );
	if( cryptStatusOK( status ) )
		status = dualMacData( handshakeInfo, data, dataLength );
	return( status );
	}

/* Complete the dual MD5/SHA1 hash/MAC used in the finished message */

int completeSSLDualMAC( const CRYPT_CONTEXT md5context,
						const CRYPT_CONTEXT sha1context, 
						BYTE *hashValues, const int hashValuesMaxLen,
						int *hashValuesLen, const char *label, 
						const int labelLength, const BYTE *masterSecret, 
						const int masterSecretLen )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isHandleRangeValid( md5context ) );
	assert( isHandleRangeValid( sha1context ) );
	assert( isWritePtr( hashValues, hashValuesMaxLen ) );
	assert( isWritePtr( hashValuesLen, sizeof( int ) ) );
	assert( isReadPtr( label, labelLength ) );
	assert( isReadPtr( masterSecret, masterSecretLen ) );
	assert( hashValuesMaxLen >= MD5MAC_SIZE + SHA1MAC_SIZE );

	/* Clear return value */
	*hashValuesLen = 0;

	/* Generate the inner portion of the handshake message's MAC:

		hash( handshake_messages || cl/svr_label || master_secret || pad1 ).

	   Note that the SHA-1 pad size is 40 bytes and not 44 (to get a total
	   length of 64 bytes), this is due to an error in the spec */
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, ( void * ) label, 
					 labelLength );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, ( void * ) label,
					 labelLength );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, ( void * ) masterSecret,
					 masterSecretLen );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, ( void * ) masterSecret,
					 masterSecretLen );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, PROTOHMAC_PAD1, 48 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, PROTOHMAC_PAD1, 40 );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, "", 0 );
	setMessageData( &msgData, hashValues, MD5MAC_SIZE );
	status = krnlSendMessage( md5context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hashValues + MD5MAC_SIZE, SHA1MAC_SIZE );
		status = krnlSendMessage( sha1context, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Reset the hash contexts */
	krnlSendMessage( md5context, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( sha1context, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_HASHVALUE );

	/* Generate the outer portion of the handshake message's MAC:

		hash( master_secret || pad2 || inner_hash ) */
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, ( void * ) masterSecret,
					 masterSecretLen );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, ( void * ) masterSecret,
					 masterSecretLen );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, PROTOHMAC_PAD2, 48 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, PROTOHMAC_PAD2, 40 );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, hashValues,
					 MD5MAC_SIZE );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, hashValues + MD5MAC_SIZE,
					 SHA1MAC_SIZE );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, "", 0 );
	setMessageData( &msgData, hashValues, MD5MAC_SIZE );
	status = krnlSendMessage( md5context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, hashValues + MD5MAC_SIZE, SHA1MAC_SIZE );
	status = krnlSendMessage( sha1context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		*hashValuesLen = MD5MAC_SIZE + SHA1MAC_SIZE;
	return( status );
	}

int completeTLSHashedMAC( const CRYPT_CONTEXT md5context,
						  const CRYPT_CONTEXT sha1context, 
						  BYTE *hashValues, const int hashValuesMaxLen,
						  int *hashValuesLen, const char *label, 
						  const int labelLength, const BYTE *masterSecret, 
						  const int masterSecretLen )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	BYTE hashBuffer[ 64 + ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	int status;

	assert( isHandleRangeValid( md5context ) );
	assert( isHandleRangeValid( sha1context ) );
	assert( isWritePtr( hashValues, hashValuesMaxLen ) );
	assert( isWritePtr( hashValuesLen, sizeof( int ) ) );
	assert( isReadPtr( label, labelLength ) );
	assert( isReadPtr( masterSecret, masterSecretLen ) );
	assert( hashValuesMaxLen >= TLS_HASHEDMAC_SIZE );
	assert( labelLength <= 64 && \
			labelLength + MD5MAC_SIZE + SHA1MAC_SIZE <= \
				64 + ( CRYPT_MAX_HASHSIZE * 2 ) );

	/* Clear return value */
	*hashValuesLen = 0;

	memcpy( hashBuffer, label, labelLength );

	/* Complete the hashing and get the MD5 and SHA-1 hashes */
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, "", 0 );
	setMessageData( &msgData, hashBuffer + labelLength, MD5MAC_SIZE );
	status = krnlSendMessage( md5context, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, hashBuffer + labelLength + MD5MAC_SIZE,
						SHA1MAC_SIZE );
		status = krnlSendMessage( sha1context, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the TLS check value.  This isn't really a hash or a MAC, but
	   is generated by feeding the MD5 and SHA1 hashes of the handshake
	   messages into the TLS key derivation (PRF) function and truncating
	   the result to 12 bytes (96 bits) for no adequately explored reason,
	   most probably it's IPsec cargo cult protocol design:

		TLS_PRF( label || MD5_hash || SHA1_hash ) */
	setMechanismDeriveInfo( &mechanismInfo, hashValues, TLS_HASHEDMAC_SIZE,
							( void * ) masterSecret, masterSecretLen, 
							CRYPT_USE_DEFAULT, hashBuffer, 
							labelLength + MD5MAC_SIZE + SHA1MAC_SIZE, 1 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_DERIVE,
							  &mechanismInfo, MECHANISM_DERIVE_TLS );
	if( cryptStatusOK( status ) )
		*hashValuesLen = TLS_HASHEDMAC_SIZE;
	return( status );
	}

/****************************************************************************
*																			*
*							Signature Functions								*
*																			*
****************************************************************************/

/* Create/check the signature on an SSL certificate verify message.
   SSLv3/TLS use a weird signature format that dual-MACs (SSLv3) or hashes
   (TLS) all of the handshake messages exchanged to date (SSLv3 additionally
   hashes in further data like the master secret), then signs them using
   nonstandard PKCS #1 RSA without the ASN.1 wrapper (that is, it uses the
   private key to encrypt the concatenated SHA-1 and MD5 MAC or hash of the
   handshake messages with PKCS #1 padding prepended), unless we're using
   DSA in which case it drops the MD5 MAC/hash and uses only the SHA-1 one.
   This is an incredible pain to support because it requires running a
   parallel hash of handshake messages that terminates before the main
   hashing does, further hashing/MAC'ing of additional data, and the use of
   weird nonstandard data formats and signature mechanisms that aren't
   normally supported by anything.  For example if the signing is to be done
   via a smart card then we can't use the standard PKCS #1 sig mechanism, we
   can't even use raw RSA and kludge the format together ourselves because
   some PKCS #11 implementations don't support the _X509 (raw) mechanism,
   what we have to do is tunnel the nonstandard sig.format info down through
   several cryptlib layers and then hope that the PKCS #11 implementation
   that we're using (a) supports this format and (b) gets it right.  Another
   problem (which only occurs for SSLv3) is that the MAC requires the use of
   the master secret, which isn't available for several hundred more lines
   of code, so we have to delay producing any more data packets until the
   master secret is available, which severely screws up the handshake
   processing flow.

   The chances of all of this working correctly are fairly low, and in any
   case there's no advantage to the weird mechanism and format used in
   SSL/TLS, all we actually need to do is sign the client and server nonces
   to ensure signature freshness.  Because of this what we actually do is
   just this, after which we create a standard PKCS #1 signature via the
   normal cryptlib mechanisms, which guarantees that it'll work with native
   cryptlib as well as any crypto hardware implementation.  Since client
   certs are hardly ever used and when they are it's in a closed environment,
   it's extremely unlikely that anyone will ever notice.  There'll be far
   more problems in trying to use the nonstandard SSL/TLS signature mechanism
   than there are with using a standard (but not-in-the-spec) one */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static CRYPT_CONTEXT createCertVerifyHash( const SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* Hash the client and server nonces */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA1 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	memcpy( nonceBuffer, "certificate verify", 18 );
	memcpy( nonceBuffer + 18, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	memcpy( nonceBuffer + 18 + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
			SSL_NONCE_SIZE );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
					 nonceBuffer, 18 + SSL_NONCE_SIZE + SSL_NONCE_SIZE );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
					 nonceBuffer, 0 );

	return( createInfo.cryptHandle );
	}

int createCertVerify( const SESSION_INFO *sessionInfoPtr,
					  const SSL_HANDSHAKE_INFO *handshakeInfo,
					  STREAM *stream )
	{
	CRYPT_CONTEXT iHashContext;
	void *dataPtr;
	int dataLength, length = DUMMY_INIT, status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Create the hash of the data to sign */
	iHashContext = createCertVerifyHash( handshakeInfo );
	if( cryptStatusError( iHashContext ) )
		return( iHashContext );

	/* Create the signature.  The reason for the min() part of the
	   expression is that iCryptCreateSignature() gets suspicious of very
	   large buffer sizes, for example when the user has specified the use
	   of a huge send buffer */
	status = sMemGetDataBlockRemaining( stream, &dataPtr, &dataLength );
	if( cryptStatusOK( status ) )
		{
		status = iCryptCreateSignature( dataPtr, 
										min( dataLength, \
											 MAX_INTLENGTH_SHORT - 1 ),
										&length, CRYPT_FORMAT_CRYPTLIB,
										sessionInfoPtr->privateKey,
										iHashContext, CRYPT_UNUSED,
										CRYPT_UNUSED );
		}
	if( cryptStatusOK( status ) )
		status = sSkip( stream, length );
	krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

int checkCertVerify( const SESSION_INFO *sessionInfoPtr,
					 const SSL_HANDSHAKE_INFO *handshakeInfo,
					 STREAM *stream, const int sigLength )
	{
	CRYPT_CONTEXT iHashContext;
	void *dataPtr;
	int status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sigLength > MIN_CRYPT_OBJECTSIZE );

	/* Create the hash of the data to sign */
	iHashContext = createCertVerifyHash( handshakeInfo );
	if( cryptStatusError( iHashContext ) )
		return( iHashContext );

	/* Verify the signature.  The reason for the min() part of the
	   expression is that iCryptCheckSignature() gets suspicious of very
	   large buffer sizes, for example when the user has specified the use
	   of a huge send buffer */
	status = sMemGetDataBlock( stream, &dataPtr, sigLength );
	if( cryptStatusOK( status ) )
		{
		status = iCryptCheckSignature( dataPtr, 
									   min( sigLength, \
											MAX_INTLENGTH_SHORT - 1 ), 
									   CRYPT_FORMAT_CRYPTLIB, 
									   sessionInfoPtr->iKeyexAuthContext,
									   iHashContext, CRYPT_UNUSED, NULL );
		}
	krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Create/check the signature on the server key data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
static int createKeyexHashes( const SSL_HANDSHAKE_INFO *handshakeInfo,
							  IN_BUFFER( keyDataLength ) \
							  const void *keyData, const int keyDataLength,
							  OUT CRYPT_CONTEXT *md5Context,
							  OUT CRYPT_CONTEXT *shaContext )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE nonceBuffer[ SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( keyData, keyDataLength ) );
	assert( isWritePtr( md5Context, sizeof( CRYPT_CONTEXT ) ) );
	assert( isWritePtr( shaContext, sizeof( CRYPT_CONTEXT ) ) );

	/* Clear return values */
	*md5Context = *shaContext = CRYPT_ERROR;

	/* Create the dual hash contexts */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_MD5 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	*md5Context = createInfo.cryptHandle;
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA1 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( *md5Context, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*shaContext = createInfo.cryptHandle;

	/* Hash the client and server nonces and key data */
	memcpy( nonceBuffer, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	memcpy( nonceBuffer + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
			SSL_NONCE_SIZE );
	krnlSendMessage( *md5Context, IMESSAGE_CTX_HASH,
					 nonceBuffer, SSL_NONCE_SIZE + SSL_NONCE_SIZE );
	krnlSendMessage( *shaContext, IMESSAGE_CTX_HASH,
					 nonceBuffer, SSL_NONCE_SIZE + SSL_NONCE_SIZE );
	krnlSendMessage( *md5Context, IMESSAGE_CTX_HASH,
					 ( void * ) keyData, keyDataLength );
	krnlSendMessage( *shaContext, IMESSAGE_CTX_HASH,
					 ( void * ) keyData, keyDataLength );
	krnlSendMessage( *md5Context, IMESSAGE_CTX_HASH,
					 nonceBuffer, 0 );
	krnlSendMessage( *shaContext, IMESSAGE_CTX_HASH,
					 nonceBuffer, 0 );

	return( CRYPT_OK );
	}

int createKeyexSignature( SESSION_INFO *sessionInfoPtr,
						  SSL_HANDSHAKE_INFO *handshakeInfo,
						  STREAM *stream, const void *keyData,
						  const int keyDataLength )
	{
	CRYPT_CONTEXT md5Context, shaContext;
	void *dataPtr;
	int dataLength, sigLength = DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( keyData, keyDataLength ) );

	/* Hash the data to be signed */
	status = createKeyexHashes( handshakeInfo, keyData, keyDataLength,
								&md5Context, &shaContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Sign the hashes.  The reason for the min() part of the expression is
	   that iCryptCreateSignature() gets suspicious of very large buffer
	   sizes, for example when the user has specified the use of a huge send
	   buffer */
	status = sMemGetDataBlockRemaining( stream, &dataPtr, &dataLength );
	if( cryptStatusOK( status ) )
		{
		status = iCryptCreateSignature( dataPtr, 
										min( dataLength, \
											 MAX_INTLENGTH_SHORT - 1 ), 
										&sigLength, CRYPT_IFORMAT_SSL, 
										sessionInfoPtr->privateKey,
										md5Context, shaContext, 
										CRYPT_UNUSED );
		}
	if( cryptStatusOK( status ) )
		status = sSkip( stream, sigLength );

	/* Clean up */
	krnlSendNotifier( md5Context, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

int checkKeyexSignature( SESSION_INFO *sessionInfoPtr,
						 SSL_HANDSHAKE_INFO *handshakeInfo,
						 STREAM *stream, const void *keyData,
						 const int keyDataLength )
	{
	CRYPT_CONTEXT md5Context, shaContext;
	void *dataPtr;
	int dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( keyData, keyDataLength ) );

	/* Make sure that there's enough data present for at least a minimal-
	   length signature */
	if( sMemDataLeft( stream ) < MIN_PKCSIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Hash the data to be signed */
	status = createKeyexHashes( handshakeInfo, keyData, keyDataLength,
								&md5Context, &shaContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Check the signature on the hashes.  The reason for the min() part of
	   the expression is that iCryptCreateSignature() gets suspicious of
	   very large buffer sizes, for example when the user has specified the
	   use of a huge send buffer */
	status = sMemGetDataBlockRemaining( stream, &dataPtr, &dataLength );
	if( cryptStatusOK( status ) )
		{
		status = iCryptCheckSignature( dataPtr, 
									   min( dataLength, \
											MAX_INTLENGTH_SHORT - 1 ),
									   CRYPT_IFORMAT_SSL,
									   sessionInfoPtr->iKeyexCryptContext,
									   md5Context, shaContext, NULL );
		}
	if( cryptStatusOK( status ) )
		status = readUniversal16( stream );

	/* Clean up */
	krnlSendNotifier( md5Context, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}
#endif /* USE_SSL */
