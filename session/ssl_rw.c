/****************************************************************************
*																			*
*				cryptlib SSL v3/TLS Session Read/Write Routines				*
*					   Copyright Peter Gutmann 1998-2008					*
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

#ifdef USE_SSL

/****************************************************************************
*																			*
*								Legacy SSLv2 Functions						*
*																			*
****************************************************************************/

#if 0	/* 28/01/08 Disabled since it's now finally removed in MSIE and 
		   Firefox */

/* Handle a legacy SSLv2 client hello:

	uint16	length code = { 0x80, len }
	byte	type = SSL_HAND_CLIENT_HELLO
	byte[2]	vers = { 0x03, 0x0n } */

static int handleSSLv2Header( SESSION_INFO *sessionInfoPtr, 
							  SSL_HANDSHAKE_INFO *handshakeInfo, 
							  const BYTE *bufPtr )
	{
	STREAM stream;
	int length, value, status;

	assert( bufPtr[ 0 ] == SSL_MSG_V2HANDSHAKE );

	/* Make sure that the length is in order.  Beyond the header we need at 
	   least the three 16-bit field lengths, one 24-bit cipher suite, and at 
	   least 16 bytes of nonce */
	bufPtr++;			/* Skip SSLv2 length ID, already checked by caller */
	length = *bufPtr++;
	if( length < ID_SIZE + VERSIONINFO_SIZE + \
				 ( UINT16_SIZE * 3 ) + 3 + 16 || \
		length > sessionInfoPtr->receiveBufSize )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid legacy SSLv2 hello packet length %d", length ) );
		}

	/* Due to the different ordering of header fields in SSLv2, the type and 
	   version is regarded as part of the payload that needs to be 
	   hashed, rather than the header as for SSLv3 */
	sMemConnect( &stream, bufPtr, ID_SIZE + VERSIONINFO_SIZE );
	status = dualMacDataRead( handshakeInfo, &stream );
	if( cryptStatusError( status ) )
		retIntError();
	value = sgetc( &stream );
	if( value != SSL_HAND_CLIENT_HELLO )
		{
		sMemDisconnect( &stream );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Unexpected legacy SSLv2 packet type %d, should be %d", 
				  value, SSL_HAND_CLIENT_HELLO ) );
		}
	status = processVersionInfo( sessionInfoPtr, &stream, 
								 &handshakeInfo->clientOfferedVersion );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	length -= stell( &stream );
	sMemDisconnect( &stream );

	/* Read the packet payload */
	status = sread( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 
					length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  &sessionInfoPtr->errorInfo );
		return( status );
		}
	if( status < length )
		{
		/* If we timed out during the handshake phase, treat it as a hard 
		   timeout error */
		retExt( CRYPT_ERROR_TIMEOUT,
				( CRYPT_ERROR_TIMEOUT, SESSION_ERRINFO, 
				  "Timeout during legacy SSLv2 hello packet read, only got "
				  "%d of %d bytes", status, length ) );
		}
	sessionInfoPtr->receiveBufPos = 0;
	sessionInfoPtr->receiveBufEnd = length;
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = dualMacDataRead( handshakeInfo, &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		retIntError();

	/* SSLv2 puts the version info in the header, so we set the SSLv2 flag 
	   in the handshake info to ensure that it doesn't get confused with a 
	   normal SSL packet type */
	handshakeInfo->isSSLv2 = TRUE;

	return( length );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							Read Packet Utility Functions					*
*																			*
****************************************************************************/

/* Process version information */

int processVersionInfo( SESSION_INFO *sessionInfoPtr, STREAM *stream,
						int *clientVersion )
	{
	int version;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( clientVersion == NULL || \
			isWritePtr( clientVersion, sizeof( int ) ) );

	/* Clear return value */
	if( clientVersion != NULL )
		*clientVersion = CRYPT_ERROR;

	/* Check the major version number */
	version = sgetc( stream );
	if( version != SSL_MAJOR_VERSION )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid major version number %d, should be 3", version ) );
		}

	/* Check the minor version number.  If we've already got the version
	   established, make sure that it matches the existing one, otherwise
	   determine which version we'll be using */
	version = sgetc( stream );
	if( clientVersion == NULL )
		{
		if( version != sessionInfoPtr->version )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid version number 3.%d, should be 3.%d", 
					  version, sessionInfoPtr->version ) );
			}
		return( CRYPT_OK );
		}
	switch( version )
		{
		case SSL_MINOR_VERSION_SSL:
			/* If the other side can't do TLS, fall back to SSL */
			if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS )
				sessionInfoPtr->version = SSL_MINOR_VERSION_SSL;
			break;

		case SSL_MINOR_VERSION_TLS:
			/* If the other side can't do TLS 1.1, fall back to TLS 1.0 */
			if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS11 )
				sessionInfoPtr->version = SSL_MINOR_VERSION_TLS;
			break;

		case SSL_MINOR_VERSION_TLS11:
			/* If the other side can't do TLS 1.2, fall back to TLS 1.1 */
			if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS12 )
				sessionInfoPtr->version = SSL_MINOR_VERSION_TLS11;
			break;

		case SSL_MINOR_VERSION_TLS12:
			/* If the other side can't do post-TLS 1.2, fall back to 
			   TLS 1.2 */
			if( sessionInfoPtr->version > SSL_MINOR_VERSION_TLS12 )
				sessionInfoPtr->version = SSL_MINOR_VERSION_TLS12;
			break;

		default:
			/* If we're the server and the client has offered a vaguely 
			   sensible version, fall back to the highest version that we
			   support */
			if( isServer( sessionInfoPtr ) && version <= 5 )
				{
				sessionInfoPtr->version = SSL_MINOR_VERSION_TLS11;
				break;
				}

			/* It's nothing that we can handle */
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid protocol version 3.%d", version ) );
		}

	*clientVersion = version;
	return( CRYPT_OK );
	}

/* Check that the header of an SSL packet is in order:

	byte	type
	byte[2]	vers = { 0x03, 0x0n }
	uint16	length
  [ byte[]	iv	- TLS 1.1 ]

  If this is the initial hello packet we request a dummy version info read 
  since the peer's version isn't known yet at this point.  The actual 
  version info is taken from the hello packet data, not from the SSL 
  wrapper */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int checkPacketHeader( INOUT SESSION_INFO *sessionInfoPtr, 
							  INOUT STREAM *stream,
							  OUT int *packetLength, const int packetType, 
							  const int minLength, const int maxLength )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	const int expectedPacketType = \
					( packetType == SSL_MSG_FIRST_HANDSHAKE ) ? \
					SSL_MSG_HANDSHAKE : packetType;
	int value, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( packetType >= SSL_MSG_FIRST && packetType <= SSL_MSG_LAST ) || \
			( packetType == SSL_MSG_FIRST_HANDSHAKE ) );
	assert( ( packetType == SSL_MSG_APPLICATION_DATA && minLength == 0 ) || \
			( minLength > 0 ) );
	assert( isWritePtr( packetLength, sizeof( int ) ) );

	/* Clear return value */
	*packetLength = 0;

	/* Check the packet type */
	value = sgetc( stream );
	if( value != expectedPacketType )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Unexpected packet type %d, expected %d", 
				  value, expectedPacketType ) );
		}
	status = processVersionInfo( sessionInfoPtr, stream, 
				( packetType == SSL_MSG_FIRST_HANDSHAKE ) ? &value : NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Check the packet length */
	length = readUint16( stream );
	if( sessionInfoPtr->flags & SESSION_ISSECURE_READ )
		{
		if( length < sslInfo->ivSize + minLength + \
					 sessionInfoPtr->authBlocksize || \
			length > sslInfo->ivSize + MAX_PACKET_SIZE + \
					 sessionInfoPtr->authBlocksize + 256 || \
			length > maxLength )
			status = CRYPT_ERROR_BADDATA;
		}
	else
		{
		if( length < minLength || length > MAX_PACKET_SIZE || \
			length > maxLength )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid packet length %d for packet type %d", 
				  length, packetType ) );
		}

	/* Load the TLS 1.1 explicit IV if necessary */
	if( ( sessionInfoPtr->flags & SESSION_ISSECURE_READ ) && \
		sslInfo->ivSize > 0 )
		{
		int ivLength;

		status = loadExplicitIV( sessionInfoPtr, stream, &ivLength );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Error loading TLS explicit IV" ) );
			}
		length -= ivLength;
		if( length < minLength + sessionInfoPtr->authBlocksize || \
			length > maxLength )
			retIntError();
		}
	*packetLength = length;

	return( CRYPT_OK );
	}

/* Check that the header of an SSL packet and SSL handshake packet is in 
   order */

int checkPacketHeaderSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream,
						  int *packetLength )
	{
	return( checkPacketHeader( sessionInfoPtr, stream, packetLength,
							   SSL_MSG_APPLICATION_DATA, 0, 
							   sessionInfoPtr->receiveBufSize ) );
	}

int checkHSPacketHeader( SESSION_INFO *sessionInfoPtr, STREAM *stream,
						 int *packetLength, const int packetType, 
						 const int minSize )
	{
	int type, length;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( packetType >= SSL_HAND_FIRST && packetType <= SSL_HAND_LAST );
	assert( minSize >= 0 );	/* May be zero for change cipherspec */
	assert( isWritePtr( packetLength, sizeof( int ) ) );

	/* Clear return value */
	*packetLength = 0;

	/*	byte		ID = type
		uint24		length */
	type = sgetc( stream );
	if( type != packetType )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid handshake packet type %d, expected %d", 
				  type, packetType ) );
		}
	length = readUint24( stream );
	if( length < minSize || length > MAX_PACKET_SIZE || \
		length > sMemDataLeft( stream ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid length %d for handshake packet type %d", 
				  length, type ) );
		}
	*packetLength = length;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read/Unwrap a Packet						*
*																			*
****************************************************************************/

/* Unwrap an SSL data packet:

			  data
				|-----------				MAC'd
				v=======================  Encrypted
	+-----+-----+-----------+-----+-----+
	| hdr |(IV)	|	data	| MAC | pad |
	+-----+-----+-----------+-----+-----+
				|<---- dataMaxLen ----->|
				|<- dLen -->|

   This decrypts the data, removes the padding, checks and removes the MAC, 
   and returns the payload length.  Processing of the header and IV have 
   already been performed during the packet header read */

int unwrapPacketSSL( SESSION_INFO *sessionInfoPtr, void *data, 
					 const int dataMaxLength, int *dataLength, 
					 const int packetType )
	{
	BOOLEAN badDecrypt = FALSE;
	int length, payloadLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) && \
			sessionInfoPtr->flags & SESSION_ISSECURE_READ );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );
	assert( dataMaxLength >= sessionInfoPtr->authBlocksize && \
			dataMaxLength <= MAX_PACKET_SIZE + sessionInfoPtr->authBlocksize + \
							 256 );

	/* Sanity-check the state */
	if( dataMaxLength < sessionInfoPtr->authBlocksize || \
		dataMaxLength > MAX_PACKET_SIZE + sessionInfoPtr->authBlocksize + 256 )
		retIntError();

	/* Clear return value */
	*dataLength = 0;

	/* Make sure that the length is a multiple of the block cipher size */
	if( sessionInfoPtr->cryptBlocksize > 1 && \
		( dataMaxLength % sessionInfoPtr->cryptBlocksize ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid encrypted packet length %d relative to cipher "
				  "block size %d for packet type %d", dataMaxLength, 
				  sessionInfoPtr->cryptBlocksize, packetType ) );
		}

	/* Decrypt the packet in the buffer.  We allow zero-length blocks (once
	   the padding is stripped) because some versions of OpenSSL send these 
	   as a kludge to work around pre-TLS 1.1 chosen-IV attacks */
	status = decryptData( sessionInfoPtr, data, dataMaxLength, &length );
	if( cryptStatusError( status ) )
		{
		/* If there's a padding error, don't exit immediately but record 
		   that there was a problem for after we've done the MAC'ing.  
		   Delaying the error reporting until then helps prevent timing 
		   attacks of the kind described by Brice Canvel, Alain Hiltgen,
		   Serge Vaudenay, and Martin Vuagnoux in "Password Interception 
		   in a SSL/TLS Channel", Crypto'03, LNCS No.2729, p.583.  These 
		   are close to impossible in most cases because we delay sending 
		   the close notify over a much longer period than the MAC vs.non-
		   MAC time difference and because it requires repeatedly connecting
		   with a fixed-format secret such as a password at the same location
		   in the packet (which MS Outlook does however manage to do), but 
		   we take this step anyway just to be safe */
		if( status == CRYPT_ERROR_BADDATA )
			{
			badDecrypt = TRUE;
			length = dataMaxLength;
			}
		else
			return( status );
		}
	payloadLength = length - sessionInfoPtr->authBlocksize;
	if( payloadLength < 0 || payloadLength > MAX_PACKET_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid packet payload length %d for packet type %d", 
				  payloadLength, packetType ) );
		}

	/* MAC the decrypted data.  The badDecrypt flag suppresses the reporting
	   of a MAC error due to an earlier bad decrypt, which has already been
	   reported by decryptData() */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		status = checkMacSSL( sessionInfoPtr, data, length, payloadLength, 
							  packetType, badDecrypt );
	else
		status = checkMacTLS( sessionInfoPtr, data, length, payloadLength, 
							  packetType, badDecrypt );
	if( badDecrypt )
		{
		/* Report the delayed decrypt error, held to this point to make 
		   timing attacks more difficult */
		return( CRYPT_ERROR_BADDATA );
		}
	if( cryptStatusError( status ) )
		return( status );

	*dataLength = payloadLength;
	return( CRYPT_OK );
	}

/* Read an SSL handshake packet.  Since the data transfer phase has its own 
   read/write code we can perform some special-case handling based on this */

int readHSPacketSSL( SESSION_INFO *sessionInfoPtr,
					 SSL_HANDSHAKE_INFO *handshakeInfo, int *packetLength,
				     const int packetType )
	{
	STREAM stream;
	BYTE headerBuffer[ SSL_HEADER_SIZE + CRYPT_MAX_IVSIZE + 8 ];
	int bytesToRead, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( ( handshakeInfo == NULL ) || \
			isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( packetLength, sizeof( int ) ) );
	assert( ( packetType >= SSL_MSG_FIRST && packetType <= SSL_MSG_LAST ) || \
			( packetType == SSL_MSG_FIRST_HANDSHAKE ) );
	assert( sessionInfoPtr->receiveBufStartOfs >= SSL_HEADER_SIZE && \
			sessionInfoPtr->receiveBufStartOfs < \
				SSL_HEADER_SIZE + CRYPT_MAX_IVSIZE );

	/* Sanity-check the state */
	if( sessionInfoPtr->receiveBufStartOfs < SSL_HEADER_SIZE || \
		sessionInfoPtr->receiveBufStartOfs >= \
			SSL_HEADER_SIZE + CRYPT_MAX_IVSIZE )
		retIntError();

	/* Clear return value */
	*packetLength = 0;

	/* Read and process the header */
	status = readFixedHeaderAtomic( sessionInfoPtr, headerBuffer,
									sessionInfoPtr->receiveBufStartOfs );
	if( cryptStatusError( status ) )
		return( status );

	/* Check for an SSL alert message */
	if( headerBuffer[ 0 ] == SSL_MSG_ALERT )
		return( processAlert( sessionInfoPtr, headerBuffer, 
							  sessionInfoPtr->receiveBufStartOfs ) );

	/* Decode and process the SSL packet header */
	if( packetType == SSL_MSG_FIRST_HANDSHAKE && \
		headerBuffer[ 0 ] == SSL_MSG_V2HANDSHAKE )
		{
#if 0	/* 28/01/08 Disabled since it's now finally been removed from MSIE 
		   and Firefox */
		/* It's an SSLv2 handshake, handle it specially */
		return( handleSSLv2Header( sessionInfoPtr, handshakeInfo, 
								   headerBuffer ) );
#else
		retExt( CRYPT_ERROR_NOSECURE,
				( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
				  "Client sent obsolete handshake for the insecure SSLv2 "
				  "protocol" ) );
#endif /* 0 */
		}
	sMemConnect( &stream, headerBuffer, sessionInfoPtr->receiveBufStartOfs );
	status = checkPacketHeader( sessionInfoPtr, &stream, &bytesToRead, 
								packetType, 
								( packetType == SSL_MSG_CHANGE_CIPHER_SPEC ) ? \
									1 : MIN_PACKET_SIZE,
								sessionInfoPtr->receiveBufSize ); 
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the payload packet(s) */
	status = length = \
		sread( &sessionInfoPtr->stream, sessionInfoPtr->receiveBuffer, 
			   bytesToRead );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  &sessionInfoPtr->errorInfo );
		return( status );
		}
	if( length < bytesToRead )
		{
		/* If we timed out during the handshake phase, treat it as a hard 
		   timeout error */
		retExt( CRYPT_ERROR_TIMEOUT,
				( CRYPT_ERROR_TIMEOUT, SESSION_ERRINFO, 
				  "Timed out reading packet data for packet type %d, only "
				  "got %d of %d bytes", packetType, length, bytesToRead ) );
		}
	sessionInfoPtr->receiveBufPos = 0;
	sessionInfoPtr->receiveBufEnd = length;
	if( handshakeInfo != NULL )
		{
		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		status = dualMacDataRead( handshakeInfo, &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		}
	*packetLength = length;

	return( CRYPT_OK );
	}

/* Read the next handshake stream packet */

int refreshHSStream( SESSION_INFO *sessionInfoPtr, 
					 SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* If there's still data present in the stream, there's nothing left
	   to do */
	if( sMemDataLeft( stream ) > 0 )
		return( CRYPT_OK );

	/* Refill the stream */
	sMemDisconnect( stream );
	status = readHSPacketSSL( sessionInfoPtr, handshakeInfo, &length,
							  SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	assert( length > 0 );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );

	return( CRYPT_OK );
	}		

/****************************************************************************
*																			*
*							Write Packet Utility Functions					*
*																			*
****************************************************************************/

/* Open and complete an SSL packet:

	 offset										packetEndOfs
		|											|
		v											v
		+---+---+---+----+--------------------------+
		|ID	|Ver|Len|(IV)|							|
		+---+---+---+----+--------------------------+

   An initial openXXX() starts a new packet at the start of a stream and 
   continueXXX() adds another packet after an existing one, or (for the
   xxxHSXXX() variants) adds a handshake sub-packet within an existing 
   packet.  The continueXXX() operations return the start offset of the new 
   packet within the stream, openXXX() always starts at the start of the SSL 
   send buffer so the start offset is an implied 0.  completeXXX() then goes 
   back to the given offset and deposits the appropriate length value in the 
   header that was written earlier.  So typical usage would be:

	// Change-cipher-spec packet
	openPacketStreamSSL( CRYPT_USE_DEFAULT, SSL_MSG_CHANGE_CIPHER_SPEC );
	write( stream, ... );
	completePacketStreamSSL( stream, 0 );

	// Finished handshake sub-packet within a handshake packet
	continuePacketStreamSSL( SSL_MSG_HANDSHAKE );
	offset = continueHSPacketStream( SSL_HAND_FINISHED );
	write( stream, ... );
	completeHSPacketStream( stream, offset );
	// (Packet stream is completed by wrapPacketSSL())

   Errors are propagated and caught at the completeXXX() stage */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int openPacketStream( INOUT STREAM *stream, 
							 const SESSION_INFO *sessionInfoPtr, 
							 const int packetType )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( packetType >= SSL_MSG_FIRST && packetType <= SSL_MSG_LAST );

	/* Write the packet header:

		byte		ID = packetType
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 0 (placeholder) 
	  [ byte[]		iv	- TLS 1.1 only ] */
	sputc( stream, packetType );
	sputc( stream, SSL_MAJOR_VERSION );
	sputc( stream, sessionInfoPtr->version );
	status = writeUint16( stream, 0 );		/* Placeholder */
	if( ( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE ) && \
		sslInfo->ivSize > 0 )
		{
		MESSAGE_DATA msgData;
		BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];

		setMessageData( &msgData, iv, sslInfo->ivSize );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		status = swrite( stream, iv, sslInfo->ivSize );
		}
	return( status );
	}

int openPacketStreamSSL( STREAM *stream, const SESSION_INFO *sessionInfoPtr, 
						 const int bufferSize, const int packetType )
	{
	const int streamSize = ( bufferSize == CRYPT_USE_DEFAULT ) ? \
						   sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE : \
						   bufferSize + sessionInfoPtr->sendBufStartOfs;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) && \
			isWritePtr( sessionInfoPtr->sendBuffer, streamSize ) );
	assert( bufferSize == CRYPT_USE_DEFAULT || \
			( packetType == SSL_MSG_APPLICATION_DATA && bufferSize == 0 ) || \
			bufferSize > 0 );
			/* When wrapping up data packets we only write the implicit-
			   length header so the buffer size is zero */
	assert( packetType >= SSL_MSG_FIRST && packetType <= SSL_MSG_LAST );

	/* Sanity-check the state */
	if( streamSize < sessionInfoPtr->sendBufStartOfs || \
		streamSize > sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE )
		retIntError();

	/* Create the stream */
	sMemOpen( stream, sessionInfoPtr->sendBuffer, streamSize );
	return( openPacketStream( stream, sessionInfoPtr, packetType ) );
	}

int continuePacketStreamSSL( STREAM *stream, 
							  const SESSION_INFO *sessionInfoPtr, 
							  const int packetType )
	{
	const int offset = stell( stream );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stell( stream ) >= SSL_HEADER_SIZE );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( packetType >= SSL_MSG_FIRST && packetType <= SSL_MSG_LAST );

	/* We don't have to check the return value of the continue/open since 
	   it's implicitly communicated via the stream state */
	( void ) openPacketStream( stream, sessionInfoPtr, packetType );
	return( offset );
	}

int completePacketStreamSSL( STREAM *stream, const int offset )
	{
	const int packetEndOffset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( offset == 0 || offset >= SSL_HEADER_SIZE ) && \
			offset <= packetEndOffset - ( ID_SIZE + VERSIONINFO_SIZE ) );

	/* Sanity-check the state */
	if( ( offset != 0 && offset < SSL_HEADER_SIZE ) || \
		offset > packetEndOffset - ( ID_SIZE + VERSIONINFO_SIZE ) )
		retIntError();

	/* Update the length field at the start of the packet */
	sseek( stream, offset + ID_SIZE + VERSIONINFO_SIZE );
	status = writeUint16( stream, ( packetEndOffset - offset ) - \
								  SSL_HEADER_SIZE );
	sseek( stream, packetEndOffset );
	return( status );
	}

/* Start and complete a handshake packet within an SSL packet.  Since this
   continues an existing packet stream that's been opened using 
   openPacketStreamSSL(), it's denoted as continueXXX() rather than 
   openXXX() */

int continueHSPacketStream( STREAM *stream, const int packetType )
	{
	const int offset = stell( stream );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( packetType >= SSL_HAND_FIRST && packetType <= SSL_HAND_LAST );

	/* Write the handshake packet header:

		byte		ID = packetType
		uint24		len = 0 (placeholder) */
	sputc( stream, packetType );
	writeUint24( stream, 0 );	/* Placeholder */
	return( offset );
	}

int completeHSPacketStream( STREAM *stream, const int offset )
	{
	const int packetEndOffset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( offset >= SSL_HEADER_SIZE && \
			offset <= packetEndOffset - ( ID_SIZE + LENGTH_SIZE ) );
			/* HELLO_DONE has size zero so ofs == pEO - HDR_SIZE */

	/* Sanity-check the state */
	if( offset < SSL_HEADER_SIZE || \
		offset > packetEndOffset - ( ID_SIZE + LENGTH_SIZE ) )
		retIntError();

	/* Update the length field at the start of the packet */
	sseek( stream, offset + ID_SIZE );
	status = writeUint24( stream, packetEndOffset - \
								  ( offset + ID_SIZE + LENGTH_SIZE ) );
	sseek( stream, packetEndOffset );
	return( status );
	}

/****************************************************************************
*																			*
*							Write/wrap a Packet								*
*																			*
****************************************************************************/

/* Wrap an SSL data packet:

	sendBuffer hdrPtr	dataPtr
		|		|			|-------------------			  MAC'd
		v		v			v================================ Encrypted
		+-------+-----+-----+-------------------+-----+-----+
		|///////| hdr | IV	|		data		| MAC | pad |
		+-------+-----+-----+-------------------+-----+-----+
				^<--------->|<- payloadLength ->^			|
				|	  |		 <-------- bMaxLen -|---------->
			 offset sBufStartOfs			stell( stream )

   This MACs the data, adds the IV if necessary, pads and encrypts, and
   updates the header */

int wrapPacketSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream, 
				   const int offset )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	STREAM lengthStream;
	const int payloadLength = stell( stream ) - \
							  ( offset + sessionInfoPtr->sendBufStartOfs );
	const int bufMaxLen = payloadLength + sMemDataLeft( stream );
	BYTE lengthBuffer[ UINT16_SIZE + 8 ];
	BYTE *dataPtr, *headerPtr;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( offset >= 0 && \
			offset <= stell( stream ) - \
					  ( payloadLength + sessionInfoPtr->sendBufStartOfs ) );
	assert( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE && \
			payloadLength < sessionInfoPtr->sendBufSize - \
							( sessionInfoPtr->sendBufStartOfs + sslInfo->ivSize ) );

	/* Sanity-check the state */
	if( offset < 0 || \
		offset > stell( stream ) - \
				 ( payloadLength + sessionInfoPtr->sendBufStartOfs ) || \
		payloadLength < 0 || payloadLength > MAX_PACKET_SIZE || \
		payloadLength >= sessionInfoPtr->sendBufSize - \
						 ( sessionInfoPtr->sendBufStartOfs + sslInfo->ivSize ) )
		retIntError();

	/* Get pointers into the data stream for the crypto processing */
	status = sMemGetDataBlockAbs( stream, offset, ( void ** ) &headerPtr, 
								  bufMaxLen );
	if( cryptStatusError( status ) )
		return( status );
	dataPtr = headerPtr + SSL_HEADER_SIZE + sslInfo->ivSize;
	assert( *headerPtr >= SSL_MSG_FIRST && *headerPtr <= SSL_MSG_LAST );

	/* MAC the payload */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		status = createMacSSL( sessionInfoPtr, dataPtr, bufMaxLen, &length, 
							   payloadLength, *headerPtr );
	else
		status = createMacTLS( sessionInfoPtr, dataPtr, bufMaxLen, &length,
							   payloadLength, *headerPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's TLS 1.1 or newer and we're using a block cipher, adjust for 
	   the explicit IV that precedes the data.  We know that the resulting
	   values are within bounds because dataPtr = headerPtr + hdr + IV */
	if( sslInfo->ivSize > 0 )
		{
		assert( sessionInfoPtr->sendBufStartOfs >= \
				SSL_HEADER_SIZE + sslInfo->ivSize ); 

		dataPtr -= sslInfo->ivSize;
		assert( dataPtr > headerPtr );
		length += sslInfo->ivSize;
		if( length > bufMaxLen )
			retIntError();
		}

	/* Pad and encrypt the payload */
	status = encryptData( sessionInfoPtr, dataPtr, bufMaxLen, &length, 
						  length );
	if( cryptStatusError( status ) )
		return( status );

	/* Insert the final packet payload length into the packet header.  We 
	   directly copy the data in because the stream may have been opened in 
	   read-only mode if we're using it to write pre-assembled packet data 
	   that's been passed in by the caller */
	sMemOpen( &lengthStream, lengthBuffer, UINT16_SIZE );
	status = writeUint16( &lengthStream, length );
	sMemDisconnect( &lengthStream );
	memcpy( headerPtr + ID_SIZE + VERSIONINFO_SIZE, lengthBuffer, 
			UINT16_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Sync the stream info to match the new payload size */
	return( sSkip( stream, length - ( sslInfo->ivSize + payloadLength ) ) );
	}

/* Wrap up and send an SSL packet */

int sendPacketSSL( SESSION_INFO *sessionInfoPtr, STREAM *stream,
				   const BOOLEAN sendOnly )
	{
	const int length = stell( stream );
	void *dataPtr;
	int status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( stell( stream ) >= SSL_HEADER_SIZE );

	/* Safety check to make sure that the stream is OK */
	if( !sStatusOK( stream ) )
		{
		assert( DEBUG_WARN );
		return( sGetStatus( stream ) );
		}

	/* Update the length field at the start of the packet if necessary */
	if( !sendOnly )
		{
		status = completePacketStreamSSL( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Send the packet to the peer */
	status = sMemGetDataBlockAbs( stream, 0, &dataPtr, length );
	if( cryptStatusOK( status ) )
		status = swrite( &sessionInfoPtr->stream, dataPtr, length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  &sessionInfoPtr->errorInfo );
		return( status );
		}
	return( CRYPT_OK );	/* swrite() returns a byte count */
	}

/****************************************************************************
*																			*
*							Send/Receive SSL Alerts							*
*																			*
****************************************************************************/

/* Process an alert packet.  IIS often just drops the connection rather than 
   sending an alert when it encounters a problem (although we try and work
   around some of the known problems, e.g. by sending a canary in the client
   hello to force IIS to at least send back something rather than just 
   dropping the connection, see ssl_cli.c), so when communicating with IIS 
   the only error indication that we sometimes get will be a "Connection 
   closed by remote host" rather than an SSL-level error message.  In 
   addition when it encounters an unknown cert MSIE will complete the 
   handshake and then close the connection (via a proper close alert in this 
   case rather than just closing the connection), wait while the user clicks 
   OK several times, and then restart the connection via an SSL resume.  
   Netscape in contrast just hopes that the session won't time out while 
   waiting for the user to click OK.  As a result, cryptlib sees a closed 
   connection and aborts the session setup process, requiring a second call 
   to the session setup to continue with the resumed session */

int processAlert( SESSION_INFO *sessionInfoPtr, const void *header, 
				  const int headerLength )
	{
	typedef struct {
		const int type;
		const char *message;
		const int messageLength;
		const int cryptlibError;
		} ALERT_INFO;
	const static ALERT_INFO alertInfo[] = {
		{ SSL_ALERT_CLOSE_NOTIFY, "Close notify", 12, CRYPT_ERROR_COMPLETE },
		{ SSL_ALERT_UNEXPECTED_MESSAGE, "Unexpected message", 18, CRYPT_ERROR_FAILED },
		{ SSL_ALERT_BAD_RECORD_MAC, "Bad record MAC", 14, CRYPT_ERROR_SIGNATURE },
		{ TLS_ALERT_DECRYPTION_FAILED, "Decryption failed", 17, CRYPT_ERROR_WRONGKEY },
		{ TLS_ALERT_RECORD_OVERFLOW, "Record overflow", 15, CRYPT_ERROR_OVERFLOW },
		{ SSL_ALERT_DECOMPRESSION_FAILURE, "Decompression failure", 21, CRYPT_ERROR_FAILED },
		{ SSL_ALERT_HANDSHAKE_FAILURE, "Handshake failure", 17, CRYPT_ERROR_FAILED },
		{ SSL_ALERT_NO_CERTIFICATE, "No certificate", 14, CRYPT_ERROR_PERMISSION },
		{ SSL_ALERT_BAD_CERTIFICATE, "Bad certificate", 15, CRYPT_ERROR_INVALID },
		{ SSL_ALERT_UNSUPPORTED_CERTIFICATE, "Unsupported certificate", 23, CRYPT_ERROR_INVALID },
		{ SSL_ALERT_CERTIFICATE_REVOKED, "Certificate revoked", 19, CRYPT_ERROR_INVALID },
		{ SSL_ALERT_CERTIFICATE_EXPIRED, "Certificate expired", 19, CRYPT_ERROR_INVALID },
		{ SSL_ALERT_CERTIFICATE_UNKNOWN, "Certificate unknown", 19, CRYPT_ERROR_INVALID },
		{ SSL_ALERT_ILLEGAL_PARAMETER, "Illegal parameter", 17, CRYPT_ERROR_FAILED },
		{ TLS_ALERT_UNKNOWN_CA, "Unknown CA", 10, CRYPT_ERROR_INVALID },
		{ TLS_ALERT_ACCESS_DENIED, "Access denied", 13, CRYPT_ERROR_PERMISSION },
		{ TLS_ALERT_DECODE_ERROR, "Decode error", 12, CRYPT_ERROR_FAILED },
		{ TLS_ALERT_DECRYPT_ERROR, "Decrypt error", 13, CRYPT_ERROR_WRONGKEY },
		{ TLS_ALERT_EXPORT_RESTRICTION, "Export restriction", 18, CRYPT_ERROR_FAILED },
		{ TLS_ALERT_PROTOCOL_VERSION, "Protocol version", 16, CRYPT_ERROR_NOTAVAIL },
		{ TLS_ALERT_INSUFFICIENT_SECURITY, "Insufficient security", 21, CRYPT_ERROR_NOSECURE },
		{ TLS_ALERT_INTERNAL_ERROR, "Internal error", 14, CRYPT_ERROR_FAILED },
		{ TLS_ALERT_USER_CANCELLED, "User cancelled", 14, CRYPT_ERROR_FAILED },
		{ TLS_ALERT_NO_RENEGOTIATION, "No renegotiation", 16, CRYPT_ERROR_FAILED },
		{ TLS_ALERT_UNSUPPORTED_EXTENSION, "Unsupported extension", 21, CRYPT_ERROR_NOTAVAIL },
		{ TLS_ALERT_CERTIFICATE_UNOBTAINABLE, "Certificate unobtainable", 24, CRYPT_ERROR_NOTFOUND },
		{ TLS_ALERT_UNRECOGNIZED_NAME, "Unrecognized name", 17, CRYPT_ERROR_FAILED },
		{ TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE, "Bad certificate status response", 31, CRYPT_ERROR_FAILED },
		{ TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE, "Bad certificate hash value", 26, CRYPT_ERROR_FAILED },
		{ TLS_ALERT_UNKNOWN_PSK_IDENTITY, "Unknown PSK identity", 20, CRYPT_ERROR_NOTFOUND },
 		{ CRYPT_ERROR, NULL }, { CRYPT_ERROR, NULL }
		};
	ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;
	STREAM stream;
	BYTE buffer[ 256 + 8 ];
	int length, type, i, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( header, headerLength ) );

	/* Process the alert packet header */
	sMemConnect( &stream, header, headerLength );
	status = checkPacketHeader( sessionInfoPtr, &stream, &length, 
								SSL_MSG_ALERT, ALERTINFO_SIZE,
								sessionInfoPtr->receiveBufSize );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( sessionInfoPtr->flags & SESSION_ISSECURE_READ )
		{
		if( length < ALERTINFO_SIZE || length > 256 )
			status = CRYPT_ERROR_BADDATA;
		}
	else
		{
		if( length != ALERTINFO_SIZE )
			status = CRYPT_ERROR_BADDATA;
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid alert message length %d", length ) );
		}

	/* Read and process the alert packet */
	status = sread( &sessionInfoPtr->stream, buffer, length );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  &sessionInfoPtr->errorInfo );
		return( status );
		}
	if( status < length )
		{
		/* If we timed out before we could get all of the alert data, bail
		   out without trying to perform any further processing.  We're 
		   about to shut down the session anyway so there's no point in 
		   potentially stalling for ages trying to find a lost byte */
		sendCloseAlert( sessionInfoPtr, TRUE );
		sessionInfoPtr->flags |= SESSION_SENDCLOSED;
		retExt( CRYPT_ERROR_TIMEOUT, 
				( CRYPT_ERROR_TIMEOUT, SESSION_ERRINFO, 
				  "Timed out reading alert message, only got %d of %d "
				  "bytes", status, length ) );
		}
	sessionInfoPtr->receiveBufEnd = length;
	if( ( sessionInfoPtr->flags & SESSION_ISSECURE_READ ) && \
		( length > ALERTINFO_SIZE || \
		  isStreamCipher( sessionInfoPtr->cryptAlgo ) ) )
		{
		/* We only try and decrypt if the alert info is big enough to be
		   encrypted, i.e. it contains the fixed-size data + padding.  This
		   situation can occur if there's an error moving from the non-
		   secure to the secure state.  However, if it's a stream cipher the 
		   ciphertext and plaintext are the same size so we always have to 
		   try the decryption */
		status = unwrapPacketSSL( sessionInfoPtr, buffer, length, &length, 
								  SSL_MSG_ALERT );
		if( cryptStatusError( status ) )
			{
			sendCloseAlert( sessionInfoPtr, TRUE );
			sessionInfoPtr->flags |= SESSION_SENDCLOSED;
			return( status );
			}
		}

	/* Tell the other side that we're going away */
	sendCloseAlert( sessionInfoPtr, TRUE );
	sessionInfoPtr->flags |= SESSION_SENDCLOSED;

	/* Process the alert info.  In theory we should also make the session 
	   non-resumable if the other side goes away without sending a close 
	   alert, but this leads to too many problems with non-resumable 
	   sessions if we do it.  For example many protocols do their own end-of-
	   data indication (e.g. "Connection: close" in HTTP and BYE in SMTP) 
	   and so don't bother with a close alert.  In other cases 
	   implementations just drop the connection without sending a close 
	   alert, carried over from many early Unix protocols that used a 
	   connection close to signify end-of-data, which has caused problems 
	   ever since for newer protocols that want to keep the connection open.  
	   Other implementations still send their alert but then immediately 
	   close the connection.  Because of this haphazard approach to closing 
	   connections, many implementations allow a session to be resumed even 
	   if no close alert is sent.  In order to be compatible with this 
	   behaviour, we do the same (thus perpetuating the problem).  If 
	   necessary this can be fixed by calling deleteSessionCacheEntry() if 
	   the connection is closed without a close alert having been sent */
	if( buffer[ 0 ] != SSL_ALERTLEVEL_WARNING && \
		buffer[ 0 ] != SSL_ALERTLEVEL_FATAL )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid alert message level %d", buffer[ 0 ] ) );
		}
	errorInfo->errorCode = type = buffer[ 1 ];
	for( i = 0; alertInfo[ i ].type != CRYPT_ERROR && \
				alertInfo[ i ].type != type && \
				i < FAILSAFE_ARRAYSIZE( alertInfo, ALERT_INFO ); i++ );
	if( i >= FAILSAFE_ARRAYSIZE( alertInfo, ALERT_INFO ) )
		retIntError();
	if( alertInfo[ i ].type == CRYPT_ERROR )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Unknown alert message type %d at alert level %d", 
				  type, buffer[ 0 ] ) );
		}
	retExtStr( alertInfo[ i ].cryptlibError,
			   ( alertInfo[ i ].cryptlibError, SESSION_ERRINFO, 
				 alertInfo[ i ].message, alertInfo[ i ].messageLength,
				 ( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
					"Received SSL alert message: " : \
					"Received TLS alert message: " ) );
	}

/* Send a close alert, with appropriate protection if necessary */

STDC_NONNULL_ARG( ( 1 ) ) \
static void sendAlert( INOUT SESSION_INFO *sessionInfoPtr, 
					   const int alertLevel, const int alertType,
					   const BOOLEAN alertReceived )
	{
	STREAM stream;
	int length = DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( alertLevel == SSL_ALERTLEVEL_WARNING || \
			alertLevel == SSL_ALERTLEVEL_FATAL );
	assert( alertType >= SSL_ALERT_FIRST && \
			alertType <= SSL_ALERT_LAST );

	/* Make sure that we only send a single alert.  Normally we do this 
	   automatically on shutdown, but we may have already sent it earlier 
	   as part of an error-handler */
	if( sessionInfoPtr->protocolFlags & SSL_PFLAG_ALERTSENT )
		return;
	sessionInfoPtr->protocolFlags |= SSL_PFLAG_ALERTSENT;

	/* Create the alert.  We can't really do much with errors at this point, 
	   although we can throw an exception in the debug version to draw 
	   attention to the fact that there's a problem.  The one error type 
	   that we don't complain about is an access permission problem, which 
	   can occur when cryptlib is shutting down, for example when the 
	   current thread is blocked waiting for network traffic and another 
	   thread shuts cryptlib down */
	status = openPacketStreamSSL( &stream, sessionInfoPtr, 
								  CRYPT_USE_DEFAULT, SSL_MSG_ALERT );
	if( cryptStatusOK( status ) )
		{
		sputc( &stream, alertLevel );
		sputc( &stream, alertType );
		if( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE )
			{
			status = wrapPacketSSL( sessionInfoPtr, &stream, 0 );
			assert( cryptStatusOK( status ) || \
					status == CRYPT_ERROR_PERMISSION );
			}
		else
			{
			status = completePacketStreamSSL( &stream, 0 );
			}
		if( cryptStatusOK( status ) )
			length = stell( &stream );
		sMemDisconnect( &stream );
		}
	/* Fall through with status passed on to the following code */

	/* Send the alert.  Note that we don't exit on an error status in the
	   previous operation (for the reasons given in the comment earlier) 
	   since we can at least perform a clean shutdown even if the creation
	   of the close alert fails */
	if( cryptStatusOK( status ) )
		status = sendCloseNotification( sessionInfoPtr, 
										sessionInfoPtr->sendBuffer, length );
	else
		status = sendCloseNotification( sessionInfoPtr, NULL, 0 );
	if( cryptStatusError( status ) || alertReceived )
		return;

	/* Read back the other side's close alert acknowledgement.  Again, since 
	   we're closing down the session anyway there's not much that we can do 
	   in response to an error */
	( void ) readHSPacketSSL( sessionInfoPtr, NULL, &length, 
							  SSL_MSG_ALERT );
	}

void sendCloseAlert( SESSION_INFO *sessionInfoPtr, 
					 const BOOLEAN alertReceived )
	{
	sendAlert( sessionInfoPtr, SSL_ALERTLEVEL_WARNING, 
			   SSL_ALERT_CLOSE_NOTIFY, alertReceived );
	}

void sendHandshakeFailAlert( SESSION_INFO *sessionInfoPtr )
	{
	/* We set the alertReceived flag to true when sending a handshake
	   failure alert to avoid waiting to get back an ack, since this 
	   alert type isn't acknowledged by the other side */
	sendAlert( sessionInfoPtr, SSL_ALERTLEVEL_FATAL, 
			   SSL_ALERT_HANDSHAKE_FAILURE, TRUE );
	}
#endif /* USE_SSL */
