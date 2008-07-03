/****************************************************************************
*																			*
*					cryptlib SSHv2 Session Read/Write Routines				*
*						Copyright Peter Gutmann 1998-2008					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssh.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/ssh.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSH

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Processing handshake data can run into a number of special-case 
   conditions due to buggy SSH implementations, we handle these in a special
   function to avoid cluttering up the main packet-read code */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int checkHandshakePacketStatus( INOUT SESSION_INFO *sessionInfoPtr,
									   const int headerStatus,
									   IN_BUFFER( headerLength ) \
									   const BYTE *header, const int headerLength,
									   const int expectedType )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( headerStatus == CRYPT_ERROR_READ || cryptStatusOK( headerStatus ) );
	assert( isReadPtr( header, headerLength ) );
	assert( expectedType >= SSH2_MSG_DISCONNECT && \
			expectedType <= SSH2_MSG_SPECIAL_REQUEST );

	/* If the other side has simply dropped the connection, see if we can 
	   get further details on what went wrong */
	if( headerStatus == CRYPT_ERROR_READ )
		{
		/* Some servers just close the connection in response to a bad 
		   password rather than returning an error, if it looks like this 
		   has occurred we return a more informative error than the low-
		   level networking one */
		if( !isServer( sessionInfoPtr ) && \
			( expectedType == SSH2_MSG_SPECIAL_USERAUTH || \
			  expectedType == SSH2_MSG_SPECIAL_USERAUTH_PAM ) )
			{
			retExt( headerStatus,
					( headerStatus, SESSION_ERRINFO, 
					  "Remote server has closed the connection, possibly "
					  "in response to an incorrect password or other "
					  "authentication value" ) );
			}

		/* Some versions of CuteFTP simply drop the connection with no
		   diagnostics or error information when they get the phase 2 keyex
		   packet, the best that we can do is tell the user to hassle the
		   CuteFTP vendor about this */
		if( isServer( sessionInfoPtr ) && \
			( sessionInfoPtr->protocolFlags & SSH_PFLAG_CUTEFTP ) && \
			expectedType == SSH2_MSG_NEWKEYS )
			{
			retExt( headerStatus,
					( headerStatus, SESSION_ERRINFO, 
					  "CuteFTP client has aborted the handshake due to a "
					  "CuteFTP bug, please contact the CuteFTP vendor" ) );
			}

		return( CRYPT_OK );
		}

	assert( cryptStatusOK( headerStatus ) );

	/* Versions of SSH derived from the original SSH code base can sometimes
	   dump raw text strings (that is, strings not encapsulated in SSH
	   packets such as error packets) onto the connection if something
	   unexpected occurs.  Normally this would result in a bad data or MAC
	   error since they decrypt to garbage, so we try and catch them here */
	if( ( sessionInfoPtr->protocolFlags & SSH_PFLAG_TEXTDIAGS ) && \
		header[ 0 ] == 'F' && \
		( !memcmp( header, "FATAL: ", 7 ) || \
		  !memcmp( header, "FATAL ERROR:", 12 ) ) )
		{
		BYTE *bufPtr;
		const int maxLength = min( MAX_ERRMSG_SIZE - 128, 
								   sessionInfoPtr->receiveBufSize - 128 );
		int length;

		/* Copy across what we've got so far.  Since this is a fatal error,
		   we use the receive buffer to contain the data since we don't need
		   it for any further processing */
		memcpy( sessionInfoPtr->receiveBuffer, header, 
				MIN_PACKET_SIZE );

		/* Read the rest of the error message */
		for( length = MIN_PACKET_SIZE; length < maxLength; length++ )
			{
			const int ch = sgetc( &sessionInfoPtr->stream );

			if( cryptStatusError( ch ) || ch == '\n' || ch == '\r' )
				break;
			sessionInfoPtr->receiveBuffer[ length ] = ch;
			}

		/* Remove trailing garbage.  We check for CR and LF even though 
		   they're excluded by the loop above because they may have been read
		   as part of the initial read of MIN_PACKET_SIZE bytes */
		for( bufPtr = sessionInfoPtr->receiveBuffer; length > 0; length-- )
			{
			const int ch = bufPtr[ length - 1 ];

			if( ch != '\r' && ch != '\n' && ch != '\t' && ch != ' ' )
				break;
			}
		bufPtr[ length ] = '\0';

		/* Report the error as a problem with the remote software.  Since
		   the other side has bailed out, we mark the channel as closed to
		   prevent any attempt to try and perform a standard shutdown */
		sessionInfoPtr->flags |= SESSION_SENDCLOSED;
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Remote SSH software has crashed, diagnostic was: '%s'",
				  sanitiseString( sessionInfoPtr->receiveBuffer, 
				  MAX_ERRMSG_SIZE - 64, length ) ) );
		}

	/* No buggy behaviour detected */
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read/Unwrap a Packet						*
*																			*
****************************************************************************/

/* Get the reason why the peer closed the connection */

int getDisconnectInfo( SESSION_INFO *sessionInfoPtr, STREAM *stream )
	{
	typedef struct {
		const int sshStatus, cryptlibStatus;
		} ERRORMAP_INFO;
	static const ERRORMAP_INFO FAR_BSS errorMap[] = {
		/* A mapping of SSH error codes that have cryptlib equivalents to
		   the equivalent cryptlib codes.  If there's no mapping available,
		   we use a default of CRYPT_ERROR_READ */
		{ SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT, CRYPT_ERROR_PERMISSION },
		{ SSH2_DISCONNECT_MAC_ERROR, CRYPT_ERROR_SIGNATURE },
		{ SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE, CRYPT_ERROR_NOTAVAIL },
		{ SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, CRYPT_ERROR_NOTAVAIL },
		{ SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, CRYPT_ERROR_WRONGKEY },
		{ CRYPT_ERROR, CRYPT_ERROR_READ }, { CRYPT_ERROR, CRYPT_ERROR_READ }
		};
	ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;
	char errorString[ MAX_ERRMSG_SIZE + 8 ];
	int errorCode, length, i, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Peer is disconnecting, find out why:

	  [	byte	SSH2_MSG_DISCONNECT ]
		uint32	reason
		string	description
		string	language_tag */
	errorCode = readUint32( stream );
	if( cryptStatusError( errorCode ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid disconnect status information in disconnect "
				  "message" ) );
		}
	errorInfo->errorCode = errorCode;
	status = readString32( stream, errorString, MAX_ERRMSG_SIZE - 64, 
						   &length );
	if( cryptStatusOK( status ) )
		sanitiseString( errorString, MAX_ERRMSG_SIZE - 64, length );
	else
		{
		memcpy( errorString, "<No details available>", 22 + 1 );
		}

	/* Try and map the SSH status to an equivalent cryptlib one */
	for( i = 0; errorMap[ i ].sshStatus != CRYPT_ERROR && \
				i < FAILSAFE_ARRAYSIZE( errorMap, ERRORMAP_INFO ); i++ )
		{
		if( errorMap[ i ].sshStatus == errorInfo->errorCode )
			break;
		}
	if( i >= FAILSAFE_ARRAYSIZE( errorMap, ERRORMAP_INFO ) )
		retIntError();
	retExt( errorMap[ i ].cryptlibStatus,
			( errorMap[ i ].cryptlibStatus, SESSION_ERRINFO, 
			  "Received disconnect message: %s", errorString ) );
	}

/* Read, decrypt if necessary, and check the start of a packet header */

int readPacketHeaderSSH2( SESSION_INFO *sessionInfoPtr,
						  const int expectedType, long *packetLength,
						  int *packetExtraLength,
						  READSTATE_INFO *readInfo )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	STREAM stream;
	BYTE headerBuffer[ MIN_PACKET_SIZE + 8 ];
	const BOOLEAN isHandshake = ( readInfo == NULL ) ? TRUE : FALSE;
	BYTE *headerBufPtr = isHandshake ? headerBuffer : sshInfo->headerBuffer;
	long length;
	int extraLength = 0, status = CRYPT_OK;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( expectedType >= SSH2_MSG_DISCONNECT && \
			expectedType <= SSH2_MSG_SPECIAL_REQUEST );
	assert( isWritePtr( packetLength, sizeof( long ) ) );
	assert( isWritePtr( packetExtraLength, sizeof( int ) ) );
	assert( readInfo == NULL || \
			isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	/* Clear return values */
	*packetLength = 0;
	*packetExtraLength = 0;

	assert( CRYPT_MAX_IVSIZE >= MIN_PACKET_SIZE );
			/* Packet header is a single cipher block */

	/* SSHv2 encrypts everything but the MAC (including the packet length)
	   so we need to speculatively read ahead for the minimum packet size
	   and decrypt that in order to figure out what to do */
	if( isHandshake )
		{
		int localStatus;

		/* Processing handshake data can run into a number of special-case
		   conditions due to buggy SSH implementations, to handle these we
		   check the return code as well as the returned data to see if we
		   need to process it specially */
		status = readFixedHeaderAtomic( sessionInfoPtr, headerBufPtr, 
										MIN_PACKET_SIZE );
		if( status == CRYPT_ERROR_READ || cryptStatusOK( status ) )
			{
			localStatus = checkHandshakePacketStatus( sessionInfoPtr, 
									status, headerBufPtr, MIN_PACKET_SIZE, 
									expectedType );
			if( cryptStatusError( localStatus ) )
				status = localStatus;
			}
		}
	else
		{
		status = readFixedHeader( sessionInfoPtr, headerBufPtr, 
								  MIN_PACKET_SIZE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If we're in the data-processing stage (i.e. it's a post-handshake
	   data packet read), exception conditions need to be handled specially
	   if they occur */
	if( !isHandshake )
		{
		/* Since data errors are always fatal, when we're in the data-
		   processing stage we make all errors fatal until we've finished
		   handling the header */
		*readInfo = READINFO_FATAL;
		}

	/* Decrypt the header if necessary */
	if( sessionInfoPtr->flags & SESSION_ISSECURE_READ )
		{
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
								  IMESSAGE_CTX_DECRYPT, headerBufPtr,
								  MIN_PACKET_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process the packet header.  The dual minimum-length checks actually
	   simplify to the following:

		Non-secure mode: length < SSH2_HEADER_REMAINDER_SIZE (extraLength = 0).
			In this case there's no MAC being used, so all that we need to
			guarantee is that the packet is at least as long as the
			(remaining) data that we've already read.

		Secure mode: length < ID_SIZE + PADLENGTH_SIZE +
			SSH2_MIN_PADLENGTH_SIZE.  In this case there's an (implicit) MAC
			present so the packet (length + extraLength) will always be
			larger than the (remaining) data that we've already read.  For
			this case we need to check that the data payload is at least as
			long as the minimum-length packet */
	sMemConnect( &stream, headerBufPtr, MIN_PACKET_SIZE );
	length = readUint32( &stream );
	assert( SSH2_HEADER_REMAINDER_SIZE == MIN_PACKET_SIZE - LENGTH_SIZE );
	if( sessionInfoPtr->flags & SESSION_ISSECURE_READ )
		{
		/* The MAC size isn't included in the packet length so we have to
		   add it manually */
		extraLength = sessionInfoPtr->authBlocksize;
		}
	if( cryptStatusError( length ) || \
		length + extraLength < SSH2_HEADER_REMAINDER_SIZE || \
		length < ID_SIZE + PADLENGTH_SIZE + SSH2_MIN_PADLENGTH_SIZE || \
		length + extraLength >= sessionInfoPtr->receiveBufSize )
		{
		sMemDisconnect( &stream );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid packet length %ld, should be %d...%d", 
				  cryptStatusError( length ) ? 0 : length,
				  ID_SIZE + PADLENGTH_SIZE + SSH2_MIN_PADLENGTH_SIZE,
				  sessionInfoPtr->receiveBufSize - extraLength ) );
		}
	assert( ( isHandshake && sessionInfoPtr->receiveBufPos == 0 ) || \
			!isHandshake );
	status = sread( &stream, sessionInfoPtr->receiveBuffer + \
							 sessionInfoPtr->receiveBufPos, 
					SSH2_HEADER_REMAINDER_SIZE );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	*packetLength = length;
	*packetExtraLength = extraLength;
	return( CRYPT_OK );
	}

/* Read an SSHv2 handshake packet.  This function is only used during the 
   handshake phase (the data transfer phase has its own read/write code) so 
   we can perform some special-case handling based on this.  In particular 
   we know that packets will always be read into the start of the receive 
   buffer so we don't have to perform special buffer-space-remaining 
   calculations */

int readHSPacketSSH2( SESSION_INFO *sessionInfoPtr, int expectedType,
					  const int minPacketSize )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	long length;
	int padLength = 0, packetType, minPacketLength = minPacketSize;
	int iterationCount = 0, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( expectedType >= SSH2_MSG_DISCONNECT && \
			expectedType <= SSH2_MSG_SPECIAL_REQUEST );
	assert( minPacketSize >= 1 && minPacketSize < 1024 );

	/* Alongside the expected handshake packets the server can send us all 
	   sorts of no-op messages, ranging from explicit no-ops 
	   (SSH2_MSG_IGNORE) through to general chattiness (SSH2_MSG_DEBUG, 
	   SSH2_MSG_USERAUTH_BANNER).  Because we can receive any quantity of 
	   these at any time, we have to run the receive code in a (bounds-
	   checked) loop to strip them out */
	do
		{
		int extraLength;

		/* Read the SSHv2 handshake packet header:

			uint32		length (excluding MAC size)
			byte		padLen
		  [	byte		type - checked but not removed ]
			byte[]		data
			byte[]		padding
			byte[]		MAC

		  The reason why the length and pad length precede the packet type
		  and other information is that these two fields are part of the
		  SSHv2 transport layer while the type and payload are seen as part
		  of the connection layer, although the different RFCs tend to mix
		  them up quite thoroughly */
		assert( sessionInfoPtr->receiveBufPos == 0 && \
				sessionInfoPtr->receiveBufEnd == 0 );
		status = readPacketHeaderSSH2( sessionInfoPtr, expectedType, &length,
									   &extraLength, NULL );
		if( cryptStatusError( status ) )
			return( status );
		assert( length + extraLength >= SSH2_HEADER_REMAINDER_SIZE && \
				length + extraLength < sessionInfoPtr->receiveBufSize );
				/* Guaranteed by readPacketHeaderSSH2() */

		/* Read the remainder of the handshake-packet message.  The change 
		   cipherspec message has length 0 so we only perform the read if 
		   there's packet data present */
		if( length + extraLength > SSH2_HEADER_REMAINDER_SIZE )
			{
			const long remainingLength = length + extraLength - \
										 SSH2_HEADER_REMAINDER_SIZE;

			/* Because this code is called conditionally, we can't make the
			   read part of the fixed-header read but have to do independent
			   handling of shortfalls due to read timeouts */
			status = sread( &sessionInfoPtr->stream,
							sessionInfoPtr->receiveBuffer + \
								SSH2_HEADER_REMAINDER_SIZE,
							remainingLength );
			if( cryptStatusError( status ) )
				{
				sNetGetErrorInfo( &sessionInfoPtr->stream,
								  &sessionInfoPtr->errorInfo );
				return( status );
				}
			if( status != remainingLength )
				{
				retExt( CRYPT_ERROR_TIMEOUT,
						( CRYPT_ERROR_TIMEOUT, SESSION_ERRINFO, 
						  "Timeout during handshake packet remainder read, "
						  "only got %d of %ld bytes", status,
						  remainingLength ) );
				}
			}

		/* Decrypt and MAC the packet if required */
		if( sessionInfoPtr->flags & SESSION_ISSECURE_READ )
			{
			/* Decrypt the remainder of the packet except for the MAC.
			   Sometimes the payload can be zero-length, so we have to check
			   for this before we try the decrypt */
			if( length > SSH2_HEADER_REMAINDER_SIZE )
				{
				status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
										  IMESSAGE_CTX_DECRYPT,
										  sessionInfoPtr->receiveBuffer + \
											SSH2_HEADER_REMAINDER_SIZE,
										  length - SSH2_HEADER_REMAINDER_SIZE );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* MAC the decrypted payload */
			status = checkMacSSH( sessionInfoPtr->iAuthInContext,
								  sshInfo->readSeqNo,
								  sessionInfoPtr->receiveBuffer, 
								  length + extraLength, length, 0, MAC_ALL, 
								  extraLength );
			if( cryptStatusError( status ) )
				{
				/* If we're expecting a service control packet after a change
				   cipherspec packet and don't get it then it's more likely
				   that the problem is due to the wrong key being used than
				   data corruption, so we return a wrong key error instead
				   of bad data */
				if( expectedType == SSH2_MSG_SERVICE_REQUEST || \
					expectedType == SSH2_MSG_SERVICE_ACCEPT )
					{
					retExt( CRYPT_ERROR_WRONGKEY,
							( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
							  "Bad message MAC for handshake packet type "
							  "%d, length %ld, probably due to an "
							  "incorrect key being used to generate the "
							  "MAC", sessionInfoPtr->receiveBuffer[ 1 ], 
							  length ) );
					}
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Bad message MAC for handshake packet type %d, "
						  "length %ld", sessionInfoPtr->receiveBuffer[ 1 ],
						  length ) );
				}
			}
		padLength = sessionInfoPtr->receiveBuffer[ 0 ];
		packetType = sessionInfoPtr->receiveBuffer[ 1 ];
		sshInfo->readSeqNo++;
		}
	while( ( packetType == SSH2_MSG_IGNORE || \
			 packetType == SSH2_MSG_DEBUG || \
			 packetType == SSH2_MSG_USERAUTH_BANNER ) && \
		   ( iterationCount++ < FAILSAFE_ITERATIONS_SMALL ) );
	if( iterationCount >= FAILSAFE_ITERATIONS_SMALL )
		{
		/* We have to be a bit careful here in case this is a strange
		   implementation that sends large numbers of no-op packets as cover
		   traffic.  Complaining after FAILSAFE_ITERATIONS_SMALL consecutive 
		   no-ops seems to be a safe tradeoff between catching DoS's and 
		   handling cover traffic */
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "Peer sent an excessive number of consecutive no-op "
				  "packets, it may be stuck in a loop" ) );
		}
	sshInfo->packetType = packetType;

	/* Adjust the length to account for the fixed-size fields, remember
	   where the data starts, and make sure that there's some payload
	   present (there should always be at least one byte, the packet type) */
	length -= PADLENGTH_SIZE + padLength;
	if( packetType == SSH2_MSG_DISCONNECT )
		{
		/* If we're expecting a standard data packet and we get a disconnect
		   packet due to an error, the length can be less than the expected
		   mimimum length, so we adjust the length to the minimum packet 
		   length of a disconnect packet */
		minPacketLength = ID_SIZE + UINT32_SIZE + \
						  sizeofString32( "", 1 ) + sizeofString32( "", 0 );
		}
	if( length < minPacketLength || \
		length > sessionInfoPtr->receiveBufSize - PADLENGTH_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid length %ld for handshake packet type %d, should "
				  "be %d...%d", length, packetType, minPacketLength,
				  sessionInfoPtr->receiveBufSize - PADLENGTH_SIZE ) );
		}

	/* Move the data down in the buffer to get rid of the header info.
	   This isn't as inefficient as it seems since it's only used for the
	   short handshake messages */
	memmove( sessionInfoPtr->receiveBuffer,
			 sessionInfoPtr->receiveBuffer + PADLENGTH_SIZE, length );

	/* If the other side has gone away, report the details */
	if( packetType == SSH2_MSG_DISCONNECT )
		{
		STREAM stream;

		sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
		assert( sPeek( &stream ) == SSH2_MSG_DISCONNECT );
		status = sgetc( &stream );	/* Skip packet type */
		if( !cryptStatusError( status ) )
			status = getDisconnectInfo( sessionInfoPtr, &stream );
		sMemDisconnect( &stream );
		return( status );
		}

	/* Make sure that we either got what we asked for or one of the allowed
	   special-case packets */
	switch( expectedType )
		{
		case SSH2_MSG_SPECIAL_USERAUTH:
			/* If we're reading a response to a user authentication message
			   then getting a failure response is valid (even if it's not
			   what we're expecting) since it's an indication that an
			   incorrect password was used rather than that there was some
			   general type of failure */
			expectedType = ( packetType == SSH2_MSG_USERAUTH_FAILURE ) ? \
								SSH2_MSG_USERAUTH_FAILURE : \
								SSH2_MSG_USERAUTH_SUCCESS;
			break;

		case SSH2_MSG_SPECIAL_USERAUTH_PAM:
			/* PAM authentication can go through multiple iterations of back-
			   and-forth negotiation, for this case an info-request is also
			   a valid response, otherwise the responses are as for
			   SSH2_MSG_SPECIAL_USERAUTH */
			expectedType = ( packetType == SSH2_MSG_USERAUTH_INFO_REQUEST ) ? \
								SSH2_MSG_USERAUTH_INFO_REQUEST : \
						   ( packetType == SSH2_MSG_USERAUTH_FAILURE ) ? \
								SSH2_MSG_USERAUTH_FAILURE : \
								SSH2_MSG_USERAUTH_SUCCESS;
			break;

		case SSH2_MSG_SPECIAL_CHANNEL:
			/* If we're reading a response to a channel open message then
			   getting a failure response is valid (even if it's not what
			   we're expecting) since it's an indication that the channel
			   open (for example a port-forwarding operation) failed rather
			   than that there was some general type of failure */
			expectedType = ( packetType == SSH2_MSG_CHANNEL_OPEN_FAILURE ) ? \
								SSH2_MSG_CHANNEL_OPEN_FAILURE : \
								SSH2_MSG_CHANNEL_OPEN_CONFIRMATION;
			break;

		case SSH2_MSG_SPECIAL_REQUEST:
			/* If we're at the end of the handshake phase we can get either
			   a global or a channel request to tell us what to do next */
			if( packetType != SSH2_MSG_GLOBAL_REQUEST && \
				packetType != SSH2_MSG_CHANNEL_REQUEST )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid handshake packet type %d, expected "
						  "global or channel request", packetType ) );
				}
			expectedType = packetType;
			break;

		case SSH2_MSG_KEXDH_GEX_REQUEST_OLD:
			/* The ephemeral DH key exchange spec was changed halfway
			   through to try and work around problems with key negotiation,
			   because of this we can see two different types of ephemeral
			   DH request, although they're functionally identical */
			if( packetType == SSH2_MSG_KEXDH_GEX_REQUEST_NEW )
				expectedType = SSH2_MSG_KEXDH_GEX_REQUEST_NEW;
			break;
		}
	if( packetType != expectedType )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid handshake packet type %d, expected %d", 
				  packetType, expectedType ) );
		}

	return( length );
	}

/****************************************************************************
*																			*
*								Write/Wrap a Packet							*
*																			*
****************************************************************************/

/* Unlike SSL, SSH only hashes portions of the handshake, and even then not
   complete packets but arbitrary bits and pieces.  In order to handle this
   we have to be able to break out bits and pieces of data from the stream
   buffer in order to hash them.  The following function extracts a block
   of data from a given position in the stream buffer */

int streamBookmarkComplete( STREAM *stream, void **dataPtrPtr, int *length, 
							const int position )
	{
	const int dataLength = stell( stream ) - position;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( dataPtrPtr, sizeof( void * ) ) );
	assert( isWritePtr( length, sizeof( int ) ) );
	assert( position >= 0 );
	assert( dataLength > 0 || dataLength < stell( stream ) );

	/* Clear return values */
	*dataPtrPtr = NULL;
	*length = 0;

	/* Sanity-check the state */
	if( position < 0 || dataLength <= 0 || dataLength >= stell( stream ) )
		retIntError();

	*length = dataLength;
	return( sMemGetDataBlockAbs( stream, position, dataPtrPtr, dataLength ) );
	}

/* Open a stream to write an SSH2 packet or continue an existing stream to
   write further packets.  This opens the stream (if it's an open), skips
   the storage for the packet header, and writes the packet type */

int openPacketStreamSSH( STREAM *stream, const SESSION_INFO *sessionInfoPtr,
						 const int bufferSize, const int packetType )
	{
	const int streamSize = ( bufferSize == CRYPT_USE_DEFAULT ) ? \
						   sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE : \
						   bufferSize + SSH2_HEADER_SIZE;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( sessionInfoPtr->sendBuffer, streamSize ) );
	assert( streamSize > SSH2_HEADER_SIZE && \
			streamSize <= sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE );

	/* Sanity-check the state */
	if( streamSize <= SSH2_HEADER_SIZE || \
		streamSize > sessionInfoPtr->sendBufSize - EXTRA_PACKET_SIZE )
		retIntError();

	sMemOpen( stream, sessionInfoPtr->sendBuffer, streamSize );
	swrite( stream, "\x00\x00\x00\x00\x00", SSH2_HEADER_SIZE );
	return( sputc( stream, packetType ) );
	}

int continuePacketStreamSSH( STREAM *stream, const int packetType,
							 int *packetOffset )
	{
	const int offset = stell( stream );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( stell( stream ) == 0 || stell( stream ) > SSH2_HEADER_SIZE + 1 );
	assert( isWritePtr( packetOffset, sizeof( int ) ) );

	/* Clear return value */
	*packetOffset = 0;

	swrite( stream, "\x00\x00\x00\x00\x00", SSH2_HEADER_SIZE );
	status = sputc( stream, packetType );
	if( cryptStatusError( status ) )
		return( status );
	*packetOffset = offset;

	return( CRYPT_OK );
	}

/* Send an SSHv2 packet.  During the handshake phase we may be sending
   multiple packets at once, however unlike SSL, SSH requires that each
   packet in a multi-packet group be individually gift-wrapped so we have to
   provide a facility for separately wrapping and sending packets to handle
   this:

	sendBuffer	bStartPtr	
		|			|
		v			v	|<-- payloadLen --->|<-eLen->
		+-----------+---+-------------------+---+---+
		|///////////|hdr|		data		|pad|MAC|
		+-----------+---+-------------------+---+---+
					^<------- length ------>^	|
					|						|	|
				 offset					  stell(s)
					|<------- totalLen -------->| */

int wrapPacketSSH2( SESSION_INFO *sessionInfoPtr, STREAM *stream,
					const int offset, const BOOLEAN useQuantisedPadding,
					const BOOLEAN isWriteableStream )
	{
	SSH_INFO *sshInfo = sessionInfoPtr->sessionSSH;
	const int length = stell( stream ) - offset;
	const int payloadLength = length - SSH2_HEADER_SIZE;
	const int padBlockSize = max( sessionInfoPtr->cryptBlocksize, 8 );
	void *bufStartPtr;
	int extraLength = ( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE ) ? \
					  sessionInfoPtr->authBlocksize : 0;
	int padLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( offset >= 0 );
	assert( length >= SSH2_HEADER_SIZE );
	assert( payloadLength >= 0 && payloadLength < length && \
			offset + length + extraLength <= sessionInfoPtr->sendBufSize );

	/* Sanity-check the state */
	if( payloadLength < 0 || payloadLength >= length || \
		offset + length + extraLength > sessionInfoPtr->sendBufSize )
		retIntError();

	/* Evaluate the number of padding bytes that we need to add to a packet
	   to make it a multiple of the cipher block size long, with a minimum
	   padding size of SSH2_MIN_PADLENGTH_SIZE bytes.  Note that this padding
	   is required even when there's no encryption being applied(?), although 
	   we set the padding to all zeroes in this case */
	if( useQuantisedPadding )
		{
		/* It's something like a user-authentication packet that (probably) 
		   contains a password, make it fixed-length to hide the length 
		   information */
		for( padLength = 256;
			 ( length + SSH2_MIN_PADLENGTH_SIZE ) > padLength;
			 padLength += 256 );
		padLength -= length;
		}
	else
		{
		padLength = roundUp( length + SSH2_MIN_PADLENGTH_SIZE,
							 padBlockSize ) - length;
		}
	assert( padLength >= SSH2_MIN_PADLENGTH_SIZE && padLength < 256 );
	if( padLength < SSH2_MIN_PADLENGTH_SIZE || padLength >= 256 )
		retIntError();
	extraLength += padLength;

	/* Make sure that there's enough room for the padding and MAC */
	status = sMemGetDataBlockAbs( stream, offset, &bufStartPtr, 
								  length + extraLength );
	if( cryptStatusError( status ) )
		{
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_OVERFLOW );
		}

	/* Add the SSH packet header, padding, and MAC:

		uint32		length (excluding MAC size)
		byte		padLen
	  [	byte[]		data ]
		byte[]		padding
		byte[]		MAC */
	if( isWriteableStream )
		{
		sseek( stream, offset );
		writeUint32( stream, 1 + payloadLength + padLength );
		sputc( stream, padLength );
		sSkip( stream, payloadLength );
		}
	else
		{
		STREAM headerStream;

		/* If it's a non-writeable stream we have to insert the header data
		   directly into the stream buffer */
		assert( offset == 0 && \
				stell( stream ) == SSH2_HEADER_SIZE + payloadLength );
		sMemOpen( &headerStream, bufStartPtr, SSH2_HEADER_SIZE );
		writeUint32( &headerStream, 1 + payloadLength + padLength );
		sputc( &headerStream, padLength );
		sMemDisconnect( &headerStream );
		}
	if( sessionInfoPtr->flags & SESSION_ISSECURE_WRITE )
		{
		MESSAGE_DATA msgData;
		BYTE padding[ 256 + 8 ];
		const int totalLength = SSH2_HEADER_SIZE + payloadLength + padLength;

		/* Append the padding */
		setMessageData( &msgData, padding, padLength );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( isWriteableStream )
			status = swrite( stream, padding, padLength );
		else
			{
			STREAM trailerStream;

			assert( stell( stream ) == length );
			sMemOpen( &trailerStream, ( BYTE * ) bufStartPtr + length, 
					  padLength );
			status = swrite( &trailerStream, padding, padLength );
			sMemDisconnect( &trailerStream );
			sSkip( stream, padLength );
			}
		if( cryptStatusError( status ) )
			retIntError();

		/* MAC the data and append the MAC to the stream.  We skip the 
		   length value at the start since this is computed by the MAC'ing 
		   code */
		status = createMacSSH( sessionInfoPtr->iAuthOutContext,
							   sshInfo->writeSeqNo, 
							   ( BYTE * ) bufStartPtr + LENGTH_SIZE,
							   length + extraLength - LENGTH_SIZE, 
							   totalLength - LENGTH_SIZE );
		if( cryptStatusError( status ) )
			return( status );
		sSkip( stream, sessionInfoPtr->authBlocksize );

		/* Encrypt the entire packet except for the MAC */
		status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
								  IMESSAGE_CTX_ENCRYPT, bufStartPtr,
								  totalLength );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		BYTE padding[ 256 + 8 ];

		/* If there's no security in effect yet, the padding is all zeroes */
		assert( isWriteableStream );
		memset( padding, 0, padLength );
		status = swrite( stream, padding, padLength );
		if( cryptStatusError( status ) )
			retIntError();
		}
	sshInfo->writeSeqNo++;

	return( CRYPT_OK );
	}

int sendPacketSSH2( SESSION_INFO *sessionInfoPtr, STREAM *stream,
					const BOOLEAN sendOnly )
	{
	int length = stell( stream );
	void *dataPtr;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* If it's not a pre-assembled packet, wrap up the payload in an SSH
	   packet */
	if( !sendOnly )
		{
		status = wrapPacketSSH2( sessionInfoPtr, stream, 0, FALSE, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Send the contents of the stream to the peer */
	length = stell( stream );
	status = sMemGetDataBlockAbs( stream, 0, &dataPtr, length );
	if( cryptStatusOK( status ) )
		status = swrite( &sessionInfoPtr->stream, dataPtr, length );
	if( cryptStatusError( status ) && \
		!( sessionInfoPtr->flags & SESSION_NOREPORTERROR ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream,
						  &sessionInfoPtr->errorInfo );
		return( status );
		}
	return( CRYPT_OK );	/* swrite() returns a byte count */
	}
#endif /* USE_SSH */