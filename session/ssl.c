/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Session Management					*
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
*								Utility Functions							*
*																			*
****************************************************************************/

/* Initialise and destroy the handshake state information */

STDC_NONNULL_ARG( ( 1 ) ) \
static void destroyHandshakeInfo( INOUT SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* Destroy any active contexts.  We need to do this here (even though
	   it's also done in the general session code) to provide a clean exit in
	   case the session activation fails, so that a second activation attempt
	   doesn't overwrite still-active contexts */
	destroyHandshakeCryptInfo( handshakeInfo );

	zeroise( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int initHandshakeInfo( INOUT SESSION_INFO *sessionInfoPtr,
							  OUT SSL_HANDSHAKE_INFO *handshakeInfo,
							  const BOOLEAN isServer )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	memset( handshakeInfo, 0, sizeof( SSL_HANDSHAKE_INFO ) );
	if( isServer )
		initSSLserverProcessing( handshakeInfo );
	else
		initSSLclientProcessing( handshakeInfo );
	return( initHandshakeCryptInfo( handshakeInfo ) );
	}

/* SSL uses 24-bit lengths in some places even though the maximum packet 
   length is only 16 bits (actually it's limited even further by the spec 
   to 14 bits).  To handle this odd length we define our own read/
   writeUint24() functions that always set the high byte to zero */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
int readUint24( INOUT STREAM *stream )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( status != 0 )
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
	return( readUint16( stream ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
int writeUint24( INOUT STREAM *stream, IN_LENGTH const int length )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES_S( length >= 0 && \
				length < CRYPT_MAX_IVSIZE + MAX_PACKET_SIZE + \
						 CRYPT_MAX_HASHSIZE + CRYPT_MAX_IVSIZE );

	sputc( stream, 0 );
	return( writeUint16( stream, length ) );
	}

/****************************************************************************
*																			*
*						Read/Write SSL Certificate Chains					*
*																			*
****************************************************************************/

/* Read/write an SSL certificate chain:

	byte		ID = SSL_HAND_CERTIFICATE
	uint24		len
	uint24		certListLen
	uint24		certLen			| 1...n certificates ordered
	byte[]		certificate		|   leaf -> root */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readSSLCertChain( INOUT SESSION_INFO *sessionInfoPtr, 
					  INOUT SSL_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT STREAM *stream,
					  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertChain, 
					  const BOOLEAN isServer )
	{
	CRYPT_ALGO_TYPE algorithm;
	CRYPT_CERTIFICATE iLocalCertChain;
	const ATTRIBUTE_LIST *fingerprintPtr = \
				findSessionInfo( sessionInfoPtr->attributeList,
								 CRYPT_SESSINFO_SERVER_FINGERPRINT );
	MESSAGE_DATA msgData;
	BYTE certFingerprint[ CRYPT_MAX_HASHSIZE + 8 ];
#ifdef USE_ERRMSGS
	const char *peerTypeName = isServer ? "Client" : "Server";
#endif /* USE_ERRMSGS */
	int certFingerprintLength, chainLength, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( iCertChain, sizeof( CRYPT_CERTIFICATE ) ) );

	/* Clear return value */
	*iCertChain = CRYPT_ERROR;

	/* Make sure that the packet header is in order */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  SSL_HAND_CERTIFICATE, 
								  isServer ? 0 : LENGTH_SIZE + MIN_CERTSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( isServer && ( length == 0 || length == LENGTH_SIZE ) )
		{
		ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;

		/* There is a special case in which a too-short certificate packet 
		   is valid and that's where it constitutes the TLS equivalent of an 
		   SSL no-certificates alert.  SSLv3 sent an 
		   SSL_ALERT_NO_CERTIFICATE alert to indicate that the client 
		   doesn't have a certificate, which is handled by the 
		   readHSPacketSSL() call.  TLS changed this to send an empty 
		   certificate packet instead, supposedly because it lead to 
		   implementation problems (presumably it's necessary to create a 
		   state machine-based implementation to reproduce these problems, 
		   whatever they are).  The TLS 1.0 spec is ambiguous as to what 
		   constitutes an empty packet, it could be either a packet with a 
		   length of zero or a packet containing a zero-length certificate 
		   list so we check for both.  TLS 1.1 fixed this to say that that 
		   certListLen entry has a length of zero.  To report this condition 
		   we fake the error indicators for consistency with the status 
		   obtained from an SSLv3 no-certificate alert */
		errorInfo->errorCode = SSL_ALERT_NO_CERTIFICATE;
		retExt( CRYPT_ERROR_PERMISSION,
				( CRYPT_ERROR_PERMISSION, SESSION_ERRINFO, 
				  "Received TLS alert message: No certificate" ) );
		}
	status = chainLength = readUint24( stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate chain" ) );
		}
	if( chainLength < MIN_CERTSIZE || chainLength != length - LENGTH_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate chain length %d, should be %d",
				  chainLength, length - LENGTH_SIZE ) );
		}

	/* Import the certificate chain.  This isn't a true certificate chain (in 
	   the sense of being degenerate PKCS #7 SignedData) but a special-case 
	   SSL-encoded certificate chain */
	status = importCertFromStream( stream, &iLocalCertChain, 
								   DEFAULTUSER_OBJECT_HANDLE,
								   CRYPT_ICERTTYPE_SSL_CERTCHAIN,
								   chainLength );
	if( cryptStatusError( status ) )
		{
		/* There are sufficient numbers of broken certificates around that 
		   if we run into a problem importing one we provide a custom error
		   message telling the user to try again with a reduced compliance
		   level */
		if( status == CRYPT_ERROR_BADDATA || status == CRYPT_ERROR_INVALID )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "%s provided a broken/invalid certificate, try again "
					  "with a reduced level of certificate compliance "
					  "checking", peerTypeName ) );
			}
		retExt( status, 
				( status, SESSION_ERRINFO, "Invalid certificate chain" ) );
		}

	/* Get information on the chain */
	status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE,
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	setMessageData( &msgData, certFingerprint, CRYPT_MAX_HASHSIZE );
	if( fingerprintPtr != NULL )
		{
		const CRYPT_ATTRIBUTE_TYPE fingerprintAttribute = \
							( fingerprintPtr->valueLength == 16 ) ? \
								CRYPT_CERTINFO_FINGERPRINT_MD5 : \
							( fingerprintPtr->valueLength == 32 ) ? \
								CRYPT_IATTRIBUTE_FINGERPRINT_SHA2 : \
							CRYPT_CERTINFO_FINGERPRINT_SHA;

		/* Use the hint provided by the fingerprint size to select the
		   appropriate algorithm to generate the fingerprint that we want
		   to compare against */
		status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, fingerprintAttribute );
		}
	else
		{
		/* There's no algorithm hint available, use the default of SHA-1 */
		status = krnlSendMessage( iLocalCertChain, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_FINGERPRINT_SHA );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	certFingerprintLength = msgData.length;
	if( !isServer && algorithm != handshakeInfo->authAlgo )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
				  "Server key algorithm %d doesn't match negotiated "
				  "algorithm %d", algorithm, handshakeInfo->authAlgo ) );
		}

	/* Either compare the certificate fingerprint to a supplied one or save 
	   it for the caller to examine */
	if( fingerprintPtr != NULL )
		{
		/* The caller has supplied a certificate fingerprint, compare it to 
		   the received certificate's fingerprint to make sure that we're 
		   talking to the right system */
		if( fingerprintPtr->valueLength != certFingerprintLength || \
			memcmp( fingerprintPtr->value, certFingerprint, 
					certFingerprintLength ) )
			{
			krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
					  "%s key didn't match key fingerprint", peerTypeName ) );
			}
		}
	else
		{
		/* Remember the certificate fingerprint in case the caller wants to 
		   check it.  We don't worry if the add fails, it's a minor thing 
		   and not worth aborting the handshake for */
		( void ) addSessionInfoS( &sessionInfoPtr->attributeList,
								  CRYPT_SESSINFO_SERVER_FINGERPRINT,
								  certFingerprint, certFingerprintLength );
		}

	/* Make sure that we can perform the required operation using the key
	   that we've been given.  For a client key we need signing capability,
	   for a server key when using DH/ECDH key agreement we also need 
	   signing capability to authenticate the DH/ECDH parameters, and for 
	   an RSA key transport key we need encryption capability.  This 
	   operation also performs a variety of additional checks alongside the 
	   obvious one so it's a good general health check before we go any 
	   further */
	status = krnlSendMessage( iLocalCertChain, IMESSAGE_CHECK, NULL,
							  isServer || \
								isKeyxAlgo( handshakeInfo->keyexAlgo ) ? \
								MESSAGE_CHECK_PKC_SIGCHECK : \
								MESSAGE_CHECK_PKC_ENCRYPT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iLocalCertChain, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_WRONGKEY,
				( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
				  "%s provided a key incapable of being used for %s",
				  peerTypeName,
				  isServer ? "client authentication" : \
				  isKeyxAlgo( algorithm ) ? "key exchange authentication" : \
										    "encryption" ) );
		}
	*iCertChain = iLocalCertChain;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSSLCertChain( INOUT SESSION_INFO *sessionInfoPtr, 
					   INOUT STREAM *stream )
	{
	int packetOffset, certListOffset = DUMMY_INIT, certListEndPos, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	status = continueHSPacketStream( stream, SSL_HAND_CERTIFICATE, 
									 &packetOffset );
	if( cryptStatusError( status ) )
		return( status );
	if( sessionInfoPtr->privateKey == CRYPT_ERROR )
		{
		/* If there's no private key available, write an empty certificate 
		   chain */
		status = writeUint24( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		return( completeHSPacketStream( stream, packetOffset ) );
		}

	/* Write a dummy length and export the certificate list to the stream */
	status = writeUint24( stream, 0 );
	if( cryptStatusOK( status ) )
		{
		certListOffset = stell( stream );
		status = exportCertToStream( stream, sessionInfoPtr->privateKey,
									 CRYPT_ICERTFORMAT_SSL_CERTCHAIN );
		}
	if( cryptStatusError( status ) )
		return( status );
	certListEndPos = stell( stream );

	/* Go back and insert the length, then wrap up the packet */
	sseek( stream, certListOffset - LENGTH_SIZE );
	status = writeUint24( stream, certListEndPos - certListOffset );
	sseek( stream, certListEndPos );
	if( cryptStatusError( status ) )
		return( status );
	return( completeHSPacketStream( stream, packetOffset ) );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Close a previously-opened SSL session */

STDC_NONNULL_ARG( ( 1 ) ) \
static void shutdownFunction( INOUT SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	sendCloseAlert( sessionInfoPtr, FALSE );
	sNetDisconnect( &sessionInfoPtr->stream );
	}

/* Connect to an SSL server/client */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int abortStartup( INOUT SESSION_INFO *sessionInfoPtr,
						 INOUT_OPT SSL_HANDSHAKE_INFO *handshakeInfo,
						 const BOOLEAN cleanupSecurityContexts,
						 IN_ERROR const int status )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( handshakeInfo == NULL || \
			isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	REQUIRES( cryptStatusError( status ) );

	sendHandshakeFailAlert( sessionInfoPtr );
	if( cleanupSecurityContexts )
		destroySecurityContextsSSL( sessionInfoPtr );
	if( handshakeInfo != NULL )
		destroyHandshakeInfo( handshakeInfo );
	sNetDisconnect( &sessionInfoPtr->stream );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int commonStartup( INOUT SESSION_INFO *sessionInfoPtr,
						  const BOOLEAN isServer )
	{
	SSL_HANDSHAKE_INFO handshakeInfo;
	BOOLEAN resumedSession = FALSE;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Initialise the handshake information and begin the handshake */
	status = initHandshakeInfo( sessionInfoPtr, &handshakeInfo, isServer );
	if( cryptStatusOK( status ) )
		status = handshakeInfo.beginHandshake( sessionInfoPtr,
											   &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		if( status == OK_SPECIAL )
			resumedSession = TRUE;
		else
			{
			return( abortStartup( sessionInfoPtr, &handshakeInfo, FALSE,
								  status ) );
			}
		}

	/* Exchange keys with the server */
	if( !resumedSession )
		{
		status = handshakeInfo.exchangeKeys( sessionInfoPtr,
											 &handshakeInfo );
		if( cryptStatusError( status ) )
			return( abortStartup( sessionInfoPtr, &handshakeInfo, TRUE,
								  status ) );
		}

	/* Complete the handshake */
	status = completeHandshakeSSL( sessionInfoPtr, &handshakeInfo, !isServer,
								   resumedSession );
	destroyHandshakeInfo( &handshakeInfo );
	if( cryptStatusError( status ) )
		return( abortStartup( sessionInfoPtr, NULL, TRUE, status ) );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientStartup( INOUT SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Complete the handshake using the common client/server code */
	return( commonStartup( sessionInfoPtr, FALSE ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int serverStartup( INOUT SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Complete the handshake using the common client/server code */
	return( commonStartup( sessionInfoPtr, TRUE ) );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getAttributeFunction( INOUT SESSION_INFO *sessionInfoPtr,
								 OUT void *data, 
								 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CERTIFICATE *certPtr = ( CRYPT_CERTIFICATE * ) data;
	CRYPT_CERTIFICATE iCryptCert = isServer( sessionInfoPtr ) ? \
		sessionInfoPtr->iKeyexAuthContext : sessionInfoPtr->iKeyexCryptContext;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( type == CRYPT_SESSINFO_RESPONSE );

	/* If we didn't get a client/server certificate there's nothing to 
	   return */
	if( iCryptCert == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Return the information to the caller */
	krnlSendNotifier( iCryptCert, IMESSAGE_INCREFCOUNT );
	*certPtr = iCryptCert;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Get/Put Data Functions						*
*																			*
****************************************************************************/

/* Read/write data over the SSL link */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readHeaderFunction( INOUT SESSION_INFO *sessionInfoPtr,
							   INOUT READSTATE_INFO *readInfo )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	STREAM stream;
	int packetLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	/* Clear return value */
	*readInfo = READINFO_NONE;

	/* Read the SSL packet header data */
	status = readFixedHeader( sessionInfoPtr, sslInfo->headerBuffer, 
							  sessionInfoPtr->receiveBufStartOfs );
	if( cryptStatusError( status ) )
		{
		/* OK_SPECIAL means that we got a soft timeout before the entire 
		   header was read */
		return( ( status == OK_SPECIAL ) ? 0 : status );
		}

	/* Since data errors are always fatal, we make all errors fatal until
	   we've finished handling the header */
	*readInfo = READINFO_FATAL;

	/* Check for an SSL alert message */
	if( sslInfo->headerBuffer[ 0 ] == SSL_MSG_ALERT )
		return( processAlert( sessionInfoPtr, sslInfo->headerBuffer, 
							  sessionInfoPtr->receiveBufStartOfs ) );

	/* Process the header data */
	sMemConnect( &stream, sslInfo->headerBuffer, 
				 sessionInfoPtr->receiveBufStartOfs );
	status = checkPacketHeaderSSL( sessionInfoPtr, &stream, &packetLength );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Determine how much data we'll be expecting */
	sessionInfoPtr->pendingPacketLength = \
		sessionInfoPtr->pendingPacketRemaining = packetLength;

	/* Indicate that we got the header */
	*readInfo = READINFO_NOOP;
	return( OK_SPECIAL );
	}

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int processBodyFunction( INOUT SESSION_INFO *sessionInfoPtr,
								INOUT READSTATE_INFO *readInfo )
	{
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( readInfo, sizeof( READSTATE_INFO ) ) );

	/* All errors processing the payload are fatal */
	*readInfo = READINFO_FATAL;

	/* Unwrap the payload */
	status = unwrapPacketSSL( sessionInfoPtr, 
							  sessionInfoPtr->receiveBuffer + \
								sessionInfoPtr->receiveBufPos, 
							  sessionInfoPtr->pendingPacketLength, 
							  &length, SSL_MSG_APPLICATION_DATA );
	if( cryptStatusError( status ) )
		return( status );

	*readInfo = READINFO_NONE;
	return( length );
	}

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
static int preparePacketFunction( INOUT SESSION_INFO *sessionInfoPtr )
	{
	STREAM stream;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( !( sessionInfoPtr->flags & SESSION_SENDCLOSED ) );
	REQUIRES( !( sessionInfoPtr->protocolFlags & SSL_PFLAG_ALERTSENT ) );

	/* Wrap up the payload ready for sending.  Since this is wrapping in-
	   place data we first open a write stream to add the header, then open
	   a read stream covering the full buffer in preparation for wrapping
	   the packet (the first operation looks a bit counter-intuitive because
	   we're opening a packet stream and then immediately closing it again,
	   but this is as intended since all that we're using it for is to write
	   the packet header at the start).  Note that we connect the later read 
	   stream to the full send buffer (bufSize) even though we only advance 
	   the current stream position to the end of the stream contents 
	   (bufPos), since the packet-wrapping process adds further data to the 
	   stream that exceeds the current stream position */
	status = openPacketStreamSSL( &stream, sessionInfoPtr, 0,
								  SSL_MSG_APPLICATION_DATA );
	if( cryptStatusError( status ) )
		return( status );
	sMemDisconnect( &stream );
	sMemConnect( &stream, sessionInfoPtr->sendBuffer,
				 sessionInfoPtr->sendBufSize );
	status = sSkip( &stream, sessionInfoPtr->sendBufPos );
	if( cryptStatusOK( status ) )
		status = wrapPacketSSL( sessionInfoPtr, &stream, 0 );
	if( cryptStatusOK( status ) )
		status = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setAccessMethodSSL( INOUT SESSION_INFO *sessionInfoPtr )
	{
	static const ALTPROTOCOL_INFO altProtocolInfo = {
		/* SSL tunnelled via an HTTP proxy.  This is a special case in that
		   the initial connection is made using HTTP, but subsequent
		   communications are via a direct TCP/IP connection that goes
		   through the proxy */
		STREAM_PROTOCOL_TCPIP,		/* Alt.protocol type */
		"https://", 8,				/* Alt.protocol URI type */
		80,							/* Alt.protocol port */
		0,							/* Protocol flags to replace */
		SESSION_USEHTTPTUNNEL		/* Alt.protocol flags */
		};
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		FALSE,						/* Request-response protocol */
		SESSION_NONE,				/* Flags */
		SSL_PORT,					/* SSL port */
		SESSION_NEEDS_PRIVKEYSIGN,	/* Client attributes */
			/* The client private key is optional but if present, it has to
			   be signature-capable */
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYCRYPT | \
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_KEYORPASSWORD,
			/* In theory we need neither a private key nor a password 
			   because the caller can provide the password during the
			   handshake in response to a CRYPT_ENVELOPE_RESOURCE
			   notification, however this facility is likely to be 
			   barely-used in comparison to users forgetting to add server
			   certificates and the like, so we require some sort of 
			   server-side key set in advance */
		SSL_MINOR_VERSION_TLS,		/* TLS 1.0 */
			SSL_MINOR_VERSION_SSL, SSL_MINOR_VERSION_TLS11,
			/* We default to TLS 1.0 rather than TLS 1.1 because it's likely 
			   that support for the latter will be hit-and-miss for some 
			   time */

		/* Protocol-specific information */
		EXTRA_PACKET_SIZE + \
			MAX_PACKET_SIZE,		/* Send/receive buffer size */
		SSL_HEADER_SIZE,			/* Payload data start */
			/* This may be adjusted during the handshake if we're talking
			   TLS 1.1, which prepends extra data in the form of an IV to
			   the payload */
		MAX_PACKET_SIZE,			/* (Default) maximum packet size */
		&altProtocolInfo			/* Alt.transport protocol */
		};

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Set the access method pointers */
	sessionInfoPtr->protocolInfo = &protocolInfo;
	sessionInfoPtr->shutdownFunction = shutdownFunction;
	sessionInfoPtr->transactFunction = isServer( sessionInfoPtr ) ? \
									   serverStartup : clientStartup;
	sessionInfoPtr->getAttributeFunction = getAttributeFunction;
	sessionInfoPtr->readHeaderFunction = readHeaderFunction;
	sessionInfoPtr->processBodyFunction = processBodyFunction;
	sessionInfoPtr->preparePacketFunction = preparePacketFunction;

	return( CRYPT_OK );
	}
#endif /* USE_SSL */
