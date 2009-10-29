/****************************************************************************
*																			*
*			cryptlib SSL v3/TLS Handshake Completion Management				*
*					Copyright Peter Gutmann 1998-2008						*
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
*					Read/Write Handshake Completion Messages				*
*																			*
****************************************************************************/

/* Pre-encoded finished message templates that we can hash when we're
   creating our own finished message */

#define FINISHED_TEMPLATE_SIZE				4

typedef BYTE SSL_MESSAGE_TEMPLATE[ FINISHED_TEMPLATE_SIZE ];

static const SSL_MESSAGE_TEMPLATE FAR_BSS finishedTemplate[] = {
	/*	byte		ID = SSL_HAND_FINISHED
		uint24		len = 16 + 20 (SSL), 12 (TLS) */
	{ SSL_HAND_FINISHED, 0, 0, MD5MAC_SIZE + SHA1MAC_SIZE },
	{ SSL_HAND_FINISHED, 0, 0, TLS_HASHEDMAC_SIZE },
	{ SSL_HAND_FINISHED, 0, 0, TLS_HASHEDMAC_SIZE },
	{ SSL_HAND_FINISHED, 0, 0, TLS_HASHEDMAC_SIZE }
	};

/* Read/write the handshake completion data (change cipherspec + finished) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readHandshakeCompletionData( INOUT SESSION_INFO *sessionInfoPtr,
										IN_BUFFER( hashValuesLength ) \
											const BYTE *hashValues,
										IN_LENGTH_SHORT const int hashValuesLength )
	{
	STREAM stream;
	BYTE macBuffer[ MD5MAC_SIZE + SHA1MAC_SIZE + 8 ];
	const int macValueLength = \
					( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL ) ? \
					MD5MAC_SIZE + SHA1MAC_SIZE : TLS_HASHEDMAC_SIZE;
	int length, value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( hashValues, hashValuesLength ) );

	REQUIRES( hashValuesLength == macValueLength );

	/* Process the other side's change cipher spec:

		byte		type = SSL_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 1
		byte		1 */
	status = readHSPacketSSL( sessionInfoPtr, NULL, &length,
							  SSL_MSG_CHANGE_CIPHER_SPEC );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	value = sgetc( &stream );
	sMemDisconnect( &stream );
	if( value != 1 )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid change cipher spec packet payload, expected "
				  "0x01, got 0x%02X", value ) );
		}

	/* Change cipher spec was the last message not subject to security
	   encapsulation so we turn on security for the read channel after
	   seeing it.  In addition if we're using TLS 1.1 explicit IVs the
	   effective header size changes because of the extra IV data, so we
	   record the size of the additional IV data and update the receive
	   buffer start offset to accomodate it */
	sessionInfoPtr->flags |= SESSION_ISSECURE_READ;
	if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS11 && \
		sessionInfoPtr->cryptBlocksize > 1 )
		{
		sessionInfoPtr->sessionSSL->ivSize = sessionInfoPtr->cryptBlocksize;
		sessionInfoPtr->receiveBufStartOfs += sessionInfoPtr->cryptBlocksize;
		}

	/* Process the other side's finished message.  Since this is the first 
	   chance that we have to test whether our crypto keys are set up 
	   correctly, we report problems with decryption or MAC'ing or a failure 
	   to find any recognisable header as a wrong key rather than a bad data 
	   error:

		byte		ID = SSL_HAND_FINISHED
		uint24		len
			SSLv3						TLS
		byte[16]	MD5 MAC			byte[12]	hashedMAC
		byte[20]	SHA-1 MAC */
	status = readHSPacketSSL( sessionInfoPtr, NULL, &length, 
							  SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	status = unwrapPacketSSL( sessionInfoPtr, sessionInfoPtr->receiveBuffer, 
							  length, &length, SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_BADDATA || \
			status == CRYPT_ERROR_SIGNATURE )
			{
			retExtErr( CRYPT_ERROR_WRONGKEY,
					   ( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
						 SESSION_ERRINFO, 
						 "Decrypted data was corrupt, probably due to "
						 "incorrect encryption keys being negotiated "
						 "during the handshake: " ) );
			}
		return( status );
		}
	sMemConnect( &stream, sessionInfoPtr->receiveBuffer, length );
	status = checkHSPacketHeader( sessionInfoPtr, &stream, &length,
								  SSL_HAND_FINISHED, macValueLength );
	if( cryptStatusOK( status ) )
		{
		if( length != macValueLength )
			{
			/* A length mis-match can only be an overflow, since an
			   underflow would be caught by checkHSPacketHeader() */
			status = CRYPT_ERROR_OVERFLOW;
			}
		else
			status = sread( &stream, macBuffer, macValueLength );
		}
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_BADDATA )
			{
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
					  "Invalid handshake finished packet, probably due to "
					  "incorrect encryption keys being negotiated during "
					  "the handshake" ) );
			}
		return( status );
		}

	/* Make sure that the dual MAC/hashed MAC of all preceding messages is
	   valid */
	if( !compareDataConstTime( hashValues, macBuffer, macValueLength ) )
		{
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Bad MAC for handshake messages, handshake messages were "
				  "corrupted/modified" ) );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int writeHandshakeCompletionData( INOUT SESSION_INFO *sessionInfoPtr,
										 INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
										 IN_BUFFER( hashValuesLength ) \
											const BYTE *hashValues, 
										 IN_LENGTH_SHORT const int hashValuesLength,
										 const BOOLEAN continuedStream )
	{
	STREAM *stream = &handshakeInfo->stream;
	int offset = 0, ccsEndPos, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( hashValues, hashValuesLength ) );

	REQUIRES( hashValuesLength > 0 && \
			  hashValuesLength < MAX_INTLENGTH_SHORT );

	/* Build the change cipher spec packet:

		byte		type = SSL_MSG_CHANGE_CIPHER_SPEC
		byte[2]		version = { 0x03, 0x0n }
		uint16		len = 1
		byte		1

	   Since change cipher spec is its own protocol, we use SSL-level packet
	   encoding rather than handshake protocol-level encoding */
	if( continuedStream )
		{
		status = continuePacketStreamSSL( stream, sessionInfoPtr,
										  SSL_MSG_CHANGE_CIPHER_SPEC, 
										  &offset );
		}
	else
		{
		status = openPacketStreamSSL( stream, sessionInfoPtr, 
									  CRYPT_USE_DEFAULT,
									  SSL_MSG_CHANGE_CIPHER_SPEC );
		}
	if( cryptStatusError( status ) )
		return( status );
	status = sputc( stream, 1 );
	if( cryptStatusOK( status ) )
		status = completePacketStreamSSL( stream, offset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* Change cipher spec was the last message not subject to security
	   encapsulation so we turn on security for the write channel after
	   seeing it.  In addition if we're using TLS 1.1 explicit IVs the
	   effective header size changes because of the extra IV data, so we
	   record the size of the additional IV data and update the receive
	   buffer start offset to accomodate it */
	sessionInfoPtr->flags |= SESSION_ISSECURE_WRITE;
	if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS11 && \
		sessionInfoPtr->cryptBlocksize > 1 )
		{
		sessionInfoPtr->sessionSSL->ivSize = sessionInfoPtr->cryptBlocksize;
		sessionInfoPtr->sendBufStartOfs += sessionInfoPtr->cryptBlocksize;
		}

	/* Build the finished packet.  The initiator sends the MAC of the
	   contents of every handshake packet before the finished packet, the
	   responder sends the MAC of the contents of every packet before its own
	   finished packet but including the MAC of the initiator's packet
	   contents:

		byte		ID = SSL_HAND_FINISHED
		uint24		len
			SSLv3						TLS
		byte[16]	MD5 MAC			byte[12]	hashedMAC
		byte[20]	SHA-1 MAC */
	status = continuePacketStreamSSL( stream, sessionInfoPtr,
									  SSL_MSG_HANDSHAKE, &ccsEndPos );
	if( cryptStatusOK( status ) )
		status = continueHSPacketStream( stream, SSL_HAND_FINISHED, 
										 &offset );
	if( cryptStatusOK( status ) )
		{
		status = swrite( stream, hashValues, hashValuesLength );
		if( cryptStatusOK( status ) )
			status = completeHSPacketStream( stream, offset );
		}
	if( cryptStatusOK( status ) )
		status = wrapPacketSSL( sessionInfoPtr, stream, ccsEndPos );
	if( cryptStatusOK( status ) )
		status = sendPacketSSL( sessionInfoPtr, stream,
								TRUE );
	sMemDisconnect( stream );

	return( status );
	}

/****************************************************************************
*																			*
*						Complete the SSL/TLS Handshake						*
*																			*
****************************************************************************/

/* Complete the handshake with the client or server.  The logic gets a bit
   complex here because the roles of the client and server are reversed if
   we're resuming a session:

		Normal					Resumed
	Client		Server		Client		Server
	------		------		------		------
		   <--- ...			Hello  --->
	KeyEx  --->					   <---	Hello
	CCS	   --->					   <--- CCS
	Fin	   --->					   <--- Fin
		   <---	CCS			CCS	   --->
		   <---	Fin			Fin	   --->

   Because of this the handshake-completion step treats the two sides as
   initiator and responder rather than client and server.  The overall flow
   is then:

	dualMAC( initiator );
	if( !initiator )
		read initiator CCS + Fin;
	dualMAC( responder );
	send initiator/responder CCS + Fin;
	if( initiator )
		read responder CCS + Fin; */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int completeHandshakeSSL( INOUT SESSION_INFO *sessionInfoPtr,
						  INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						  const BOOLEAN isClient,
						  const BOOLEAN isResumedSession )
	{
	CRYPT_CONTEXT initiatorMD5context, initiatorSHA1context;
	CRYPT_CONTEXT responderMD5context, responderSHA1context;
	BYTE masterSecret[ SSL_SECRET_SIZE + 8 ];
	BYTE keyBlock[ MAX_KEYBLOCK_SIZE + 8 ];
	BYTE initiatorHashes[ ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	BYTE responderHashes[ ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	const void *sslInitiatorString, *sslResponderString;
	const void *tlsInitiatorString, *tlsResponderString;
	const BOOLEAN isInitiator = isResumedSession ? !isClient : isClient;
	int initiatorHashLength, responderHashLength;
	int sslLabelLength, tlsLabelLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	REQUIRES( MAX_KEYBLOCK_SIZE >= ( sessionInfoPtr->authBlocksize + \
									 handshakeInfo->cryptKeysize +
									 sessionInfoPtr->cryptBlocksize ) * 2 );
	REQUIRES( handshakeInfo->authAlgo == CRYPT_ALGO_NONE || \
			  ( isEccAlgo( handshakeInfo->keyexAlgo ) && \
				handshakeInfo->premasterSecretSize >= MIN_PKCSIZE_ECC ) || \
			  ( !isEccAlgo( handshakeInfo->keyexAlgo ) && \
				handshakeInfo->premasterSecretSize >= SSL_SECRET_SIZE ) );

	/* Perform the necessary juggling of values for the reversed message
	   flow of resumed sessions */
	if( isResumedSession )
		{
		/* Resumed session, initiator = server, responder = client */
		initiatorMD5context = handshakeInfo->serverMD5context;
		initiatorSHA1context = handshakeInfo->serverSHA1context;
		responderMD5context = handshakeInfo->clientMD5context;
		responderSHA1context = handshakeInfo->clientSHA1context;
		sslInitiatorString = SSL_SENDER_SERVERLABEL;
		sslResponderString = SSL_SENDER_CLIENTLABEL;
		tlsInitiatorString = "server finished";
		tlsResponderString = "client finished";
		}
	else
		{
		/* Normal session, initiator = client, responder = server */
		initiatorMD5context = handshakeInfo->clientMD5context;
		initiatorSHA1context = handshakeInfo->clientSHA1context;
		responderMD5context = handshakeInfo->serverMD5context;
		responderSHA1context = handshakeInfo->serverSHA1context;
		sslInitiatorString = SSL_SENDER_CLIENTLABEL;
		sslResponderString = SSL_SENDER_SERVERLABEL;
		tlsInitiatorString = "client finished";
		tlsResponderString = "server finished";
		}
	sslLabelLength = SSL_SENDERLABEL_SIZE;
	tlsLabelLength = 15;

	/* Create the security contexts required for the session */
	status = initSecurityContextsSSL( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a fresh (i.e. non-cached) session, convert the premaster 
	   secret into the master secret */
	if( !isResumedSession )
		{
		status = premasterToMaster( sessionInfoPtr, handshakeInfo,
									masterSecret, SSL_SECRET_SIZE );
		if( cryptStatusError( status ) )
			return( status );

		/* Everything is OK so far, if we're the server (which caches 
		   sessions) add the master secret to the session cache */
		if( !isClient )
			{
			int cachedID;

			status = cachedID = \
				addScoreboardEntry( sessionInfoPtr->sessionSSL->scoreboardInfoPtr,
									handshakeInfo->sessionID,
									handshakeInfo->sessionIDlength,
									masterSecret, SSL_SECRET_SIZE );
			if( cryptStatusError( status ) )
				{
				zeroise( masterSecret, SSL_SECRET_SIZE );
				return( status );
				}
			sessionInfoPtr->sessionSSL->sessionCacheID = cachedID;
			}
		}
	else
		{
		/* We've already got the master secret present from the session that
		   we're resuming from, reuse that */
		ENSURES( rangeCheckZ( 0, handshakeInfo->premasterSecretSize, 
							  SSL_SECRET_SIZE ) );
		memcpy( masterSecret, handshakeInfo->premasterSecret,
				handshakeInfo->premasterSecretSize );
		}

	/* Convert the master secret into keying material.  Unfortunately we
	   can't delete the master secret at this point because it's still 
	   needed to calculate the MAC for the handshake messages */
	status = masterToKeys( sessionInfoPtr, handshakeInfo, masterSecret,
						   SSL_SECRET_SIZE, keyBlock, MAX_KEYBLOCK_SIZE );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}

	/* Load the keys and secrets */
	status = loadKeys( sessionInfoPtr, handshakeInfo, keyBlock, 
					   MAX_KEYBLOCK_SIZE, isClient );
	zeroise( keyBlock, MAX_KEYBLOCK_SIZE );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}

	/* Complete the dual-MAC hashing of the initiator-side messages and, if
	   we're the responder, check that the MACs match the ones supplied by
	   the initiator */
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		status = completeSSLDualMAC( initiatorMD5context, initiatorSHA1context,
									 initiatorHashes, CRYPT_MAX_HASHSIZE * 2,
									 &initiatorHashLength, sslInitiatorString, 
									 sslLabelLength, masterSecret, 
									 SSL_SECRET_SIZE );
		}
	else
		{
		status = completeTLSHashedMAC( initiatorMD5context, initiatorSHA1context,
									   initiatorHashes, CRYPT_MAX_HASHSIZE * 2,
									   &initiatorHashLength, tlsInitiatorString, 
									   tlsLabelLength, masterSecret, 
									   SSL_SECRET_SIZE );
		}
	if( cryptStatusOK( status ) && !isInitiator )
		{
		status = readHandshakeCompletionData( sessionInfoPtr, 
											  initiatorHashes, 
											  initiatorHashLength );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}

	/* Now that we have the initiator MACs, complete the dual-MAC hashing of
	   the responder-side messages and destroy the master secret.  We 
	   haven't created the full message yet at this point so we manually 
	   hash the individual pieces so that we can finally get rid of the 
	   master secret */
	status = krnlSendMessage( responderMD5context, IMESSAGE_CTX_HASH,
				( MESSAGE_CAST ) finishedTemplate[ sessionInfoPtr->version ],
				FINISHED_TEMPLATE_SIZE );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( responderSHA1context, IMESSAGE_CTX_HASH,
				( MESSAGE_CAST ) finishedTemplate[ sessionInfoPtr->version ],
				FINISHED_TEMPLATE_SIZE );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( responderMD5context, IMESSAGE_CTX_HASH, 
								  initiatorHashes, initiatorHashLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( responderSHA1context, IMESSAGE_CTX_HASH,
								  initiatorHashes, initiatorHashLength );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		status = completeSSLDualMAC( responderMD5context, responderSHA1context,
									 responderHashes, CRYPT_MAX_HASHSIZE * 2,
									 &responderHashLength, sslResponderString, 
									 sslLabelLength, masterSecret, 
									 SSL_SECRET_SIZE );
		}
	else
		{
		status = completeTLSHashedMAC( responderMD5context, responderSHA1context,
									   responderHashes, CRYPT_MAX_HASHSIZE * 2,
									   &responderHashLength, tlsResponderString, 
									   tlsLabelLength, masterSecret, 
									   SSL_SECRET_SIZE );
		}
	zeroise( masterSecret, SSL_SECRET_SIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Send our MACs to the other side and read back their response if
	   necessary.  The initiatorHashLength is the same as the 
	   responderHashLength (it's just a naming difference based on the
	   role that we're playing) so we use initiatorHashLength for both */
	status = writeHandshakeCompletionData( sessionInfoPtr, handshakeInfo,
										   isInitiator ? initiatorHashes : \
														 responderHashes,
										   initiatorHashLength,	
										   /* Same as responderHashLength */
										   ( isClient && !isResumedSession ) || \
										   ( !isClient && isResumedSession ) );
	if( cryptStatusError( status ) || !isInitiator )
		return( status );
	return( readHandshakeCompletionData( sessionInfoPtr, responderHashes,
										 initiatorHashLength ) );
	}
#endif /* USE_SSL */
