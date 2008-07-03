/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Server Management					*
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

/* Process an SSLv2 client hello:

	uint16		suiteLen
	uint16		sessIDlen
	uint16		nonceLen
	uint24[]	suites
	byte[]		sessID
	byte[]		nonce

   The v2 type and version have already been processed in readHSPacketSSL() 
   since this information, which is moved into the header in v3, is part of 
   the body in v2.  What's left for the v2 hello is the remainder of the 
   payload */

static int processHelloSSLv2( SESSION_INFO *sessionInfoPtr, 
							  SSL_HANDSHAKE_INFO *handshakeInfo, 
							  STREAM *stream, int *resumedSessionID )
	{
	int suiteLength, sessionIDlength, nonceLength, status;

	/* Clear return values */
	*resumedSessionID = SCOREBOARD_UNIQUEID_NONE;

	/* Read the SSLv2 hello */
	suiteLength = readUint16( stream );
	sessionIDlength = readUint16( stream );
	nonceLength = readUint16( stream );
	if( suiteLength < 3 || ( suiteLength % 3 ) != 0 || \
		sessionIDlength < 0 || sessionIDlength > MAX_SESSIONID_SIZE || \
		nonceLength < 16 || nonceLength > SSL_NONCE_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid legacy SSLv2 hello packet" ) );
		}
	status = processCipherSuite( sessionInfoPtr, handshakeInfo, stream, 
								 suiteLength / 3 );
	if( cryptStatusError( status ) )
		return( status );
	if( sessionIDlength > 0 )
		sSkip( stream, sessionIDlength );
	return( sread( stream, handshakeInfo->clientNonce + \
						   SSL_NONCE_SIZE - nonceLength, nonceLength ) );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							Server-side Connect Functions					*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the client */

int beginServerHandshake( SESSION_INFO *sessionInfoPtr, 
						  SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	MESSAGE_DATA msgData;
	int length, resumedSessionID = SCOREBOARD_UNIQUEID_NONE;
	int packetOffset, status;

	/* Read the hello packet from the client */
	status = readHSPacketSSL( sessionInfoPtr, handshakeInfo, &length,
							  SSL_MSG_FIRST_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the client hello.  Although this should be a v3 hello, 
	   Netscape always sends a v2 hello (even if SSLv2 is disabled) and
	   in any case both MSIE and Mozilla still have SSLv2 enabled by
	   default (!!) so we have to process both types */
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
#if 0	/* 28/01/08 Disabled since it's now finally removed in MSIE and 
		   Firefox */
	if( handshakeInfo->isSSLv2 )
		status = processHelloSSLv2( sessionInfoPtr, handshakeInfo, 
									stream, &resumedSessionID );
	else
#endif /* 0 */
		status = processHelloSSL( sessionInfoPtr, handshakeInfo, stream, 
								  TRUE );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		return( status );

	/* Handle session resumption */
	if( status == OK_SPECIAL )
		{
		resumedSessionID = \
				findScoreboardEntry( sessionInfoPtr->sessionSSL->scoreboardInfoPtr,
						handshakeInfo->sessionID, handshakeInfo->sessionIDlength,
						handshakeInfo->premasterSecret, SSL_SECRET_SIZE,
						&handshakeInfo->premasterSecretSize );
		}
	if( resumedSessionID == SCOREBOARD_UNIQUEID_NONE )
		{
		/* It's a new session or the session data has expired from the 
		   cache, generate a new session ID */
		setMessageData( &msgData, handshakeInfo->sessionID, SESSIONID_SIZE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		handshakeInfo->sessionIDlength = SESSIONID_SIZE;
		}

	/* Get the nonce that's used to randomise all crypto ops and set up the
	   server DH context if necessary */
	setMessageData( &msgData, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusOK( status ) && isKeyxAlgo( handshakeInfo->keyexAlgo ) )
		{
		status = initDHcontextSSL( &handshakeInfo->dhContext, NULL, 0,
							( handshakeInfo->authAlgo != CRYPT_ALGO_NONE ) ? \
							sessionInfoPtr->privateKey : CRYPT_UNUSED );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Build the server hello, cert, optional cert request, and done packets:

		byte		ID = SSL_HAND_SERVER_HELLO
		uint24		len
		byte[2]		version = { 0x03, 0x0n }
		uint32		time			| Server nonce
		byte[28]	nonce			|
		byte		sessIDlen
		byte[]		sessID
		uint16		suite
		byte		copr = 0
		... */
	status = openPacketStreamSSL( stream, sessionInfoPtr, CRYPT_USE_DEFAULT, 
								  SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	packetOffset = continueHSPacketStream( stream, SSL_HAND_SERVER_HELLO );
	sputc( stream, SSL_MAJOR_VERSION );
	sputc( stream, sessionInfoPtr->version );
	swrite( stream, handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	sputc( stream, handshakeInfo->sessionIDlength );
	if( handshakeInfo->sessionIDlength > 0 )
		swrite( stream, handshakeInfo->sessionID, 
				handshakeInfo->sessionIDlength );
	writeUint16( stream, handshakeInfo->cipherSuite ); 
	sputc( stream, 0 );	/* No compression */
#if 0	
	if( handshakeInfo->hasExtensions )
		{
		/* TLS extension code.  Since almost no clients/servers (except maybe 
		   some obscure bits of code embedded in cellphones) do this, we'll 
		   have to wait for something that implements it to come along so we 
		   can send back the appropriate response.  The RFC makes the rather 
		   optimistic assumption that implementations can handle the presence 
		   of unexpected data at the end of the hello packet, since  this is 
		   rarely the case we leave the following disabled by default so as 
		   not to confuse clients that leave some garbage at the end of their
		   client hello and suddenly get back an extension response from the
		   server */
		writeUint16( stream, ID_SIZE + UINT16_SIZE + 1 );
		writeUint16( stream, TLS_EXT_MAX_FRAGMENT_LENTH );
		writeUint16( stream, 1 );
		sputc( stream, 3 );
		}
#endif /* 0 */
	status = completeHSPacketStream( stream, packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* If it's a resumed session, the server hello is followed immediately 
	   by the change cipherspec, which is sent by the shared handshake
	   completion code */
	if( resumedSessionID != SCOREBOARD_UNIQUEID_NONE )
		{
		status = completePacketStreamSSL( stream, 0 );
		if( cryptStatusOK( status ) )
			status = dualMacDataWrite( handshakeInfo, stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		return( OK_SPECIAL );	/* Tell caller that it's a resumed session */
		}

	/*	...	(optional server supplemental data)
		byte		ID = SSL_HAND_SUPPLEMENTAL_DATA
		uint24		len
		uint16		type
		uint16		len
		byte[]		value
		... */

	/*	...
		(optional server cert chain)
		... */
	if( handshakeInfo->authAlgo != CRYPT_ALGO_NONE )
		{
		status = writeSSLCertChain( sessionInfoPtr, stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}

	/*	...			(optional server keyex)
		byte		ID = SSL_HAND_SERVER_KEYEXCHANGE
		uint24		len
		uint16		dh_pLen
		byte[]		dh_p
		uint16		dh_gLen
		byte[]		dh_g
		uint16		dh_YsLen
		byte[]		dh_Ys
		uint16		signatureLen
		byte[]		signature */
	if( isKeyxAlgo( handshakeInfo->keyexAlgo ) )
		{
		KEYAGREE_PARAMS keyAgreeParams;
		void *keyData = DUMMY_INIT_PTR;
		int keyDataOffset, keyDataLength = DUMMY_INIT;

		/* Perform phase 1 of the DH key agreement process */
		memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
		status = krnlSendMessage( handshakeInfo->dhContext,
								  IMESSAGE_CTX_ENCRYPT, &keyAgreeParams,
								  sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			sMemDisconnect( stream );
			return( status );
			}

		/* Write the DH key parameters and DH public value and sign them */
		packetOffset = \
			continueHSPacketStream( stream, SSL_HAND_SERVER_KEYEXCHANGE );
		keyDataOffset = stell( stream );
		status = exportAttributeToStream( stream, handshakeInfo->dhContext,
										  CRYPT_IATTRIBUTE_KEY_SSL );
		if( cryptStatusOK( status ) )
			status = writeInteger16U( stream, keyAgreeParams.publicValue, 
									  keyAgreeParams.publicValueLen );
		if( cryptStatusOK( status ) )
			{
			keyDataLength = stell( stream ) - keyDataOffset;
			status = sMemGetDataBlockAbs( stream, keyDataOffset, &keyData, 
										  keyDataLength );
			}
		if( cryptStatusOK( status ) )
			{
			status = createKeyexSignature( sessionInfoPtr, handshakeInfo,
										   stream, keyData, keyDataLength );
			}
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusOK( status ) )
			status = completeHSPacketStream( stream, packetOffset );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}

	/*	...			(optional client cert request)
		byte		ID = SSL_HAND_SERVER_CERTREQUEST
		uint24		len
		byte		certTypeLen = 2
		byte[2]		certType = { 0x01, 0x02 } (RSA,DSA)
		uint16		caNameListLen = 4
		uint16		caNameLen = 2
		byte[]		caName = { 0x30, 0x00 }
		... */
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		packetOffset = \
			continueHSPacketStream( stream, SSL_HAND_SERVER_CERTREQUEST );
		sputc( stream, 2 );	
		swrite( stream, "\x01\x02", 2 );
		writeUint16( stream, 4 );
		writeUint16( stream, 2 );
		swrite( stream, "\x30\x00", 2 );
		status = completeHSPacketStream( stream, packetOffset );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}

	/*	...
		byte		ID = SSL_HAND_SERVER_HELLODONE
		uint24		len = 0 */
	packetOffset = \
		continueHSPacketStream( stream, SSL_HAND_SERVER_HELLODONE );
	status = completeHSPacketStream( stream, packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* Send the combined server packets to the client.  We perform the dual 
	   MAC'ing of the packets in between the network ops where it's 
	   effectively free */
	status = sendPacketSSL( sessionInfoPtr, stream, FALSE );
	if( cryptStatusOK( status ) )
		status = dualMacDataWrite( handshakeInfo, stream );
	sMemDisconnect( stream );
	return( status );
	}

/* Exchange keys with the client */

int exchangeServerKeys( SESSION_INFO *sessionInfoPtr, 
						SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	int length, status;

	/* Read the response from the client and, if we're expecting a client 
	   cert, make sure that it's present */
	status = readHSPacketSSL( sessionInfoPtr, handshakeInfo, &length,
							  SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		MESSAGE_DATA msgData;
		BYTE certID[ KEYID_SIZE + 8 ];

		/* Process the client cert chain */
		status = readSSLCertChain( sessionInfoPtr, handshakeInfo,
								   stream, &sessionInfoPtr->iKeyexAuthContext, 
								   TRUE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}

		/* Make sure that the client cert is present in our cert store.  
		   Since we've already got a copy of the cert, we only do a presence 
		   check rather than actually fetching the cert */
		setMessageData( &msgData, certID, KEYID_SIZE );
		status = krnlSendMessage( sessionInfoPtr->iKeyexAuthContext, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_FINGERPRINT_SHA );
		if( cryptStatusOK( status ) )
			{
			setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_CERTID, certID, 
								   KEYID_SIZE, NULL, 0, 
								   KEYMGMT_FLAG_CHECK_ONLY );
			status = krnlSendMessage( sessionInfoPtr->cryptKeyset, 
									  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
										  KEYMGMT_ITEM_PUBLICKEY );
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			retExt( CRYPT_ERROR_INVALID,
					( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
					  "Client certificate is not trusted for "
					  "authentication purposes" ) );
			}

		/* Read the next packet(s) if necessary */
		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Process the client key exchange packet:

		byte		ID = SSL_HAND_CLIENT_KEYEXCHANGE
		uint24		len
	   DH:
		uint16		yLen
		byte[]		y
	   PSK:
		uint16		userIDLen
		byte[]		userID 
	   RSA:
	  [ uint16		encKeyLen - TLS only ]
		byte[]		rsaPKCS1( byte[2] { 0x03, 0x0n } || byte[46] random ) */
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  SSL_HAND_CLIENT_KEYEXCHANGE, 
								  UINT16_SIZE + 1 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	if( isKeyxAlgo( handshakeInfo->keyexAlgo ) )
		{
		KEYAGREE_PARAMS keyAgreeParams;

		memset( &keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
		status = readInteger16UChecked( stream, keyAgreeParams.publicValue,
										&keyAgreeParams.publicValueLen,
										MIN_PKCSIZE, CRYPT_MAX_PKCSIZE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );

			/* Some misconfigured clients may use very short keys, we 
			   perform a special-case check for these and return a more 
			   specific message than the generic bad-data */
			if( status == CRYPT_ERROR_NOSECURE )
				{
				retExt( CRYPT_ERROR_NOSECURE,
						( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
						  "Insecure key used in key exchange" ) );
				}

			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid DH key agreement data" ) );
			}

		/* Perform phase 2 of the DH key agreement */
		status = krnlSendMessage( handshakeInfo->dhContext,
								  IMESSAGE_CTX_DECRYPT, &keyAgreeParams, 
								  sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			sMemDisconnect( stream );
			return( status );
			}
		memcpy( handshakeInfo->premasterSecret, keyAgreeParams.wrappedKey,
				keyAgreeParams.wrappedKeyLen );
		handshakeInfo->premasterSecretSize = keyAgreeParams.wrappedKeyLen;
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		}
	else
		{
		if( handshakeInfo->authAlgo == CRYPT_ALGO_NONE )
			{
			const ATTRIBUTE_LIST *attributeListPtr;
			BYTE userID[ CRYPT_MAX_TEXTSIZE + 8 ];

			/* Read the client user ID and make sure that it's a valid 
			   user.  Handling non-valid users is somewhat problematic,
			   we can either bail out immediately or invent a fake 
			   password for the (non-)user and continue with that.  The
			   problem with this is that it doesn't really help hide 
			   whether the user is valid or not because we're still 
			   vulnerable to a timing attack because it takes considerably 
			   longer to generate the fake password than it does to read a 
			   fixed password string from memory, so an attacker can tell 
			   from the timing whether the username is valid or not.  
			   Because of this we don't try and fake out the valid/invalid 
			   user name indication but just exit immediately if an invalid
			   name is found */
			length = readUint16( stream );
			if( length < 1 || length > CRYPT_MAX_TEXTSIZE || \
				cryptStatusError( sread( stream, userID, length ) ) )
				{
				sMemDisconnect( stream );
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid client user ID" ) );
				}
			attributeListPtr = \
				findSessionInfoEx( sessionInfoPtr->attributeList,
								   CRYPT_SESSINFO_USERNAME, userID, length );
			if( attributeListPtr == NULL )
				{
				sMemDisconnect( stream );
				retExt( CRYPT_ERROR_WRONGKEY,
						( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
						  "Unknown user name '%s'", 
						  sanitiseString( userID, CRYPT_MAX_TEXTSIZE, 
										  length ) ) );
				}

			/* Select the attribute with the user ID and move on to the
			   associated password */
			sessionInfoPtr->attributeListCurrent = \
								( ATTRIBUTE_LIST * ) attributeListPtr;
			attributeListPtr = attributeListPtr->next;
			assert( attributeListPtr->attributeID == CRYPT_SESSINFO_PASSWORD );

			/* Create the shared premaster secret from the user password */
			status = createSharedPremasterSecret( \
									handshakeInfo->premasterSecret,
									CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE,
									&handshakeInfo->premasterSecretSize, 
									attributeListPtr );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );
				retExt( status, 
						( status, SESSION_ERRINFO, 
						  "Couldn't create SSL master secret from shared "
						  "secret/password value" ) );
				}
			}
		else
			{
			BYTE wrappedKey[ CRYPT_MAX_PKCSIZE + 8 ];

			if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
				{
				/* The original Netscape SSL implementation didn't provide a 
				   length for the encrypted key and everyone copied that so 
				   it became the de facto standard way to do it (Sic faciunt 
				   omnes.  The spec itself is ambiguous on the topic).  This 
				   was fixed in TLS (although the spec is still ambigous) so 
				   the encoding differs slightly between SSL and TLS */
				if( length < MIN_PKCSIZE || length > CRYPT_MAX_PKCSIZE || \
					cryptStatusError( sread( stream, wrappedKey, length ) ) )
					status = CRYPT_ERROR_BADDATA;
				}
			else
				{
				status = readInteger16UChecked( stream, wrappedKey, &length, 
												MIN_PKCSIZE, 
												CRYPT_MAX_PKCSIZE );
				}
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );

				/* Some misconfigured clients may use very short keys, we 
				   perform a special-case check for these and return a more 
				   specific message than the generic bad-data */
				if( status == CRYPT_ERROR_NOSECURE )
					{
					retExt( CRYPT_ERROR_NOSECURE,
							( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
							  "Insecure key used in key exchange" ) );
					}

				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid RSA encrypted key data" ) );
				}

			/* Decrypt the pre-master secret */
			status = unwrapPremasterSecret( sessionInfoPtr, handshakeInfo,
											wrappedKey, length );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );
				return( status );
				}
			}
		}

	/* If we're expecting a client cert, process the client cert verify */
	if( sessionInfoPtr->cryptKeyset != CRYPT_ERROR )
		{
		/* Read the next packet(s) if necessary */
		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Process the client cert verify packet:

			byte		ID = SSL_HAND_CLIENT_CERTVERIFY
			uint24		len
			byte[]		signature */
		status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
									  SSL_HAND_CLIENT_CERTVERIFY, 
									  MIN_PKCSIZE );
		if( cryptStatusOK( status ) )
			status = checkCertVerify( sessionInfoPtr, handshakeInfo, stream, 
									  length );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}
	sMemDisconnect( stream );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

void initSSLserverProcessing( SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	handshakeInfo->beginHandshake = beginServerHandshake;
	handshakeInfo->exchangeKeys = exchangeServerKeys;
	}
#endif /* USE_SSL */
