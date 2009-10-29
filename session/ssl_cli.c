/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Client Management					*
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

/* Encode a list of available algorithms */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeCipherSuiteList( INOUT STREAM *stream, 
								 const BOOLEAN usePSK )
	{
	const CIPHERSUITE_INFO *cipherSuiteInfo;
	int availableSuites[ 32 + 8 ], cipherSuiteCount = 0, suiteIndex;
	int cipherSuiteInfoSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Get the information for the supported cipher suites */
	status = getCipherSuiteInfo( &cipherSuiteInfo, &cipherSuiteInfoSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Walk down the list of algorithms (and the corresponding cipher
	   suites) remembering each one that's available for use */
	for( suiteIndex = 0;
		 cipherSuiteInfo[ suiteIndex ].cipherSuite != SSL_NULL_WITH_NULL && \
			cipherSuiteCount < 32 && suiteIndex < cipherSuiteInfoSize;
		 /* No action */ )
		{
		const CRYPT_ALGO_TYPE keyexAlgo = \
								cipherSuiteInfo[ suiteIndex ].keyexAlgo;
		const CRYPT_ALGO_TYPE cryptAlgo = \
								cipherSuiteInfo[ suiteIndex ].cryptAlgo;
		const CRYPT_ALGO_TYPE authAlgo = \
								cipherSuiteInfo[ suiteIndex ].authAlgo;

		/* If it's a PSK suite but we're not using a PSK handshake, skip 
		   it */
		if( ( cipherSuiteInfo[ suiteIndex ].flags & CIPHERSUITE_FLAG_PSK ) && \
			!usePSK )
			{
			suiteIndex++;
			continue;
			}

		/* If the keyex algorithm for this suite isn't enabled for this 
		   build of cryptlib, skip all suites that use it.  We have to 
		   explicitly exclude the special case where there's no keyex 
		   algorithm in order to accomodate the bare TLS-PSK suites (used 
		   without DH/ECDH or RSA), whose keyex mechanism is pure PSK */
		if( cipherSuiteInfo[ suiteIndex ].keyexAlgo != CRYPT_ALGO_NONE && \
			!algoAvailable( cipherSuiteInfo[ suiteIndex ].keyexAlgo ) )
			{
			while( cipherSuiteInfo[ suiteIndex ].keyexAlgo == keyexAlgo && \
				   suiteIndex < cipherSuiteInfoSize )
				suiteIndex++;
			ENSURES( suiteIndex < cipherSuiteInfoSize );
			continue;
			}

		/* If the bulk encryption algorithm for this suite isn't enabled for 
		   this build of cryptlib, skip all suites that use it */
		if( !algoAvailable( cipherSuiteInfo[ suiteIndex ].cryptAlgo ) )
			{
			while( cipherSuiteInfo[ suiteIndex ].cryptAlgo == cryptAlgo && \
				   suiteIndex < cipherSuiteInfoSize )
				suiteIndex++;
			ENSURES( suiteIndex < cipherSuiteInfoSize );
			continue;
			}

		/* The suite is supported, remember it.  In theory there's only a
		   single combination of the various algorithms present, but these 
		   can be subsetted into different key sizes (because they're there, 
		   that's why) so we have to interate the recording of available 
		   suites instead of just assigning a single value on match */
		while( cipherSuiteInfo[ suiteIndex ].keyexAlgo == keyexAlgo && \
			   cipherSuiteInfo[ suiteIndex ].authAlgo == authAlgo && \
			   cipherSuiteInfo[ suiteIndex ].cryptAlgo == cryptAlgo && \
			   cipherSuiteCount < 32 && suiteIndex < cipherSuiteInfoSize )
			{
			availableSuites[ cipherSuiteCount++ ] = \
						cipherSuiteInfo[ suiteIndex++ ].cipherSuite;
			}
		ENSURES( suiteIndex < cipherSuiteInfoSize );
		}
	ENSURES( suiteIndex < cipherSuiteInfoSize );
	ENSURES( cipherSuiteCount < 32 );

	/* Encode the list of available cipher suites */
	status = writeUint16( stream, cipherSuiteCount * UINT16_SIZE );
	for( suiteIndex = 0; 
		 cryptStatusOK( status ) && suiteIndex < cipherSuiteCount; 
		 suiteIndex++ )
		status = writeUint16( stream, availableSuites[ suiteIndex ] );

	return( status );
	}

/* Process a server's DH/ECDH key agreement data */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processServerKeyex( INOUT STREAM *stream, 
							   INOUT KEYAGREE_PARAMS *keyAgreeParams,
							   OUT_HANDLE_OPT CRYPT_CONTEXT *dhContextPtr,
							   const BOOLEAN isECC )
	{
	void *keyData;
	const int keyDataOffset = stell( stream );
	int keyDataLength, dummy, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( keyAgreeParams, sizeof( KEYAGREE_PARAMS ) ) );
	assert( isWritePtr( dhContextPtr, sizeof( CRYPT_CONTEXT ) ) );

	/* Clear return values */
	memset( keyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
	*dhContextPtr = CRYPT_ERROR;

	/* Read the server DH/ECDH public key data */
	if( isECC )
		{
		( void ) sgetc( stream );
		status = readUint16( stream );
		}
	else
		{
		status = readInteger16UChecked( stream, NULL, &dummy, 
										MIN_PKCSIZE_THRESHOLD, 
										CRYPT_MAX_PKCSIZE );
		if( cryptStatusOK( status ) )
			status = readInteger16U( stream, NULL, &dummy, 1, 
									 CRYPT_MAX_PKCSIZE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Create a DH/ECDH context from the public key data.  If it's an ECC
	   algorithm we set a dummy curve type, the actual value is determined
	   by the parameters sent by the server */
	keyDataLength = stell( stream ) - keyDataOffset;
	status = sMemGetDataBlockAbs( stream, keyDataOffset, &keyData, 
								  keyDataLength );
	if( cryptStatusOK( status ) )
		{
		status = initDHcontextSSL( dhContextPtr, keyData, keyDataLength, 
								   CRYPT_UNUSED, 
								   isECC ? CRYPT_ECCCURVE_P256 : \
										   CRYPT_ECCCURVE_NONE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the DH/ECDH public value */
	if( isECC )
		{
		int length;

		/* The ECDH public value is a bit complex to process because it's
		   the usual X9.62 stuff-point-data-into-a-byte-string value, and 
		   to make things even messier it's stored with an 8-bit length
		   instead of a 16-bit one so we can't even read it as an
		   integer16U().  To work around this we have to duplicate a 
		   certain amount of the integer-read code here */
		status = length = sgetc( stream );
		if( cryptStatusError( status ) )
			return( status );
		if( isShortECCKey( length / 2 ) )
			return( CRYPT_ERROR_NOSECURE );
		if( length < MIN_PKCSIZE_ECCPOINT || length > MAX_PKCSIZE_ECCPOINT )
			return( CRYPT_ERROR_BADDATA );
		keyAgreeParams->publicValueLen = length;
		return( sread( stream, keyAgreeParams->publicValue, length ) );
		}
	return( readInteger16UChecked( stream, keyAgreeParams->publicValue,
								   &keyAgreeParams->publicValueLen,
								   MIN_PKCSIZE_THRESHOLD, 
								   CRYPT_MAX_PKCSIZE ) );
	}

/* Make sure that the server URL matches the value in the returned
   certificate.  This code isn't currently called because it's not certain
   what the best way to report this to the user is because there are all 
   sorts of oddball matching rules and requirements that people consider
   produce a valid match or should be valid, and because there are quite a 
   few servers out there where the server name doesn't match what's in the 
   certificate but for which the user will just click "OK" anyway even if we 
   can tunnel a warning indication back to them (or get upset if they can't
   override the built-in matching rules).  No matter what decision we make
   here it'll be seen as too permissive by some users and too restrictive
   by others and it's really a case for the calling application to decide 
   what it will or won't accept, so we leave it to the caller to perform 
   whatever checking and take whatever action they consider necessary.  
   
   Note that the code below is merely a template and shouldn't be used as 
   is since it doesn't take any precautions to handle malformed/malicious
   names, it's merely a sketch of how to do the matching */

#if 0

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int checkURL( INOUT SESSION_INFO *sessionInfoPtr )
	{
	MESSAGE_DATA msgData;
	char hostName[ MAX_URL_SIZE + 8 ];
	const int serverNameLength = strlen( sessionInfoPtr->serverName );
	int hostNameLength, splatPos = CRYPT_ERROR, postSplatLen, i, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Read the server name specification from the server's certificate */
	setMessageData( &msgData, hostName, MAX_URL_SIZE );
	status = krnlSendMessage( sessionInfoPtr->iKeyexCryptContext,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CERTINFO_DNSNAME );
	if( cryptStatusError( status ) )
		{
		status = krnlSendMessage( sessionInfoPtr->iKeyexCryptContext,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_CERTINFO_COMMONNAME );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't read server name from server certificate" ) );
		}
	hostNameLength = msgData.length;

	/* Look for a splat in the host name spec */
	for( i = 0; i < hostNameLength; i++ )
		{
		if( hostName[ i ] == '*' )
			{
			if( splatPos != CRYPT_ERROR )
				{
				/* Can't have more than one splat in a host name */
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Server name in certificate contains more than "
						  "one wildcard" ) );
				}
			splatPos = i;
			}
		}

	/* If there's no wildcarding, perform a direct match */
	if( splatPos == CRYPT_ERROR )
		{
		if( hostNameLength != serverNameLength || \
			strCompare( hostName, sessionInfoPtr->serverName,
						serverNameLength ) )
			{
			/* Host doesn't match the name in the certificate */
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Server name doesn't match name in server "
					  "certificate" ) );
			}

		return( CRYPT_OK );
		}

	/* Determine how much to match before and after the splat */
	postSplatLen = hostNameLength - splatPos - 1;
	if( postSplatLen + splatPos > serverNameLength )
		{
		/* The fixed name spec text is longer than the server name, a match
		   can't be possible */
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Server name doesn't match name in server certificate" ) );
		}

	/* Check that the pre- and post-splat URL components match */
	if( splatPos > 0 && \
		strCompare( hostName, sessionInfoPtr->serverName, splatPos ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Server name doesn't match name in server certificate" ) );
		}
	if( strCompare( hostName + splatPos + 1,
					sessionInfoPtr->serverName + serverNameLength - postSplatLen,
					postSplatLen ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Server name doesn't match name in server certificate" ) );
		}

	/* Make sure that no-one tries to enable us in this form */
	#error This code shouldn't be used in its current form

	return( CRYPT_OK );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							Client-side Connect Functions					*
*																			*
****************************************************************************/

/* Perform the initial part of the handshake with the server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int beginClientHandshake( INOUT SESSION_INFO *sessionInfoPtr,
								 INOUT SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	MESSAGE_DATA msgData;
	int packetOffset, length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* Get the nonce that's used to randomise all crypto ops */
	setMessageData( &msgData, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
	if( cryptStatusError( status ) )
		return( status );

	/* Build the client hello packet:

		byte		ID = SSL_HAND_CLIENT_HELLO
		uint24		len
		byte[2]		version = { 0x03, 0x0n }
		uint32		time			| Client nonce
		byte[28]	nonce			|
		byte		sessIDlen = 0
		[ byte[]		sessID		| Omitted since len == 0 ]
		uint16		suiteLen
		uint16[]	suite
		byte		coprLen = 1
		byte[]		copr = { 0x00 }
		[ uint16	extListLen		| RFC 3546
			byte	extType
			uint16	extLen
			byte[]	extData ] */
	status = openPacketStreamSSL( stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
								  SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	status = continueHSPacketStream( stream, SSL_HAND_CLIENT_HELLO, 
									 &packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	sputc( stream, SSL_MAJOR_VERSION );
	sputc( stream, sessionInfoPtr->version );
	handshakeInfo->clientOfferedVersion = sessionInfoPtr->version;
	swrite( stream, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	sputc( stream, 0 );	/* No session ID */
	status = writeCipherSuiteList( stream,
					findSessionInfo( sessionInfoPtr->attributeList,
									 CRYPT_SESSINFO_USERNAME ) ? TRUE : FALSE );
	if( cryptStatusOK( status ) )
		{
		sputc( stream, 1 );		/* No compression */
		status = sputc( stream, 0 );
		}
	if( cryptStatusOK( status ) )
		status = completeHSPacketStream( stream, packetOffset );
	if( cryptStatusOK( status ) )
		status = sendPacketSSL( sessionInfoPtr, stream, FALSE );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* Perform the dual MAC'ing of the client hello in between the network
	   ops where it's effectively free */
	status = dualMacDataWrite( handshakeInfo, stream );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the server hello.  The server usually sends us a session ID,
	   indicated by a return status of OK_SPECIAL, but we don't do anything
	   further with it since we won't be resuming this session */
	status = readHSPacketSSL( sessionInfoPtr, handshakeInfo, &length,
							  SSL_MSG_FIRST_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( stream, sessionInfoPtr->receiveBuffer, length );
	status = processHelloSSL( sessionInfoPtr, handshakeInfo, stream, FALSE );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		{
		sMemDisconnect( stream );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Exchange keys with the server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int exchangeClientKeys( INOUT SESSION_INFO *sessionInfoPtr,
							   INOUT SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	STREAM *stream = &handshakeInfo->stream;
	BYTE keyexPublicValue[ CRYPT_MAX_PKCSIZE + 8 ];
	BOOLEAN needClientCert = FALSE;
	int packetOffset, length, keyexPublicValueLen = DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* Process the optional server supplemental data:

		byte		ID = SSL_HAND_SUPPLEMENTAL_DATA
		uint24		len
		uint16		type
		uint16		len
		byte[]		value

	   This is a kitchen-sink mechanism for exchanging arbitrary further 
	   data during the TLS handshake (see RFC 4680), the presence of the
	   supplemental data has to be negotiated using TLS extensions, however
	   the nature of this negotiation is unspecified so we can't just
	   reject an unexpected supplemental data message as required by the RFC 
	   because it may have been quite legitimately negotiated by a TLS
	   extension that we don't know about.  Because of this we perform
	   basic validity checks on any supplemental data messages that arrive
	   but otherwise ignore them */
	status = refreshHSStream( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( sPeek( stream ) == SSL_HAND_SUPPLEMENTAL_DATA )
		{
		status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
									  SSL_HAND_SUPPLEMENTAL_DATA, 
									  UINT16_SIZE + UINT16_SIZE + 1 );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		readUint16( stream );
		status = readUniversal16( stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid supplemental data" ) );
			}
		}

	/* Process the optional server certificate chain:

		byte		ID = SSL_HAND_CERTIFICATE
		uint24		len
		uint24		certLen			| 1...n certificates ordered
		byte[]		certificate		|   leaf -> root */
	if( handshakeInfo->authAlgo != CRYPT_ALGO_NONE )
		{
		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );
		status = readSSLCertChain( sessionInfoPtr, handshakeInfo,
							stream, &sessionInfoPtr->iKeyexCryptContext,
							FALSE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}

	/* Process the optional server keyex:

		byte		ID = SSL_HAND_SERVER_KEYEXCHANGE
		uint24		len
	   DH:
		uint16		dh_pLen
		byte[]		dh_p
		uint16		dh_gLen
		byte[]		dh_g
		uint16		dh_YsLen
		byte[]		dh_Ys
		uint16		signatureLen
		byte[]		signature 
	   ECDH:
		byte		curveType
		uint16		namedCurve
		uint8		ecPointLen	-- NB uint8 not uint16
		byte[]		ecPoint
		uint16		signatureLen
		byte[]		signature */
	if( isKeyxAlgo( handshakeInfo->keyexAlgo ) )
		{
		KEYAGREE_PARAMS keyAgreeParams, tempKeyAgreeParams;
		void *keyData = DUMMY_INIT_PTR;
		const BOOLEAN isECC = isEccAlgo( handshakeInfo->keyexAlgo );
		int keyDataOffset, keyDataLength = DUMMY_INIT;

		status = refreshHSStream( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Make sure that we've got an appropriate server keyex packet.  We 
		   set the minimum key size to MIN_PKCSIZE_THRESHOLD/
		   MIN_PKCSIZE_ECC_THRESHOLD instead of MIN_PKCSIZE/MIN_PKCSIZE_ECC 
		   in order to provide better diagnostics if the server is using 
		   weak keys since otherwise the data will be rejected in the packet 
		   read long before we get to the keysize check */
		status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
						SSL_HAND_SERVER_KEYEXCHANGE, 
						isECC ? \
							( 1 + UINT16_SIZE + \
							  1 + MIN_PKCSIZE_ECCPOINT_THRESHOLD + \
							  UINT16_SIZE + MIN_PKCSIZE_ECCPOINT_THRESHOLD ) : \
							( UINT16_SIZE + MIN_PKCSIZE_THRESHOLD + \
							  UINT16_SIZE + 1 + \
							  UINT16_SIZE + MIN_PKCSIZE_THRESHOLD + \
							  UINT16_SIZE + MIN_PKCSIZE_THRESHOLD ) );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}

		/* Process the server keyex and convert it into a DH/ECDH context */
		keyDataOffset = stell( stream );
		status = processServerKeyex( stream, &keyAgreeParams, 
									 &handshakeInfo->dhContext, isECC );
		if( cryptStatusOK( status ) )
			{
			keyDataLength = stell( stream ) - keyDataOffset;
			status = sMemGetDataBlockAbs( stream, keyDataOffset, &keyData, 
										  keyDataLength );
			}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );

			/* Some misconfigured servers may use very short keys, we 
			   perform a special-case check for these and return a more 
			   specific message than the generic bad-data */
			if( status == CRYPT_ERROR_NOSECURE )
				{
				retExt( CRYPT_ERROR_NOSECURE,
						( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
						  "Insecure key used in key exchange" ) );
				}

			retExt( cryptArgError( status ) ? \
					CRYPT_ERROR_BADDATA : status,
					( cryptArgError( status ) ? CRYPT_ERROR_BADDATA : status,
					  SESSION_ERRINFO, 
					  "Invalid server key agreement parameters" ) );
			}

		/* Check the server's signature on the DH/ECDH parameters */
		status = checkKeyexSignature( sessionInfoPtr, handshakeInfo,
									  stream, keyData, keyDataLength,
									  isECC );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Bad server key agreement parameter signature" ) );
			}

		/* Perform phase 1 of the DH/ECDH key agreement process and save the 
		   result so that we can send it to the server later on.  The order 
		   of the SSL messages is a bit unfortunate since we get the one for 
		   phase 2 before we need the phase 1 value, so we have to cache the 
		   phase 1 result for when we need it later on */
		memset( &tempKeyAgreeParams, 0, sizeof( KEYAGREE_PARAMS ) );
		status = krnlSendMessage( handshakeInfo->dhContext,
								  IMESSAGE_CTX_ENCRYPT, &tempKeyAgreeParams,
								  sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			zeroise( &tempKeyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			sMemDisconnect( stream );
			return( status );
			}
		ENSURES( rangeCheckZ( 0, tempKeyAgreeParams.publicValueLen,
							  CRYPT_MAX_PKCSIZE ) );
		memcpy( keyexPublicValue, tempKeyAgreeParams.publicValue,
				tempKeyAgreeParams.publicValueLen );
		keyexPublicValueLen = tempKeyAgreeParams.publicValueLen;
		zeroise( &tempKeyAgreeParams, sizeof( KEYAGREE_PARAMS ) );

		/* Perform phase 2 of the DH/ECDH key agreement */
		status = krnlSendMessage( handshakeInfo->dhContext,
								  IMESSAGE_CTX_DECRYPT, &keyAgreeParams,
								  sizeof( KEYAGREE_PARAMS ) );
		if( cryptStatusError( status ) )
			{
			zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
			sMemDisconnect( stream );
			return( status );
			}
		if( isECC )
			{
			const int xCoordLen = ( keyAgreeParams.wrappedKeyLen - 1 ) / 2;

			/* The output of the ECDH operation is an ECC point, but for
			   some unknown reason TLS only uses the x coordinate and not 
			   the full point.  To work around this we have to rewrite the
			   point as a standalone x coordinate, which is relatively
			   easy because we're using an "uncompressed" point format: 

				+---+---------------+---------------+
				|04	|		qx		|		qy		|
				+---+---------------+---------------+
					|<- fldSize --> |<- fldSize --> | */
			REQUIRES( keyAgreeParams.wrappedKeyLen >= MIN_PKCSIZE_ECCPOINT && \
					  keyAgreeParams.wrappedKeyLen <= MAX_PKCSIZE_ECCPOINT && \
					  ( keyAgreeParams.wrappedKeyLen & 1 ) == 1 && \
					  keyAgreeParams.wrappedKey[ 0 ] == 0x04 );
			memmove( keyAgreeParams.wrappedKey, 
					 keyAgreeParams.wrappedKey + 1, xCoordLen );
			keyAgreeParams.wrappedKeyLen = xCoordLen;
			}
		ENSURES( rangeCheckZ( 0, keyAgreeParams.wrappedKeyLen,
							  CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE ) );
		memcpy( handshakeInfo->premasterSecret, keyAgreeParams.wrappedKey,
				keyAgreeParams.wrappedKeyLen );
		handshakeInfo->premasterSecretSize = keyAgreeParams.wrappedKeyLen;
		zeroise( &keyAgreeParams, sizeof( KEYAGREE_PARAMS ) );
		}

	/* Process the optional server certificate request:

		byte	ID = SSL_HAND_SERVER_CERTREQUEST
		uint24	len
		byte	certTypeLen
		byte[]	certType
		uint16	caNameListLen
			uint16	caNameLen
			byte[]	caName

	   We don't really care what's in the certificate request packet since 
	   the contents are irrelevant, in a number of cases servers have been
	   known to send out superfluous certificate requests without the admins 
	   even knowning that they're doing it, in other cases servers send out
	   requests for every CA that they know of (150-160 CAs), which is 
	   pretty much meaningless since they can't possibly trust all of those 
	   CAs to authorise access to their site.  Because of this, all that we 
	   do here is perform a basic sanity check and remember that we may need 
	   to submit a certificate later on.

	   Since we're about to peek ahead into the stream to see if we need to
	   process a server certificate request, we have to refresh the stream 
	   at this point in case the certificate request wasn't bundled with the 
	   preceding packets */
	status = refreshHSStream( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( sPeek( stream ) == SSL_HAND_SERVER_CERTREQUEST )
		{
		/* Although the spec says that at least one CA name entry must be
		   present, some implementations send a zero-length list so we allow 
		   this as well.  The spec was changed in late TLS 1.1 drafts to 
		   reflect this practice */
		status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
									  SSL_HAND_SERVER_CERTREQUEST,
									  1 + 1 + UINT16_SIZE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		length = sgetc( stream );
		if( cryptStatusError( length ) || \
			length < 1 || cryptStatusError( sSkip( stream, length ) ) )
			{
			sMemDisconnect( stream );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid certificate request certificate type" ) );
			}
		status = readUniversal16( stream );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid certificate request CA name list" ) );
			}
		needClientCert = TRUE;
		}

	/* Process the server hello done:

		byte		ID = SSL_HAND_SERVER_HELLODONE
		uint24		len = 0 */
	status = refreshHSStream( sessionInfoPtr, handshakeInfo );
	if( cryptStatusError( status ) )
		return( status );
	status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
								  SSL_HAND_SERVER_HELLODONE, 0 );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* If we need a client certificate, build the client certificate packet */
	status = openPacketStreamSSL( stream, sessionInfoPtr, CRYPT_USE_DEFAULT,
								  SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );
	if( needClientCert )
		{
		BOOLEAN sentResponse = FALSE;

		/* If we haven't got a certificate available, tell the server.  SSL 
		   and TLS differ here, SSL sends a no-certificate alert while TLS 
		   sends an empty client certificate packet, which is handled 
		   further on */
		if( sessionInfoPtr->privateKey == CRYPT_ERROR )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_PRIVATEKEY,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
				{
				static const BYTE FAR_BSS noCertAlertSSLTemplate[] = {
					SSL_MSG_ALERT,							/* ID */
					SSL_MAJOR_VERSION, SSL_MINOR_VERSION_SSL,/* Version */
					0, 2,									/* Length */
					SSL_ALERTLEVEL_WARNING, SSL_ALERT_NO_CERTIFICATE
					};

				/* This is an alert-protocol message rather than a handshake
				   message so we don't add it to the handshake packet stream
				   but write it directly to the network stream */
				swrite( &sessionInfoPtr->stream, noCertAlertSSLTemplate, 7 );
				sentResponse = TRUE;
				}

			/* The reaction to the lack of a certificate is up to the server 
			   (some just request one anyway even though they can't do 
			   anything with it) so from here on we just continue as if 
			   nothing had happened */
			needClientCert = FALSE;
			}

		/* If we haven't sent a response yet, send it now.  If no private 
		   key is available this will send the zero-length chain that's 
		   required by TLS  */
		if( !sentResponse )
			{
			status = writeSSLCertChain( sessionInfoPtr, stream );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );
				return( status );
				}
			}
		}

	/* Build the client key exchange packet:

		byte		ID = SSL_HAND_CLIENT_KEYEXCHANGE
		uint24		len
	   DH:
		uint16		yLen
		byte[]		y
	   ECDH:
		uint8		ecPointLen	-- NB uint8 not uint16
		byte[]		ecPoint
	   PSK:
		uint16		userIDLen
		byte[]		userID
	   RSA:
	  [ uint16		encKeyLen - TLS only ]
		byte[]		rsaPKCS1( byte[2] { 0x03, 0x0n } || byte[46] random ) */
	status = continueHSPacketStream( stream, SSL_HAND_CLIENT_KEYEXCHANGE,
									 &packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}
	if( isKeyxAlgo( handshakeInfo->keyexAlgo ) )
		{
		/* Write the DH/ECDH public value that we saved earlier when we
		   performed phase 1 of the key agreement process */
		if( isEccAlgo( handshakeInfo->keyexAlgo ) )
			{
			sputc( stream, keyexPublicValueLen );
			status = swrite( stream, keyexPublicValue,
							 keyexPublicValueLen );
			}
		else
			{
			status = writeInteger16U( stream, keyexPublicValue,
									  keyexPublicValueLen );
			}
		}
	else
		{
		if( handshakeInfo->authAlgo == CRYPT_ALGO_NONE )
			{
			const ATTRIBUTE_LIST *passwordPtr = \
						findSessionInfo( sessionInfoPtr->attributeList,
										 CRYPT_SESSINFO_PASSWORD );
			const ATTRIBUTE_LIST *userNamePtr = \
						findSessionInfo( sessionInfoPtr->attributeList,
										 CRYPT_SESSINFO_PASSWORD );

			REQUIRES( passwordPtr != NULL );
			REQUIRES( userNamePtr != NULL );

			/* Create the shared premaster secret from the user password */
			status = createSharedPremasterSecret( \
							handshakeInfo->premasterSecret,
							CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE,
							&handshakeInfo->premasterSecretSize,
							passwordPtr->value, 
							passwordPtr->valueLength,
							( passwordPtr->flags & ATTR_FLAG_ENCODEDVALUE ) ? \
								TRUE : FALSE );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );
				retExt( status,
						( status, SESSION_ERRINFO, 
						  "Couldn't create SSL master secret from shared "
						  "secret/password value" ) );
				}

			/* Write the PSK client identity */
			writeUint16( stream, userNamePtr->valueLength );
			status = swrite( stream, userNamePtr->value,
							 userNamePtr->valueLength );
			}
		else
			{
			BYTE wrappedKey[ CRYPT_MAX_PKCSIZE + 8 ];
			int wrappedKeyLength;

			status = wrapPremasterSecret( sessionInfoPtr, handshakeInfo,
										  wrappedKey, CRYPT_MAX_PKCSIZE,
										  &wrappedKeyLength );
			if( cryptStatusError( status ) )
				{
				sMemDisconnect( stream );
				return( status );
				}
			if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
				{
				/* The original Netscape SSL implementation didn't provide a
				   length for the encrypted key and everyone copied that so
				   it became the de facto standard way to do it (Sic faciunt
				   omnes.  The spec itself is ambiguous on the topic).  This
				   was fixed in TLS (although the spec is still ambiguous) so
				   the encoding differs slightly between SSL and TLS */
				status = swrite( stream, wrappedKey, wrappedKeyLength );
				}
			else
				{
				status = writeInteger16U( stream, wrappedKey, 
										  wrappedKeyLength );
				}
			}
		}
	if( cryptStatusOK( status ) )
		status = completeHSPacketStream( stream, packetOffset );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( stream );
		return( status );
		}

	/* If we need to supply a client certificate, send the signature 
	   generated with the certificate to prove possession of the private 
	   key */
	if( needClientCert )
		{
		/* Write the packet header and drop in the signature data */
		status = continueHSPacketStream( stream, SSL_HAND_CLIENT_CERTVERIFY,
										 &packetOffset );
		if( cryptStatusOK( status ) )
			status = createCertVerify( sessionInfoPtr, handshakeInfo, 
									   stream );
		if( cryptStatusOK( status ) )
			status = completeHSPacketStream( stream, packetOffset );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		}

	/* Wrap and MAC the packet.  This is followed by the change cipherspec
	   packet so we don't send it at this point but leave it to be sent by
	   the shared handshake-completion code */
	status = completePacketStreamSSL( stream, 0 );
	if( cryptStatusOK( status ) )
		status = dualMacDataWrite( handshakeInfo, stream );
	return( status );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initSSLclientProcessing( INOUT SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	handshakeInfo->beginHandshake = beginClientHandshake;
	handshakeInfo->exchangeKeys = exchangeClientKeys;
	}
#endif /* USE_SSL */
