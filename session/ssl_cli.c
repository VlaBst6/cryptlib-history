/****************************************************************************
*																			*
*					cryptlib SSL v3/TLS Client Management					*
*					   Copyright Peter Gutmann 1998-2010					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "ssl.h"
#else
  #include "crypt.h"
  #include "enc_dec/misc_rw.h"
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
								 const BOOLEAN usePSK, 
								 const BOOLEAN useTLS12,
								 const int suiteBinfo )
	{
	const CIPHERSUITE_INFO **cipherSuiteInfo;
#ifdef CONFIG_SUITEB
	BOOLEAN firstSuite = TRUE;
#endif /* CONFIG_SUITEB */
	int availableSuites[ 32 + 8 ], cipherSuiteCount = 0, suiteIndex;
	int cipherSuiteInfoSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Get the information for the supported cipher suites */
	status = getCipherSuiteInfo( &cipherSuiteInfo, &cipherSuiteInfoSize );
	if( cryptStatusError( status ) )
		return( status );

#if defined( CONFIG_SUITEB ) && 0
	/* Add a non-Suite B suite for Suite B compliance testing */
	availableSuites[ cipherSuiteCount++ ] = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
#endif /* CONFIG_SUITEB special-case */

	/* Walk down the list of algorithms (and the corresponding cipher
	   suites) remembering each one that's available for use */
	for( suiteIndex = 0;
		 suiteIndex < cipherSuiteInfoSize && \
			cipherSuiteInfo[ suiteIndex ]->cipherSuite != SSL_NULL_WITH_NULL && \
			cipherSuiteCount < 32;
		 /* No action */ )
		{
		const CIPHERSUITE_INFO *cipherSuiteInfoPtr = cipherSuiteInfo[ suiteIndex ];
		const CRYPT_ALGO_TYPE keyexAlgo = cipherSuiteInfoPtr->keyexAlgo;
		const CRYPT_ALGO_TYPE cryptAlgo = cipherSuiteInfoPtr->cryptAlgo;
		const CRYPT_ALGO_TYPE authAlgo = cipherSuiteInfoPtr->authAlgo;
		const CRYPT_ALGO_TYPE macAlgo = cipherSuiteInfoPtr->macAlgo;
		const int suiteFlags = cipherSuiteInfoPtr->flags;

#ifdef CONFIG_SUITEB
		/* For Suite B the first suite must be ECDHE/AES128-GCM/SHA256 or 
		   ECDHE/AES256-GCM/SHA384 depending on the security level */
		if( firstSuite && suiteBinfo != 0 )
			{
			const int cipherSuite = cipherSuiteInfoPtr->cipherSuite;

			if( ( suiteBinfo == SSL_PFLAG_SUITEB_128 && \
				  cipherSuite != TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ) || \
				( suiteBinfo == SSL_PFLAG_SUITEB_256 && \
				  cipherSuite != TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ) )
				{
				suiteIndex++;
				continue;
				}
			firstSuite = FALSE;
			}
#endif /* CONFIG_SUITEB */

		/* If it's a PSK or TLS 1.2 suite but we're not using PSK or a TLS 
		   1.2 handshake, skip it */
		if( ( ( suiteFlags & CIPHERSUITE_FLAG_PSK ) && !usePSK ) || \
			( ( suiteFlags & CIPHERSUITE_FLAG_TLS12 ) && !useTLS12 ) )
			{
			suiteIndex++;
			continue;
			}

		/* If the keyex algorithm for this suite isn't enabled for this 
		   build of cryptlib, skip all suites that use it.  We have to 
		   explicitly exclude the special case where there's no keyex 
		   algorithm in order to accomodate the bare TLS-PSK suites (used 
		   without DH/ECDH or RSA), whose keyex mechanism is pure PSK */
		if( keyexAlgo != CRYPT_ALGO_NONE && !algoAvailable( keyexAlgo ) )
			{
			while( cipherSuiteInfo[ suiteIndex ]->keyexAlgo == keyexAlgo && \
				   suiteIndex < cipherSuiteInfoSize )
				suiteIndex++;
			ENSURES( suiteIndex < cipherSuiteInfoSize );
			continue;
			}

		/* If the bulk encryption algorithm or MAC algorithm for this suite 
		   isn't enabled for this build of cryptlib, skip all suites that 
		   use it */
		if( !algoAvailable( cryptAlgo ) )
			{
			while( cipherSuiteInfo[ suiteIndex ]->cryptAlgo == cryptAlgo && \
				   suiteIndex < cipherSuiteInfoSize )
				suiteIndex++;
			ENSURES( suiteIndex < cipherSuiteInfoSize );
			continue;
			}
		if( !algoAvailable( macAlgo ) )
			{
			while( cipherSuiteInfo[ suiteIndex ]->macAlgo == macAlgo && \
				   suiteIndex < cipherSuiteInfoSize )
				suiteIndex++;
			ENSURES( suiteIndex < cipherSuiteInfoSize );
			continue;
			}

		/* The suite is supported, remember it.  In theory there's only a
		   single combination of the various algorithms present, but these 
		   can be subsetted into different key sizes (because they're there, 
		   that's why) so we have to iterate the recording of available 
		   suites instead of just assigning a single value on match */
		while( cipherSuiteInfo[ suiteIndex ]->keyexAlgo == keyexAlgo && \
			   cipherSuiteInfo[ suiteIndex ]->authAlgo == authAlgo && \
			   cipherSuiteInfo[ suiteIndex ]->cryptAlgo == cryptAlgo && \
			   cipherSuiteInfo[ suiteIndex ]->macAlgo == macAlgo && \
			   cipherSuiteCount < 32 && suiteIndex < cipherSuiteInfoSize )
			{
			availableSuites[ cipherSuiteCount++ ] = \
						cipherSuiteInfo[ suiteIndex++ ]->cipherSuite;
			}
		ENSURES( suiteIndex < cipherSuiteInfoSize );
		ENSURES( cipherSuiteCount < 32 );
		}
	ENSURES( suiteIndex < cipherSuiteInfoSize );
	ENSURES( cipherSuiteCount > 0 && cipherSuiteCount < 32 );

	/* Encode the list of available cipher suites */
	status = writeUint16( stream, cipherSuiteCount * UINT16_SIZE );
	for( suiteIndex = 0; 
		 cryptStatusOK( status ) && suiteIndex < cipherSuiteCount; 
		 suiteIndex++ )
		status = writeUint16( stream, availableSuites[ suiteIndex ] );

	return( status );
	}

/* Process a server's DH/ECDH key agreement data:

	   DH:
		uint16		dh_pLen
		byte[]		dh_p
		uint16		dh_gLen
		byte[]		dh_g
		uint16		dh_YsLen
		byte[]		dh_Ys
	   ECDH:
		byte		curveType
		uint16		namedCurve
		uint8		ecPointLen		-- NB uint8 not uint16
		byte[]		ecPoint */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processServerKeyex( INOUT STREAM *stream, 
							   OUT KEYAGREE_PARAMS *keyAgreeParams,
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
								   CRYPT_UNUSED, isECC ? \
										CRYPT_ECCCURVE_P256 /* Dummy */ : \
										CRYPT_ECCCURVE_NONE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the DH/ECDH public value */
	if( isECC )
		{
		return( readEcdhValue( stream, keyAgreeParams->publicValue,
							   CRYPT_MAX_PKCSIZE, 
							   &keyAgreeParams->publicValueLen ) );
		}
	return( readInteger16UChecked( stream, keyAgreeParams->publicValue,
								   &keyAgreeParams->publicValueLen,
								   MIN_PKCSIZE_THRESHOLD, 
								   CRYPT_MAX_PKCSIZE ) );
	}

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
		byte[32]	nonce
		byte		sessIDlen = 0
	  [	byte[]		sessID			-- Omitted since len == 0 ]
		uint16		suiteLen
		uint16[]	suite
		byte		coprLen = 1
		byte[]		copr = { 0x00 }
	  [	uint16	extListLen			-- RFC 3546/RFC 4366
			byte	extType
			uint16	extLen
			byte[]	extData ] 

	   Extensions present a bit of an interoperability problem on the client
	   side, if we use them then we have to add them to the client hello 
	   before we know whether the server can handle them, and many servers
	   can't (this is particularly bad in cryptlib's case where it's used
	   with embedded systems, which have ancient and buggy SSL/TLS
	   implementations that are rarely if ever updated).  A reasonable 
	   compromise is to only enable the use of extensions when the user has 
	   asked for TLS 1.1+ support */
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
										 CRYPT_SESSINFO_USERNAME ) != NULL ? \
							TRUE : FALSE,
						( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS12 ) ? \
							TRUE : FALSE,
						sessionInfoPtr->protocolFlags & SSL_PFLAG_SUITEB );
	if( cryptStatusOK( status ) )
		{
		sputc( stream, 1 );		/* No compression */
		status = sputc( stream, 0 );
		}
	if( cryptStatusOK( status ) && \
		sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS11 )
		{
		/* Extensions are only written when newer versions of TLS are 
		   enabled, see the comment earlier for details */
		status = writeClientExtensions( stream, sessionInfoPtr );
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

	/* Perform the assorted hashing of the client hello in between the 
	   network ops where it's effectively free */
	status = hashHSPacketWrite( handshakeInfo, stream, 0 );
	sMemDisconnect( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the server hello.  The server usually sends us a session ID 
	   to indicate a (potentially) resumable session, indicated by a return 
	   status of OK_SPECIAL, but we don't do anything further with it since 
	   we won't be resuming the session.

	   Note that this processing leads to a slight inefficiency in hashing 
	   when multiple hash algorithms need to be accomodated (as they do
	   when TLS 1.2+ is enabled) because readHSPacketSSL() hashes the 
	   incoming packet data as it arrives, and if all possible server 
	   handshake packets are combined into a single SSL message packet then 
	   they'll arrive, and need to be hashed, before the server hello is
	   processed and we can selectively disable the hash algorithms that
	   won't be needed.  Fixing this would require adding special-case
	   processing to readHSPacketSSL() to detect the use of 
	   SSL_MSG_FIRST_HANDSHAKE for the client and skip the hashing, relying
	   on the calling code to then pick out the portions that need to be
	   hashed.  This probably isn't worth the effort required, since it adds
	   a lot of code complexity and custom processing just to save a small
	   amount of hashing on the client, which will generally be the less
	   resource-constrained of the two parties */
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
	int packetOffset, packetStreamOffset = 0, length;
	int keyexPublicValueLen = DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* Process the optional server supplemental data:

		byte		ID = SSL_HAND_SUPPLEMENTAL_DATA
		uint24		len
		uint16		type
		uint16		len
		byte[]		value

	   This is a kitchen-sink mechanism for exchanging arbitrary further 
	   data during the TLS handshake (see RFC 4680).  The presence of the
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
		uint24		certLen			-- 1...n certificates ordered
		byte[]		certificate		-- leaf -> root */
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
	 [	byte		hashAlgoID		-- TLS 1.2 ]
	 [	byte		sigAlgoID		-- TLS 1.2 ]
		uint16		signatureLen
		byte[]		signature 
	   ECDH:
		byte		curveType
		uint16		namedCurve
		uint8		ecPointLen		-- NB uint8 not uint16
		byte[]		ecPoint
	 [	byte		hashAlgoID		-- TLS 1.2 ]
	 [	byte		sigAlgoID		-- TLS 1.2 ]
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
			   specific message than the generic bad-data error */
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
		ANALYSER_HINT( keyData != NULL );

		/* Check the server's signature on the DH/ECDH parameters */
		status = checkKeyexSignature( sessionInfoPtr, handshakeInfo,
									  stream, keyData, keyDataLength,
									  isECC );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Invalid server key agreement parameter signature" ) );
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
	 [	uint16	sigHashListLen		-- TLS 1.2 ]
	 [		byte	hashAlgoID		-- TLS 1.2 ]
	 [		byte	sigAlgoID		-- TLS 1.2 ]
		uint16	caNameListLen
			uint16	caNameLen
			byte[]	caName

	   We don't really care what's in the certificate request packet since 
	   the contents are irrelevant, in a number of cases servers have been
	   known to send out superfluous certificate requests without the admins 
	   even knowing that they're doing it, in other cases servers send out
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
									  1 + 1 + \
									  ( ( sessionInfoPtr->version >= \
										  SSL_MINOR_VERSION_TLS12 ) ? \
										( UINT16_SIZE + 1 + 1 ) : 0 ) + \
									  UINT16_SIZE );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}
		status = length = sgetc( stream );
		if( cryptStatusError( status ) || \
			length < 1 || length > 64 || \
			cryptStatusError( sSkip( stream, length ) ) )
			{
			sMemDisconnect( stream );
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid certificate request certificate-type "
					  "information" ) );
			}
		if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS12 )
			{
			status = length = readUint16( stream );
			if( cryptStatusError( status ) || \
				length < UINT16_SIZE || length > 64 || \
				cryptStatusError( sSkip( stream, length ) ) )
				{
				sMemDisconnect( stream );
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid certificate request signature/hash "
						  "algorithm information" ) );
				}
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
		uint8		ecPointLen		-- NB uint8 not uint16
		byte[]		ecPoint
	   PSK:
		uint16		userIDLen
		byte[]		userID
	   RSA:
	  [ uint16		encKeyLen		-- TLS only ]
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
						  "Couldn't create master secret from shared "
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
			if( sessionInfoPtr->version <= SSL_MINOR_VERSION_SSL )
				{
				/* The original Netscape SSL implementation didn't provide a
				   length for the encrypted key and everyone copied that so
				   it became the de facto standard way to do it (sic faciunt
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
		/* Since the client certificate-verify message requires the hash of
		   all handshake packets up to this point, we have to interrupt the
		   processing to hash them before we continue */
		status = completePacketStreamSSL( stream, 0 );
		if( cryptStatusOK( status ) )
			status = hashHSPacketWrite( handshakeInfo, stream, 0 );
		if( cryptStatusOK( status ) )
			status = createCertVerifyHash( sessionInfoPtr, handshakeInfo );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( stream );
			return( status );
			}

		/* Write the packet header and drop in the signature data.  Since 
		   we've interrupted the packet stream to perform the hashing we 
		   have to restart it at this point */
		status = continuePacketStreamSSL( stream, sessionInfoPtr, 
										  SSL_MSG_HANDSHAKE, 
										  &packetStreamOffset );
		if( cryptStatusError( status ) )
			return( status );
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

	/* Wrap the packet and perform the assorted hashing for it.  This is 
	   followed by the change cipherspec packet so we don't send it at this 
	   point but leave it to be sent by the shared handshake-completion 
	   code */
	status = completePacketStreamSSL( stream, packetStreamOffset );
	if( cryptStatusOK( status ) )
		status = hashHSPacketWrite( handshakeInfo, stream, 
									packetStreamOffset );
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
