/****************************************************************************
*																			*
*				cryptlib SSL v3/TLS Hello Handshake Management				*
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
*								Utility Functions							*
*																			*
****************************************************************************/

/* Process a session ID */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processSessionID( INOUT SESSION_INFO *sessionInfoPtr,
							 INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
							 INOUT STREAM *stream )
	{
	BYTE sessionID[ SESSIONID_SIZE + 8 ];
	int sessionIDlength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Get the session ID information and if it's not (potentially) one of 
	   ours (length = SESSIONID_SIZE), skip it.  In addition if we're the 
	   client we also skip it since session cacheing is only done by the 
	   server */
	status = sessionIDlength = sgetc( stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid session ID information" ) );
		}
	if( sessionIDlength < 0 || sessionIDlength > MAX_SESSIONID_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid session ID length %d, should be 0...%d", 
				  sessionIDlength, MAX_SESSIONID_SIZE ) );
		}
	if( sessionIDlength != SESSIONID_SIZE )
		{
		if( sessionIDlength > 0 )
			{
			status = sSkip( stream, sessionIDlength );
			if( cryptStatusError( status ) )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid session ID" ) );
				}
			}
		return( CRYPT_OK );
		}

	/* It's a potentially resumed session, remember the details and let the 
	   caller know */
	status = sread( stream, sessionID, SESSIONID_SIZE );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid session ID" ) );
		}
	memcpy( handshakeInfo->sessionID, sessionID, SESSIONID_SIZE );
	handshakeInfo->sessionIDlength = SESSIONID_SIZE;
	return( OK_SPECIAL );
	}

/****************************************************************************
*																			*
*							Process TLS Extensions							*
*																			*
****************************************************************************/

/* TLS extension information */

typedef struct {
	const int type;					/* Extension type */
	const int minLength, maxLength;	/* Min, max lengths */
	const char *typeName;			/* Name for error messages */
	} EXT_CHECK_INFO;

static const EXT_CHECK_INFO extCheckInfoTbl[] = {
	/* Server name:

		uint16		listLen
			byte	nameType
			uint16	nameLen
			byte[]	name */
	{ TLS_EXT_SERVER_NAME, 1, 8192, "host name" },

	/* Maximm fragment length:

		byte		fragmentLength */
	{ TLS_EXT_MAX_FRAGMENT_LENTH, 1, 1, "fragment length" },

	/* Client certificate URL.  This dangerous extension allows a client to 
	   direct a server to grope around in arbitrary external (and untrusted) 
	   URLs trying to locate certificates, provinding a convenient mechanism 
	   for bounce attacks and all manner of similar firewall/trusted-host 
	   subversion problems:

		byte		chainType
		uint16		urlAndHashList
			uint16	urlLen
			byte[]	url
			byte	hashPresent
			byte[20] hash			-- If hashPresent flag set */
	{ TLS_EXT_CLIENT_CERTIFICATE_URL, 
	  1 + UINT16_SIZE + UINT16_SIZE + MIN_URL_SIZE + 1, 8192,
	  "client certificate URL" },

	/* Trusted CA certificate(s).  This allows a client to specify which CA 
	   certificates it trusts and by extension which server certificates it 
	   trusts, supposedly to reduce handshake messages in constrained 
	   clients.  Since the server usually has only a single certificate 
	   signed by a single CA, specifying the CAs that the client trusts 
	   doesn't serve much purpose:

		uint16		caList
			byte	idType
			[ choice of keyHash, certHash, or DN, another 
			  ASN.1-as-TLS structure ] */
	{ TLS_EXT_TRUSTED_CA_KEYS, UINT16_SIZE + 1, 8192, "trusted CA" },

	/* Truncate the HMAC to a nonstandard 80 bits (rather than the de 
	   facto IPsec cargo-cult standard of 96 bits) */
	{ TLS_EXT_TRUNCATED_HMAC, 0, 0, "truncated HMAC" },

	/* OCSP status request.  Another bounce-attack enabler, this time on 
	   both the server and an OCSP responder:

		byte		statusType
		uint16		ocspResponderList
			uint16	responderLength
			byte[]	responder
			uint16	extensionLength
			byte[]	extensions */
	{ TLS_EXT_STATUS_REQUEST, 
	  1 + UINT16_SIZE + UINT16_SIZE + MIN_URL_SIZE + UINT16_SIZE, 8192, 
	  "OCSP status request" },

	/* User mapping.  Used with a complex RFC 4680 mechanism (the extension 
	   itself is in RFC 4681):

		byte		mappingLength
		byte[]		mapping */
	{ TLS_EXT_USER_MAPPING, 1 + 1, 1 + 255, "user-mapping" },

	/* OpenPGP key.  From an experimental RFC with support for OpenPGP keys:

		byte		certTypeListLength
		byte[]		certTypeList */
	{ TLS_EXT_CERTTYPE, 1 + 1, 1 + 255, "cert-type (OpenPGP keying)" },

	/* Supported ECC curve IDs:

		uint16		namedCurveListLength
		uint16[]	namedCurve */
	{ TLS_EXT_ELLIPTIC_CURVES, UINT16_SIZE + UINT16_SIZE, 512, "ECDH/ECDSA curve ID" },

	/* Supported ECC point formats:

		byte		pointFormatListLength
		byte[]		pointFormat */
	{ TLS_EXT_EC_POINT_FORMATS, 1 + 1, 255, "ECDH/ECDSA point format" },

	/* SRP user name:

		byte		userNameLength
		byte[]		userName */
	{ TLS_EXT_SRP, 1 + 1, 1 + 255, "SRP username" },

	/* Signature algorithms:

		uint16		algorithmListLength
			byte	hashAlgo
			byte	sigAlgo */
	{ TLS_EXT_SIGNATURE_ALGORITHMS, UINT16_SIZE + 1 + 1, 512, 
	  "signature algorithm" },

	/* Session ticket.  The client can send a zero-length session ticket to 
	   indicate that it supports the extension but doesn't have a session 
	   ticket yet:

		uint16		sessionTicketSize (may be zero)
		byte[]		sessionTicket */
	{ TLS_EXT_SESSIONTICKET, UINT16_SIZE, 8192, "session ticket" },

	/* End-of-list marker */
	{ CRYPT_ERROR, 0, 0, NULL }, { CRYPT_ERROR, 0, 0, NULL }
	};

/* Process a single extension.  The internal structure of some of these 
   things shows that they were created by ASN.1 people... */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processExtension( INOUT SESSION_INFO *sessionInfoPtr, 
							 INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
							 INOUT STREAM *stream, 
							 IN_RANGE( 0, 65536 ) const int type,
							 IN_LENGTH_SHORT_Z const int extLength )
	{
	int value, listLen, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( type >= 0 && type <= 65536 );
	REQUIRES( extLength >= 0 && extLength < MAX_INTLENGTH_SHORT );

	switch( type )
		{
		case TLS_EXT_SERVER_NAME:
			/* Response: Send zero-length reply to peer:

				uint16		listLen
					byte	nameType
					uint16	nameLen
					byte[]	name */
			status = listLen = readUint16( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( listLen != extLength - UINT16_SIZE || \
				listLen < 1 + UINT16_SIZE || \
				listLen > MAX_INTLENGTH_SHORT )
				return( CRYPT_ERROR_BADDATA );
			status = sSkip( stream, listLen );
			if( cryptStatusError( status ) )
				return( status );

			/* Parsing of further SEQUENCE OF SEQUENCE data omitted */
			return( CRYPT_OK );

		case TLS_EXT_MAX_FRAGMENT_LENTH:
			{
/*			static const int fragmentTbl[] = \
					{ 0, 512, 1024, 2048, 4096, 8192, 16384, 16384 }; */

			/* Response: If fragment-size == 3...5, send same to peer.  Note 
			   that we also allow a fragment-size value of 5, which isn't 
			   specified in the standard but should probably be present 
			   since it would otherwise result in a missing value between 
			   4096 and the default of 16384:

				byte		fragmentLength */
			status = value = sgetc( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( value < 1 || value > 5 )
				return( CRYPT_ERROR_BADDATA );

/*			sessionInfoPtr->maxPacketSize = fragmentTbl[ value ]; */
			return( CRYPT_OK );
			}

		case TLS_EXT_ELLIPTIC_CURVES:
			{
			/* Read the list of preferred curves, selecting the best one.  
			   We somewhat arbitrarily define 'best' as 'biggest':

				uint16		namedCurveListLength
				uint16[]	namedCurve */
			static const MAP_TABLE curveIDTbl[] = {
				{ 19, CRYPT_ECCCURVE_P192 },
				{ 21, CRYPT_ECCCURVE_P224 },
				{ 23, CRYPT_ECCCURVE_P256 },
				{ 24, CRYPT_ECCCURVE_P384 },
				{ 25, CRYPT_ECCCURVE_P521 },
				{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
				};
			int curveID, preferredCurveID = CRYPT_ERROR, i;

			status = listLen = readUint16( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( listLen != extLength - UINT16_SIZE || \
				listLen < UINT16_SIZE || listLen > 256 )
				return( CRYPT_ERROR_BADDATA );

			/* Read the list of curve IDs, recording the most preferred one */
			for( i = 0; i < listLen / UINT16_SIZE; i++ )
				{
				status = value = readUint16( stream );
				if( cryptStatusError( status ) )
					return( status );
				status = mapValue( value, &curveID, curveIDTbl, 
								   FAILSAFE_ARRAYSIZE( curveIDTbl, MAP_TABLE ) );
				if( cryptStatusOK( status ) && \
					curveID > preferredCurveID )
					preferredCurveID = curveID;
				}

			/* If we couldn't find a curve that we have in common with the 
			   other side, disable the use of ECC algorithms.  This is a 
			   somewhat nasty failure mode because it means that something 
			   like a buggy implementation that sends the wrong hello 
			   extension (which is rather more likely than, say, an 
			   implementation not supporting the de facto universal-standard 
			   Suite B curves) means that the crypto is quietly switched to 
			   non-ECC with the user being none the wiser, but there's no 
			   way for an implementation to negotiate ECC-only encryption */
			if( preferredCurveID == CRYPT_ERROR )
				handshakeInfo->disableECC = TRUE;
			else
				handshakeInfo->eccCurveID = preferredCurveID;

			return( CRYPT_OK );
			}

		case TLS_EXT_EC_POINT_FORMATS:
			/* We don't really need to process this extension because every 
			   implementation is required to support uncompressed points (it 
			   also seems to be the universal standard that everyone uses by 
			   default anyway) so all that we do is treat the presence of 
			   the overall extension as an indicator that we should send 
			   back our own one in the server hello:

				byte		pointFormatListLength
				byte[]		pointFormat */
			handshakeInfo->sendECCPointExtn = TRUE;

			/* Fall through */

		default:
			/* Default: Ignore the extension */
			if( extLength > 0 )
				{
				status = sSkip( stream, extLength );
				if( cryptStatusError( status ) )
					return( status );
				}

			return( CRYPT_OK );
		}

	retIntError();
	}

/* Process RFC 3546 TLS extensions, with further types defined at
   http://www.iana.org/assignments/tls-extensiontype-values:

	uint16		extListLen		| RFC 3546
		uint16	extType
		uint16	extLen
		byte[]	extData */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processExtensions( INOUT SESSION_INFO *sessionInfoPtr, 
							  INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
							  INOUT STREAM *stream, 
							  IN_LENGTH_SHORT const int length )
	{
	const int endPos = stell( stream ) + length;
	int extListLen, noExtensions, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( length > 0 && length < MAX_INTLENGTH_SHORT );
	REQUIRES( endPos > 0 && endPos < MAX_INTLENGTH_SHORT );

	/* Read the extension header and make sure that it's valid */
	if( length < UINT16_SIZE + UINT16_SIZE + UINT16_SIZE + 1 )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "TLS hello contains %d bytes extraneous data", length ) );
		}
	status = extListLen = readUint16( stream );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid TLS extension information" ) );
		}
	if( extListLen != length - UINT16_SIZE )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid TLS extension data length %d, should be %d",
				  extListLen, length - UINT16_SIZE ) );
		}

	/* Process the extensions */
	for( noExtensions = 0; stell( stream ) < endPos && \
						   noExtensions < FAILSAFE_ITERATIONS_MED; 
		 noExtensions++ )
		{
		const EXT_CHECK_INFO *extCheckInfoPtr = NULL;
		int type, extLen, i;

		/* Read the header for the next extension and get the extension-
		   checking information */
		type = readUint16( stream );
		status = extLen = readUint16( stream );
		if( cryptStatusError( status ) || extLen < 0 || extLen > 16384 )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid TLS extension list item header" ) );
			}
		for( i = 0; extCheckInfoTbl[ i ].type != CRYPT_ERROR && \
					i < FAILSAFE_ARRAYSIZE( extCheckInfoTbl, EXT_CHECK_INFO ); 
			 i++ )
			{
			if( extCheckInfoTbl[ i ].type == type )
				{
				extCheckInfoPtr = &extCheckInfoTbl[ i ];
				break;
				}
			}
		ENSURES( i < FAILSAFE_ARRAYSIZE( extCheckInfoTbl, EXT_CHECK_INFO ) ); 
		if( extCheckInfoPtr != NULL )
			{
			/* Perform any necessary initial checking of the extension */
			if( extLen < extCheckInfoPtr->minLength || \
				extLen > extCheckInfoPtr->maxLength )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid TLS %s extension length %d, should be "
						  "%d...%d", extCheckInfoPtr->typeName, extLen,
						  extCheckInfoPtr->minLength, 
						  extCheckInfoPtr->maxLength ) );
				}
			}

		/* Process the extension data */
		status = processExtension( sessionInfoPtr, handshakeInfo, stream, 
								   type, extLen );
		if( cryptStatusError( status ) )
			{
			if( extCheckInfoPtr != NULL )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid TLS %s extension data", 
						  extCheckInfoPtr->typeName ) );
				}
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid TLS extension data for extension "
					  "type %d", type ) );
			}
		}
	if( noExtensions >= FAILSAFE_ITERATIONS_MED )
		{
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, SESSION_ERRINFO, 
				  "Excessive number (%d) of TLS extensions encountered", 
				  noExtensions ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Negotiate a Cipher Suite						*
*																			*
****************************************************************************/

/* Set up the crypto information based on the cipher suite */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int setSuiteInfo( INOUT SESSION_INFO *sessionInfoPtr,
						 INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						 const CIPHERSUITE_INFO *cipherSuiteInfoPtr )
	{
	CRYPT_QUERY_INFO queryInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( cipherSuiteInfoPtr, sizeof( CIPHERSUITE_INFO ) ) );

	handshakeInfo->cipherSuite = cipherSuiteInfoPtr->cipherSuite;
	handshakeInfo->keyexAlgo = cipherSuiteInfoPtr->keyexAlgo;
	handshakeInfo->authAlgo = cipherSuiteInfoPtr->authAlgo;
	handshakeInfo->cryptKeysize = cipherSuiteInfoPtr->cryptKeySize;
	sessionInfoPtr->cryptAlgo = cipherSuiteInfoPtr->cryptAlgo;
	sessionInfoPtr->integrityAlgo = cipherSuiteInfoPtr->macAlgo;
	if( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL )
		{
		/* SSL uses a proto-HMAC which requires that we synthesize it from
		   raw hash functionality */
		sessionInfoPtr->integrityAlgo = \
			( sessionInfoPtr->integrityAlgo == CRYPT_ALGO_HMAC_MD5 ) ? \
			CRYPT_ALGO_MD5 : CRYPT_ALGO_SHA1;
		}
	sessionInfoPtr->authBlocksize = cipherSuiteInfoPtr->macBlockSize;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_QUERYCAPABILITY, &queryInfo,
							  sessionInfoPtr->cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );
	sessionInfoPtr->cryptBlocksize = queryInfo.blockSize;

	return( CRYPT_OK );
	}

/* Choose the best cipher suite from a list of suites */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int processCipherSuite( INOUT SESSION_INFO *sessionInfoPtr, 
							   INOUT SSL_HANDSHAKE_INFO *handshakeInfo, 
							   INOUT STREAM *stream, 
							   IN_RANGE( 1, MAX_CIPHERSUITES ) \
									const int noSuites )
	{
	const CIPHERSUITE_INFO *cipherSuiteInfo;
	const BOOLEAN isServer = isServer( sessionInfoPtr ) ? TRUE : FALSE;
	BOOLEAN allowDH = algoAvailable( CRYPT_ALGO_DH );
	BOOLEAN allowECC = algoAvailable( CRYPT_ALGO_ECDH );
	int cipherSuiteInfoSize, suiteIndex = 999, altSuiteIndex = 999;
	int i, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( noSuites > 0 && noSuites <= MAX_CIPHERSUITES );

	/* Get the information for the supported cipher suites */
	status = getCipherSuiteInfo( &cipherSuiteInfo, &cipherSuiteInfoSize );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're the server then our choice of possible suites is constrained 
	   by the server key that we're using, figure out what we can use */
	if( isServer && sessionInfoPtr->privateKey != CRYPT_ERROR )
		{
		int value;

		/* To be usable for DH/ECC the server key has to be signature-
		   capable */
		status = krnlSendMessage( sessionInfoPtr->privateKey, 
								  IMESSAGE_CHECK, NULL, 
								  MESSAGE_CHECK_PKC_SIGN );
		if( cryptStatusError( status ) )
			allowDH = allowECC = FALSE;

		/* To be usable for ECC the server key has to itself be an ECC 
		   key */
		status = krnlSendMessage( sessionInfoPtr->privateKey, 
								  IMESSAGE_GETATTRIBUTE, &value,
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) || !isEccAlgo( value ) )
			allowECC = FALSE;
		}

	for( i = 0; i < noSuites; i++ )
		{
		const CIPHERSUITE_INFO *cipherSuiteInfoPtr = NULL;
		int newSuite, newSuiteIndex;

#if 0	/* 28/01/08 Disabled since it's now finally removed in MSIE and 
		   Firefox (but see also the comment in ssl_rd.c) */
		/* If we're reading an SSLv2 hello and it's an SSLv2 suite (the high
		   byte is nonzero), skip it and continue */
		if( handshakeInfo->isSSLv2 )
			{
			newSuite = sgetc( stream );
			if( cryptStatusError( newSuite ) )
				{
				retExt( newSuite,
						( newSuite, SESSION_ERRINFO, 
						  "Invalid cipher suite information" ) );
				}
			if( newSuite != 0 )
				{
				readUint16( stream );
				continue;
				}
			}
#endif /* 0 */

		/* Get the cipher suite information */
		status = newSuite = readUint16( stream );
		if( cryptStatusError( status ) )
			{
			retExt( status,
					( status, SESSION_ERRINFO, 
					  "Invalid cipher suite information" ) );
			}

#if 0	/* When resuming a cached session the client is required to offer
		   as one of its suites the original suite that was used.  There's
		   no good reason for this requirement (it's probable that the spec
		   is intending that there be at least one cipher suite and that if
		   there's only one it should really be the one originally
		   negotiated) and it complicates implementation of shared-secret
		   key sessions so we don't perform this check */
		/* If we have to match a specific suite and this isn't it,
		   continue */
		if( requiredSuite > 0 && requiredSuite != newSuite )
			continue;
#endif /* 0 */

		/* If we're the client and we got back our canary method-of-last-
		   resort suite from the server without having seen another suite
		   that we can use first, the server is incapable of handling non-
		   crippled crypto.  Veni, vidi, volo in domum redire */
		if( !isServer && suiteIndex >= cipherSuiteInfoSize && \
			newSuite == SSL_RSA_EXPORT_WITH_RC4_40_MD5 )
			{
			retExt( CRYPT_ERROR_NOSECURE,
					( CRYPT_ERROR_NOSECURE, SESSION_ERRINFO, 
					  "Server rejected attempt to connect using "
					  "non-crippled encryption" ) );
			}

		/* Try and find the information for the proposed cipher suite */
		for( newSuiteIndex = 0; 
			 cipherSuiteInfo[ newSuiteIndex ].cipherSuite != SSL_NULL_WITH_NULL && \
				newSuiteIndex < cipherSuiteInfoSize; 
			 newSuiteIndex++ )
			{
			if( cipherSuiteInfo[ newSuiteIndex ].cipherSuite == newSuite )
				{
				cipherSuiteInfoPtr = &cipherSuiteInfo[ newSuiteIndex ];
				break;
				}
			}
		ENSURES( newSuiteIndex < cipherSuiteInfoSize );
		if( cipherSuiteInfoPtr == NULL )
			continue;

		/* Make sure that the required algorithms are available.  We don't
		   have to check the MAC algorithms since MD5 and SHA-1 are always
		   available as they're required for the handshake */
		if( !algoAvailable( cipherSuiteInfoPtr->cryptAlgo ) )
			continue;
		if( ( cipherSuiteInfoPtr->keyexAlgo != cipherSuiteInfoPtr->authAlgo ) && \
			!algoAvailable( cipherSuiteInfoPtr->keyexAlgo ) )
			continue;

		/* If it's a suite that's disabled because of external constraints, 
		   we can't use it */
		if( ( cipherSuiteInfoPtr->flags & CIPHERSUITE_FLAG_DH ) && \
			!allowDH )
			continue;
		if( ( cipherSuiteInfoPtr->flags & CIPHERSUITE_FLAG_ECC ) && \
			!allowECC )
			continue;

		/* If we're only able to do basic TLS-PSK because there's no private 
		   key present and the suite requires a private key then we can't 
		   use this suite */
		if( isServer && sessionInfoPtr->privateKey == CRYPT_ERROR && \
			cipherSuiteInfoPtr->keyexAlgo != CRYPT_ALGO_NONE )
			continue;

		/* If the new suite is more preferred (i.e. with a lower index) than 
		   the existing one, use that.  The presence of the ECC suites 
		   significantly complicates this process because the ECC curve 
		   information sent later on in the handshake can retroactively 
		   disable an already-negotiated ECC cipher suite, forcing a fallback 
		   to a non-ECC suite (this soft-fail fallback is also nasty for the
		   user since they can't guarantee that they're actually using ECC
		   if they ask for it).  To handle this we keep track of both the
		   most-preferred (non-ECC) suite and the most preferred ECC suite 
		   so that we can switch later if necessary */
		if( cipherSuiteInfoPtr->flags & CIPHERSUITE_FLAG_ECC )
			{
			if( newSuiteIndex < altSuiteIndex )
				altSuiteIndex = newSuiteIndex;
			}
		else
			{
			if( newSuiteIndex < suiteIndex )
				suiteIndex = newSuiteIndex;
			}
		}

	/* If the only matching suite that we found was an ECC one, set it to 
	   the primary suite (which can then be retroactively knocked out as per 
	   the comment earlier) */
	if( suiteIndex >= cipherSuiteInfoSize )
		{
		suiteIndex = altSuiteIndex;
		altSuiteIndex = 999;
		}

	/* If we couldn't find anything to use, exit.  The range comparison is 
	   actually for whether it's still set to the original value of 999 but 
	   some source analysis tools think that it's an index check so we 
	   compare to the upper bound of the array size instead */
	if( suiteIndex >= cipherSuiteInfoSize && \
		altSuiteIndex >= cipherSuiteInfoSize )
		{
		retExt( CRYPT_ERROR_NOTAVAIL,
				( CRYPT_ERROR_NOTAVAIL, SESSION_ERRINFO, 
				  "No encryption mechanism compatible with the remote "
				  "system could be found" ) );
		}

	/* We got a cipher suite that we can handle, set up the crypto information */
	status = setSuiteInfo( sessionInfoPtr, handshakeInfo,
						   &cipherSuiteInfo[ suiteIndex ] );
	if( cryptStatusError( status ) )
		return( status );

	/* If we found an ECC suite, remember this in case we later find out 
	   that we can use it */
	if( altSuiteIndex < cipherSuiteInfoSize )
		{
		REQUIRES( allowECC );

		handshakeInfo->eccSuiteInfoPtr = &cipherSuiteInfo[ altSuiteIndex ];
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Process Client/Server Hello 						*
*																			*
****************************************************************************/

/* Process the client/server hello:

	byte		ID = SSL_HAND_CLIENT_HELLO / SSL_HAND_SERVER_HELLO
	uint24		len
	byte[2]		version = { 0x03, 0x0n }
	uint32		time		| Client/server nonce
	byte[28]	nonce		|
	byte		sessIDlen	| May receive nonzero len +
	byte[]		sessID		|	<len> bytes data

		Client						Server
	uint16		suiteLen		-
	uint16[]	suites			uint16		suite
	byte		coprLen = 1		-
	byte		copr = 0		byte		copr = 0 */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int processHelloSSL( INOUT SESSION_INFO *sessionInfoPtr, 
					 INOUT SSL_HANDSHAKE_INFO *handshakeInfo, 
					 INOUT STREAM *stream, const BOOLEAN isServer )
	{
	BOOLEAN potentiallyResumedSession = FALSE;
	int endPos, length, suiteLength = 1, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Check the header and version information */
	if( isServer )
		{
		status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
									  SSL_HAND_CLIENT_HELLO,
									  VERSIONINFO_SIZE + SSL_NONCE_SIZE + \
										1 + ( UINT16_SIZE * 2 ) + 1 + 1 );
		}
	else
		{
		status = checkHSPacketHeader( sessionInfoPtr, stream, &length,
									  SSL_HAND_SERVER_HELLO,
									  VERSIONINFO_SIZE + SSL_NONCE_SIZE + \
										1 + UINT16_SIZE + 1 );
		}
	if( cryptStatusError( status ) )
		return( status );
	endPos = stell( stream ) + length;
	status = processVersionInfo( sessionInfoPtr, stream,
								 isServer ? \
									&handshakeInfo->clientOfferedVersion : \
									NULL );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the nonce and session ID */
	status = sread( stream, isServer ? \
						handshakeInfo->clientNonce : \
						handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	if( cryptStatusOK( status ) )
		status = processSessionID( sessionInfoPtr, handshakeInfo, stream );
	if( cryptStatusError( status ) )
		{
		if( status == OK_SPECIAL )
			potentiallyResumedSession = TRUE;
		else
			return( status );
		}

	/* Process the cipher suite information */
	if( isServer )
		{
		/* We're reading the client hello, the packet contains a
		   selection of suites preceded by a suite count */
		status = suiteLength = readUint16( stream );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid cipher suite information" ) );
			}
		if( suiteLength < UINT16_SIZE || \
			suiteLength > ( UINT16_SIZE * MAX_CIPHERSUITES ) || \
			( suiteLength % UINT16_SIZE ) != 0 )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid cipher suite length %d", 
					  suiteLength ) );
			}
		suiteLength /= UINT16_SIZE;
		}
	status = processCipherSuite( sessionInfoPtr, handshakeInfo, stream,
								 suiteLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the compression suite information.  Since we don't implement
	   compression all that we need to do is check that the format is valid
	   and then skip the suite information */
	if( isServer )
		{
		/* We're reading the client hello, the packet contains a selection 
		   of suites preceded by a suite count */
		status = suiteLength = sgetc( stream );
		if( cryptStatusError( status ) )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid compression suite information" ) );
			}
		if( suiteLength < 1 || suiteLength > 20 )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "Invalid compression suite length %d, should be "
					  "1...20", suiteLength ) );
			}
		}
	status = sSkip( stream, suiteLength );
	if( cryptStatusError( status ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid compression algorithm information" ) );
		}

	/* If there's extra data present at the end of the packet, check for TLS
	   extension data */
	if( endPos - stell( stream ) > 0 )
		{
		const int extensionLength = endPos - stell( stream );

		if( extensionLength < UINT16_SIZE || \
			extensionLength >= MAX_INTLENGTH_SHORT )
			{
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
					  "TLS hello contains %d bytes extraneous data", 
					  extensionLength ) );
			}
		status = processExtensions( sessionInfoPtr, handshakeInfo, stream,
									extensionLength );
		if( cryptStatusError( status ) )
			return( status );
		handshakeInfo->hasExtensions = TRUE;
		}

	/* If we're the server and the client has chosen an ECC suite and it 
	   hasn't subsequently been disabled by an incompatible choice of
	   client-selected parameters, switch to the ECC suite */
	if( isServer && handshakeInfo->eccSuiteInfoPtr != NULL && \
		!handshakeInfo->disableECC )
		{
		status = setSuiteInfo( sessionInfoPtr, handshakeInfo, 
							   handshakeInfo->eccSuiteInfoPtr );
		if( cryptStatusError( status ) )
			return( status );

		/* If there's no ECC curve selected by the client, default to P256 */
		if( handshakeInfo->eccCurveID == CRYPT_ECCCURVE_NONE )
			handshakeInfo->eccCurveID = CRYPT_ECCCURVE_P256;
		}

	return( potentiallyResumedSession ? OK_SPECIAL : CRYPT_OK );
	}
#endif /* USE_SSL */
