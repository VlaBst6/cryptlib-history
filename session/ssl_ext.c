/****************************************************************************
*																			*
*					cryptlib TLS Extension Management						*
*					Copyright Peter Gutmann 1998-2010						*
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
*							TLS Extension Definitions						*
*																			*
****************************************************************************/

/* TLS extension information.  We specify distinct minimum and maximum 
   lengths for client- and server-side use (so minLengthClient is the 
   minimum length that a client can send).  A value of CRYPT_ERROR means 
   that this extension isn't valid when sent by the client or server */

typedef struct {
	const int type;					/* Extension type */
	const int minLengthClient, minLengthServer;	/* Min.length */
	const int maxLength;			/* Max.length */
	const char *typeName;			/* Name for error messages */
	} EXT_CHECK_INFO;

static const EXT_CHECK_INFO extCheckInfoTbl[] = {
	/* Server name indication (SNI):

		uint16		listLen
			byte	nameType
			uint16	nameLen
			byte[]	name */
	{ TLS_EXT_SERVER_NAME, 1, 0, 8192, 
	  "server name indication" },

	/* Maximm fragment length:

		byte		fragmentLength */
	{ TLS_EXT_MAX_FRAGMENT_LENTH, 1, 1, 1, 
	  "fragment length" },

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
	  1 + UINT16_SIZE + UINT16_SIZE + MIN_URL_SIZE + 1, CRYPT_ERROR, 8192,
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
	{ TLS_EXT_TRUSTED_CA_KEYS, UINT16_SIZE + 1, CRYPT_ERROR, 8192, 
	  "trusted CA" },

	/* Truncate the HMAC to a nonstandard 80 bits (rather than the de 
	   facto IPsec cargo-cult standard of 96 bits) */
	{ TLS_EXT_TRUNCATED_HMAC, 0, 0, 0, 
	  "truncated HMAC" },

	/* OCSP status request.  Another bounce-attack enabler, this time on 
	   both the server and an OCSP responder:

		byte		statusType
		uint16		ocspResponderList
			uint16	responderLength
			byte[]	responder
			uint16	extensionLength
			byte[]	extensions */
	{ TLS_EXT_STATUS_REQUEST, 
	  1 + UINT16_SIZE + UINT16_SIZE + MIN_URL_SIZE + UINT16_SIZE, CRYPT_ERROR, 8192, 
	  "OCSP status request" },

	/* User mapping.  Used with a complex RFC 4680 mechanism (the extension 
	   itself is in RFC 4681):

		byte		mappingLength
		byte[]		mapping */
	{ TLS_EXT_USER_MAPPING, 1 + 1, CRYPT_ERROR, 1 + 255, 
	  "user-mapping" },

	/* OpenPGP key.  From an experimental RFC with support for OpenPGP keys:

		byte		certTypeListLength
		byte[]		certTypeList */
	{ TLS_EXT_CERTTYPE, 1 + 1, CRYPT_ERROR, 1 + 255, 
	  "cert-type (OpenPGP keying)" },

	/* Supported ECC curve IDs:

		uint16		namedCurveListLength
		uint16[]	namedCurve */
	{ TLS_EXT_ELLIPTIC_CURVES, UINT16_SIZE + UINT16_SIZE, CRYPT_ERROR, 512, 
	  "ECDH/ECDSA curve ID" },

	/* Supported ECC point formats:

		byte		pointFormatListLength
		byte[]		pointFormat */
	{ TLS_EXT_EC_POINT_FORMATS, 1 + 1, 1 + 1, 255, 
	  "ECDH/ECDSA point format" },

	/* SRP user name:

		byte		userNameLength
		byte[]		userName */
	{ TLS_EXT_SRP, 1 + 1, CRYPT_ERROR, 1 + 255, 
	  "SRP username" },

	/* Signature algorithms:

		uint16		algorithmListLength
			byte	hashAlgo
			byte	sigAlgo */
	{ TLS_EXT_SIGNATURE_ALGORITHMS, UINT16_SIZE + 1 + 1, CRYPT_ERROR, 512, 
	  "signature algorithm" },

	/* Session ticket.  The client can send a zero-length session ticket to
	   indicate that it supports the extension but doesn't have a session 
	   ticket yet, and the server can send a zero-length ticket to indicate 
	   that it'll send the client a new ticket later in the handshake.  
	   Confusing this even more, the specification says that the client 
	   sends "a zero-length ticket" but the server sends "a zero-length 
	   extension".  The original specification, RFC 4507, was later updated 
	   by a second version, RFC 5077, that makes explicit (via Appendix A) 
	   the fact that there's no "ticket length" field in the extension, so 
	   that the entire extension consists of the opaque ticket data:

		byte[]		sessionTicket (implicit size) */
	{ TLS_EXT_SESSIONTICKET, 0, 0, 8192,
	  "session ticket" },

	/* End-of-list marker */
	{ CRYPT_ERROR, 0, 0, 0, NULL }, { CRYPT_ERROR, 0, 0, 0, NULL }
	};

/****************************************************************************
*																			*
*							Read TLS Extensions								*
*																			*
****************************************************************************/

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
					byte[]	name 

			   If we're the client and we sent this extension to the server
			   then the server may responed with a zero-length server-name
			   extension for no immediately obvious purpose (if the server
			   doesn't recognise the name then it's required to send an
			   'unrecognised-name' alert so any non-alert return means that
			   the value was accepted, but for some reason it's required to
			   send a zero-length response anyway), in which case we have to 
			   special-case the check for this */
			if( !isServer( sessionInfoPtr ) )
				{
				if( extLength <= 0 )
					return( CRYPT_OK );
				}
			else
				{
				/* Remember that we've seen the server-name extension so that
				   we can send a zero-length reply to the client */
				handshakeInfo->needSNIResponse = TRUE;
				}
			status = listLen = readUint16( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( listLen != extLength - UINT16_SIZE || \
				listLen < 1 + UINT16_SIZE || \
				listLen >= MAX_INTLENGTH_SHORT )
				return( CRYPT_ERROR_BADDATA );

			/* Parsing of further SEQUENCE OF SEQUENCE data omitted */
			return( sSkip( stream, listLen ) );

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
			   We somewhat arbitrarily define 'best' as 'biggest' because
			   everyone knows that bigger is better, however we also
			   bound the curve size by the size of the server's signing
			   key, since there's not much point in using a P521 curve
			   that the server then authenticates with a P192 key:

				uint16		namedCurveListLength
				uint16[]	namedCurve */
			static const MAP_TABLE curveIDTbl[] = {
				{ TLS_CURVE_SECP192R1, CRYPT_ECCCURVE_P192 },
				{ TLS_CURVE_SECP224R1, CRYPT_ECCCURVE_P224 },
				{ TLS_CURVE_SECP256R1, CRYPT_ECCCURVE_P256 },
				{ TLS_CURVE_SECP384R1, CRYPT_ECCCURVE_P384 },
				{ TLS_CURVE_SECP521R1, CRYPT_ECCCURVE_P521 },
				{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
				};
			static const MAP_TABLE curveSizeTbl[] = {
				{ CRYPT_ECCCURVE_P192, bitsToBytes( 192 ) },
				{ CRYPT_ECCCURVE_P224, bitsToBytes( 224 ) },
				{ CRYPT_ECCCURVE_P256, bitsToBytes( 256 ) },
				{ CRYPT_ECCCURVE_P384, bitsToBytes( 384 ) },
				{ CRYPT_ECCCURVE_P521, bitsToBytes( 521 ) },
				{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
				};
			int preferredCurveID = CRYPT_ERROR, keySize, i;

			/* Get the size of the server's signing key to bound the curve 
			   size */
			status = krnlSendMessage( sessionInfoPtr->privateKey,
									  IMESSAGE_GETATTRIBUTE, &keySize,
									  CRYPT_CTXINFO_KEYSIZE );
			if( cryptStatusError( status ) )
				return( status );

			/* Read and check the ECC curve list header */
			status = listLen = readUint16( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( listLen != extLength - UINT16_SIZE || \
				listLen < UINT16_SIZE || listLen > 256 )
				return( CRYPT_ERROR_BADDATA );

			/* Read the list of curve IDs, recording the most preferred one */
			for( i = 0; i < listLen / UINT16_SIZE; i++ )
				{
				int curveID, curveSize;

				status = value = readUint16( stream );
				if( cryptStatusError( status ) )
					return( status );
				status = mapValue( value, &curveID, curveIDTbl, 
								   FAILSAFE_ARRAYSIZE( curveIDTbl, MAP_TABLE ) );
				if( cryptStatusError( status ) )
					continue;	/* Unrecognised curve type */
				status = mapValue( curveID, &curveSize, curveSizeTbl, 
								   FAILSAFE_ARRAYSIZE( curveSizeTbl, MAP_TABLE ) );
				ENSURES( cryptStatusOK( status ) );
				if( curveSize > keySize )
					{
					/* The curve size exceeds the security provided by the 
					   server key, there's no point in using a curve of this
					   size */
					continue;
					}
				if( sessionInfoPtr->protocolFlags & SSL_PFLAG_SUITEB )
					{
					const int suiteBinfo = \
						sessionInfoPtr->protocolFlags & SSL_PFLAG_SUITEB;

					/* Suite B only allows P256 and P384 */
					switch( curveID )
						{
						case CRYPT_ECCCURVE_P256:
							if( !( suiteBinfo & SSL_PFLAG_SUITEB_128 ) )
								continue;
							break;

						case CRYPT_ECCCURVE_P384:
							if( !( suiteBinfo & SSL_PFLAG_SUITEB_256 ) )
								continue;
							break;

						default:
							continue;
						}
					}
				if( curveID > preferredCurveID )
					preferredCurveID = curveID;
				}

			/* If we couldn't find a curve that we have in common with the 
			   other side, disable the use of ECC algorithms.  This is a 
			   somewhat nasty failure mode because it means that something 
			   like a buggy implementation that sends the wrong hello 
			   extension (which is rather more likely than, say, an 
			   implementation not supporting the de facto universal-standard 
			   NIST curves) means that the crypto is quietly switched to 
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
			if( extLength > 0 )
				{
				status = sSkip( stream, extLength );
				if( cryptStatusError( status ) )
					return( status );
				}

			return( CRYPT_OK );

		case TLS_EXT_SIGNATURE_ALGORITHMS:
			/* This is a complex and confusing TLS 1.2+ extension with weird 
			   requirements attached to it, for example if the client 
			   indicates hash algorithm X then the server (section 7.4.2) 
			   has to somehow produce a certificate chain signed only using 
			   that hash algorithm, as if a particular algorithm choice for 
			   TLS use could somehow dictate what algorithms the CA and 
			   certificate-processing library that's being used will provide 
			   (in addition the spec is rather confused on this issue, 
			   giving it first as a MUST and then a paragraph later as a 
			   SHOULD).  This also makes some certificate signature 
			   algorithms like RSA-PSS impossible even if the hash algorithm 
			   used is supported by both the TLS and certificate library, 
			   because TLS only allows the specification of PKCS #1 v1.5 
			   signatures.  What's worse, it creates a situation from which 
			   there's no recovery because in the case of a problem all that 
			   the server can say is "failed", but not "try again using this 
			   algorithm", while returning certificates or a signature with 
			   the server's available algorithm (ignoring the requirement to 
			   summarily abort the handshake in the case of a mismatch) at 
			   least tells the client what the problem is.

			   To avoid this mess we assume that everyone can do SHA-256,
			   the TLS 1.2 default.  Since the extension isn't valid for
			   earlier versions, we ignore it if we're not using TLS 1.2+:

				uint16		algorithmListLength
					byte	hashAlgo
					byte	sigAlgo */
			status = listLen = readUint16( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( listLen != extLength - UINT16_SIZE || \
				listLen < 1 + 1 || listLen > 64 + 64 || \
				listLen & 1 )
				return( CRYPT_ERROR_BADDATA );
			if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS12 )
				{
#ifdef CONFIG_SUITEB
				/* For the more strict handling in Suite B there are two 
				   paths that we can take, either require that the client 
				   send at least one hash algorithm that matches the server 
				   key size (thus ensuring that our server certificate 
				   matches what the client wants), or we can strictly apply 
				   the Suite B requirements so that only 256-bit algorithms
				   are allowed for SSL_PFLAG_SUITEB_128 and only 384-bit
				   algorithms are allowed for SSL_PFLAG_SUITEB_256 */
  #if 0	/* Check for client match of server key size */
				static const MAP_TABLE curveSizeTbl[] = {
					{ bitsToBytes( 256 ), TLS_HASHALGO_SHA2 },
					{ bitsToBytes( 384 ), TLS_HASHALGO_SHA384 },
					{ CRYPT_ERROR, 0 }, { CRYPT_ERROR, 0 }
					};
				int keySize, hashType;

				/* If we don't find anything else that matches we default to 
				   SHA2 */
				handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;

				/* Get the size of the server's signing key to try and match
				   the client's preferred hash size */
				status = krnlSendMessage( sessionInfoPtr->privateKey,
										  IMESSAGE_GETATTRIBUTE, &keySize,
										  CRYPT_CTXINFO_KEYSIZE );
				if( cryptStatusError( status ) )
					return( status );
				status = mapValue( keySize, &hashType, curveSizeTbl, 
								   FAILSAFE_ARRAYSIZE( curveSizeTbl, MAP_TABLE ) );
				if( cryptStatusError( status ) )
					{
					/* In theory we could continue with SHA-2 as the generic 
					   hash algorithm, but Suite B only allows P256 and P384
					   keys (checked by the higher-level code) so we should 
					   never get to this situation */
					return( status );
					}
  #else	/* Strict _128/_256 match */
				const int suiteBinfo = \
							sessionInfoPtr->protocolFlags & SSL_PFLAG_SUITEB;

				handshakeInfo->keyexSigHashAlgo = CRYPT_ERROR;
  #endif /* Suite B parameter match type */

				/* Read the hash and signature algorithms and try and choose 
				   the best one to use.  See the long comment above to 
				   understand the somewhat optimistic way in which the choice
				   is made */
				for( ; listLen > 0; listLen -= 1 + 1 )
					{
					int hashAlgo, sigAlgo;

					/* Read the hash and signature algorithm and make sure
					   that it's one that we can use */
					hashAlgo = sgetc( stream );			/* Hash algorithm */
					status = sigAlgo = sgetc( stream );	/* Sig.algorithm */
					if( cryptStatusError( status ) )
						return( status );
					if( sigAlgo != TLS_SIGALGO_ECDSA || \
						( hashAlgo != TLS_HASHALGO_SHA2 && \
						  hashAlgo != TLS_HASHALGO_SHA384 ) )
						continue;
  #if 0	/* Check for client match of server key size */
					if( hashType != hashAlgo )
						continue;
  #else	/* Strict _128/_256 match */
					if( ( suiteBinfo == SSL_PFLAG_SUITEB_128 && \
						  hashAlgo != TLS_HASHALGO_SHA2 ) || \
						( suiteBinfo == SSL_PFLAG_SUITEB_256 && \
						  hashAlgo != TLS_HASHALGO_SHA384 ) )
						continue;
  #endif /* Suite B parameter match type */

					/* We've found one that we can use, set the appropriate 
					   variant.  Note that since SHA384 is just a variant of 
					   SHA2, we always choose this if it's available, so even
					   if the order is { SHA384, SHA256 } the parameter value
					   for the original SHA384 will remain set when SHA256 is
					   subsequently read */
					handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;
					if( hashAlgo == TLS_HASHALGO_SHA384 )
						{
						handshakeInfo->keyexSigHashAlgoParam = \
													bitsToBytes( 384 );
						}
					}

				/* For strict Suite B compliance the client must send either 
				   SHA256 or SHA384 as an option */
  #if 1	/* Strict _128/_256 match */
				if( handshakeInfo->keyexSigHashAlgo == CRYPT_ERROR )
					return( CRYPT_ERROR_BADDATA );
  #endif /* Suite B parameter match type */

				return( CRYPT_OK );
#else
				handshakeInfo->keyexSigHashAlgo = CRYPT_ALGO_SHA2;
#endif /* CONFIG_SUITEB */
				}
			return( sSkip( stream, listLen ) );

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

/* Read TLS extensions.  Further types are defined at
   http://www.iana.org/assignments/tls-extensiontype-values:

	uint16		extListLen			-- RFC 3546/RFC 4366
		uint16	extType
		uint16	extLen
		byte[]	extData */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readExtensions( INOUT SESSION_INFO *sessionInfoPtr, 
					INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
					INOUT STREAM *stream, 
					IN_LENGTH_SHORT const int length )
	{
	const int endPos = stell( stream ) + length;
	int minPayloadLength = 1, extListLen, noExtensions, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( length > 0 && length < MAX_INTLENGTH_SHORT );
	REQUIRES( endPos > 0 && endPos < MAX_INTLENGTH_SHORT );

	/* If we're the client and we've sent a server-name extension to the
	   server, the server can optionally send back a zero-length server-name
	   extension for no immediately obvious purpose, in which case the 
	   minimum payload length may be zero */
	if( !isServer( sessionInfoPtr ) && \
		sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS )
		minPayloadLength = 0;

	/* Read the extension header and make sure that it's valid */
	if( length < UINT16_SIZE + UINT16_SIZE + UINT16_SIZE + minPayloadLength )
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
		if( cryptStatusError( status ) || \
			extLen < 0 || extLen > MAX_PACKET_SIZE )
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
			const int minLength = isServer( sessionInfoPtr ) ? \
						extCheckInfoPtr->minLengthClient : \
						extCheckInfoPtr->minLengthServer;

			/* Perform any necessary initial checking of the extension */
			if( minLength == CRYPT_ERROR )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Received disallowed TLS %s extension from %s", 
						  extCheckInfoPtr->typeName, 
						  isServer( sessionInfoPtr ) ? "server" : "client" ) );
				}
			if( extLen < minLength || extLen > extCheckInfoPtr->maxLength )
				{
				retExt( CRYPT_ERROR_BADDATA,
						( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
						  "Invalid TLS %s extension length %d, should be "
						  "%d...%d", extCheckInfoPtr->typeName, extLen,
						  minLength, extCheckInfoPtr->maxLength ) );
				}
			}
		DEBUG_PRINT(( "Read extension %s (%d), length %d.\n",
					  ( extCheckInfoPtr != NULL ) ? \
						extCheckInfoPtr->typeName : "<Unknown>", type, extLen ));
		DEBUG_DUMP_STREAM( stream, stell( stream ), extLen );

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
*							Write TLS Extensions							*
*																			*
****************************************************************************/

/* Write the list of supported signature and hash algorithms as a 
   combinatorial explosion of { hash, sig } algorithm pairs (they're called
   SignatureAndHashAlgorithm in the spec, but are actually encoded as
   HashAndSignatureAlgorithm).  This is used both for extensions and for the 
   TLS 1.2 signature format.
   
   This gets a bit complicated because we both have to emit the values in
   preferred-algorithm order and some combinations aren't available, so 
   instead of simply iterating down two lists we have to exhaustively
   enumerate each possible algorithm combination */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int writeSigHashAlgoList( STREAM *stream )
	{
	typedef struct {
		CRYPT_ALGO_TYPE sigAlgo, hashAlgo;
		TLS_SIGALGO_TYPE tlsSigAlgoID;
		TLS_HASHALGO_TYPE tlsHashAlgoID;
		} SIG_HASH_INFO;
	static const SIG_HASH_INFO algoTbl[] = {
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHAng, 
		  TLS_SIGALGO_RSA, 255 },
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA2, 
		  TLS_SIGALGO_RSA, TLS_HASHALGO_SHA2 },
		{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA1, 
		  TLS_SIGALGO_RSA, TLS_HASHALGO_SHA1 },
		{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHAng, 
		  TLS_SIGALGO_DSA, 255 },
		{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA2, 
		  TLS_SIGALGO_DSA, TLS_HASHALGO_SHA2 },
		{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA1, 
		  TLS_SIGALGO_DSA, TLS_HASHALGO_SHA1 },
		{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHAng, 
		  TLS_SIGALGO_ECDSA, 255 },
#ifdef CONFIG_SUITEB
		{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, 
		  TLS_SIGALGO_ECDSA, TLS_HASHALGO_SHA384 },
#endif /* CONFIG_SUITEB */
		{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA2, 
		  TLS_SIGALGO_ECDSA, TLS_HASHALGO_SHA2 },
		{ CRYPT_ALGO_ECDSA, CRYPT_ALGO_SHA1, 
		  TLS_SIGALGO_ECDSA, TLS_HASHALGO_SHA1 },
		{ CRYPT_ALGO_NONE, CRYPT_ERROR }, { CRYPT_ALGO_NONE, CRYPT_ERROR }
		};
	BYTE algoList[ 32 + 8 ];
	int algoIndex = 0, i;

	/* Determine which signature and hash algorithms are available for use.
	   Since RSA and SHA-1 are always available we short-circuit the
	   availability check for them */
	for( i = 0; algoTbl[ i ].sigAlgo != CRYPT_ALGO_NONE && \
				i < FAILSAFE_ARRAYSIZE( algoTbl, SIG_HASH_INFO ); i++ )
		{
		const CRYPT_ALGO_TYPE sigAlgo = algoTbl[ i ].sigAlgo;

		/* If the given signature algorithm isn't enabled, skip any further
		   occurrences of this algorithm */
		if( !algoAvailable( sigAlgo ) )
			{
			while( algoTbl[ i ].sigAlgo == sigAlgo && \
				   i < FAILSAFE_ARRAYSIZE( algoTbl, SIG_HASH_INFO ) )
				 i++;
			ENSURES( i < FAILSAFE_ARRAYSIZE( algoTbl, SIG_HASH_INFO ) );
			i--;	/* Adjust for increment also done in outer loop */

			continue;
			}

		/* If the hash algorithm isn't enabled, skip this entry */
		if( !algoAvailable( algoTbl[ i ].hashAlgo ) )
			continue;

		/* Add the TLS IDs for this signature and hash algorithm combination.  
		   Although the record is called SignatureAndHashAlgorithm, what's 
		   written first is the hash algorithm and not the signature 
		   algorithm */
		algoList[ algoIndex++ ] = intToByte( algoTbl[ i ].tlsHashAlgoID );
		algoList[ algoIndex++ ] = intToByte( algoTbl[ i ].tlsSigAlgoID );
		ENSURES( algoIndex <= 32 );
		}
	ENSURES( i < FAILSAFE_ARRAYSIZE( algoTbl, SIG_HASH_INFO ) );

	/* Write the combination of hash and signature algorithms */
	writeUint16( stream, algoIndex );
	return( swrite( stream, algoList, algoIndex ) );
	}

/* Write the server name indication (SNI) */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeServerName( INOUT STREAM *stream,
							INOUT SESSION_INFO *sessionInfoPtr )
	{
	const ATTRIBUTE_LIST *serverNamePtr = \
				findSessionInfo( sessionInfoPtr->attributeList,
								 CRYPT_SESSINFO_SERVER_NAME );
	URL_INFO urlInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( serverNamePtr != NULL );

	/* Extract the server FQDN from the overall server name value */
	status = sNetParseURL( &urlInfo, serverNamePtr->value, 
						   serverNamePtr->valueLength, URL_TYPE_HTTPS );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the server name */
	writeUint16( stream, 1 + UINT16_SIZE + urlInfo.hostLen );
	sputc( stream, 0 );		/* DNS name */
	writeUint16( stream, urlInfo.hostLen );
	return( swrite( stream, urlInfo.host, urlInfo.hostLen ) );
	}

/* Write TLS extensions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeClientExtensions( INOUT STREAM *stream,
						   INOUT SESSION_INFO *sessionInfoPtr )
	{
	STREAM nullStream;
	static const BYTE eccCurveInfo[] = {
		0, TLS_CURVE_SECP521R1, 0, TLS_CURVE_SECP384R1, 
		0, TLS_CURVE_SECP256R1, 0, TLS_CURVE_SECP224R1, 
		0, TLS_CURVE_SECP192R1, 0, 0 
		};
#ifdef CONFIG_SUITEB
	static const BYTE eccCurveSuiteBInfo[] = {
		0, TLS_CURVE_SECP384R1, 0, TLS_CURVE_SECP256R1, 0, 0 
		};
	static const BYTE eccCurveSuiteB128Info[] = {
		0, TLS_CURVE_SECP256R1, 0, 0 
		};
	static const BYTE eccCurveSuiteB256Info[] = {
		0, TLS_CURVE_SECP384R1, 0, 0 
		};
#endif /* CONFIG_SUITEB */
	const void *eccCurveInfoPtr = DUMMY_INIT_PTR;
	int offset = DUMMY_INIT, status;
	int serverNameExtLen, sigHashHdrLen = 0, sigHashExtLen = 0;
	int eccCurveTypeLen = DUMMY_INIT, eccInfoLen = 0;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS );

	/* Determine the overall length of the extension data.  We do this
	   by writing each extension to a null stream and tracking the
	   extData length around the extension data write:

		uint16	extType
		uint16	extLen
		byte[]	extData */
	sMemNullOpen( &nullStream );

	/* Sever name indication (SNI) */
	writeUint16( &nullStream, TLS_EXT_SERVER_NAME );
	status = writeUint16( &nullStream, 0 );		/* Dummy length */
	if( cryptStatusOK( status ) )
		{
		offset = stell( &nullStream );
		status = writeServerName( &nullStream, sessionInfoPtr );
		}
	if( cryptStatusError( status ) )
		{
		sMemClose( &nullStream );
		return( status );
		}
	serverNameExtLen = stell( &nullStream ) - offset;

	/* Signature and hash algorithms.  These are only used with TLS 1.2+ so 
	   we only write them if we're using these versions of the protocol */
	if( sessionInfoPtr->version >= SSL_MINOR_VERSION_TLS12 )
		{
		writeUint16( &nullStream, TLS_EXT_SIGNATURE_ALGORITHMS );
		status = writeUint16( &nullStream, 0 );		/* Dummy length */
		if( cryptStatusOK( status ) )
			{
			offset = stell( &nullStream );
			status = writeSigHashAlgoList( &nullStream );
			}
		if( cryptStatusError( status ) )
			{
			sMemClose( &nullStream );
			return( status );
			}
		sigHashHdrLen = UINT16_SIZE + UINT16_SIZE;
		sigHashExtLen = stell( &nullStream ) - offset;
		}
	sMemClose( &nullStream );

	/* ECC information.  This is only sent if we're proposing ECC suites in
	   the client hello */
	if( algoAvailable( CRYPT_ALGO_ECDH ) && \
		algoAvailable( CRYPT_ALGO_ECDSA ) )
		{
#ifdef CONFIG_SUITEB
		if( sessionInfoPtr->protocolFlags & SSL_PFLAG_SUITEB )
			{
			const int suiteBinfo = \
					sessionInfoPtr->protocolFlags & SSL_PFLAG_SUITEB;

			if( suiteBinfo == SSL_PFLAG_SUITEB_128 )
				{
				eccCurveInfoPtr = eccCurveSuiteB128Info;
				eccCurveTypeLen = UINT16_SIZE;
				}
			else
				{
				if( suiteBinfo == SSL_PFLAG_SUITEB_256 )
					{
					eccCurveInfoPtr = eccCurveSuiteB256Info;
					eccCurveTypeLen = UINT16_SIZE;
					}
				else
					{
					eccCurveInfoPtr = eccCurveSuiteBInfo;
					eccCurveTypeLen = 2 * UINT16_SIZE;
					}
				}
			}
		else
#endif /* CONFIG_SUITEB */
			{
			eccCurveInfoPtr = eccCurveInfo;
			eccCurveTypeLen = 5 * UINT16_SIZE;
			}
		eccInfoLen = UINT16_SIZE + UINT16_SIZE + \
					 UINT16_SIZE + eccCurveTypeLen;
		eccInfoLen += UINT16_SIZE + UINT16_SIZE + 1 + 1;
		}

	/* Write the list of extensions */
	writeUint16( stream, UINT16_SIZE + UINT16_SIZE + serverNameExtLen + \
						 sigHashHdrLen + sigHashExtLen + eccInfoLen );
	writeUint16( stream, TLS_EXT_SERVER_NAME );
	writeUint16( stream, serverNameExtLen );
	status = writeServerName( stream, sessionInfoPtr );
	DEBUG_PRINT(( "Wrote extension server name indication (%d), length %d.\n",
				  TLS_EXT_SERVER_NAME, serverNameExtLen ));
	DEBUG_DUMP_STREAM( stream, stell( stream ) - serverNameExtLen, 
					   serverNameExtLen );
	if( cryptStatusOK( status ) && sigHashExtLen > 0 )
		{
		writeUint16( stream, TLS_EXT_SIGNATURE_ALGORITHMS );
		writeUint16( stream, sigHashExtLen );
		status = writeSigHashAlgoList( stream );
		DEBUG_PRINT(( "Wrote extension signature algorithm (%d), length %d.\n",
					  TLS_EXT_SIGNATURE_ALGORITHMS, sigHashExtLen ));
		DEBUG_DUMP_STREAM( stream, 
						   stell( stream ) - sigHashExtLen, sigHashExtLen );
		}
	if( cryptStatusOK( status ) && eccInfoLen > 0 )
		{
		/* Write the ECC curve type extension */
		writeUint16( stream, TLS_EXT_ELLIPTIC_CURVES );
		writeUint16( stream, UINT16_SIZE + eccCurveTypeLen );/* Ext.len */
		writeUint16( stream, eccCurveTypeLen );				/* Curve list len.*/
		swrite( stream, eccCurveInfoPtr, eccCurveTypeLen );	/* Curve list */
		DEBUG_PRINT(( "Wrote extension ECC curve type (%d), length %d.\n",
					  TLS_EXT_ELLIPTIC_CURVES, eccCurveTypeLen ));
		DEBUG_DUMP_STREAM( stream, 
						   stell( stream ) - ( UINT16_SIZE + eccCurveTypeLen ), 
						   UINT16_SIZE + eccCurveTypeLen );

		/* Write the ECC point format extension */
		writeUint16( stream, TLS_EXT_EC_POINT_FORMATS );
		writeUint16( stream, 1 + 1 );		/* Extn. length */
		sputc( stream, 1 );					/* Point-format list len.*/
		status = sputc( stream, 0 );		/* Uncompressed points */
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension ECC point format (%d), length %d.\n",
					  TLS_EXT_EC_POINT_FORMATS, 1 + 1 ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - 1 + 1, 1 + 1 );
		}
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeServerExtensions( INOUT STREAM *stream,
						   INOUT SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	int extListLen = 0, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );

	/* Calculate the size of the extensions */
	if( isEccAlgo( handshakeInfo->keyexAlgo ) && \
		handshakeInfo->sendECCPointExtn )
		extListLen += UINT16_SIZE + UINT16_SIZE + 1 + 1;
	if( handshakeInfo->needSNIResponse )
		extListLen += UINT16_SIZE + UINT16_SIZE;
	if( extListLen <= 0 )
		{
		/* No extensions to write, we're done */
		return( CRYPT_OK );
		}

	/* Write the overall extension list length */
	writeUint16( stream, extListLen );

	/* If the client sent ECC extensions and we've negotiated an ECC cipher 
	   suite, send back the appropriate response.  We don't have to send 
	   back the curve ID that we've chosen because this is communicated 
	   explicitly in the server keyex */
	if( isEccAlgo( handshakeInfo->keyexAlgo ) && \
		handshakeInfo->sendECCPointExtn )
		{
		writeUint16( stream, TLS_EXT_EC_POINT_FORMATS );
		writeUint16( stream, 1 + 1 );	/* Extn. length */
		sputc( stream, 1 );				/* Point-format list len.*/
		status = sputc( stream, 0 );	/* Uncompressed points */
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension ECC point format (%d), length %d.\n",
					  TLS_EXT_EC_POINT_FORMATS, 1 + 1 ));
		DEBUG_DUMP_STREAM( stream, stell( stream ) - 1 + 1, 1 + 1 );
		}

	/* If the client sent an SNI extension then we have to acknowledge it
	   with a zero-length SNI extension response.  This is slightly 
	   dishonest because we haven't passed the SNI data back to the caller,
	   but SNI will (at some point in the future) be sent by default by 
	   clients and since we're highly unlikely to be used with multihomed 
	   servers but likely to be used in oddball environments like ones 
	   without DNS we just accept any SNI and allow a connect.  SNI is 
	   merely a courtesy notification to allow selection of the correct 
	   server certificate for multihomed servers with the actual virtual-
	   host management being done via the HTTP Host: header, so not making 
	   use of it isn't a real problem */
	if( handshakeInfo->needSNIResponse )
		{
		writeUint16( stream, TLS_EXT_SERVER_NAME );
		status = writeUint16( stream, 0 );
		if( cryptStatusError( status ) )
			return( status );
		DEBUG_PRINT(( "Wrote extension extension server name indication (%d), "
					  "length 0.\n", TLS_EXT_SERVER_NAME, 0 ));
		}

	return( CRYPT_OK );
	}
#endif /* USE_SSL */
