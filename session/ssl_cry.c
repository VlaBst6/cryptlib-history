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
*							Cipher Suite Information						*
*																			*
****************************************************************************/

/* cryptlib's SSL/TLS cipher suites, in preferred-suite order.  There are a 
   pile of DH cipher suites, in practice only DHE is used, DH requires the 
   use of X9.42 DH certificates (there aren't any) and DH_anon uses 
   unauthenticated DH which implementers seem to have an objection to even 
   though it's not much different in effect from the way RSA cipher suites 
   are used in practice.

   To keep things simple for the caller we only allow RSA auth for DH key
   agreement and not DSA, since the former also automatically works for the
   far more common RSA key exchange that's usually used for key setup.
   Similarly we only allow ECDSA for ECDH, since anyone who wants to make 
   the ECC fashion statement isn't going to then fall back to RSA for the 
   server authentication.  In both cases the actions for the unused suites
   are present in the table but commented out.

   We prefer AES-128 to AES-256 since -256 has a weaker key schedule than
   -128, so if anyone's going to attack it they'll go for the key schedule
   rather than the (mostly irrelevant) -128 vs. -256.

   Some buggy older versions of IIS that only support crippled crypto drop 
   the connection when they see a client hello advertising strong crypto 
   rather than sending an alert as they should.  To work around this we 
   advertise a dummy cipher suite SSL_RSA_EXPORT_WITH_RC4_40_MD5 as a canary 
   to force IIS to send back a response that we can then turn into an error 
   message.  The need to do this is somewhat unfortunate since it will 
   appear to an observer that cryptlib will use crippled crypto (in fact it 
   won't even load such a key) but there's no other way to detect the buggy 
   IIS apart from completely restarting the session activation at the 
   session level with crippled-crypto advertised in the restarted session */

static const CIPHERSUITE_INFO cipherSuiteInfo[] = {
	/* PSK suites */
	{ TLS_PSK_WITH_3DES_EDE_CBC_SHA,
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE, CIPHERSUITE_FLAG_PSK },
	{ TLS_PSK_WITH_AES_128_CBC_SHA,
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_PSK },
	{ TLS_PSK_WITH_AES_256_CBC_SHA,
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_PSK },
	{ TLS_PSK_WITH_RC4_128_SHA,
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_RC4,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_PSK },

#ifdef USE_ECC
	/* ECDH with ECDSA suites */
	{ TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, 
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE, CIPHERSUITE_FLAG_ECC },
	{ TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_ECC },
	{ TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_ECDSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_ECC },
	{ TLS_ECDHE_RSA_WITH_RC4_128_SHA, 
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_RC4,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_ECC },

	/* ECDH with RSA suites */
/*	{ TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, 
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE, CIPHERSUITE_FLAG_ECC },
	{ TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_ECC }, 
	{ TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 
	  CRYPT_ALGO_ECDH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_ECC }, */
#endif /* USE_ECC */

#ifdef PREFER_DH_SUITES
	/* 3DES with DH */
	{ TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH },
/*	{ TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_DSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH }, */

	/* AES with DH */
	{ TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH },
/*	{ TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_DSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH }, */
	{ TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH },
/*	{ TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_DSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH }, */

	/* 3DES with RSA */
	{ SSL_RSA_WITH_3DES_EDE_CBC_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },

	/* AES with RSA */
	{ TLS_RSA_WITH_AES_128_CBC_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },
	{ TLS_RSA_WITH_AES_256_CBC_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },
#else
	/* 3DES with RSA */
	{ SSL_RSA_WITH_3DES_EDE_CBC_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },

	/* AES with RSA */
	{ TLS_RSA_WITH_AES_128_CBC_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },
	{ TLS_RSA_WITH_AES_256_CBC_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },

	/* 3DES with DH */
	{ TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH },
/*	{ TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_DSA, CRYPT_ALGO_3DES,
	  CRYPT_ALGO_HMAC_SHA, 24, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH }, */

	/* AES with DH */
	{ TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH },
/*	{ TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_DSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH }, */
	{ TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH },
/*	{ TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_DSA, CRYPT_ALGO_AES,
	  CRYPT_ALGO_HMAC_SHA, 32, SHA1MAC_SIZE, CIPHERSUITE_FLAG_DH }, */
#endif /* PREFER_DH_SUITES */

	/* IDEA + RSA */
	{ SSL_RSA_WITH_IDEA_CBC_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_IDEA,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },

	/* RC4 + RSA */
	{ SSL_RSA_WITH_RC4_128_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_RC4,
	  CRYPT_ALGO_HMAC_SHA, 16, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },
	{ SSL_RSA_WITH_RC4_128_MD5,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_RC4,
	  CRYPT_ALGO_HMAC_MD5, 16, MD5MAC_SIZE, CIPHERSUITE_FLAG_NONE },

	/* DES + RSA */
	{ SSL_RSA_WITH_DES_CBC_SHA,
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_DES,
	  CRYPT_ALGO_HMAC_SHA, 8, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },
	{ TLS_DHE_RSA_WITH_DES_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_RSA, CRYPT_ALGO_DES,
	  CRYPT_ALGO_HMAC_SHA, 8, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE },
/*	{ TLS_DHE_DSS_WITH_DES_CBC_SHA,
	  CRYPT_ALGO_DH, CRYPT_ALGO_DSA, CRYPT_ALGO_DES,
	  CRYPT_ALGO_HMAC_SHA, 8, SHA1MAC_SIZE, CIPHERSUITE_FLAG_NONE }, */

	/* Canary used to detect the use of weak ciphers by the peer (where the
	   peer in this case would be "older versions of IIS") */
	{ SSL_RSA_EXPORT_WITH_RC4_40_MD5, 
	  CRYPT_ALGO_RSA, CRYPT_ALGO_RSA, CRYPT_ALGO_RC4,
	  CRYPT_ALGO_HMAC_MD5, 16, MD5MAC_SIZE, CIPHERSUITE_FLAG_NONE },

	/* End-of-list marker */
	{ SSL_NULL_WITH_NULL,
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, CIPHERSUITE_FLAG_NONE },
	{ SSL_NULL_WITH_NULL,
	  CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, 
	  CRYPT_ALGO_NONE, 0, 0, CIPHERSUITE_FLAG_NONE }
	};

CHECK_RETVAL \
int getCipherSuiteInfo( OUT const CIPHERSUITE_INFO **cipherSuiteInfoPtrPtr,
						OUT_INT_Z int *noSuiteEntries )
	{
	assert( isReadPtr( cipherSuiteInfoPtrPtr, \
					   sizeof( CIPHERSUITE_INFO * ) ) );
	assert( isWritePtr( noSuiteEntries, sizeof( int ) ) );

	*cipherSuiteInfoPtrPtr = cipherSuiteInfo;
	*noSuiteEntries = FAILSAFE_ARRAYSIZE( cipherSuiteInfo, CIPHERSUITE_INFO );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Encrypt/Decrypt Functions						*
*																			*
****************************************************************************/

/* Encrypt/decrypt a data block (this includes the MAC, which has been added
   to the data by the caller).  The handling of length arguments for these 
   is a bit tricky, for encryption the input is { data, payloadLength } 
   which is padded (if necessary) and the padded length returned in 
   '*dataLength', for decryption the entire data block will be processed but 
   only 'processedDataLength' bytes of result are valid output */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int encryptData( const SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER( dataMaxLength, *dataLength ) \
					BYTE *data, 
				 IN_LENGTH const int dataMaxLength,
				 OUT_LENGTH_Z int *dataLength,
				 IN_LENGTH const int payloadLength )
	{
	int length = payloadLength, status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( dataMaxLength > 0 && dataMaxLength < MAX_INTLENGTH );
	REQUIRES( payloadLength > 0 && \
			  payloadLength <= MAX_PACKET_SIZE + 20 && \
			  payloadLength <= sessionInfoPtr->sendBufSize && \
			  payloadLength <= dataMaxLength );

	/* Clear return value */
	*dataLength = 0;

	/* If it's a block cipher, we need to add end-of-block padding */
	if( sessionInfoPtr->cryptBlocksize > 1 )
		{
		const int padSize = ( sessionInfoPtr->cryptBlocksize - 1 ) - \
						    ( payloadLength & ( sessionInfoPtr->cryptBlocksize - 1 ) );
		int i;

		ENSURES( padSize >= 0 && padSize <= CRYPT_MAX_IVSIZE && \
				 length + padSize + 1 <= dataMaxLength );

		/* Add the PKCS #5-style padding (PKCS #5 uses n, TLS uses n-1) */
		for( i = 0; i < padSize + 1; i++ )
			data[ length++ ] = intToByte( padSize );
		}

	/* Encrypt the data and optional padding */
	status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
							  IMESSAGE_CTX_ENCRYPT, data, length );
	if( cryptStatusError( status ) )
		return( status );
	*dataLength = length;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int decryptData( SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER_FIXED( dataLength ) \
					BYTE *data, 
				 IN_LENGTH const int dataLength, 
				 OUT_LENGTH_Z int *processedDataLength )
	{
	int length = dataLength, padSize, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( data, dataLength ) );
	assert( isWritePtr( processedDataLength, sizeof( int ) ) );

	REQUIRES( dataLength > 0 && \
			  dataLength <= sessionInfoPtr->receiveBufEnd && \
			  dataLength < MAX_INTLENGTH );

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
	   padded data space in any way, leaving it containing whatever was 
	   there before (which can include old plaintext (!!)).  Almost all TLS 
	   implementations get it right (even though in TLS 1.0 there was only a 
	   requirement to generate, but not to check, the PKCS #5-style 
	   padding).  Because of this we only check the padding bytes if we're 
	   talking TLS.

	   First we make sure that the padding information looks OK.  TLS allows 
	   up to 256 bytes of padding (only GnuTLS actually seems to use this 
	   capability though) so we can't check for a sensible (small) padding 
	   length, however we can check this for SSL, which is good because for 
	   that we can't check the padding itself */
	padSize = byteToInt( data[ dataLength - 1 ] );
	if( padSize < 0 || padSize > 255 || \
		( sessionInfoPtr->version == SSL_MINOR_VERSION_SSL && \
		  padSize > sessionInfoPtr->cryptBlocksize - 1 ) )
		{
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid encryption padding value 0x%02X (%d)", 
				  padSize, padSize ) );
		}
	length -= padSize + 1;
	if( length < 0 || length > MAX_INTLENGTH )
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
   as a kludge in SSL/TLS 1.0 to work around chosen-IV attacks.

   In the following functions we don't check the return value of every 
   single component MAC operation since it would lead to endless sequences
   of 'status = x; if( cSOK( x ) ) ...' chains, on the remote chance that
   there's some transient failure in a single component operation it'll be
   picked up at the end anyway when the overall MAC check fails */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3 ) ) \
static int macDataSSL( IN_HANDLE const CRYPT_CONTEXT iHashContext, 
					   IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
					   IN_BUFFER( macSecretLength ) \
							const void *macSecret, 
					   IN_LENGTH_SHORT const int macSecretLength,
					   IN_INT_Z const long seqNo, 
					   IN_BUFFER_OPT( dataLength ) const void *data, 
					   IN_LENGTH_Z const int dataLength, 
					   IN_RANGE( 0, 255 ) const int type )
	{
	MESSAGE_DATA msgData;
	STREAM stream;
	BYTE buffer[ 128 + 8 ];
	const int padSize = ( hashAlgo == CRYPT_ALGO_MD5 ) ? 48 : 40;
	int length = DUMMY_INIT, status;

	assert( isReadPtr( macSecret, macSecretLength ) );
	assert( ( data == NULL && dataLength == 0 ) || \
			isReadPtr( data, dataLength ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( hashAlgo == CRYPT_ALGO_MD5 || \
			  hashAlgo == CRYPT_ALGO_SHA1 );
	REQUIRES( macSecretLength > 0 && \
			  macSecretLength < MAX_INTLENGTH_SHORT );
	REQUIRES( seqNo >= 0 );
	REQUIRES( ( data == NULL && dataLength == 0 ) || \
			  ( data != NULL && \
				dataLength > 0 && dataLength <= MAX_PACKET_SIZE ) );
	REQUIRES( type >= 0 && type <= 255 );

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
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
					 ( MESSAGE_CAST ) macSecret, macSecretLength );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer,
					 padSize + length );
	if( dataLength > 0 )
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
						 ( MESSAGE_CAST ) data, dataLength );
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
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
					 ( MESSAGE_CAST ) macSecret, macSecretLength );
	krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, buffer,
					 padSize + msgData.length );
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacSSL( INOUT SESSION_INFO *sessionInfoPtr, 
				  INOUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
				  IN_LENGTH const int dataMaxLength, 
				  OUT_LENGTH_Z int *dataLength,
				  IN_LENGTH const int payloadLength, 
				  IN_RANGE( 0, 255 ) const int type )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( dataMaxLength > 0 && dataMaxLength < MAX_INTLENGTH );
	REQUIRES( payloadLength > 0 && payloadLength <= MAX_PACKET_SIZE && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataMaxLength );
	REQUIRES( type >= 0 && type <= 255 );

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

	/* Append the MAC value to the end of the packet */
	ENSURES( rangeCheck( payloadLength, sessionInfoPtr->authBlocksize,
						 dataMaxLength ) );
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

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacSSL( INOUT SESSION_INFO *sessionInfoPtr, 
				 IN_BUFFER( dataLength ) const void *data, 
				 IN_LENGTH const int dataLength, 
				 IN_LENGTH_Z const int payloadLength, 
				 IN_RANGE( 0, 255 ) const int type, 
				 const BOOLEAN noReportError )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, dataLength ) );

	REQUIRES( dataLength > 0 && dataLength < MAX_INTLENGTH );
	REQUIRES( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataLength );
	REQUIRES( type >= 0 && type <= 255 );

	/* MAC the payload.  If the payload length is zero then there's no data 
	   payload, this can happen with some versions of OpenSSL that send 
	   zero-length blocks as a kludge to work around pre-TLS 1.1 chosen-IV
	   attacks */
	if( payloadLength == 0 )
		{
		status = macDataSSL( sessionInfoPtr->iAuthInContext, 
							 sessionInfoPtr->integrityAlgo,
							 sslInfo->macReadSecret, 
							 sessionInfoPtr->authBlocksize, 
							 sslInfo->readSeqNo, NULL, 0, type );
		}
	else
		{
		status = macDataSSL( sessionInfoPtr->iAuthInContext, 
							 sessionInfoPtr->integrityAlgo,
							 sslInfo->macReadSecret, 
							 sessionInfoPtr->authBlocksize, 
							 sslInfo->readSeqNo, data, payloadLength, type );
		}
	if( cryptStatusError( status ) )
		return( status );
	sslInfo->readSeqNo++;

	/* Compare the calculated MAC to the MAC present at the end of the 
	   data */
	ENSURES( rangeCheckZ( payloadLength, sessionInfoPtr->authBlocksize,
						  dataLength ) );
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
							  IMESSAGE_COMPARE, &msgData, 
							  MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		{
		/* If the error message has already been set at a higher level, 
		   don't update the error information */
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
   as a kludge in SSL/TLS 1.0 to work around chosen-IV attacks.

   In the following functions we don't check the return value of every 
   single component MAC operation since it would lead to endless sequences
   of 'status = x; if( cSOK( x ) ) ...' chains, on the remote chance that
   there's some transient failure in a single component operation it'll be
   picked up at the end anyway when the overall MAC check fails */

CHECK_RETVAL \
static int macDataTLS( IN_HANDLE const CRYPT_CONTEXT iHashContext, 
					   IN_INT_Z const long seqNo, 
					   IN_RANGE( 1, 3 ) const int version,
					   IN_BUFFER_OPT( dataLength ) const void *data, 
					   IN_LENGTH_Z const int dataLength, 
					   IN_RANGE( 0, 255 ) const int type )
	{
	STREAM stream;
	BYTE buffer[ 64 + 8 ];
	int length = DUMMY_INIT, status;

	assert( ( data == NULL && dataLength == 0 ) || \
			isReadPtr( data, dataLength ) );

	REQUIRES( isHandleRangeValid( iHashContext ) );
	REQUIRES( seqNo >= 0 );
	REQUIRES( version >= 1 && version <= 3 );
	REQUIRES( ( data == NULL && dataLength == 0 ) || \
			  ( data != NULL && \
				dataLength > 0 && dataLength <= MAX_PACKET_SIZE ) );
	REQUIRES( type >= 0 && type <= 255 );

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
		krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, 
						 ( MESSAGE_CAST ) data, dataLength );
	return( krnlSendMessage( iHashContext, IMESSAGE_CTX_HASH, "", 0 ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacTLS( INOUT SESSION_INFO *sessionInfoPtr, 
				  OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
				  IN_LENGTH const int dataMaxLength, 
				  OUT_LENGTH_Z int *dataLength,
				  IN_LENGTH const int payloadLength, 
				  IN_RANGE( 0, 255 ) const int type )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	REQUIRES( dataMaxLength > 0 && dataMaxLength < MAX_INTLENGTH );
	REQUIRES( payloadLength > 0 && payloadLength <= MAX_PACKET_SIZE && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataMaxLength );
	REQUIRES( type >= 0 && type <= 255 );

	/* Clear return value */
	*dataLength = 0;

	/* MAC the payload */
	status = macDataTLS( sessionInfoPtr->iAuthOutContext, sslInfo->writeSeqNo,
						 sessionInfoPtr->version, data, payloadLength, type );
	if( cryptStatusError( status ) )
		return( status );
	sslInfo->writeSeqNo++;

	/* Append the MAC value to the end of the packet */
	ENSURES( rangeCheck( payloadLength, sessionInfoPtr->authBlocksize,
						 dataMaxLength ) );
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

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacTLS( INOUT SESSION_INFO *sessionInfoPtr, 
				 IN_BUFFER( dataLength ) const void *data, 
				 IN_LENGTH const int dataLength, 
				 IN_LENGTH_Z const int payloadLength, 
				 IN_RANGE( 0, 255 ) const int type, 
				 const BOOLEAN noReportError )
	{
	SSL_INFO *sslInfo = sessionInfoPtr->sessionSSL;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, dataLength ) );

	REQUIRES( dataLength > 0 && dataLength < MAX_INTLENGTH );
	REQUIRES( payloadLength >= 0 && payloadLength <= MAX_PACKET_SIZE && \
			  payloadLength + sessionInfoPtr->authBlocksize <= dataLength );
	REQUIRES( type >= 0 && type <= 255 );

	/* MAC the payload.  If the payload length is zero then there's no data 
	   payload, this can happen with some versions of OpenSSL that send 
	   zero-length blocks as a kludge to work around pre-TLS 1.1 chosen-IV
	   attacks */
	if( payloadLength == 0 )
		{
		status = macDataTLS( sessionInfoPtr->iAuthInContext, 
							 sslInfo->readSeqNo, sessionInfoPtr->version, 
							 NULL, 0, type );
		}
	else
		{
		status = macDataTLS( sessionInfoPtr->iAuthInContext, 
							 sslInfo->readSeqNo, sessionInfoPtr->version, 
							 data, payloadLength, type );
		}
	if( cryptStatusError( status ) )
		return( status );
	sslInfo->readSeqNo++;

	/* Compare the calculated MAC to the MAC present at the end of the 
	   data */
	ENSURES( rangeCheckZ( payloadLength, sessionInfoPtr->authBlocksize,
						  dataLength ) );
	setMessageData( &msgData, ( BYTE * ) data + payloadLength,
					sessionInfoPtr->authBlocksize );
	status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
							  IMESSAGE_COMPARE, &msgData, 
							  MESSAGE_COMPARE_HASH );
	if( cryptStatusError( status ) )
		{
		/* If the error message has already been set at a higher level, 
		   don't update the error information */
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

/* Perform a dual MAC of a data block.  Since this is part of an ongoing 
   message exchange (in other words a failure potentially won't be detected
   for some time) we check each return value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int dualMacData( const SSL_HANDSHAKE_INFO *handshakeInfo,
						IN_BUFFER( dataLength ) const void *data, 
						IN_LENGTH const int dataLength )
	{
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( data, dataLength ) );

	REQUIRES( dataLength > 0 && dataLength < MAX_INTLENGTH );

	status = krnlSendMessage( handshakeInfo->clientMD5context,
							  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
							  dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->clientSHA1context,
								  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
								  dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->serverMD5context,
								  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
								  dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->serverSHA1context,
								  IMESSAGE_CTX_HASH, ( MESSAGE_CAST ) data,
								  dataLength );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int dualMacDataRead( const SSL_HANDSHAKE_INFO *handshakeInfo, 
					 INOUT STREAM *stream )
	{
	const int dataLength = sMemDataLeft( stream );
	void *data;
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( dataLength > 0 && dataLength < MAX_INTLENGTH );

	/* On a read we've just processed the packet header and everything 
	   that's left in the stream is the data to be MACd */
	status = sMemGetDataBlock( stream, &data, dataLength );
	if( cryptStatusOK( status ) )
		status = dualMacData( handshakeInfo, data, dataLength );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int dualMacDataWrite( const SSL_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT STREAM *stream )
	{
	const int dataLength = stell( stream ) - SSL_HEADER_SIZE;
	void *data;
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	
	REQUIRES( dataLength > 0 && dataLength < MAX_INTLENGTH );

	/* On a write we've just finished writing the packet and everything but
	   the header needs to be MACd */
	status = sMemGetDataBlockAbs( stream, SSL_HEADER_SIZE, &data, 
								  dataLength );
	if( cryptStatusOK( status ) )
		status = dualMacData( handshakeInfo, data, dataLength );
	return( status );
	}

/* Complete the dual MD5/SHA1 hash/MAC used in the finished message.  We 
   don't check the return value of every single component MAC operation 
   since it would lead to endless sequences of 
   'status = x; if( cSOK( x ) ) ...' chains, on the remote chance that
   there's some transient failure in a single component operation it'll be 
   picked up at the end anyway when the overall MAC check fails */

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 6, 8 ) ) \
int completeSSLDualMAC( IN_HANDLE const CRYPT_CONTEXT md5context,
						IN_HANDLE const CRYPT_CONTEXT sha1context, 
						OUT_BUFFER( hashValuesMaxLen, *hashValuesLen )
							BYTE *hashValues, 
						IN_LENGTH_SHORT_MIN( MD5MAC_SIZE + SHA1MAC_SIZE ) \
							const int hashValuesMaxLen,
						OUT_LENGTH_SHORT_Z int *hashValuesLen,
						IN_BUFFER( labelLength ) const char *label, 
						IN_RANGE( 1, 64 ) const int labelLength, 
						IN_BUFFER( masterSecretLen ) const BYTE *masterSecret, 
						IN_LENGTH_SHORT const int masterSecretLen )
	{
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( hashValues, hashValuesMaxLen ) );
	assert( isWritePtr( hashValuesLen, sizeof( int ) ) );
	assert( isReadPtr( label, labelLength ) );
	assert( isReadPtr( masterSecret, masterSecretLen ) );

	REQUIRES( isHandleRangeValid( md5context ) );
	REQUIRES( isHandleRangeValid( sha1context ) );
	REQUIRES( hashValuesMaxLen >= MD5MAC_SIZE + SHA1MAC_SIZE && \
			  hashValuesMaxLen < MAX_INTLENGTH_SHORT );
	REQUIRES( labelLength > 0 && labelLength <= 64 );
	REQUIRES( masterSecretLen > 0 && masterSecretLen < MAX_INTLENGTH_SHORT );

	/* Clear return value */
	*hashValuesLen = 0;

	/* Generate the inner portion of the handshake message's MAC:

		hash( handshake_messages || cl/svr_label || master_secret || pad1 ).

	   Note that the SHA-1 pad size is 40 bytes and not 44 (to get a total
	   length of 64 bytes), this is due to an error in the spec */
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, 
					 ( MESSAGE_CAST ) label, labelLength );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, 
					 ( MESSAGE_CAST ) label, labelLength );
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, 
					 ( MESSAGE_CAST ) masterSecret, masterSecretLen );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, 
					 ( MESSAGE_CAST ) masterSecret, masterSecretLen );
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
	krnlSendMessage( md5context, IMESSAGE_CTX_HASH, 
					 ( MESSAGE_CAST ) masterSecret, masterSecretLen );
	krnlSendMessage( sha1context, IMESSAGE_CTX_HASH, 
					 ( MESSAGE_CAST ) masterSecret, masterSecretLen );
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

CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 6, 8 ) ) \
int completeTLSHashedMAC( IN_HANDLE const CRYPT_CONTEXT md5context,
						  IN_HANDLE const CRYPT_CONTEXT sha1context, 
						  OUT_BUFFER( hashValuesMaxLen, *hashValuesLen )
								BYTE *hashValues, 
						  IN_LENGTH_SHORT_MIN( TLS_HASHEDMAC_SIZE ) \
								const int hashValuesMaxLen,
						  OUT_LENGTH_SHORT_Z int *hashValuesLen,
						  IN_BUFFER( labelLength ) const char *label, 
						  IN_RANGE( 1, 64 ) const int labelLength, 
						  IN_BUFFER( masterSecretLen ) const BYTE *masterSecret, 
						  IN_LENGTH_SHORT const int masterSecretLen )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	MESSAGE_DATA msgData;
	BYTE hashBuffer[ 64 + ( CRYPT_MAX_HASHSIZE * 2 ) + 8 ];
	int status;

	assert( isWritePtr( hashValues, hashValuesMaxLen ) );
	assert( isWritePtr( hashValuesLen, sizeof( int ) ) );
	assert( isReadPtr( label, labelLength ) );
	assert( isReadPtr( masterSecret, masterSecretLen ) );

	REQUIRES( isHandleRangeValid( md5context ) );
	REQUIRES( isHandleRangeValid( sha1context ) );
	REQUIRES( hashValuesMaxLen >= TLS_HASHEDMAC_SIZE && \
			  hashValuesMaxLen < MAX_INTLENGTH_SHORT );
	REQUIRES( labelLength > 0 && labelLength <= 64 && \
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
							( MESSAGE_CAST ) masterSecret, masterSecretLen, 
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
   private key to encrypt the raw concatenated SHA-1 and MD5 MAC or hash of 
   the handshake messages with PKCS #1 padding prepended), unless we're 
   using DSA in which case it drops the MD5 MAC/hash and uses only the SHA-1 
   one.  This is an incredible pain to support because it requires running a 
   parallel hash of handshake messages that terminates before the main 
   hashing does, further hashing/MAC'ing of additional data, and the use of 
   weird nonstandard data formats and signature mechanisms that aren't 
   normally supported by anything.  For example if the signing is to be done 
   via a smart card then we can't use the standard PKCS #1 sig mechanism, we 
   can't even use raw RSA and kludge the format together ourselves because 
   some PKCS #11 implementations don't support the _X509 (raw) mechanism, 
   what we have to do is tunnel the nonstandard sig.format information down 
   through several cryptlib layers and then hope that the PKCS #11 
   implementation that we're using (a) supports this format and (b) gets it 
   right.  Another problem (which only occurs for SSLv3) is that the MAC 
   requires the use of the master secret, which isn't available for several 
   hundred more lines of code, so we have to delay producing any more data 
   packets until the master secret is available, which severely screws up 
   the handshake processing flow.  TLS is slightly better here since it 
   simply signs MD5-hash || SHA1-hash, but even then it requires 
   speculatively running an MD5 and SHA-1 hash of all messages on every 
   exchange on the remote chance that the client will be using client 
   certificates.

   The chances of all of this working correctly are fairly low, and in any
   case there's no advantage to the weird mechanism and format used in
   SSL/TLS, all we actually need to do is sign the client and server nonces
   to ensure signature freshness.  Because of this what we actually do is
   just this, after which we create a standard PKCS #1 signature via the
   normal cryptlib mechanisms, which guarantees that it'll work with native
   cryptlib as well as any crypto hardware implementation.  Since client
   certificates are hardly ever used and when they are it's in a closed 
   environment, it's extremely unlikely that anyone will ever notice.  
   There'll be far more problems in trying to use the nonstandard SSL/TLS 
   signature mechanism than there are with using a standard (but not-in-the-
   spec) one */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int createCertVerifyHash( const SSL_HANDSHAKE_INFO *handshakeInfo,
								 OUT_HANDLE_OPT CRYPT_CONTEXT *iHashContext )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE nonceBuffer[ 64 + SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( iHashContext, sizeof( CRYPT_CONTEXT ) ) );

	/* Clear return value */
	*iHashContext = CRYPT_ERROR;

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
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_CTX_HASH,
							  nonceBuffer, 
							  18 + SSL_NONCE_SIZE + SSL_NONCE_SIZE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_CTX_HASH, nonceBuffer, 0 );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iHashContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int createCertVerify( const SESSION_INFO *sessionInfoPtr,
					  const SSL_HANDSHAKE_INFO *handshakeInfo,
					  INOUT STREAM *stream )
	{
	CRYPT_CONTEXT iHashContext;
	void *dataPtr;
	int dataLength, length = DUMMY_INIT, status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Create the hash of the data to sign */
	status = createCertVerifyHash( handshakeInfo, &iHashContext );
	if( cryptStatusError( status ) )
		return( status );

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
										iHashContext, NULL );
		}
	if( cryptStatusOK( status ) )
		status = sSkip( stream, length );
	krnlSendNotifier( iHashContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkCertVerify( const SESSION_INFO *sessionInfoPtr,
					 const SSL_HANDSHAKE_INFO *handshakeInfo,
					 INOUT STREAM *stream, 
					 IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
						const int sigLength )
	{
	CRYPT_CONTEXT iHashContext;
	void *dataPtr;
	int status;

	assert( isReadPtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES( sigLength >= MIN_CRYPT_OBJECTSIZE && \
			  sigLength < MAX_INTLENGTH_SHORT );

	/* Create the hash of the data to sign */
	status = createCertVerifyHash( handshakeInfo, &iHashContext );
	if( cryptStatusError( status ) )
		return( status );

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
							  IN_BUFFER( keyDataLength ) const void *keyData, 
							  IN_LENGTH_SHORT const int keyDataLength,
							  OUT_HANDLE_OPT CRYPT_CONTEXT *md5Context,
							  OUT_HANDLE_OPT CRYPT_CONTEXT *shaContext )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE nonceBuffer[ SSL_NONCE_SIZE + SSL_NONCE_SIZE + 8 ];
	int status;

	assert( isReadPtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isReadPtr( keyData, keyDataLength ) );
	assert( isWritePtr( md5Context, sizeof( CRYPT_CONTEXT ) ) );
	assert( isWritePtr( shaContext, sizeof( CRYPT_CONTEXT ) ) );

	REQUIRES( keyDataLength > 0 && keyDataLength < MAX_INTLENGTH_SHORT );

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
		*md5Context = CRYPT_ERROR;
		return( status );
		}
	*shaContext = createInfo.cryptHandle;

	/* Hash the client and server nonces and key data */
	memcpy( nonceBuffer, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	memcpy( nonceBuffer + SSL_NONCE_SIZE, handshakeInfo->serverNonce,
			SSL_NONCE_SIZE );
	status = krnlSendMessage( *md5Context, IMESSAGE_CTX_HASH,
							  nonceBuffer, SSL_NONCE_SIZE + SSL_NONCE_SIZE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( *shaContext, IMESSAGE_CTX_HASH, nonceBuffer, 
								  SSL_NONCE_SIZE + SSL_NONCE_SIZE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( *md5Context, IMESSAGE_CTX_HASH,
								  ( MESSAGE_CAST ) keyData, keyDataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( *shaContext, IMESSAGE_CTX_HASH,
								  ( MESSAGE_CAST ) keyData, keyDataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( *md5Context, IMESSAGE_CTX_HASH,
								  nonceBuffer, 0 );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( *shaContext, IMESSAGE_CTX_HASH,
								  nonceBuffer, 0 );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( *md5Context, IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( *shaContext, IMESSAGE_DECREFCOUNT );
		*md5Context = *shaContext = CRYPT_ERROR;
		return( status );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int createKeyexSignature( INOUT SESSION_INFO *sessionInfoPtr, 
						  INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						  INOUT STREAM *stream, 
						  IN_BUFFER( keyDataLength ) const void *keyData, 
						  IN_LENGTH_SHORT const int keyDataLength )
	{
	CRYPT_CONTEXT md5Context, shaContext;
	void *dataPtr;
	int dataLength, sigLength = DUMMY_INIT, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( keyData, keyDataLength ) );

	REQUIRES( keyDataLength > 0 && keyDataLength < MAX_INTLENGTH_SHORT );

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
		SIGPARAMS sigParams;

		initSigParams( &sigParams );
		sigParams.iSecondHash = shaContext;
		status = iCryptCreateSignature( dataPtr, 
										min( dataLength, \
											 MAX_INTLENGTH_SHORT - 1 ), 
										&sigLength, CRYPT_IFORMAT_SSL, 
										sessionInfoPtr->privateKey,
										md5Context, &sigParams );
		}
	if( cryptStatusOK( status ) )
		status = sSkip( stream, sigLength );

	/* Clean up */
	krnlSendNotifier( md5Context, IMESSAGE_DECREFCOUNT );
	krnlSendNotifier( shaContext, IMESSAGE_DECREFCOUNT );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int checkKeyexSignature( INOUT SESSION_INFO *sessionInfoPtr, 
						 INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						 INOUT STREAM *stream, 
						 IN_BUFFER( keyDataLength ) const void *keyData, 
						 IN_LENGTH_SHORT const int keyDataLength,
						 const BOOLEAN isECC )
	{
	CRYPT_CONTEXT md5Context, shaContext;
	void *dataPtr;
	int dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( keyData, keyDataLength ) );

	REQUIRES( keyDataLength > 0 && keyDataLength < MAX_INTLENGTH_SHORT );

	/* Make sure that there's enough data present for at least a minimal-
	   length signature */
	if( sMemDataLeft( stream ) < ( isECC ? \
								   MIN_PKCSIZE_ECCPOINT : MIN_PKCSIZE ) )
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
