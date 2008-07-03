/****************************************************************************
*																			*
*						Public/Private Key Read Routines					*
*						Copyright Peter Gutmann 1992-2007					*
*																			*
****************************************************************************/

#include <stdio.h>
#define PKC_CONTEXT		/* Indicate that we're working with PKC contexts */
#if defined( INC_ALL )
  #include "context.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "context/context.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/* Although there is a fair amount of commonality between public and private-
   key functions, we keep them distinct to enforce red/black separation.

   The DLP algorithms split the key components over the information in the
   AlgorithmIdentifier and the actual public/private key components, with the
   (p, q, g) set classed as domain parameters and included in the
   AlgorithmIdentifier and y being the actual key.

	params = SEQ {
		p INTEGER,
		q INTEGER,				-- q for DSA
		g INTEGER,				-- g for DSA
		j INTEGER OPTIONAL,		-- X9.42 only
		validationParams [...]	-- X9.42 only
		}

	key = y INTEGER				-- g^x mod p

   For peculiar historical reasons (copying errors and the use of obsolete
   drafts as reference material) the X9.42 interpretation used in PKIX 
   reverses the second two parameters from FIPS 186 (so it uses p, g, q 
   instead of p, q, g), so when we read/write the parameter information we 
   have to switch the order in which we read the values if the algorithm 
   isn't DSA */

#define hasReversedParams( cryptAlgo ) \
		( ( cryptAlgo ) == CRYPT_ALGO_DH || \
		  ( cryptAlgo ) == CRYPT_ALGO_ELGAMAL )

#ifdef USE_PKC

/****************************************************************************
*																			*
*								KeyID Routines								*
*																			*
****************************************************************************/

/* Generate a key ID, which is the SHA-1 hash of the SubjectPublicKeyInfo.
   There are about half a dozen incompatible ways of generating X.509
   keyIdentifiers, the following is conformant with the PKIX specification
   ("use whatever you like as long as it's unique") but differs slightly
   from one common method that hashes the SubjectPublicKey without the
   BIT STRING encapsulation.  The problem with that method is that some 
   DLP-based algorithms use a single integer as the SubjectPublicKey, 
   leading to potential key ID clashes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int calculateFlatKeyID( IN_BUFFER( keyInfoSize ) const void *keyInfo, 
							   IN_LENGTH_SHORT_MIN( 16 ) const int keyInfoSize,
							   OUT_BUFFER_FIXED( keyIdMaxLen ) BYTE *keyID, 
							   IN_LENGTH_FIXED( KEYID_SIZE ) const int keyIdMaxLen )
	{
	HASHFUNCTION_ATOMIC hashFunctionAtomic;

	assert( isReadPtr( keyInfo, keyInfoSize ) );
	assert( isWritePtr( keyID, keyIdMaxLen ) );

	REQUIRES( keyInfoSize >= 16 && keyInfoSize < MAX_INTLENGTH_SHORT );
	REQUIRES( keyIdMaxLen == KEYID_SIZE );

	/* Hash the key info to get the key ID */
	getHashAtomicParameters( CRYPT_ALGO_SHA1, &hashFunctionAtomic, NULL );
	hashFunctionAtomic( keyID, keyIdMaxLen, keyInfo, keyInfoSize );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int calculateKeyIDFromEncoded( INOUT CONTEXT_INFO *contextInfoPtr,
									  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	PKC_INFO *publicKey = contextInfoPtr->ctxPKC;
	STREAM stream;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 4 ) + 50 + 8 ];
	int length, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
			  cryptAlgo <= CRYPT_ALGO_LAST_PKC );

	status = calculateFlatKeyID( publicKey->publicKeyInfo, 
								 publicKey->publicKeyInfoSize, 
								 publicKey->keyID, KEYID_SIZE );
	if( cryptStatusError( status ) )
		retIntError();
	if( cryptAlgo != CRYPT_ALGO_KEA && cryptAlgo != CRYPT_ALGO_RSA )
		return( CRYPT_OK );

	/* If it's an RSA context we also need to remember the PGP 2 key ID 
	   alongside the cryptlib one */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		sMemConnect( &stream, publicKey->publicKeyInfo, 
					 publicKey->publicKeyInfoSize );
		readSequence( &stream, NULL );
		readUniversal( &stream );
		readBitStringHole( &stream, &length, MIN_PKCSIZE, DEFAULT_TAG );
		readSequence( &stream, NULL );
		status = readInteger( &stream, buffer, CRYPT_MAX_PKCSIZE, &length );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			retIntError();

		if( length > PGP_KEYID_SIZE )
			{
			memcpy( publicKey->pgp2KeyID, buffer + length - PGP_KEYID_SIZE, 
					PGP_KEYID_SIZE );
			}
		return( CRYPT_OK );
		}

#ifdef USE_KEA
	/* If it's a KEA context we also need to remember the start and length 
	   of the domain parameters and key agreement public value in the 
	   encoded key data */
	sMemConnect( &stream, publicKey->publicKeyInfo, 
				 publicKey->publicKeyInfoSize );
	readSequence( &stream, NULL );
	readSequence( &stream, NULL );
	readUniversal( &stream );
	readOctetStringHole( &stream, &length, MIN_PKCSIZE, DEFAULT_TAG );
	publicKey->domainParamPtr = sMemBufPtr( &stream );
	publicKey->domainParamSize = ( int ) length;
	sSkip( &stream, length );
	readBitStringHole( &stream, &length, MIN_PKCSIZE, DEFAULT_TAG );
	publicKey->publicValuePtr = sMemBufPtr( &stream );
	publicKey->publicValueSize = ( int ) length - 1;
	assert( sSkip( &stream, length ) == CRYPT_OK );
	sMemDisconnect( &stream );
#endif /* USE_KEA */

	return( CRYPT_OK );
	}

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int calculateOpenPGPKeyID( INOUT CONTEXT_INFO *contextInfoPtr,
								  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	PKC_INFO *publicKey = contextInfoPtr->ctxPKC;
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo;
	STREAM stream;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 4 ) + 50 + 8 ];
	BYTE hash[ CRYPT_MAX_HASHSIZE + 8 ], packetHeader[ 64 + 8 ];
	int hashSize, length, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
			  cryptAlgo <= CRYPT_ALGO_LAST_PKC );

	/* Since calculation of the OpenPGP ID requires the presence of data 
	   that isn't usually present in a non-PGP key we can't calculate a 
	   real OpenPGP ID for some keys but have to use the next-best thing, 
	   the first 64 bits of the key ID.  This shouldn't be a major problem 
	   because it's really only going to be used with private keys, public 
	   keys will be in PGP format and selected by user ID (for encryption) 
	   or PGP 2 ID/genuine OpenPGP ID (signing) */
	if( ( cryptAlgo != CRYPT_ALGO_RSA && cryptAlgo != CRYPT_ALGO_DSA && \
		  cryptAlgo != CRYPT_ALGO_ELGAMAL ) || \
		publicKey->pgpCreationTime <= MIN_TIME_VALUE )
		{
		/* No creation time or non-PGP algorithm, fake it */
		memcpy( publicKey->openPgpKeyID, publicKey->keyID,
				PGP_KEYID_SIZE );
		publicKey->openPgpKeyIDSet = TRUE;
		
		return( CRYPT_OK );
		}

	/* There's a creation time present, generate a real OpenPGP key ID:

		byte		ctb = 0x99
		byte[2]		length
		-- Key data --
		byte		version = 4
		byte[4]		key generation time 
		byte		algorithm
		byte[]		key data

	  We do this by writing the public key fields to a buffer and creating a 
	  separate PGP public key header, then hashing the two */
	sMemOpen( &stream, buffer, ( CRYPT_MAX_PKCSIZE * 4 ) + 50 );
	status = publicKey->writePublicKeyFunction( &stream, contextInfoPtr, 
												KEYFORMAT_PGP, 
												"public_key", 10 );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		return( status );
		}
	length = stell( &stream );
	packetHeader[ 0 ] = 0x99;
	packetHeader[ 1 ] = ( length >> 8 ) & 0xFF;
	packetHeader[ 2 ] = length & 0xFF;

	/* Hash the data needed to generate the OpenPGP keyID */
	getHashParameters( CRYPT_ALGO_SHA1, &hashFunction, &hashSize );
	hashFunction( hashInfo, NULL, 0, packetHeader, 1 + 2, 
				  HASH_STATE_START );
	hashFunction( hashInfo, hash, CRYPT_MAX_HASHSIZE, buffer, length, 
				  HASH_STATE_END );
	memcpy( publicKey->openPgpKeyID, hash + hashSize - PGP_KEYID_SIZE, 
			PGP_KEYID_SIZE );
	sMemClose( &stream );
	publicKey->openPgpKeyIDSet = TRUE;

	return( CRYPT_OK );
	}
#endif /* USE_PGP || USE_PGPKEYS */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writePKCS3Key( INOUT STREAM *stream, 
						  const PKC_INFO *dlpKey,
						  IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const int parameterSize = ( int ) sizeofObject( \
								sizeofBignum( &dlpKey->dlpParam_p ) + \
								3 +		/* INTEGER value 0 */
								sizeofBignum( &dlpKey->dlpParam_g ) );
	const int componentSize = sizeofBignum( &dlpKey->dlpParam_y );
	int totalSize;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( dlpKey, sizeof( PKC_INFO ) ) );

	REQUIRES( isDlpAlgo( cryptAlgo ) );

	/* Implement a cut-down version of writeDlpSubjectPublicKey(), writing a 
	   zero value for q */
	totalSize = sizeofAlgoIDex( cryptAlgo, CRYPT_ALGO_NONE, parameterSize ) + \
				( int ) sizeofObject( componentSize + 1 );
	writeSequence( stream, totalSize );
	writeAlgoIDex( stream, cryptAlgo, CRYPT_ALGO_NONE, parameterSize );
	writeBignum( stream, &dlpKey->dlpParam_p );
	swrite( stream, "\x02\x01\x00", 3 );	/* Integer value 0 */
	writeBignum( stream, &dlpKey->dlpParam_g );
	writeBitStringHole( stream, componentSize, DEFAULT_TAG );
	return( writeBignum( stream, &dlpKey->dlpParam_y ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int calculateKeyID( INOUT CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *publicKey = contextInfoPtr->ctxPKC;
	STREAM stream;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 4 ) + 50 + 8 ];
	const CRYPT_ALGO_TYPE cryptAlgo = contextInfoPtr->capabilityInfo->cryptAlgo;
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC );

	/* If the public key info is present in pre-encoded form, calculate the
	   key ID directly from that */
	if( publicKey->publicKeyInfo != NULL )
		return( calculateKeyIDFromEncoded( contextInfoPtr, cryptAlgo ) );

	/* Write the public key fields to a buffer and hash them to get the key
	   ID */
	sMemOpen( &stream, buffer, ( CRYPT_MAX_PKCSIZE * 4 ) + 50 );
	if( isDlpAlgo( cryptAlgo ) && BN_is_zero( &publicKey->dlpParam_q ) )
		{
		/* OpenPGP Elgamal keys and SSL/SSH DH keys don't have a q 
		   parameter, which makes it impossible to write them in the X.509 
		   format.  If this situation occurs we write them in a cut-down
		   version of the format, which is OK because the X.509 keyIDs are 
		   explicit and not implicitly generated from the key data like 
		   OpenPGP one */
		status = writePKCS3Key( &stream, publicKey, cryptAlgo );
		}
	else
		{
		status = publicKey->writePublicKeyFunction( &stream, contextInfoPtr, 
													KEYFORMAT_CERT, 
													"public_key", 10 );
		}
	if( cryptStatusOK( status ) )
		status = calculateFlatKeyID( buffer, stell( &stream ), 
									 publicKey->keyID, KEYID_SIZE );
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's an RSA key, we need to calculate the PGP 2 key ID alongside 
	   the cryptlib one */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		const PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
		int length;

		status = getBignumData( &pkcInfo->rsaParam_n, buffer, 
								CRYPT_MAX_PKCSIZE, &length );
		if( cryptStatusError( status ) )
			return( status );
		if( length > PGP_KEYID_SIZE )
			{
			memcpy( publicKey->pgp2KeyID, 
					buffer + length - PGP_KEYID_SIZE, PGP_KEYID_SIZE );
			}
		}

#if defined( USE_PGP ) || defined( USE_PGPKEYS )
	/* If the OpenPGP ID is already set by having the key loaded from a PGP
	   keyset, we're done */
	if( publicKey->openPgpKeyIDSet )
		return( CRYPT_OK );

	/* Finally, set the OpenPGP key ID */
	status = calculateOpenPGPKeyID( contextInfoPtr, cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );
#endif /* USE_PGP || USE_PGPKEYS */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read Public Keys							*
*																			*
****************************************************************************/

/* Read X.509 SubjectPublicKeyInfo public keys */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readRsaSubjectPublicKey( INOUT STREAM *stream, 
									INOUT CONTEXT_INFO *contextInfoPtr,
									OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the SubjectPublicKeyInfo header field and parameter data if
	   there's any present.  We read the outer wrapper in generic form since
	   it may be context-specific-tagged if it's coming from a keyset (RSA
	   public keys is the one place where PKCS #15 keys differ from X.509
	   ones) or something odd from CRMF */
	readGenericHole( stream, NULL, 8 + RSAPARAM_MIN_N + RSAPARAM_MIN_E, 
					 DEFAULT_TAG );
	status = readAlgoID( stream, &cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptAlgo != CRYPT_ALGO_RSA )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  More restrictive permissions may 
	   be set by higher-level code if required and in particular if the key 
	   is a pure public key rather than merely the public portions of a 
	   private key the actions will be restricted at that point to encrypt 
	   and signature-check only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL );

	/* Read the BITSTRING encapsulation and the public key fields */
	readBitStringHole( stream, NULL, MIN_PKCSIZE, DEFAULT_TAG );
	readSequence( stream, NULL );
	status = readBignumChecked( stream, &rsaKey->rsaParam_n, 
								RSAPARAM_MIN_N, RSAPARAM_MAX_N, NULL );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_e,
							 RSAPARAM_MIN_E, RSAPARAM_MAX_E, 
							 &rsaKey->rsaParam_n );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readDlpSubjectPublicKey( INOUT STREAM *stream, 
									INOUT CONTEXT_INFO *contextInfoPtr,
									OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	CRYPT_ALGO_TYPE cryptAlgo;
	int extraLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the SubjectPublicKeyInfo header field and parameter data if
	   there's any present */
	readGenericHole( stream, NULL, 8 + DLPPARAM_MIN_P + DLPPARAM_MIN_G + \
								   DLPPARAM_MIN_Q, DEFAULT_TAG );
	status = readAlgoIDparams( stream, &cryptAlgo, &extraLength );
	if( cryptStatusError( status ) )
		return( status );
	if( extraLength > 0 )
		{
		if( contextInfoPtr->capabilityInfo->cryptAlgo != cryptAlgo )
			return( CRYPT_ERROR_BADDATA );

		/* Read the header and key parameters */
		readSequence( stream, NULL );
		status = readBignumChecked( stream, &dlpKey->dlpParam_p, 
									DLPPARAM_MIN_P, DLPPARAM_MAX_P, NULL );
		if( cryptStatusError( status ) )
			return( status );
		if( hasReversedParams( cryptAlgo ) )
			{
			status = readBignum( stream, &dlpKey->dlpParam_g,
								 DLPPARAM_MIN_G, DLPPARAM_MAX_G,
								 &dlpKey->dlpParam_p );
			if( cryptStatusOK( status ) )
				status = readBignum( stream, &dlpKey->dlpParam_q,
									 DLPPARAM_MIN_Q, DLPPARAM_MAX_Q,
									 &dlpKey->dlpParam_p );
			}
		else
			{
			status = readBignum( stream, &dlpKey->dlpParam_q,
								 DLPPARAM_MIN_Q, DLPPARAM_MAX_Q,
								 &dlpKey->dlpParam_p );
			if( cryptStatusOK( status ) )
				status = readBignum( stream, &dlpKey->dlpParam_g,
									 DLPPARAM_MIN_G, DLPPARAM_MAX_G,
									 &dlpKey->dlpParam_p );
			}
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for DLP algorithms we make the usage 
	   internal-only.  If the key is a pure public key rather than merely 
	   the public portions of a private key the actions will be restricted 
	   by higher-level code to signature-check only */
	if( cryptAlgo == CRYPT_ALGO_DSA )
		{
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
									   ACTION_PERM_NONE_EXTERNAL );
		}
	else
		{
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
									   ACTION_PERM_NONE_EXTERNAL );
		}

	/* Read the BITSTRING encapsulation and the public key fields */
	readBitStringHole( stream, NULL, MIN_PKCSIZE, DEFAULT_TAG );
	return( readBignumChecked( stream, &dlpKey->dlpParam_y,
							   DLPPARAM_MIN_Y, DLPPARAM_MAX_Y,
							   &dlpKey->dlpParam_p ) );
	}

#ifdef USE_ECC

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readEccSubjectPublicKey( INOUT STREAM *stream, 
									INOUT CONTEXT_INFO *contextInfoPtr,
									OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ECDSA );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for DLP algorithms we make the usage 
	   internal-only.  If the key is a pure public key rather than merely 
	   the public portions of a private key the actions will be restricted 
	   by higher-level code to signature-check only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
								   ACTION_PERM_NONE_EXTERNAL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
								   ACTION_PERM_NONE_EXTERNAL );

	return( CRYPT_ERROR_NOTAVAIL );
	}
#endif /* USE_ECC */

#ifdef USE_SSH1

/* Read SSHv1 public keys:

	uint32		keysize_bits
	mpint		exponent
	mpint		modulus */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readSsh1RsaPublicKey( INOUT STREAM *stream, 
								 INOUT CONTEXT_INFO *contextInfoPtr,
								 OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Make sure that the nominal keysize value is valid */
	status = length = readUint32( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( length < bytesToBits( RSAPARAM_MIN_E + RSAPARAM_MIN_N ) || \
		length > bytesToBits( RSAPARAM_MAX_E + RSAPARAM_MAX_N ) )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  SSH keys are only used internally
	   so we restrict the usage to internal-only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the SSH public key information */
	status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_e, 
									   bytesToBits( RSAPARAM_MIN_E ), 
									   bytesToBits( RSAPARAM_MAX_E ), 
									   NULL );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_n,
										   bytesToBits( RSAPARAM_MIN_N ), 
										   bytesToBits( RSAPARAM_MAX_N ),
										   NULL );
	return( status );
	}
#endif /* USE_SSH1 */

#ifdef USE_SSH

/* Read SSHv2 public keys:

	string	certificate
		string	"ssh-rsa"	"ssh-dss"
		mpint	e			p
		mpint	n			q
		mpint				g
		mpint				y */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readSshRsaPublicKey( INOUT STREAM *stream, 
								INOUT CONTEXT_INFO *contextInfoPtr,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	char buffer[ 16 + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the wrapper and make sure that it's OK */
	readUint32( stream );
	status = readString32( stream, buffer, 7, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 7 || memcmp( buffer, "ssh-rsa", 7 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  SSH keys are only used internally
	   so we restrict the usage to internal-only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the SSH public key information */
	status = readBignumInteger32( stream, &rsaKey->rsaParam_e, 
								  RSAPARAM_MIN_E, RSAPARAM_MAX_E, 
								  NULL );
	if( cryptStatusOK( status ) )
		status = readBignumInteger32Checked( stream, &rsaKey->rsaParam_n,
											 RSAPARAM_MIN_N, RSAPARAM_MAX_N );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readSshDlpPublicKey( INOUT STREAM *stream, 
								INOUT CONTEXT_INFO *contextInfoPtr,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *dsaKey = contextInfoPtr->ctxPKC;
	const BOOLEAN isDH = \
			( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH );
	char buffer[ 16 + 8 ];
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA ) );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the wrapper and make sure that it's OK.  SSHv2 uses PKCS #3 
	   rather than X9.42-style DH keys so we have to treat this algorithm 
	   type specially */
	readUint32( stream );
	if( isDH )
		{
		status = readString32( stream, buffer, 6, &length );
		if( cryptStatusError( status ) )
			return( status );
		if( length != 6 || memcmp( buffer, "ssh-dh", 6 ) )
			return( CRYPT_ERROR_BADDATA );

		/* Set the maximum permitted actions.  SSH keys are only used 
		   internally so we restrict the usage to internal-only.  Since DH 
		   keys can be both public and private keys we allow both usage 
		   types even though technically it's a public key */
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
									   ACTION_PERM_NONE_EXTERNAL );

		/* Read the SSH public key information */
		status = readBignumInteger32Checked( stream, &dsaKey->dlpParam_p,
											 DLPPARAM_MIN_P, DLPPARAM_MAX_P );
		if( cryptStatusOK( status ) )
			status = readBignumInteger32( stream, &dsaKey->dlpParam_g,
										  DLPPARAM_MIN_G, DLPPARAM_MAX_G,
										  &dsaKey->dlpParam_p );
		return( status );
		}

	/* It's a standard DLP key, read the wrapper and make sure that it's 
	   OK */
	status = readString32( stream, buffer, 7, &length );
	if( cryptStatusError( status ) )
		return( status );
	if( length != 7 || memcmp( buffer, "ssh-dss", 7 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Set the maximum permitted actions.  SSH keys are only used internally
	   so we restrict the usage to internal-only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the SSH public key information */
	status = readBignumInteger32Checked( stream, &dsaKey->dlpParam_p,
										 DLPPARAM_MIN_P, DLPPARAM_MAX_P );
	if( cryptStatusOK( status ) )
		status = readBignumInteger32( stream, &dsaKey->dlpParam_q,
									  DLPPARAM_MIN_Q, DLPPARAM_MAX_Q,
									  &dsaKey->dlpParam_p );
	if( cryptStatusOK( status ) )
		status = readBignumInteger32( stream, &dsaKey->dlpParam_g,
									  DLPPARAM_MIN_G, DLPPARAM_MAX_G,
									  &dsaKey->dlpParam_p );
	if( cryptStatusOK( status ) && !isDH )
		status = readBignumInteger32( stream, &dsaKey->dlpParam_y,
									  DLPPARAM_MIN_Y, DLPPARAM_MAX_Y,
									  &dsaKey->dlpParam_p );
	return( status );
	}
#endif /* USE_SSH */

#ifdef USE_SSL

/* Read SSL public keys:

	uint16		dh_pLen
	byte[]		dh_p
	uint16		dh_gLen
	byte[]		dh_g
  [	uint16		dh_YsLen ]
  [	byte[]		dh_Ys	 ]

   The DH y value is nominally attached to the DH p and g values but isn't 
   processed at this level since this is a pure PKCS #3 DH key and not a 
   generic DLP key */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readSslDlpPublicKey( INOUT STREAM *stream, 
								INOUT CONTEXT_INFO *contextInfoPtr,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *dhKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Set the maximum permitted actions.  SSL keys are only used 
	   internally so we restrict the usage to internal-only.  Since DH 
	   keys can be both public and private keys we allow both usage 
	   types even though technically it's a public key */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
								   ACTION_PERM_NONE_EXTERNAL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the SSL public key information */
	status = readBignumInteger16UChecked( stream, &dhKey->dlpParam_p,
										  DLPPARAM_MIN_P, DLPPARAM_MAX_P );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16U( stream, &dhKey->dlpParam_g, 
									   DLPPARAM_MIN_G, DLPPARAM_MAX_G,
									   &dhKey->dlpParam_p );
	return( status );
	}
#endif /* USE_SSL */

#ifdef USE_PGP 

/* Read PGP public keys:

	byte		version
	uint32		creationTime
	[ uint16	validity - version 2 or 3 only ]
	byte		RSA		DSA		Elgamal
	mpi			n		p		p
	mpi			e		q		g
	mpi					g		y
	mpi					y */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readPgpRsaPublicKey( INOUT STREAM *stream, 
								INOUT CONTEXT_INFO *contextInfoPtr,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	time_t creationTime;
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the header info */
	status = value = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( value != PGP_VERSION_2 && value != PGP_VERSION_3 && \
		value != PGP_VERSION_OPENPGP )
		return( CRYPT_ERROR_BADDATA );
	status = readUint32Time( stream, &creationTime );
	if( cryptStatusError( status ) )
		return( status );
	rsaKey->pgpCreationTime = creationTime;
	if( value == PGP_VERSION_2 || value == PGP_VERSION_3 )
		{
		/* Skip the validity period */
		sSkip( stream, 2 );
		}

	/* Set the maximum permitted actions.  If there are no restrictions we
	   allow external usage, if the keys are encryption-only or signature-
	   only we make the usage internal-only because of RSA's signature/
	   encryption duality.  If the key is a pure public key rather than 
	   merely the public portions of a private key the actions will be 
	   restricted by higher-level code to signature-check only  */
	status = value = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( value != PGP_ALGO_RSA && value != PGP_ALGO_RSA_ENCRYPT && \
		value != PGP_ALGO_RSA_SIGN )
		return( CRYPT_ERROR_BADDATA );
	*actionFlags = 0;
	if( value != PGP_ALGO_RSA_SIGN )
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
	if( value != PGP_ALGO_RSA_ENCRYPT )
		*actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL ) | \
						MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );
	if( value != PGP_ALGO_RSA )
		*actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( *actionFlags );

	/* Read the PGP public key information */
	status = readBignumInteger16UbitsChecked( stream, &rsaKey->rsaParam_n, 
											  bytesToBits( RSAPARAM_MIN_N ), 
											  bytesToBits( RSAPARAM_MAX_N ) );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_e, 
										   bytesToBits( RSAPARAM_MIN_E ), 
										   bytesToBits( RSAPARAM_MAX_E ),
										   &rsaKey->rsaParam_n );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readPgpDlpPublicKey( INOUT STREAM *stream, 
								INOUT CONTEXT_INFO *contextInfoPtr,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;
	time_t creationTime;
	int value, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the header info */
	status = value = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( value != PGP_VERSION_OPENPGP )
		return( CRYPT_ERROR_BADDATA );
	status = readUint32Time( stream, &creationTime );
	if( cryptStatusError( status ) )
		return( status );
	dlpKey->pgpCreationTime = creationTime;

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for DLP algorithms we make the usage 
	   internal-only.  If the key is a pure public key rather than merely 
	   the public portions of a private key the actions will be restricted 
	   by higher-level code to signature-check only  */
	status = value = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( value != PGP_ALGO_DSA && value != PGP_ALGO_ELGAMAL )
		return( CRYPT_ERROR_BADDATA );
	if( value == PGP_ALGO_DSA )
		{
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
									   ACTION_PERM_NONE_EXTERNAL );
		}
	else
		{
		*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, \
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, \
									   ACTION_PERM_NONE_EXTERNAL );
		}

	/* Read the PGP public key information */
	status = readBignumInteger16UbitsChecked( stream, &dlpKey->dlpParam_p, 
											  bytesToBits( DLPPARAM_MIN_P ), 
											  bytesToBits( DLPPARAM_MAX_P ) );
	if( cryptStatusOK( status ) && value == PGP_ALGO_DSA )
		status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_q, 
										   bytesToBits( DLPPARAM_MIN_Q ), 
										   bytesToBits( DLPPARAM_MAX_Q ),
										   &dlpKey->dlpParam_p );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_g, 
										   bytesToBits( DLPPARAM_MIN_G ), 
										   bytesToBits( DLPPARAM_MAX_G ),
										   &dlpKey->dlpParam_p );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &dlpKey->dlpParam_y, 
										   bytesToBits( DLPPARAM_MIN_Y ), 
										   bytesToBits( DLPPARAM_MAX_Y ),
										   &dlpKey->dlpParam_p );
	return( status );
	}
#endif /* USE_PGP */

/* Umbrella public-key read functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPublicKeyRsaFunction( INOUT STREAM *stream, 
									 INOUT CONTEXT_INFO *contextInfoPtr,
									 IN_ENUM( KEYFORMAT )  \
										const KEYFORMAT_TYPE formatType )
	{
	int actionFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );
	REQUIRES( formatType > KEYFORMAT_NONE && formatType < KEYFORMAT_LAST );

	switch( formatType )
		{
		case KEYFORMAT_CERT:
			status = readRsaSubjectPublicKey( stream, contextInfoPtr, 
											  &actionFlags );
			break;

#ifdef USE_SSH1
		case KEYFORMAT_SSH1:
			status = readSsh1RsaPublicKey( stream, contextInfoPtr, 
										   &actionFlags );
			break;
#endif /* USE_SSH1 */

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			status = readSshRsaPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_SSH */

#ifdef USE_PGP
		case KEYFORMAT_PGP:
			status = readPgpRsaPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_PGP */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );
	return( krnlSendMessage( contextInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE, &actionFlags, 
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPublicKeyDlpFunction( INOUT STREAM *stream, 
									 INOUT CONTEXT_INFO *contextInfoPtr,
									 IN_ENUM( KEYFORMAT )  \
										const KEYFORMAT_TYPE formatType )
	{
	int actionFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );
	REQUIRES( formatType > KEYFORMAT_NONE && formatType < KEYFORMAT_LAST );

	switch( formatType )
		{
		case KEYFORMAT_CERT:
			status = readDlpSubjectPublicKey( stream, contextInfoPtr, 
											  &actionFlags );
			break;

#ifdef USE_SSH
		case KEYFORMAT_SSH:
			status = readSshDlpPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_SSH */

#ifdef USE_SSL
		case KEYFORMAT_SSL:
			status = readSslDlpPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_SSL */
		
#ifdef USE_PGP
		case KEYFORMAT_PGP:
			status = readPgpDlpPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_PGP */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );
	return( krnlSendMessage( contextInfoPtr->objectHandle,
							 IMESSAGE_SETATTRIBUTE, &actionFlags, 
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}

#ifdef USE_ECC

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPublicKeyEccFunction( INOUT STREAM *stream, 
									 INOUT CONTEXT_INFO *contextInfoPtr,
									 IN_ENUM( KEYFORMAT )  \
										const KEYFORMAT_TYPE formatType )
	{
	int actionFlags, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ECDSA );
	REQUIRES( formatType == KEYFORMAT_CERT );

	switch( formatType )
		{
		case KEYFORMAT_CERT:
			status = readEccSubjectPublicKey( stream, contextInfoPtr, 
											  &actionFlags );
			break;

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );
	return( krnlSendMessage( contextInfoPtr->objectHandle,
							 IMESSAGE_SETATTRIBUTE, &actionFlags, 
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}
#endif /* USE_ECC */

/****************************************************************************
*																			*
*								Read Private Keys							*
*																			*
****************************************************************************/

/* Read private key components.  This function assumes that the public
   portion of the context has already been set up */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRsaPrivateKey( INOUT STREAM *stream, 
							  INOUT CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Read the header */
	status = readSequence( stream, NULL );
	if( cryptStatusOK( status ) && \
		peekTag( stream ) == MAKE_CTAG( 0 ) )
		{
		/* Erroneously written in older code */
		status = readConstructed( stream, NULL, 0 );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the key components */
	if( peekTag( stream ) == MAKE_CTAG_PRIMITIVE( 0 ) )
		{
		/* The public components may already have been read when we read a
		   corresponding public key or certificate so we only read them if
		   they're not already present */
		if( BN_is_zero( &rsaKey->rsaParam_n ) && \
			BN_is_zero( &rsaKey->rsaParam_e ) )
			{
			status = readBignumTag( stream, &rsaKey->rsaParam_n, 
									RSAPARAM_MIN_N, RSAPARAM_MAX_N, 
									NULL, 0 );
			if( cryptStatusOK( status ) )
				{
				status = readBignumTag( stream, &rsaKey->rsaParam_e, 
										RSAPARAM_MIN_E, RSAPARAM_MAX_E, 
										&rsaKey->rsaParam_n, 1 );
				}
			}
		else
			{
			/* The key components are already present, skip them */
			REQUIRES( !BN_is_zero( &rsaKey->rsaParam_n ) && \
					  !BN_is_zero( &rsaKey->rsaParam_e ) );
			readUniversal( stream );
			status = readUniversal( stream );
			}
		}
	if( cryptStatusError( status ) )
		return( status );
	if( peekTag( stream ) == MAKE_CTAG_PRIMITIVE( 2 ) )
		status = readBignumTag( stream, &rsaKey->rsaParam_d, 
								RSAPARAM_MIN_D, RSAPARAM_MAX_D, 
								&rsaKey->rsaParam_n, 2 );
	if( cryptStatusOK( status ) )
		status = readBignumTag( stream, &rsaKey->rsaParam_p, 
								RSAPARAM_MIN_P, RSAPARAM_MAX_P, 
								&rsaKey->rsaParam_n, 3 );
	if( cryptStatusOK( status ) )
		status = readBignumTag( stream, &rsaKey->rsaParam_q, 
								RSAPARAM_MIN_Q, RSAPARAM_MAX_Q, 
								&rsaKey->rsaParam_n, 4 );
	if( cryptStatusError( status ) )
		return( status );
	if( peekTag( stream ) == MAKE_CTAG_PRIMITIVE( 5 ) )
		{
		status = readBignumTag( stream, &rsaKey->rsaParam_exponent1, 
								RSAPARAM_MIN_EXP1, RSAPARAM_MAX_EXP1, 
								&rsaKey->rsaParam_n, 5 );
		if( cryptStatusOK( status ) )
			status = readBignumTag( stream, &rsaKey->rsaParam_exponent2, 
									RSAPARAM_MIN_EXP2, RSAPARAM_MAX_EXP2, 
									&rsaKey->rsaParam_n, 6 );
		if( cryptStatusOK( status ) )
			status = readBignumTag( stream, &rsaKey->rsaParam_u, 
									RSAPARAM_MIN_U, RSAPARAM_MAX_U, 
									&rsaKey->rsaParam_n, 7 );
		}
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRsaPrivateKeyOld( INOUT STREAM *stream, 
								 INOUT CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Read the header and key components */
	readOctetStringHole( stream, NULL, 7 * MIN_PKCSIZE, DEFAULT_TAG );
	readSequence( stream, NULL );
	readShortInteger( stream, NULL );
	status = readBignum( stream, &rsaKey->rsaParam_n,
						 RSAPARAM_MIN_N, RSAPARAM_MAX_N, 
						 NULL );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_e,
							 RSAPARAM_MIN_E, RSAPARAM_MAX_E,
							 &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_d,
							 RSAPARAM_MIN_D, RSAPARAM_MAX_D,
							 &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_p,
							 RSAPARAM_MIN_P, RSAPARAM_MAX_P,
							 &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_q,
							 RSAPARAM_MIN_Q, RSAPARAM_MAX_Q,
							 &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_exponent1,
							 RSAPARAM_MIN_EXP1, RSAPARAM_MAX_EXP1,
							 &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_exponent2,
							 RSAPARAM_MIN_EXP2, RSAPARAM_MAX_EXP2,
							 &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignum( stream, &rsaKey->rsaParam_u,
							 RSAPARAM_MIN_U, RSAPARAM_MAX_U,
							 &rsaKey->rsaParam_n );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readDlpPrivateKey( INOUT STREAM *stream, 
							  INOUT CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );

	/* Read the key components */
	if( peekTag( stream ) == BER_SEQUENCE )
		{
		/* Erroneously written in older code */
		readSequence( stream, NULL );
		return( readBignumTag( stream, &dlpKey->dlpParam_x,
							   DLPPARAM_MIN_X, DLPPARAM_MAX_X, 
							   &dlpKey->dlpParam_p, 0 ) );
		}
	return( readBignum( stream, &dlpKey->dlpParam_x,
						DLPPARAM_MIN_X, DLPPARAM_MAX_X,
						&dlpKey->dlpParam_p ) );
	}

#ifdef USE_ECC

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readEccPrivateKey( INOUT STREAM *stream, 
							  INOUT CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ECDSA );

	/* Read the key components */
	return( readBignum( stream, &dlpKey->dlpParam_x,
						ECCPARAM_MIN_X, ECCPARAM_MAX_X,
						&dlpKey->dlpParam_p ) );
	}
#endif /* USE_ECC */


/* Read PGP private key components.  This function assumes that the public
   portion of the context has already been set up */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPgpRsaPrivateKey( INOUT STREAM *stream, 
								 INOUT CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *rsaKey = contextInfoPtr->ctxPKC;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Read the PGP private key information */
	status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_d, 
									   bytesToBits( RSAPARAM_MIN_D ), 
									   bytesToBits( RSAPARAM_MAX_D ), 
									   &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_p, 
										   bytesToBits( RSAPARAM_MIN_P ), 
										   bytesToBits( RSAPARAM_MAX_P ),
										   &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_q, 
										   bytesToBits( RSAPARAM_MIN_Q ), 
										   bytesToBits( RSAPARAM_MAX_Q ),
										   &rsaKey->rsaParam_n );
	if( cryptStatusOK( status ) )
		status = readBignumInteger16Ubits( stream, &rsaKey->rsaParam_u, 
										   bytesToBits( RSAPARAM_MIN_U ), 
										   bytesToBits( RSAPARAM_MAX_U ),
										   &rsaKey->rsaParam_n );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPgpDlpPrivateKey( INOUT STREAM *stream, 
								 INOUT CONTEXT_INFO *contextInfoPtr )
	{
	PKC_INFO *dlpKey = contextInfoPtr->ctxPKC;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );

	/* Read the PGP private key information */
	return( readBignumInteger16Ubits( stream, &dlpKey->dlpParam_x, 
									  bytesToBits( DLPPARAM_MIN_X ), 
									  bytesToBits( DLPPARAM_MAX_X ),
									  &dlpKey->dlpParam_p ) );
	}

/* Umbrella private-key read functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPrivateKeyRsaFunction( INOUT STREAM *stream, 
									  INOUT CONTEXT_INFO *contextInfoPtr,
									  IN_ENUM( KEYFORMAT ) \
										const KEYFORMAT_TYPE formatType )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );
	REQUIRES( formatType > KEYFORMAT_NONE && formatType < KEYFORMAT_LAST );

	switch( formatType )
		{
		case KEYFORMAT_PRIVATE:
			return( readRsaPrivateKey( stream, contextInfoPtr ) );

		case KEYFORMAT_PRIVATE_OLD:
			return( readRsaPrivateKeyOld( stream, contextInfoPtr ) );

#ifdef USE_PGP
		case KEYFORMAT_PGP:
			return( readPgpRsaPrivateKey( stream, contextInfoPtr ) );
#endif /* USE_PGP */
		}

	retIntError();
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPrivateKeyDlpFunction( INOUT STREAM *stream, 
									  INOUT CONTEXT_INFO *contextInfoPtr,
									  IN_ENUM( KEYFORMAT )  \
										const KEYFORMAT_TYPE formatType )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  ( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ELGAMAL ) );
	REQUIRES( formatType > KEYFORMAT_NONE && formatType < KEYFORMAT_LAST );

	switch( formatType )
		{
		case KEYFORMAT_PRIVATE:
			return( readDlpPrivateKey( stream, contextInfoPtr ) );

#ifdef USE_PGP
		case KEYFORMAT_PGP:
			return( readPgpDlpPrivateKey( stream, contextInfoPtr ) );
#endif /* USE_PGP */
		}

	retIntError();
	}

#ifdef USE_ECC

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readPrivateKeyEccFunction( INOUT STREAM *stream, 
									  INOUT CONTEXT_INFO *contextInfoPtr,
									  IN_ENUM( KEYFORMAT )  \
										const KEYFORMAT_TYPE formatType )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ECDSA );
	REQUIRES( formatType > KEYFORMAT_NONE && formatType < KEYFORMAT_LAST );

	switch( formatType )
		{
		case KEYFORMAT_PRIVATE:
			return( readEccPrivateKey( stream, contextInfoPtr ) );
		}

	retIntError();
	}
#endif /* USE_ECC */

/****************************************************************************
*																			*
*								Read DL Values								*
*																			*
****************************************************************************/

/* Unlike the simpler RSA PKC, DL-based PKCs produce a pair of values that
   need to be encoded as structured data.  The following two functions 
   perform this en/decoding.  SSH assumes that DLP values are two fixed-size
   blocks of 20 bytes so we can't use the normal read/write routines to 
   handle these values */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
static int decodeDLValuesFunction( IN_BUFFER( bufSize ) const BYTE *buffer, 
								   IN_LENGTH_SHORT_MIN( 32 ) const int bufSize, 
								   OUT BIGNUM *value1, 
								   OUT BIGNUM *value2, 
								   const BIGNUM *maxRange,
								   IN_ENUM( CRYPT_FORMAT )  \
									const CRYPT_FORMAT_TYPE formatType )
	{
	STREAM stream;
	int status;

	assert( isReadPtr( buffer, bufSize ) );
	assert( isWritePtr( value1, sizeof( BIGNUM ) ) );
	assert( isWritePtr( value2, sizeof( BIGNUM ) ) );
	assert( isReadPtr( maxRange, sizeof( BIGNUM ) ) );

	REQUIRES( bufSize >= 32 && bufSize < MAX_INTLENGTH_SHORT );
	REQUIRES( formatType > CRYPT_FORMAT_NONE && \
			  formatType < CRYPT_FORMAT_LAST );

	sMemConnect( &stream, buffer, bufSize );

	/* Read the DL components from the buffer and make sure that they're 
	   valid, i.e. that they're in the range [1...maxRange - 1] */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			readSequence( &stream, NULL );
			status = readBignum( &stream, value1, DLPPARAM_MIN_R,
								 CRYPT_MAX_PKCSIZE, maxRange );
			if( cryptStatusOK( status ) )
				status = readBignum( &stream, value2, DLPPARAM_MIN_S,
									 CRYPT_MAX_PKCSIZE, maxRange );
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			status = readBignumInteger16Ubits( &stream, value1, DLPPARAM_MIN_R,
											   bytesToBits( CRYPT_MAX_PKCSIZE ),
											   maxRange );
			if( cryptStatusOK( status ) )
				status = readBignumInteger16Ubits( &stream, value2, DLPPARAM_MIN_S,
												   bytesToBits( CRYPT_MAX_PKCSIZE ),
												   maxRange );
			break;
#endif /* USE_PGP */
	
#ifdef USE_SSH
		case CRYPT_IFORMAT_SSH:
			status = extractBignum( value1, buffer, 20, DLPPARAM_MIN_R, 
									20, maxRange, FALSE );
			if( cryptStatusOK( status ) )
				status = extractBignum( value2, buffer + 20, 20, DLPPARAM_MIN_S, 
										20, maxRange, FALSE );
			break;
#endif /* USE_SSH */

		default:
			retIntError();
		}

	/* Clean up */
	sMemDisconnect( &stream );
	return( status );
	}

/****************************************************************************
*																			*
*							Context Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initKeyRead( INOUT CONTEXT_INFO *contextInfoPtr )
	{
	const CRYPT_ALGO_TYPE cryptAlgo = contextInfoPtr->capabilityInfo->cryptAlgo;
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES_V( contextInfoPtr->type == CONTEXT_PKC );

	/* Set the access method pointers */
	pkcInfo->calculateKeyIDFunction = calculateKeyID;
	if( isDlpAlgo( cryptAlgo ) )
		{
		pkcInfo->readPublicKeyFunction = readPublicKeyDlpFunction;
		pkcInfo->readPrivateKeyFunction = readPrivateKeyDlpFunction;
		pkcInfo->decodeDLValuesFunction = decodeDLValuesFunction;

		return;
		}
#ifdef USE_ECC
	if( isEccAlgo( cryptAlgo ) )
		{
		pkcInfo->readPublicKeyFunction = readPublicKeyEccFunction;
		pkcInfo->readPrivateKeyFunction = readPrivateKeyEccFunction;
		
		return;
		}
#endif /* USE_ECC */
	pkcInfo->readPublicKeyFunction = readPublicKeyRsaFunction;
	pkcInfo->readPrivateKeyFunction = readPrivateKeyRsaFunction;
	}
#else

STDC_NONNULL_ARG( ( 1 ) ) \
void initKeyRead( INOUT CONTEXT_INFO *contextInfoPtr )
	{
	}
#endif /* USE_PKC */
