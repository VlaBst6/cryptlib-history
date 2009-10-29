/****************************************************************************
*																			*
*						Public/Private Key Read Routines					*
*						Copyright Peter Gutmann 1992-2009					*
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
	readGenericHole( stream, NULL, 8 + MIN_PKCSIZE_THRESHOLD + RSAPARAM_MIN_E, 
					 DEFAULT_TAG );
	status = readAlgoID( stream, &cryptAlgo, ALGOID_CLASS_PKC );
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

	/* Read the BIT STRING encapsulation and the public key fields */
	readBitStringHole( stream, NULL, MIN_PKCSIZE_THRESHOLD, DEFAULT_TAG );
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

	/* Read the SubjectPublicKeyInfo header field and make sure that the DLP 
	   parameter data is present */
	readGenericHole( stream, NULL, 
					 8 + MIN_PKCSIZE_THRESHOLD + DLPPARAM_MIN_G + \
						DLPPARAM_MIN_Q, DEFAULT_TAG );
	status = readAlgoIDparams( stream, &cryptAlgo, &extraLength, 
							   ALGOID_CLASS_PKC );
	if( cryptStatusError( status ) )
		return( status );
	if( extraLength <= 0 )
		return( CRYPT_ERROR_BADDATA );
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
		status = readBignum( stream, &dlpKey->dlpParam_g, DLPPARAM_MIN_G, 
							 DLPPARAM_MAX_G, &dlpKey->dlpParam_p );
		if( cryptStatusOK( status ) )
			status = readBignum( stream, &dlpKey->dlpParam_q, DLPPARAM_MIN_Q, 
								 DLPPARAM_MAX_Q, &dlpKey->dlpParam_p );
		}
	else
		{
		status = readBignum( stream, &dlpKey->dlpParam_q, DLPPARAM_MIN_Q, 
							 DLPPARAM_MAX_Q, &dlpKey->dlpParam_p );
		if( cryptStatusOK( status ) )
			status = readBignum( stream, &dlpKey->dlpParam_g, DLPPARAM_MIN_G, 
								 DLPPARAM_MAX_G, &dlpKey->dlpParam_p );
		}
	if( cryptStatusError( status ) )
		return( status );

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

	/* Read the BIT STRING encapsulation and the public key fields */
	readBitStringHole( stream, NULL, MIN_PKCSIZE_THRESHOLD, DEFAULT_TAG );
	return( readBignumChecked( stream, &dlpKey->dlpParam_y,
							   DLPPARAM_MIN_Y, DLPPARAM_MAX_Y,
							   &dlpKey->dlpParam_p ) );
	}

#ifdef USE_ECC

static const OID_INFO FAR_BSS eccOIDinfo[] = {
	/* NIST P-192, X9.62 p192r1, SECG p192r1, 1 2 840 10045 3 1 1 */
	{ MKOID( "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x01" ), CRYPT_ECCCURVE_P192 },
	/* NIST P-224, X9.62 P224r1, SECG p224r1, 1 3 132 0 33 */
	{ MKOID( "\x06\x05\x2B\x81\x04\x00\x21" ), CRYPT_ECCCURVE_P224 },
	/* NIST P-256, X9.62 p256r1, SECG p256r1, 1 2 840 10045 3 1 7 */
	{ MKOID( "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07" ), CRYPT_ECCCURVE_P256 },
	/* NIST P-384, SECG p384r1, 1 3 132 0 34 */
	{ MKOID( "\x06\x05\x2B\x81\x04\x00\x22" ), CRYPT_ECCCURVE_P384 },
	/* NIST P-521, SECG p521r1, 1 3 132 0 35 */
	{ MKOID( "\x06\x05\x2B\x81\x04\x00\x23" ), CRYPT_ECCCURVE_P521 },
	{ NULL, 0 }, { NULL, 0 }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getECCOidTbl( OUT const OID_INFO **oidTblPtr,
				  OUT_INT_Z int *noOidTblEntries )
	{
	assert( isReadPtr( oidTblPtr, sizeof( OID_INFO * ) ) );
	assert( isWritePtr( noOidTblEntries, sizeof( int ) ) );

	*oidTblPtr = eccOIDinfo;
	*noOidTblEntries = FAILSAFE_ARRAYSIZE( eccOIDinfo, OID_INFO );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readEccSubjectPublicKey( INOUT STREAM *stream, 
									INOUT CONTEXT_INFO *contextInfoPtr,
									OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	CRYPT_ALGO_TYPE cryptAlgo;
	BYTE buffer[ MAX_PKCSIZE_ECCPOINT + 8 ];
	const OID_INFO *oidTbl;
	int oidTblSize, fieldSize = DUMMY_INIT, selectionID = DUMMY_INIT;
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ECDSA );

	/* Clear return value */
	*actionFlags = ACTION_PERM_NONE;

	/* Read the SubjectPublicKeyInfo header field and make sure that the ECC 
	   parameter data is present.  Because of the more or less arbitrary 
	   manner in which these parameters can be represented we have to be 
	   fairly open-ended in terms of the data size limits that we use, and 
	   in particular for named curves the lower bound is the size of a 
	   single OID that defines the curve */
	readGenericHole( stream, NULL, 
					 8 + MIN_OID_SIZE + MIN_PKCSIZE_ECCPOINT_THRESHOLD, 
					 DEFAULT_TAG );
	status = readAlgoIDparams( stream, &cryptAlgo, &length, 
							   ALGOID_CLASS_PKC );
	if( cryptStatusError( status ) )
		return( status );
	if( length < MIN_OID_SIZE || \
		contextInfoPtr->capabilityInfo->cryptAlgo != cryptAlgo )
		return( CRYPT_ERROR_BADDATA );

	/* Now things get messy, since the ECC standards authors carefully 
	   sidestepped having to make a decision about anything and instead
	   just created an open framework into which it's possible to drop
	   almost anything.  To keep things sane we require the use of named
	   curves (which most people seem to use) over a prime field */
	status = getECCOidTbl( &oidTbl, &oidTblSize );
	if( cryptStatusOK( status ) )
		status = readOID( stream, oidTbl, oidTblSize, &selectionID );
	if( cryptStatusOK( status ) )
		status = getECCFieldSize( selectionID, &fieldSize );
	if( cryptStatusError( status ) )
		return( status );
	eccKey->curveType = selectionID;

	/* Set the maximum permitted actions.  Because of the special-case data 
	   formatting requirements for ECC algorithms (which are a part of the 
	   DLP algorithm family) we make the usage internal-only.  If the key is 
	   a pure public key rather than merely the public portions of a private 
	   key the actions will be restricted by higher-level code to signature-
	   check only */
	*actionFlags = MK_ACTION_PERM( MESSAGE_CTX_SIGN, \
								   ACTION_PERM_NONE_EXTERNAL ) | \
				   MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, \
								   ACTION_PERM_NONE_EXTERNAL );

	/* Read the BIT STRING encapsulation and the public key fields.  Instead 
	   of encoding the necessary information as an obvious OID + SEQUENCE 
	   combination for the parameters it's all stuffed into an ad-hoc BIT 
	   STRING that we have to pick apart manually.  Note that we can't use 
	   the ECC p value for a range check because it hasn't been set yet, all 
	   that we have at this point is a curve ID */
	status = readBitStringHole( stream, &length, 
								MIN_PKCSIZE_ECCPOINT_THRESHOLD, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	if( length < MIN_PKCSIZE_ECCPOINT_THRESHOLD || \
		length > MAX_PKCSIZE_ECCPOINT )
		return( CRYPT_ERROR_BADDATA );
	status = sread( stream, buffer, length );
	if( cryptStatusError( status ) )
		return( status );
	status = importECCPoint( &eccKey->eccParam_qx, &eccKey->eccParam_qy,
							 buffer, length, MIN_PKCSIZE_ECC_THRESHOLD, 
							 CRYPT_MAX_PKCSIZE_ECC, fieldSize, NULL, 
							 SHORTKEY_CHECK_ECC );
	zeroise( buffer, length );
	return( status );
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

	DH:
		uint16		dh_pLen
		byte[]		dh_p
		uint16		dh_gLen
		byte[]		dh_g
	  [	uint16		dh_YsLen ]
	  [	byte[]		dh_Ys	 ]

	ECDH:
		byte		curveType
		uint16		namedCurve
	  [	uint8		ecPointLen	-- NB uint8 not uint16 ]
	  [	byte[]		ecPoint ]

   The DH y value is nominally attached to the DH p and g values but isn't 
   processed at this level since this is a pure PKCS #3 DH key and not a 
   generic DLP key.  The same holds for the ECDH Q value */

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

#ifdef USE_ECC

static const MAP_TABLE sslCurveInfo[] = {
	{ 19, CRYPT_ECCCURVE_P192 },
	{ 21, CRYPT_ECCCURVE_P224 },
	{ 23, CRYPT_ECCCURVE_P256 },
	{ 24, CRYPT_ECCCURVE_P384 },
	{ 25, CRYPT_ECCCURVE_P521 },
	{ CRYPT_ERROR, 0 }, 
		{ CRYPT_ERROR, 0 }
	};

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int getECCSslInfoTbl( OUT const MAP_TABLE **sslInfoTblPtr,
							 OUT_INT_Z int *noSslInfoTblEntries )
	{
	assert( isReadPtr( sslInfoTblPtr, sizeof( MAP_TABLE * ) ) );
	assert( isWritePtr( noSslInfoTblEntries, sizeof( int ) ) );

	*sslInfoTblPtr = sslCurveInfo;
	*noSslInfoTblEntries = FAILSAFE_ARRAYSIZE( sslCurveInfo, MAP_TABLE );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
static int readSslEccPublicKey( INOUT STREAM *stream, 
								INOUT CONTEXT_INFO *contextInfoPtr,
								OUT_FLAGS_Z( ACTION_PERM ) int *actionFlags )
	{
	PKC_INFO *eccKey = contextInfoPtr->ctxPKC;
	const MAP_TABLE *sslCurveInfoPtr;
	int value, curveID, sslCurveInfoNoEntries, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( actionFlags, sizeof( int ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ECDH );

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
	status = value = sgetc( stream );
	if( cryptStatusError( status ) )
		return( status );
	if( value != 0x03 )		/* NamedCurve */
		return( CRYPT_ERROR_BADDATA );
	status = value = readUint16( stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Look up the curve ID based on the SSL NamedCurve ID */
	status = getECCSslInfoTbl( &sslCurveInfoPtr, &sslCurveInfoNoEntries );
	if( cryptStatusError( status ) )
		return( status );
	status = mapValue( value, &curveID, sslCurveInfoPtr, 
					   sslCurveInfoNoEntries );
	if( cryptStatusError( status ) )
		return( status );
	eccKey->curveType = curveID;
	return( CRYPT_OK );
	}
#endif /* USE_ECC */

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

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int completePubkeyRead( INOUT CONTEXT_INFO *contextInfoPtr,
							   IN_FLAGS( ACTION_PERM ) const int actionFlags )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( actionFlags > ACTION_PERM_FLAG_NONE && \
			  actionFlags < ACTION_PERM_FLAG_MAX );

	/* If it's statically-initialised context data used in the self-test 
	   there's no corresponding cryptlib object and we're done */
	if( contextInfoPtr->flags & CONTEXT_FLAG_STATICCONTEXT )
		return( CRYPT_OK );

	/* Set the action permissions for the context */
	return( krnlSendMessage( contextInfoPtr->objectHandle, 
							 IMESSAGE_SETATTRIBUTE, ( void * ) &actionFlags, 
							 CRYPT_IATTRIBUTE_ACTIONPERMS ) );
	}

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
	return( completePubkeyRead( contextInfoPtr, actionFlags ) );
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
	return( completePubkeyRead( contextInfoPtr, actionFlags ) );
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
			  ( contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ECDSA || \
				contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ECDH ) );
	REQUIRES( formatType == KEYFORMAT_CERT || formatType == KEYFORMAT_SSL );

	switch( formatType )
		{
		case KEYFORMAT_CERT:
			status = readEccSubjectPublicKey( stream, contextInfoPtr, 
											  &actionFlags );
			break;

#ifdef USE_SSL
		case KEYFORMAT_SSL:
			status = readSslEccPublicKey( stream, contextInfoPtr, 
										  &actionFlags );
			break;
#endif /* USE_SSL */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );
	return( completePubkeyRead( contextInfoPtr, actionFlags ) );
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
	PKC_INFO *eccKey = contextInfoPtr->ctxPKC;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );

	REQUIRES( contextInfoPtr->type == CONTEXT_PKC && \
			  contextInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_ECDSA );

	/* Read the key components.  Note that we can't use the ECC p value for
	   a range check because it hasn't been set yet, all that we have at 
	   this point is a curve ID */
	return( readBignum( stream, &eccKey->eccParam_d,
						ECCPARAM_MIN_D, ECCPARAM_MAX_D, NULL ) );
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
	   valid, i.e. that they're in the range [1...maxRange - 1] (the lower
	   bound is actually DLPPARAM_MIN_SIG_x and not 1, which is > 100 bits).  
	   Although nominally intended for DLP algorithms the DLPPARAM_MIN_SIG_x 
	   values also work for ECC ones since they're also in the DLP family */
	switch( formatType )
		{
		case CRYPT_FORMAT_CRYPTLIB:
			readSequence( &stream, NULL );
			status = readBignum( &stream, value1, DLPPARAM_MIN_SIG_R,
								 CRYPT_MAX_PKCSIZE, maxRange );
			if( cryptStatusError( status ) )
				break;
			status = readBignum( &stream, value2, DLPPARAM_MIN_SIG_S,
								 CRYPT_MAX_PKCSIZE, maxRange );
			break;

#ifdef USE_PGP
		case CRYPT_FORMAT_PGP:
			status = readBignumInteger16Ubits( &stream, value1, 
											   DLPPARAM_MIN_SIG_R,
											   bytesToBits( CRYPT_MAX_PKCSIZE ),
											   maxRange );
			if( cryptStatusError( status ) )
				break;
			status = readBignumInteger16Ubits( &stream, value2, 
											   DLPPARAM_MIN_SIG_S,
											   bytesToBits( CRYPT_MAX_PKCSIZE ),
											   maxRange );
			break;
#endif /* USE_PGP */
	
#ifdef USE_SSH
		case CRYPT_IFORMAT_SSH:
			status = importBignum( value1, buffer, 20, DLPPARAM_MIN_SIG_R, 
								   20, maxRange, SHORTKEY_CHECK_NONE );
			if( cryptStatusError( status ) )
				break;
			status = importBignum( value2, buffer + 20, 20, DLPPARAM_MIN_SIG_S, 
								   20, maxRange, SHORTKEY_CHECK_NONE );
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
		pkcInfo->decodeDLValuesFunction = decodeDLValuesFunction;
		
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
