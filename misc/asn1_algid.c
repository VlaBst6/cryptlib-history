/****************************************************************************
*																			*
*						ASN.1 Algorithm Identifier Routines					*
*						Copyright Peter Gutmann 1992-2008					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Object/Algorithm Identifier Routines				*
*																			*
****************************************************************************/

/* Pull in the AlgorithmIdentifier OID table */

#if defined( INC_ALL )
  #include "asn1_oids.h"
#else
  #include "misc/asn1_oids.h"
#endif /* Compiler-specific includes */

/* Map an OID to an algorithm type.  The parameter value can be NULL if no
   sub-algorithm is expected, but we return an error code if the OID has a
   sub-algorithm type present */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
static int oidToAlgorithm( IN_BUFFER( oidLength ) const BYTE *oid, 
						   IN_RANGE( 1, MAX_OID_SIZE ) const int oidLength, 
						   OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
						   OUT_OPT_INT_Z int *parameter )
	{
	BYTE oidByte;
	int i;

	assert( isReadPtr( oid, oidLength ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( parameter == NULL || isWritePtr( parameter, sizeof( int ) ) );

	REQUIRES( oidLength >= MIN_OID_SIZE && oidLength <= MAX_OID_SIZE );

	/* Clear return values */
	*cryptAlgo = CRYPT_ALGO_NONE;
	if( parameter != NULL )
		*parameter = 0;

	/* If the OID is shorter than the minimum possible algorithm OID value, 
	   don't try and process it */
	if( oidLength < 7 )
		return( CRYPT_ERROR_BADDATA );
	oidByte = oid[ 6 ];

	/* Look for a matching OID.  For quick-reject matching we check the byte
	   furthest inside the OID that's likely to not match (large groups of 
	   OIDs have common prefixes due to being in the same arc), this rejects 
	   the majority of mismatches without requiring a full comparison */
	for( i = 0; algoIDinfoTbl[ i ].algorithm != CRYPT_ALGO_NONE && \
				i < FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO ); i++ )
		{
		const ALGOID_INFO *algoIDinfoPtr = &algoIDinfoTbl[ i ];

		if( sizeofOID( algoIDinfoPtr->oid ) == oidLength && \
			algoIDinfoPtr->oid[ 6 ] == oidByte && \
			!memcmp( algoIDinfoPtr->oid, oid, oidLength ) )
			{
			/* If we're expecting a sub-algorithm, return the sub-algorithm
			   type alongside the main algorithm type */
			if( parameter != NULL )
				{
				*cryptAlgo = algoIDinfoPtr->algorithm;
				*parameter = algoIDinfoPtr->parameter;
				return( CRYPT_OK );
				}

			/* If we're not expecting a sub-algorithm but there's one
			   present, mark it as an error */
			if( algoIDinfoPtr->parameter != CRYPT_ALGO_NONE )
				return( CRYPT_ERROR_BADDATA );

			*cryptAlgo = algoIDinfoPtr->algorithm;
			return( CRYPT_OK );
			}
		}
	ENSURES( i < FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO ) );

	/* No algorithm for this OID found */
	return( CRYPT_ERROR_NOTAVAIL );
	}

/* Map an algorithm and optional sub-algorithm/mode to an OID.  These
   functions are almost identical, the only difference is that the one used
   for checking only doesn't throw an exception when it encounters an
   algorithm value that it can't encode as an OID */

CHECK_RETVAL_PTR \
static const BYTE *algorithmToOID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
								   IN_RANGE( 0, 999 ) const int parameter )
	{
	int i;

	REQUIRES_N( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST );
	REQUIRES_N( parameter >= 0 && parameter <= 999 );

	for( i = 0; algoIDinfoTbl[ i ].algorithm != CRYPT_ALGO_NONE && \
				i < FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO ); i++ )
		{
		if( algoIDinfoTbl[ i ].algorithm == cryptAlgo )
			break;
		}
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO ) );
	while( algoIDinfoTbl[ i ].algorithm == cryptAlgo && \
		   i < FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO ) )
		{
		if( algoIDinfoTbl[ i ].parameter == parameter )
			return( algoIDinfoTbl[ i ].oid );
		i++;
		}
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO ) );

	retIntError_Null();
	}

CHECK_RETVAL_PTR \
static const BYTE *algorithmToOIDcheck( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
										IN_RANGE( 0, 999 ) const int parameter )
	{
	int i;

	REQUIRES_N( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST );
	REQUIRES_N( parameter >= 0 && parameter <= 999 );

	for( i = 0; algoIDinfoTbl[ i ].algorithm != CRYPT_ALGO_NONE && \
				i < FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO ); i++ )
		{
		if( algoIDinfoTbl[ i ].algorithm == cryptAlgo )
			break;
		}
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO ) );
	while( algoIDinfoTbl[ i ].algorithm == cryptAlgo && \
		   i < FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO ) )
		{
		if( algoIDinfoTbl[ i ].parameter == parameter )
			return( algoIDinfoTbl[ i ].oid );
		i++;
		}
	ENSURES_N( i < FAILSAFE_ARRAYSIZE( algoIDinfoTbl, ALGOID_INFO ) );

	return( NULL );
	}

/* Read the start of an AlgorithmIdentifier record, used by a number of
   routines.  'parameter' can be either a CRYPT_ALGO_TYPE or a 
   CRYPT_MODE_TYPE, which is why it's given as a generic integer rather than 
   a more specific type */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readAlgoIDheader( INOUT STREAM *stream, 
							 OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
							 OUT_OPT_RANGE( 0, 999 ) int *parameter, 
							 OUT_OPT_LENGTH_SHORT_Z int *extraLength, 
							 IN_TAG const int tag )
	{
	CRYPT_ALGO_TYPE localCryptAlgo;
	BYTE oidBuffer[ MAX_OID_SIZE + 8 ];
	int oidLength, algoParam, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( parameter == NULL || \
			isWritePtr( parameter, sizeof( int ) ) );
	assert( extraLength == NULL || \
			isWritePtr( extraLength, sizeof( int ) ) );

	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );
	
	/* Clear the return values */
	*cryptAlgo = CRYPT_ALGO_NONE;
	if( parameter != NULL )
		*parameter = 0;
	if( extraLength != NULL )
		*extraLength = 0;

	/* Determine the algorithm information based on the AlgorithmIdentifier
	   field */
	if( tag == DEFAULT_TAG )
		readSequence( stream, &length );
	else
		readConstructed( stream, &length, tag );
	status = readEncodedOID( stream, oidBuffer, MAX_OID_SIZE, &oidLength, 
							 BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	length -= oidLength;
	if( oidLength != sizeofOID( oidBuffer ) || \
		length < 0 || length >= MAX_INTLENGTH_SHORT )
		{
		/* It's a stream-related error, make it persistent */
		return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		}
	status = oidToAlgorithm( oidBuffer, oidLength, &localCryptAlgo, 
							 &algoParam );
	if( cryptStatusError( status ) )
		return( status );
	*cryptAlgo = localCryptAlgo;
	if( parameter != NULL )
		*parameter = algoParam;

	/* If the caller has specified that there should be no parameters 
	   present, make sure that there's either no data or an ASN.1 NULL
	   present and nothing else */
	if( extraLength == NULL )
		return( ( length > 0 ) ? readNull( stream ) : CRYPT_OK );

	/* If the parameters are null parameters, check them and exit */
	if( length == sizeofNull() )
		return( readNull( stream ) );

	/* Handle any remaining parameters */
	*extraLength = ( int ) length;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					EncryptionAlgorithmIdentifier Routines					*
*																			*
****************************************************************************/

/* EncryptionAlgorithmIdentifier parameters:

	aesXcbc, aesXofb: AES FIPS

		iv				OCTET STRING SIZE (16)

	aesXcfb: AES FIPS

		SEQUENCE {
			iv			OCTET STRING SIZE (16),
			noOfBits	INTEGER (128)
			}

	cast5cbc: RFC 2144
		SEQUENCE {
			iv			OCTET STRING DEFAULT 0,
			keyLen		INTEGER (128)
			}

	blowfishCBC, desCBC, desEDE3-CBC: Blowfish RFC/OIW
		iv				OCTET STRING SIZE (8)

	blowfishCFB, blowfishOFB, desCFB, desOFB: Blowfish RFC/OIW
		SEQUENCE {
			iv			OCTET STRING SIZE (8),
			noBits		INTEGER (64)
			}

	ideaCBC: Ascom Tech
		SEQUENCE {
			iv			OCTET STRING OPTIONAL
			}

	ideaCFB: Ascom Tech
		SEQUENCE {
			r	  [ 0 ]	INTEGER DEFAULT 64,
			k	  [ 1 ]	INTEGER DEFAULT 64,
			j	  [ 2 ]	INTEGER DEFAULT 64,
			iv	  [ 3 ]	OCTET STRING OPTIONAL
			}

	ideaOFB: Ascom Tech
		SEQUENCE {
			j			INTEGER DEFAULT 64,
			iv			OCTET STRING OPTIONAL
			}

	rc2CBC: RFC 2311
		SEQUENCE {
			rc2Param	INTEGER (58),	-- 128 bit key
			iv			OCTET STRING SIZE (8)
			}

	rc4: (Unsure where this one is from)
		NULL

	rc5: RFC 2040
		SEQUENCE {
			version		INTEGER (16),
			rounds		INTEGER (12),
			blockSize	INTEGER (64),
			iv			OCTET STRING OPTIONAL
			}

	skipjackCBC: SDN.701
		SEQUENCE {
			iv			OCTET STRING
			}

   Because of the somewhat haphazard nature of encryption
   AlgorithmIdentifier definitions we can only handle the following
   algorithm/mode combinations:

	AES ECB, CBC, CFB, OFB
	Blowfish ECB, CBC, CFB, OFB
	CAST128 CBC
	DES ECB, CBC, CFB, OFB
	3DES ECB, CBC, CFB, OFB
	IDEA ECB, CBC, CFB, OFB
	RC2 ECB, CBC
	RC4
	RC5 CBC
	Skipjack CBC */

/* Magic value to denote 128-bit RC2 keys */

#define RC2_KEYSIZE_MAGIC		58

/* Read an EncryptionAlgorithmIdentifier/DigestAlgorithmIdentifier */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readAlgoIDInfo( INOUT STREAM *stream, 
						   INOUT QUERY_INFO *queryInfo,
						   IN_TAG const int tag )
	{
	int mode, length, status;	/* 'mode' must be type integer */

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );

	/* Read the AlgorithmIdentifier header and OID */
	status = readAlgoIDheader( stream, &queryInfo->cryptAlgo, &mode,
							   &length, tag );
	if( cryptStatusError( status ) )
		return( status );
	queryInfo->cryptMode = mode;	/* CRYPT_MODE_TYPE vs. integer */

	/* Some broken implementations use sign + hash algoIDs in places where
	   a hash algoID is called for, if we find one of these we modify the
	   read AlgorithmIdentifier information to make it look like a hash
	   algoID */
	if( ( queryInfo->cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
		  queryInfo->cryptAlgo <= CRYPT_ALGO_LAST_PKC ) && \
		( queryInfo->cryptMode >= CRYPT_ALGO_FIRST_HASH && \
		  queryInfo->cryptMode <= CRYPT_ALGO_LAST_HASH ) )
		{
		queryInfo->cryptAlgo = ( CRYPT_ALGO_TYPE ) queryInfo->cryptMode;
		queryInfo->cryptMode = CRYPT_MODE_NONE;
		}

	/* Hash algorithms will either have NULL parameters or none at all
	   depending on which interpretation of which standard the sender used
	   so if it's not a conventional encryption algorithm we process the
	   NULL if required and return */
	if( ( queryInfo->cryptAlgo >= CRYPT_ALGO_FIRST_HASH && \
		  queryInfo->cryptAlgo <= CRYPT_ALGO_LAST_HASH ) || \
		( queryInfo->cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
		  queryInfo->cryptAlgo <= CRYPT_ALGO_LAST_MAC ) )
		return( ( length > 0 ) ? readNull( stream ) : CRYPT_OK );

	/* If it's not a hash/MAC algorithm it has to be a conventional
	   encryption algorithm */
	if( queryInfo->cryptAlgo < CRYPT_ALGO_FIRST_CONVENTIONAL || \
		queryInfo->cryptAlgo > CRYPT_ALGO_LAST_CONVENTIONAL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Read the algorithm-specific parameters.  In theory we should do
	   something with some of the values like the IV size parameter, but
	   since the standard never explains what to do if it's something other
	   than the algorithm block size (Left pad? Right pad? Sign-extend?
	   Repeat the data?) it's safer not to do anything ("Never check for an
	   error that you don't know how to handle").  In any case there are no
	   known cases of these strange values ever being used (probably because
	   all existing software would break) so we make sure that they're 
	   present but otherwise ignore them */
	switch( queryInfo->cryptAlgo )
		{
		case CRYPT_ALGO_3DES:
		case CRYPT_ALGO_AES:
		case CRYPT_ALGO_BLOWFISH:
		case CRYPT_ALGO_DES:
			if( queryInfo->cryptMode == CRYPT_MODE_ECB )
				{
				/* The NULL parameter has already been read in
				   readAlgoIDheader() */
				return( CRYPT_OK );
				}
			if( ( queryInfo->cryptMode == CRYPT_MODE_CBC ) || \
				( queryInfo->cryptAlgo == CRYPT_ALGO_AES && \
				  queryInfo->cryptMode == CRYPT_MODE_OFB ) )
				{
				return( readOctetString( stream, queryInfo->iv,
								&queryInfo->ivLength,
								( queryInfo->cryptAlgo == CRYPT_ALGO_AES ) ? \
									16 : 8, CRYPT_MAX_IVSIZE ) );
				}
			readSequence( stream, NULL );
			readOctetString( stream, queryInfo->iv, &queryInfo->ivLength,
							 8, CRYPT_MAX_IVSIZE );
			return( readShortInteger( stream, NULL ) );

#ifdef USE_CAST
		case CRYPT_ALGO_CAST:
			readSequence( stream, NULL );
			readOctetString( stream, queryInfo->iv, &queryInfo->ivLength,
							 8, CRYPT_MAX_IVSIZE );
			return( readShortInteger( stream, NULL ) );
#endif /* USE_CAST */

#ifdef USE_IDEA
		case CRYPT_ALGO_IDEA:
			{
			int paramTag;

			if( queryInfo->cryptMode == CRYPT_MODE_ECB )
				{
				/* The NULL parameter has already been read in
				   readAlgoIDheader() */
				return( CRYPT_OK );
				}
			status = readSequence( stream, NULL );
			if( cryptStatusError( status ) )
				return( status );
			paramTag = peekTag( stream );
			if( cryptStatusError( paramTag ) )
				return( paramTag );
			if( queryInfo->cryptMode == CRYPT_MODE_CFB )
				{
				int itemsProcessed;
				
				/* Skip the CFB r, k, and j parameters */
				for( itemsProcessed = 0;
					 ( paramTag == MAKE_CTAG_PRIMITIVE( 0 ) || \
					   paramTag == MAKE_CTAG_PRIMITIVE( 1 ) || \
					    paramTag == MAKE_CTAG_PRIMITIVE( 2 ) ) && \
					 itemsProcessed < 4; itemsProcessed++ )
					{
					long value;

					status = readShortIntegerTag( stream, &value, paramTag );
					if( cryptStatusError( status ) )
						return( status );
					if( value != 64 )
						return( CRYPT_ERROR_NOTAVAIL );
					paramTag = peekTag( stream );
					if( cryptStatusError( paramTag ) )
						return( paramTag );
					}
				if( itemsProcessed >= 4 )
					return( CRYPT_ERROR_BADDATA );
				return( readOctetStringTag( stream, queryInfo->iv,
											&queryInfo->ivLength,
											8, CRYPT_MAX_IVSIZE, 3 ) );
				}
			if( queryInfo->cryptMode == CRYPT_MODE_OFB && \
				paramTag == BER_INTEGER )
				{
				long value;

				/* Skip the OFB j parameter */
				status = readShortInteger( stream, &value );
				if( cryptStatusError( status ) )
					return( status );
				if( value != 64 )
					return( CRYPT_ERROR_NOTAVAIL );
				}
			return( readOctetString( stream, queryInfo->iv,
									 &queryInfo->ivLength,
									 8, CRYPT_MAX_IVSIZE ) );
			}
#endif /* USE_CAST */

#ifdef USE_RC2
		case CRYPT_ALGO_RC2:
			/* In theory we should check that the parameter value ==
			   RC2_KEYSIZE_MAGIC (corresponding to a 128-bit key) but in
			   practice this doesn't really matter, we just use whatever we
			   find inside the PKCS #1 padding */
			readSequence( stream, NULL );
			if( queryInfo->cryptMode != CRYPT_MODE_CBC )
				return( readShortInteger( stream, NULL ) );
			readShortInteger( stream, NULL );
			return( readOctetString( stream, queryInfo->iv,
									 &queryInfo->ivLength,
									 8, CRYPT_MAX_IVSIZE ) );
#endif /* USE_RC2 */

#ifdef USE_RC4
		case CRYPT_ALGO_RC4:
			/* The NULL parameter has already been read in
			   readAlgoIDheader() */
			return( CRYPT_OK );
#endif /* USE_RC4 */

#ifdef USE_RC5
		case CRYPT_ALGO_RC5:
			{
			long val1, val2, val3;

			readSequence( stream, NULL );
			readShortInteger( stream, &val1 );			/* Version */
			readShortInteger( stream, &val2 );			/* Rounds */
			status = readShortInteger( stream, &val3 );	/* Block size */
			if( cryptStatusError( status ) )
				return( status );
			if( val1 != 16 || val2 != 12 || val3 != 64 )
				{
				/* This algorithm makes enough of a feature of its variable
				   parameters that we do actually check to make sure that
				   they're sensible since it may just be possible that 
				   someone playing with an implementation decides to use
				   weird values */
				return( CRYPT_ERROR_NOTAVAIL );
				}
			return( readOctetString( stream, queryInfo->iv,
									 &queryInfo->ivLength,
									 8, CRYPT_MAX_IVSIZE ) );
			}
#endif /* USE_RC5 */

#ifdef USE_SKIPJACK
		case CRYPT_ALGO_SKIPJACK:
			readSequence( stream, NULL );
			return( readOctetString( stream, queryInfo->iv,
									 &queryInfo->ivLength,
									 8, CRYPT_MAX_IVSIZE ) );
#endif /* USE_SKIPJACK */
		}

	retIntError();
	}

/* Get the size of an EncryptionAlgorithmIdentifier record */

CHECK_RETVAL \
int sizeofCryptContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	STREAM nullStream;
	int status;

	REQUIRES( isHandleRangeValid( iCryptContext ) );

	/* Determine how large the algoID and associated parameters are.  
	   Because this is a rather complex operation the easiest way to do it 
	   is to write to a null stream and get its size */
	sMemNullOpen( &nullStream );
	status = writeCryptContextAlgoID( &nullStream, iCryptContext );
	if( cryptStatusOK( status ) )
		status = stell( &nullStream );
	sMemClose( &nullStream );
	return( status );
	}

/* Write an EncryptionAlgorithmIdentifier record */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCryptContextAlgoID( INOUT STREAM *stream,
							 IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	const BYTE *oid;
	BYTE iv[ CRYPT_MAX_IVSIZE + 8 ];
	CRYPT_ALGO_TYPE cryptAlgo;
	CRYPT_MODE_TYPE cryptMode = DUMMY_INIT;
	int oidSize, ivSize = 0, sizeofIV = 0, paramSize, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isHandleRangeValid( iCryptContext ) );

	/* Extract the information that we need to write the
	   AlgorithmIdentifier */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
								  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) && !isStreamCipher( cryptAlgo ) && \
		needsIV( cryptMode ) )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, iv, CRYPT_MAX_IVSIZE );
		status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_IV );
		if( cryptStatusOK( status ) )
			{
			ivSize = msgData.length;
			sizeofIV = ( int ) sizeofObject( ivSize );
			}
		}
	if( cryptStatusError( status ) )
		{
		assert( DEBUG_WARN );
		return( status );
		}

	ENSURES_S( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
			   cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL );

	/* Get the OID for this algorithm */
	if( ( oid = algorithmToOIDcheck( cryptAlgo, cryptMode ) ) == NULL )
		{
		/* Some algorithm+mode combinations can't be encoded using the
		   available PKCS #7 OIDs, the best that we can do in this case is
		   alert the user in debug mode and return a CRYPT_ERROR_NOTAVAIL */
		assert( DEBUG_WARN );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	oidSize = sizeofOID( oid );
	ENSURES_S( oidSize >= MIN_OID_SIZE && oidSize <= MAX_OID_SIZE );

	/* Write the algorithm-specific parameters */
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_3DES:
		case CRYPT_ALGO_AES:
		case CRYPT_ALGO_BLOWFISH:
		case CRYPT_ALGO_DES:
			{
			const int noBits = ( cryptAlgo == CRYPT_ALGO_AES ) ? 128 : 64;

			paramSize = \
				( cryptMode == CRYPT_MODE_ECB ) ? \
					sizeofNull() : \
				( ( cryptMode == CRYPT_MODE_CBC ) || \
				  ( cryptAlgo == CRYPT_ALGO_AES && cryptMode == CRYPT_MODE_OFB ) ) ? \
				  sizeofIV : \
				  ( int ) sizeofObject( sizeofIV + sizeofShortInteger( noBits ) );
			writeSequence( stream, oidSize + paramSize );
			if( cryptAlgo == CRYPT_ALGO_AES )
				{
				int keySize;

				/* AES uses a somewhat odd encoding in which the last byte
				   of the OID jumps in steps of 20 depending on the key
				   size, so we adjust the OID that we actually write based
				   on the key size.  It's somewhat unlikely that any
				   implementation actually cares about this since the size
				   information is always communicated anderswhere, but we do
				   it just in case */
				status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
										  &keySize, CRYPT_CTXINFO_KEYSIZE );
				if( cryptStatusError( status ) )
					return( status );
				swrite( stream, oid, oidSize - 1 );
				sputc( stream, oid[ oidSize - 1 ] + \
							   ( ( keySize == 16 ) ? 0 : \
								 ( keySize == 24 ) ? 20 : 40 ) );
				}
			else
				swrite( stream, oid, oidSize );
			if( cryptMode == CRYPT_MODE_ECB )
				return( writeNull( stream, DEFAULT_TAG ) );
			if( ( cryptMode == CRYPT_MODE_CBC ) || \
				( cryptAlgo == CRYPT_ALGO_AES && cryptMode == CRYPT_MODE_OFB ) )
				return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
			writeSequence( stream, sizeofIV + sizeofShortInteger( noBits ) );
			writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
			return( writeShortInteger( stream, noBits, DEFAULT_TAG ) );
			}

#ifdef USE_CAST
		case CRYPT_ALGO_CAST:
			paramSize = sizeofIV + sizeofShortInteger( 128 );
			writeSequence( stream, oidSize + \
								   ( int ) sizeofObject( paramSize ) );
			swrite( stream, oid, oidSize );
			writeSequence( stream, paramSize );
			writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
			return( writeShortInteger( stream, 128, DEFAULT_TAG ) );
#endif /* USE_CAST */

#ifdef USE_IDEA
		case CRYPT_ALGO_IDEA:
			paramSize = ( cryptMode == CRYPT_MODE_ECB ) ? \
						sizeofNull() : \
						( int ) sizeofObject( sizeofIV );
			writeSequence( stream, oidSize + paramSize );
			swrite( stream, oid, oidSize );
			if( cryptMode == CRYPT_MODE_ECB )
				return( writeNull( stream, DEFAULT_TAG ) );
			writeSequence( stream, sizeofIV );
			return( writeOctetString( stream, iv, ivSize, \
									  ( cryptMode == CRYPT_MODE_CFB ) ? \
										3 : DEFAULT_TAG ) );
#endif /* USE_IDEA */

#ifdef USE_RC2
		case CRYPT_ALGO_RC2:
			paramSize = ( ( cryptMode == CRYPT_MODE_ECB ) ? 0 : sizeofIV ) + \
						sizeofShortInteger( RC2_KEYSIZE_MAGIC );
			writeSequence( stream, oidSize + \
								   ( int ) sizeofObject( paramSize ) );
			swrite( stream, oid, oidSize );
			writeSequence( stream, paramSize );
			if( cryptMode != CRYPT_MODE_CBC )
				{
				return( writeShortInteger( stream, RC2_KEYSIZE_MAGIC,
										   DEFAULT_TAG ) );
				}
			writeShortInteger( stream, RC2_KEYSIZE_MAGIC, DEFAULT_TAG );
			return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
#endif /* USE_RC2 */

#ifdef USE_RC4
		case CRYPT_ALGO_RC4:
			writeSequence( stream, oidSize + sizeofNull() );
			swrite( stream, oid, oidSize );
			return( writeNull( stream, DEFAULT_TAG ) );
#endif /* USE_RC4 */

#ifdef USE_RC5
		case CRYPT_ALGO_RC5:
			paramSize = sizeofShortInteger( 16 ) + \
						sizeofShortInteger( 12 ) + \
						sizeofShortInteger( 64 ) + \
						sizeofIV;
			writeSequence( stream, oidSize + \
								   ( int ) sizeofObject( paramSize ) );
			swrite( stream, oid, oidSize );
			writeSequence( stream, paramSize );
			writeShortInteger( stream, 16, DEFAULT_TAG );	/* Version */
			writeShortInteger( stream, 12, DEFAULT_TAG );	/* Rounds */
			writeShortInteger( stream, 64, DEFAULT_TAG );	/* Block size */
			return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
#endif /* USE_RC5 */

#ifdef USE_SKIPJACK
		case CRYPT_ALGO_SKIPJACK:
			writeSequence( stream, oidSize + \
								   ( int ) sizeofObject( sizeofIV ) );
			swrite( stream, oid, oidSize );
			writeSequence( stream, sizeofIV );
			return( writeOctetString( stream, iv, ivSize, DEFAULT_TAG ) );
#endif /* USE_SKIPJACK */
		}

	retIntError();
	}

/****************************************************************************
*																			*
*							AlgorithmIdentifier Routines					*
*																			*
****************************************************************************/

/* Because AlgorithmIdentifiers are only defined for a subset of the
   algorithms that cryptlib supports we have to check that the algorithm
   and mode being used can be represented in encoded data before we try to
   do anything with it */

CHECK_RETVAL_BOOL \
BOOLEAN checkAlgoID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					 IN_MODE const CRYPT_MODE_TYPE cryptMode )
	{
	REQUIRES_B( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST );
	REQUIRES_B( cryptMode >= CRYPT_MODE_NONE && cryptMode < CRYPT_MODE_LAST );

	return( ( algorithmToOIDcheck( cryptAlgo, cryptMode ) != NULL ) ? \
			TRUE : FALSE );
	}

/* Determine the size of an AlgorithmIdentifier record */

CHECK_RETVAL \
int sizeofAlgoIDex( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					IN_RANGE( 0, 999 ) const int parameter, 
					IN_LENGTH_SHORT_Z const int extraLength )
	{
	const BYTE *oid = algorithmToOID( cryptAlgo, parameter );

	REQUIRES( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST );
	REQUIRES( parameter >= 0 && parameter <= 999 );
	REQUIRES( extraLength >= 0 && extraLength < MAX_INTLENGTH_SHORT );
	REQUIRES( oid != NULL );

	return( ( int ) sizeofObject( sizeofOID( oid ) + \
								  ( ( extraLength > 0 ) ? extraLength : \
														  sizeofNull() ) ) );
	}

CHECK_RETVAL \
int sizeofAlgoID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	REQUIRES( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST );

	return( sizeofAlgoIDex( cryptAlgo, CRYPT_ALGO_NONE, 0 ) );
	}

/* Write an AlgorithmIdentifier record */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeAlgoIDex( INOUT STREAM *stream, 
				   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
				   IN_RANGE( 0, 999 ) const int parameter, 
				   IN_LENGTH_SHORT_Z const int extraLength )
	{
	const BYTE *oid = algorithmToOID( cryptAlgo, parameter );
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST );
	REQUIRES_S( parameter >= 0 && parameter <= 999 );
	REQUIRES_S( extraLength >= 0 && extraLength < MAX_INTLENGTH_SHORT );
	REQUIRES_S( oid != NULL );

	/* Write the AlgorithmIdentifier field */
	writeSequence( stream, sizeofOID( oid ) + \
				   ( ( extraLength > 0 ) ? extraLength : sizeofNull() ) );
	status = swrite( stream, oid, sizeofOID( oid ) );
	if( extraLength > 0 )
		{
		/* Parameters will be written by the caller */
		return( status );
		}

	/* No extra parameters so we need to write a NULL */
	return( writeNull( stream, DEFAULT_TAG ) );
	}

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeAlgoID( INOUT STREAM *stream, 
				 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST );

	return( writeAlgoIDex( stream, cryptAlgo, CRYPT_ALGO_NONE, 0 ) );
	}

/* Read an AlgorithmIdentifier record.  There are three versions of 
   this:

	readAlgoID: Reads an algorithm, assumes that there are no secondary 
		algorithm or mode and algorithm parameters present and returns an 
		error if there are.

	readAlgoIDext: Reads an algorithm and secondary algorithm or mode, 
		assumes that there are no algorithm parameters present and returns 
		an error if there are.

	readAlgoIDparams: Reads an algorithm and the length of the extra 
		information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readAlgoID( INOUT STREAM *stream, 
				OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );

	return( readAlgoIDheader( stream, cryptAlgo, NULL, NULL, DEFAULT_TAG ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readAlgoIDext( INOUT STREAM *stream, 
				   OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo,
				   OUT_ALGO_Z CRYPT_ALGO_TYPE *altCryptAlgo )
	{
	int altAlgo, status;	/* 'altAlgo' must be type integer */

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtr( altCryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );

	/* Clear return value (the others are cleared by readAlgoIDheader()) */
	*altCryptAlgo = CRYPT_ALGO_NONE;

	status = readAlgoIDheader( stream, cryptAlgo, &altAlgo, NULL, 
							   DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		*altCryptAlgo = altAlgo;	/* CRYPT_MODE_TYPE vs. integer */
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readAlgoIDparams( INOUT STREAM *stream, 
					  OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo, 
					  OUT_LENGTH_SHORT_Z int *extraLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtr( extraLength, sizeof( int ) ) );

	return( readAlgoIDheader( stream, cryptAlgo, NULL, extraLength, 
							  DEFAULT_TAG ) );
	}

/* Determine the size of an AlgorithmIdentifier record from a context */

CHECK_RETVAL \
int sizeofContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						 IN_RANGE( 0, 999 ) const int parameter )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	int status;

	REQUIRES( isHandleRangeValid( iCryptContext ) );
	REQUIRES( parameter >= 0 && parameter <= 999 );

	/* Write the algoID only */
	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	return( sizeofAlgoIDex( cryptAlgo, parameter, 0 ) );
	}

/* Write an AlgorithmIdentifier record from a context */

RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeContextAlgoID( INOUT STREAM *stream, 
						IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						IN_RANGE( 0, 999 ) const int parameter )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	REQUIRES_S( isHandleRangeValid( iCryptContext ) );
	REQUIRES_S( parameter >= 0 && parameter <= 999 );

	status = krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	return( writeAlgoIDex( stream, cryptAlgo, parameter, 0 ) );
	}

/* Turn an AlgorithmIdentifier into a context */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int readContextAlgoID( INOUT STREAM *stream, 
					   OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
					   INOUT_OPT QUERY_INFO *queryInfo, 
					   IN_TAG const int tag )
	{
	QUERY_INFO localQueryInfo, *queryInfoPtr = queryInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( iCryptContext == NULL || \
			isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( queryInfo == NULL || \
			isWritePtr( queryInfo, sizeof( QUERY_INFO ) ) );

	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );

	/* Clear return value */
	if( iCryptContext != NULL )
		*iCryptContext = CRYPT_ERROR;

	/* If the user isn't interested in the algorithm details, use a local 
	   query structure to contain them */
	if( queryInfo == NULL )
		{
		memset( &localQueryInfo, 0, sizeof( localQueryInfo ) );
		queryInfoPtr = &localQueryInfo;
		}

	/* Read the algorithm info.  If we're not creating a context from the
	   info, we're done */
	status = readAlgoIDInfo( stream, queryInfoPtr, tag );
	if( cryptStatusError( status ) || iCryptContext == NULL )
		return( status );

	/* Create the object from it */
	setMessageCreateObjectInfo( &createInfo, queryInfoPtr->cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	if( queryInfoPtr->cryptAlgo > CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		/* If it's not a conventional encryption algorithm, we're done */
		*iCryptContext = createInfo.cryptHandle;
		return( CRYPT_OK );
		}
	ENSURES_S( queryInfoPtr->cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
			   queryInfoPtr->cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  &queryInfoPtr->cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) && \
		!isStreamCipher( queryInfoPtr->cryptAlgo ) )
		{
		int ivLength;

		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_GETATTRIBUTE, &ivLength,
								  CRYPT_CTXINFO_IVSIZE );
		if( cryptStatusOK( status ) )
			{
			MESSAGE_DATA msgData;

			setMessageData( &msgData, queryInfoPtr->iv,
							min( ivLength, queryInfoPtr->ivLength ) );
			status = krnlSendMessage( createInfo.cryptHandle,
									  IMESSAGE_SETATTRIBUTE_S, &msgData,
									  CRYPT_CTXINFO_IV );
			}
		}
	if( cryptStatusError( status ) )
		{
		/* If there's an error in the parameters stored with the key we'll
		   get an arg or attribute error when we try to set the attribute so
		   we translate it into an error code which is appropriate for the
		   situation.  In addition since this is (arguably) a stream format
		   error (the data read from the stream is invalid) we also set the
		   stream status */
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		if( cryptArgError( status ) )
			return( sSetError( stream, CRYPT_ERROR_BADDATA ) );
		return( status );
		}
	*iCryptContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/* Read/write a non-crypto algorithm identifier, used for things like 
   content types.  This just wraps the given OID up in the 
   AlgorithmIdentifier and writes it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readGenericAlgoID( INOUT STREAM *stream, 
					   IN_BUFFER( oidLength ) const BYTE *oid, 
					   IN_LENGTH_OID const int oidLength )
	{
	int length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( oid, oidLength ) && \
			oidLength == sizeofOID( oid ) );

	REQUIRES_S( oidLength >= MIN_OID_SIZE && oidLength <= MAX_OID_SIZE );

	/* Read the AlgorithmIdentifier wrapper and OID.  One possible 
	   complication here is the standard NULL vs.absent AlgorithmIdentifier 
	   parameter issue, to handle this we allow either option */
	status = readSequence( stream, &length );
	if( cryptStatusOK( status ) )
		status = readFixedOID( stream, oid, oidLength );
	if( cryptStatusError( status ) )
		return( status );
	length -= oidLength;
	if( length > 0 )
		return( readNull( stream ) );

	return( CRYPT_OK );
	}

RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeGenericAlgoID( INOUT STREAM *stream, 
						IN_BUFFER( oidLength ) const BYTE *oid, 
						IN_LENGTH_OID const int oidLength )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( oid, oidLength ) && \
			oidLength == sizeofOID( oid ) );

	REQUIRES_S( oidLength >= MIN_OID_SIZE && oidLength <= MAX_OID_SIZE );

	writeSequence( stream, oidLength );
	return( writeOID( stream, oid ) );
	}
