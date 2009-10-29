/****************************************************************************
*																			*
*					  cryptlib Dummy Crypto HAL Routines					*
*						Copyright Peter Gutmann 1998-2009					*
*																			*
****************************************************************************/

/* This module is a template for use when adding support for custom 
   cryptographic hardware to cryptlib.  It implements dummy versions of the
   cryptographic operations that are provided by the custom hardware.  See
   the inline comments for what's needed at each stage */

#ifdef USE_OLD_INTERFACE
  #define PKC_CONTEXT	/* Needed for keyID access in direct-access version */
#endif /* USE_OLD_INTERFACE */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "hardware.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "device/hardware.h"
#endif /* Compiler-specific includes */

#ifdef USE_HARDWARE

/* Define the following to use the old-style interface in which this module
   is responsible for handling key ID information and whatnot */

/* #define USE_OLD_INTERFACE */

/****************************************************************************
*																			*
*								Personality Storage							*
*																			*
****************************************************************************/

/* Each key, along with its associated identifiers, certificates, and other
   metadata, constitutes a personality.  cryptlib manages most of this 
   information externally, the only data that's stored here is the keying
   information, in whatever format the cryptgraphic hardware uses, and a 
   short binary unique-ID value, the storageID, that cryptlib uses to look
   up a personality.  
   
   Externally, cryptlib maintains a 160-bit value as a storageID but this 
   module only needs to use as much of it as required to avoid a false
   positive match.  In this case we use 64 bits of the storageID to look up
   a personality */

#define STORAGEID_SIZE	8

/* Private key data will generally be stored in a hardware-specific internal
   format.  For demonstration purposes we assume that this consists of 
   32-bit big-endian words (chosen because the most widely-deployed 
   architectures are little-endian, so this guarantees that if there's a
   problem it'll be caught by the different endianness), which we need to 
   convert to and from the generic CRYPT_PKCINFO_RSA/CRYPT_PKCINFO_DLP 
   format on import and export.  The following structure is used to store 
   data in the dummy hardware-internal format.  The layout of the data is 
   as follows:

	Index	RSA value	DLP value	ECC value
	-----	---------	---------	---------
	  0			n			p			p
	  1			e			q			a
	  2			d			q			b
	  3			p			y			gx
	  4			q			x			gy
	  5			u						r
	  6			e1						h
	  7			e2						[...] */	

typedef struct {
	LONG data[ CRYPT_MAX_PKCSIZE / sizeof( LONG ) ];
	int dataSize;
	} BIGNUM_STORAGE;

#define NO_BIGNUMS		8

/* Each personality contains (at least) the storageID used to reference it
   and whatever keying information is needed by the underlying cryptographic
   hardware.  The following structure contains the information stored for 
   each personality.  The inUse flag is a convenience feature, it can also 
   be indicated through a convention such as an all-zero storageID */

typedef struct {
	/* General management information */
	BOOLEAN inUse;				/* Whether this personality is in use */
	BYTE storageID[ STORAGEID_SIZE ];/* ID used to look up this personality */

#ifdef USE_OLD_INTERFACE
	/* Identification information */
	CRYPT_ALGO_TYPE cryptAlgo;	/* Algorithm type */
	char label[ CRYPT_MAX_TEXTSIZE ];
	int labelSize;				/* Label for this personality */
	BYTE keyID[ KEYID_SIZE ];	/* Key ID for this personality */
#endif /* USE_OLD_INTERFACE */

	/* Key data storage */
	union {
		BYTE convKeyInfo[ CRYPT_MAX_KEYSIZE ];
		BIGNUM_STORAGE pkcKeyInfo[ NO_BIGNUMS ];
		} keyInfo;
	} PERSONALITY_INFO;

/* Storage for each personality.  This would typically be held either in 
   internal protected memory (for example battery-backed device-internal 
   SRAM) or encrypted external memory that's transparently accessed as 
   standard memory */

#define NO_PERSONALITIES	8

static PERSONALITY_INFO personalityInfo[ NO_PERSONALITIES ] = { 0 };

/****************************************************************************
*																			*
*						Personality Management Routines						*
*																			*
****************************************************************************/

/* The following routines manage access to the personality storage, and 
   represent an example implementation matching the example PERSONALITY_INFO
   structure defined earlier.  The routines look up a personality given its
   storageID, find a free personality slot to use when instantiating a new
   personality (or in more high-level terms when loading or generating a
   key for an encryption context), and delete a personality */

/* Look up a personality given a key ID */

static int lookupPersonality( const CRYPT_KEYID_TYPE keyIDtype,
							  const void *keyID, const int keyIDlength,
							  int *keyHandle )
	{
	const int storageIDlength = min( keyIDlength, STORAGEID_SIZE );
	int i;

#ifdef USE_OLD_INTERFACE
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_IKEYID_KEYID );
#else
	assert( keyIDtype == CRYPT_KEYID_NONE );
#endif /* USE_OLD_INTERFACE */
	assert( isReadPtr( keyID, keyIDlength ) );
	assert( isWritePtr( keyHandle, sizeof( int ) ) );

	/* Clear return value */
	*keyHandle = CRYPT_ERROR;

	/* Scan the personality table looking for one matching the given 
	   storageID */
	for( i = 0; i < NO_PERSONALITIES; i++ )
		{
		PERSONALITY_INFO *personalityInfoPtr = &personalityInfo[ i ];

		if( !personalityInfoPtr->inUse )
			continue;
		if( !memcmp( personalityInfoPtr->storageID, keyID, storageIDlength ) )
			{
			*keyHandle = i;
			return( CRYPT_OK );
			}
#ifdef USE_OLD_INTERFACE
		if( keyIDtype == CRYPT_KEYID_NAME )
			{
			if( !memcmp( personalityInfoPtr->keyID, keyID, keyIDlength ) )
				{
				*keyHandle = i;
				return( CRYPT_OK );
				}
			}
		else
			{
			if( personalityInfoPtr->labelSize == keyIDlength && \
				!memcmp( personalityInfoPtr->label, keyID, keyIDlength ) )
				{
				*keyHandle = i;
				return( CRYPT_OK );
				}
			}
#endif /* USE_OLD_INTERFACE */
		}
	return( CRYPT_ERROR_NOTFOUND );
	}

/* Find a free personality */

static int findFreePersonality( int *keyHandle )
	{
	int i;

	assert( isWritePtr( keyHandle, sizeof( int ) ) );

	/* Clear return value */
	*keyHandle = CRYPT_ERROR;

	/* Scan the personality table looking for a free slot */
	for( i = 0; i < NO_PERSONALITIES; i++ )
		{
		PERSONALITY_INFO *personalityInfoPtr = &personalityInfo[ i ];

		if( !personalityInfoPtr->inUse )
			{
			zeroise( personalityInfoPtr, sizeof( PERSONALITY_INFO ) );
			*keyHandle = i;
			return( CRYPT_OK );
			}
		}
	return( CRYPT_ERROR_OVERFLOW );
	}

/* Delete a personality */

static void deletePersonality( const int keyHandle )
	{
	PERSONALITY_INFO *personalityInfoPtr;

	assert( keyHandle >= 0 && keyHandle < NO_PERSONALITIES );

	if( keyHandle < 0 || keyHandle >= NO_PERSONALITIES )
		return;
	personalityInfoPtr = &personalityInfo[ keyHandle ];
	zeroise( personalityInfoPtr, sizeof( PERSONALITY_INFO ) );
	}

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Functions used to convert from the dummy hardware-internal bignum format 
   (big-endian 32-bit words) to the generic external format */

static void bignumToInternal( LONG *outData, int *outDataLength, 
							  const BYTE *inData, const int inDataLength )
	{
	int inIndex, outIndex = 0, i;

	assert( isWritePtr( outData, CRYPT_MAX_PKCSIZE ) );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( isReadPtr( inData, inDataLength ) );
	assert( inDataLength > 0 && inDataLength <= CRYPT_MAX_PKCSIZE );

	for( i = 0; i < CRYPT_MAX_PKCSIZE / sizeof( LONG ); i++ )
		outData[ i ] = 0L;
	for( inIndex = 0; inIndex < inDataLength; inIndex += sizeof( LONG ) )
		{
		outData[ outIndex++ ] = mgetLong( inData );
		}
	*outDataLength = outIndex;
	}

static void bignumToExternal( BYTE *outData, int *outDataLength,
							  const LONG *inData, const int inDataLength )
	{
	int inIndex = 0, outIndex;

	assert( isWritePtr( outData, CRYPT_MAX_PKCSIZE ) );
	assert( isWritePtr( outDataLength, sizeof( int ) ) );
	assert( isReadPtr( inData, inDataLength * sizeof( LONG ) ) );
	assert( inDataLength > 0 && \
			inDataLength <= CRYPT_MAX_PKCSIZE / sizeof( LONG ) );

	memset( outData, 0, CRYPT_MAX_PKCSIZE );
	for( outIndex = 0; outIndex < inDataLength; outIndex++ )
		{
		const LONG value = inData[ inIndex++ ];

		mputLong( outData, value );
		}
	*outDataLength = outIndex * sizeof( LONG );
	}

/* Dummy functions used to "encrypt" data and generate random data in the 
   absence of any actual hardware functionality */

static void dummyEncrypt( const PERSONALITY_INFO *personalityInfoPtr,
						  BYTE *data, const int length,
						  const CRYPT_ALGO_TYPE cryptAlgo,
						  const CRYPT_MODE_TYPE cryptMode )
	{
	int i;

	assert( isReadPtr( personalityInfoPtr, sizeof( PERSONALITY_INFO ) ) );
	assert( isWritePtr( data, length ) );
	assert( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST );
	assert( cryptMode >= CRYPT_MODE_NONE && cryptMode < CRYPT_MODE_LAST );

	if( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
		cryptAlgo < CRYPT_ALGO_LAST_PKC )
		{
		BYTE bignumData[ CRYPT_MAX_PKCSIZE + 8 ];
		int bignumDataLength;

		bignumToExternal( bignumData, &bignumDataLength, 
						  personalityInfoPtr->keyInfo.pkcKeyInfo[ 0 ].data,
						  personalityInfoPtr->keyInfo.pkcKeyInfo[ 0 ].dataSize );
		for( i = 0; i < length; i++ )
			data[ i ] ^= bignumData[ i ];

		return;
		}

	/* We have to be a bit careful with the conventional encryption because 
	   the self-tests encrypt in variable-length quantities to check for 
	   things like chaining problems, which means that for stream ciphers we
	   really can't do anything more than repeatedly XOR with the first key
	   byte */
	if( cryptMode == CRYPT_MODE_CFB || cryptMode == CRYPT_MODE_OFB )
		{
		for( i = 0; i < length; i++ )
			data[ i ] ^= personalityInfoPtr->keyInfo.convKeyInfo[ 0 ];
		}
	else
		{
		/* It's a block mode, we can at least use ECB, although we still 
		   can't chain because we don't know where we are in the data 
		   stream */
		for( i = 0; i < length; i++ )
			data[ i ] ^= personalityInfoPtr->keyInfo.convKeyInfo[ i % 16 ];
		}
	}

static void dummyGenRandom( void *buffer, const int length )
	{
	HASHFUNCTION_ATOMIC hashFunctionAtomic;
	BYTE hashBuffer[ CRYPT_MAX_HASHSIZE ], *bufPtr = buffer;
	static int counter = 0;
	int hashSize, i;

	/* Fill the buffer with random-ish data.  This gets a bit tricky because
	   we need to fool the entropy tests so we can't just fill it with a 
	   fixed (or even semi-random) pattern but have to set up a somewhat
	   kludgy PRNG */
	getHashAtomicParameters( CRYPT_ALGO_SHA1, &hashFunctionAtomic, 
							 &hashSize );
	memset( hashBuffer, counter, hashSize );
	counter++;
	for( i = 0; i < length; i++ )
		{
		if( i % hashSize == 0 )
			{
			hashFunctionAtomic( hashBuffer, CRYPT_MAX_HASHSIZE, 
								hashBuffer, hashSize );
			}
		bufPtr[ i ] = hashBuffer[ i % hashSize ];
		}
	}

/****************************************************************************
*																			*
*					Symmetric Capability Interface Routines					*
*																			*
****************************************************************************/

/* Perform a self-test */

static int aesSelfTest( void )
	{
	/* Perform the self-test */
	return( CRYPT_OK );
	}

/* Load a key */

static int completeInitKeyAES( CONTEXT_INFO *contextInfoPtr, 
							   PERSONALITY_INFO *personalityInfoPtr,
							   const int keyHandle, const int keySize )
	{
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( personalityInfoPtr, sizeof( PERSONALITY_INFO ) ) );
	assert( keyHandle >= 0 && keyHandle < NO_PERSONALITIES );
	assert( keySize >= MIN_KEYSIZE && keySize <= CRYPT_MAX_KEYSIZE );

	/* This personality is now active and in use */
	status = setConvInfo( contextInfoPtr->objectHandle, keySize );
	if( cryptStatusOK( status ) )
		{
		status = setPersonalityMapping( contextInfoPtr, keyHandle, 
										personalityInfoPtr->storageID, 
										STORAGEID_SIZE );
		}
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}
	personalityInfoPtr->inUse = TRUE;

	return( CRYPT_OK );
	}

static int aesInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					   const int keyLength )
	{
	PERSONALITY_INFO *personalityInfoPtr;
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtr( key, keyLength ) );

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = &personalityInfo[ keyHandle ];

	/* Load the key into the personality */
	memcpy( personalityInfoPtr->keyInfo.convKeyInfo, key, keyLength );
	return( completeInitKeyAES( contextInfoPtr, personalityInfoPtr, 
								keyHandle, keyLength ) );
	}

/* Generate a key */

static int aesGenerateKey( CONTEXT_INFO *contextInfoPtr,
						   const int keySizeBits )
	{
	PERSONALITY_INFO *personalityInfoPtr;
	const int length = bitsToBytes( keySizeBits );
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( keySizeBits >= bytesToBits( MIN_KEYSIZE ) && \
			keySizeBits <= bytesToBits( CRYPT_MAX_KEYSIZE ) );

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = &personalityInfo[ keyHandle ];

	/* Use the hardware RNG to generate the encryption key */
	status = hwGetRandom( personalityInfoPtr->keyInfo.convKeyInfo, length );
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}
	return( completeInitKeyAES( contextInfoPtr, personalityInfoPtr, 
								keyHandle, bitsToBytes( keySizeBits ) ) );
	}

/* Encrypt/decrypt data */

static int aesEncryptECB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_AES, 
				  CRYPT_MODE_ECB );
	return( CRYPT_OK );
	}
static int aesDecryptECB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_AES, 
				  CRYPT_MODE_ECB );
	return( CRYPT_OK );
	}

static int aesEncryptCBC( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_AES,
				  CRYPT_MODE_CBC );
	return( CRYPT_OK );
	}
static int aesDecryptCBC( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_AES,
				  CRYPT_MODE_CBC );
	return( CRYPT_OK );
	}

static int aesEncryptCFB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_AES,
				  CRYPT_MODE_CFB );
	return( CRYPT_OK );
	}
static int aesDecryptCFB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_AES,
				  CRYPT_MODE_CFB );
	return( CRYPT_OK );
	}

static int aesEncryptOFB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_AES,
				  CRYPT_MODE_OFB );
	return( CRYPT_OK );
	}
static int aesDecryptOFB( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						  int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_AES,
				  CRYPT_MODE_OFB );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Asymmetric Capability Interface Routines				*
*																			*
****************************************************************************/

/* Perform a self-test */

static int rsaSelfTest( void )
	{
	/* Perform the self-test */
	return( CRYPT_OK );
	}

/* Load a key */

static int completeInitKeyRSA( CONTEXT_INFO *contextInfoPtr, 
							   PERSONALITY_INFO *personalityInfoPtr,
							   const int keyHandle )
	{
	int status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( personalityInfoPtr, sizeof( PERSONALITY_INFO ) ) );
	assert( keyHandle >= 0 && keyHandle < NO_PERSONALITIES );

	/* This personality is now active and in use, remember the details */
	status = setPersonalityMapping( contextInfoPtr, keyHandle,
									personalityInfoPtr->storageID, 
									STORAGEID_SIZE );
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}
	personalityInfoPtr->inUse = TRUE;
#ifdef USE_OLD_INTERFACE
	personalityInfoPtr->cryptAlgo = CRYPT_ALGO_RSA;
	memcpy( personalityInfoPtr->label, contextInfoPtr->label, 
			contextInfoPtr->labelSize );
	personalityInfoPtr->labelSize = contextInfoPtr->labelSize;
	contextInfoPtr->deviceObject = keyHandle;
	memcpy( personalityInfoPtr->keyID, contextInfoPtr->ctxPKC->keyID, 
			KEYID_SIZE );
#endif /* USE_OLD_INTERFACE */

	return( CRYPT_OK );
	}

static void rsaKeyToInternal( BIGNUM_STORAGE *bignumStorage,
							  const CRYPT_PKCINFO_RSA *rsaKeyInfo )
	{
	assert( isWritePtr( bignumStorage, \
						sizeof( BIGNUM_STORAGE ) * NO_BIGNUMS ) );
	assert( isReadPtr( rsaKeyInfo, sizeof( CRYPT_PKCINFO_RSA ) ) );

	/* Convert the RSA key components from the generic external 
	   representation to the hardware-specific internal format */
	bignumToInternal( bignumStorage[ 0 ].data, &bignumStorage[ 0 ].dataSize, 
					  rsaKeyInfo->n, bitsToBytes( rsaKeyInfo->nLen ) );
	bignumToInternal( bignumStorage[ 1 ].data, &bignumStorage[ 1 ].dataSize, 
					  rsaKeyInfo->e, bitsToBytes( rsaKeyInfo->eLen ) );
	if( rsaKeyInfo->isPublicKey )
		return;
	if( rsaKeyInfo->dLen > 0 )
		{
		bignumToInternal( bignumStorage[ 2 ].data, 
						  &bignumStorage[ 2 ].dataSize, 
						  rsaKeyInfo->d, bitsToBytes( rsaKeyInfo->dLen ) );
		}
	bignumToInternal( bignumStorage[ 3 ].data, 
					  &bignumStorage[ 3 ].dataSize, 
					  rsaKeyInfo->p, bitsToBytes( rsaKeyInfo->pLen ) );
	bignumToInternal( bignumStorage[ 4 ].data, 
					  &bignumStorage[ 4 ].dataSize, 
					  rsaKeyInfo->q, bitsToBytes( rsaKeyInfo->qLen ) );
	if( rsaKeyInfo->e1Len > 0 )
		{
		bignumToInternal( bignumStorage[ 5 ].data, 
						  &bignumStorage[ 5 ].dataSize, 
						  rsaKeyInfo->e1, bitsToBytes( rsaKeyInfo->e1Len ) );
		bignumToInternal( bignumStorage[ 6 ].data, 
						  &bignumStorage[ 6 ].dataSize, 
						  rsaKeyInfo->e2, bitsToBytes( rsaKeyInfo->e2Len ) );
		bignumToInternal( bignumStorage[ 7 ].data, 
						  &bignumStorage[ 7 ].dataSize, 
						  rsaKeyInfo->u, bitsToBytes( rsaKeyInfo->uLen ) );
		}
	}

static int rsaInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					   const int keyLength )
	{
	PERSONALITY_INFO *personalityInfoPtr;
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isReadPtr( key, keyLength ) );
	assert( keyLength == sizeof( CRYPT_PKCINFO_RSA ) );

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = &personalityInfo[ keyHandle ];

	/* Load the key into the personality and copy the public-key portions 
	   (needed for certificates and the like) to the context using the 
	   helper function in hardware.c */
	rsaKeyToInternal( personalityInfoPtr->keyInfo.pkcKeyInfo, key );
	status = setPKCinfo( contextInfoPtr, 
						 contextInfoPtr->capabilityInfo->cryptAlgo, key );
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}
	return( completeInitKeyRSA( contextInfoPtr, personalityInfoPtr, 
								keyHandle ) );
	}

/* Generate a key */

static int rsaGenerateKey( CONTEXT_INFO *contextInfoPtr,
						   const int keySizeBits )
	{
	CRYPT_PKCINFO_RSA rsaKeyInfo;
	PERSONALITY_INFO *personalityInfoPtr;
	int keyHandle, status;

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( keySizeBits >= bytesToBits( MIN_PKCSIZE ) && \
			keySizeBits <= bytesToBits( CRYPT_MAX_PKCSIZE ) );

	/* Find a free personality slot to store the key */
	status = findFreePersonality( &keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = &personalityInfo[ keyHandle ];

	/* Since the hardware doesn't provide native keygen capabilities we
	   generate the key components using the helper function in hardware.c */
	status = generatePKCcomponents( contextInfoPtr, &rsaKeyInfo, 
									keySizeBits );
	if( cryptStatusError( status ) )
		{
		deletePersonality( keyHandle );
		return( status );
		}
	rsaKeyToInternal( personalityInfoPtr->keyInfo.pkcKeyInfo, &rsaKeyInfo );
	zeroise( &rsaKeyInfo, sizeof( CRYPT_PKCINFO_RSA ) );
	return( completeInitKeyRSA( contextInfoPtr, personalityInfoPtr, 
								keyHandle ) );
	}

/* Encrypt/decrypt data */

static int rsaEncrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, 
					   int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_RSA, 
				  CRYPT_MODE_NONE );
	return( CRYPT_OK );
	}

static int rsaDecrypt( CONTEXT_INFO *contextInfoPtr, void *buffer, 
					   int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_RSA, 
				  CRYPT_MODE_NONE );
	return( CRYPT_OK );
	}

/* Sign/sig check data */

static int rsaSign( CONTEXT_INFO *contextInfoPtr, void *buffer, 
					int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_RSA,
				  CRYPT_MODE_NONE );
	return( CRYPT_OK );
	}

static int rsaSigCheck( CONTEXT_INFO *contextInfoPtr, void *buffer, 
						int length )
	{
	PERSONALITY_INFO *personalityInfoPtr = \
				&personalityInfo[ contextInfoPtr->deviceObject ];

	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( isWritePtr( buffer, length ) );

	dummyEncrypt( personalityInfoPtr, buffer, length, CRYPT_ALGO_RSA,
				  CRYPT_MODE_NONE );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Hash/MAC Capability Interface Routines					*
*																			*
****************************************************************************/

/* Perform a self-test */

static int shaSelfTest( void )
	{
	/* Perform the self-test */
	return( CRYPT_OK );
	}

/* Return context subtype-specific information */

static int shaGetInfo( const CAPABILITY_INFO_TYPE type, const void *ptrParam, 
					   const int intParam, int *result )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		{
		/* Return the amount of hash-state storage needed by the SHA-1 
		   routines.  This will be allocated by cryptlib and made available
		   as contextInfoPtr->ctxHash->hashInfo */
		*result = 0;

		return( CRYPT_OK );
		}

	return( getDefaultInfo( type, ptrParam, intParam, result ) );
	}

/* Hash data */

static int shaHash( CONTEXT_INFO *contextInfoPtr, void *buffer, 
					int length )
	{
	assert( isWritePtr( contextInfoPtr, sizeof( CONTEXT_INFO ) ) );
	assert( length == 0 || isWritePtr( buffer, length ) );

	/* If the hash state was reset to allow another round of hashing,
	   reinitialise things */
	if( !( contextInfoPtr->flags & CONTEXT_FLAG_HASH_INITED ) )
		{
		/* Initialise hash state in contextInfoPtr->ctxHash->hashInfo */
		/* ... */
		}

	if( length > 0 )
		{
		/* Perform the hashing using the hash state information in 
		   contextInfoPtr->ctxHash->hashInfo */
		/* ... */
		}
	else
		{
		/* Wrap up the hashing from the state information in 
		   contextInfoPtr->ctxHash->hashInfo, with the result placed in 
		   contextInfoPtr->ctxHash->hash */
		/* ... */
		memset( contextInfoPtr->ctxHash->hash, 'X', 20 );	/* Dummy hash val.*/
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Hardware External Interface						*
*																			*
****************************************************************************/

/* The capability information for this device */

static const CAPABILITY_INFO capabilities[] = {
	/* The RSA capabilities */
	{ CRYPT_ALGO_RSA, bitsToBytes( 0 ), "RSA", 3,
		MIN_PKCSIZE, bitsToBytes( 1024 ), CRYPT_MAX_PKCSIZE,
		rsaSelfTest, getDefaultInfo, cleanupHardwareContext, NULL, rsaInitKey, rsaGenerateKey, 
		rsaEncrypt, rsaDecrypt, NULL, NULL, NULL, NULL, NULL, NULL, 
		rsaSign, rsaSigCheck },

	/* The AES capabilities */
	{ CRYPT_ALGO_AES, bitsToBytes( 128 ), "AES", 3,
		bitsToBytes( 128 ), bitsToBytes( 128 ), bitsToBytes( 256 ),
		aesSelfTest, getDefaultInfo, cleanupHardwareContext, initKeyParams, aesInitKey, aesGenerateKey,
		aesEncryptECB, aesDecryptECB, aesEncryptCBC, aesDecryptCBC,
		aesEncryptCFB, aesDecryptCFB, aesEncryptOFB, aesDecryptOFB },

	/* The SHA-1 capabilities */
	{ CRYPT_ALGO_SHA1, bitsToBytes( 160 ), "SHA1", 5,
		bitsToBytes( 0 ), bitsToBytes( 0 ), bitsToBytes( 0 ),
		shaSelfTest, shaGetInfo, NULL, NULL, NULL, NULL, shaHash, shaHash },

	/* The end-of-list marker.  This value isn't linked into the 
	   capabilities list when we call initCapabilities() */
	{ CRYPT_ALGO_NONE }, { CRYPT_ALGO_NONE }
	};

/* Return the hardware capabilities list */

int hwGetCapabilities( const CAPABILITY_INFO **capabilityInfo,
					   int *noCapabilities )
	{
	assert( isReadPtr( capabilityInfo, sizeof( CAPABILITY_INFO * ) ) );
	assert( isWritePtr( noCapabilities, sizeof( int ) ) );

	*capabilityInfo = capabilities;
	*noCapabilities = FAILSAFE_ARRAYSIZE( capabilities, CAPABILITY_INFO );

	return( CRYPT_OK );
	}

/* Get random data from the hardware */

int hwGetRandom( void *buffer, const int length )
	{
	assert( isWritePtr( buffer, length ) );

	/* Fill the buffer with random-ish data */
	dummyGenRandom( buffer, length );

	return( CRYPT_OK );
	}

/* Look up an item held in the hardware */

int hwLookupItem( const CRYPT_KEYID_TYPE keyIDtype,
				  const void *keyID, const int keyIDlength,
				  int *keyHandle, HW_KEYINFO *keyInfo )
	{
#ifndef USE_OLD_INTERFACE
	assert( keyIDtype == CRYPT_KEYID_NONE );
	assert( isReadPtr( keyID, keyIDlength ) );
	assert( keyInfo == NULL );

	/* Clear return value */
	*keyHandle = CRYPT_ERROR;

	return( lookupPersonality( keyIDtype, keyID, keyIDlength, keyHandle ) );
#else
	PERSONALITY_INFO *personalityInfoPtr;
	int status;

	assert( keyIDtype == CRYPT_KEYID_NONE || \
			keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_IKEYID_KEYID );
	assert( isReadPtr( keyID, keyIDlength ) );
	assert( keyInfo == NULL || \
			isWritePtr( keyInfo, sizeof( HW_KEYINFO ) ) );

	/* Clear return value */
	*keyHandle = CRYPT_ERROR;
	if( keyInfo != NULL )
		memset( keyInfo, 0, sizeof( HW_KEYINFO ) );

	/* Try and find the personality using the given keyID */
	status = lookupPersonality( keyIDtype, keyID, keyIDlength, keyHandle );
	if( cryptStatusError( status ) )
		return( status );
	personalityInfoPtr = &personalityInfo[ *keyHandle ];

	/* Copy any further required information back to the caller */
	if( keyInfo != NULL )
		{
		keyInfo->cryptAlgo = personalityInfoPtr->cryptAlgo;
		memcpy( keyInfo->label, personalityInfoPtr->label, 
				personalityInfoPtr->labelSize );
		keyInfo->labelLength = personalityInfoPtr->labelSize;
		switch( personalityInfoPtr->cryptAlgo )
			{
			case CRYPT_ALGO_RSA:
				{
				CRYPT_PKCINFO_RSA *destKeyInfo = \
						&keyInfo->publicKeyInfo.rsaKeyInfo;
				CRYPT_PKCINFO_RSA *srcKeyInfo = \
						&personalityInfoPtr->keyInfo.rsaKeyInfo;

				memcpy( destKeyInfo->n, srcKeyInfo->n, srcKeyInfo->nLen );
				destKeyInfo->nLen = srcKeyInfo->nLen;
				memcpy( destKeyInfo->e, srcKeyInfo->e, srcKeyInfo->eLen );
				destKeyInfo->eLen = srcKeyInfo->eLen;
				break;
				}

			case CRYPT_ALGO_DSA:
				{
				CRYPT_PKCINFO_DLP *destKeyInfo = \
						&keyInfo->publicKeyInfo.dlpKeyInfo;
				CRYPT_PKCINFO_DLP *srcKeyInfo = \
						&personalityInfoPtr->keyInfo.dlpKeyInfo;

				memcpy( destKeyInfo->p, srcKeyInfo->p, srcKeyInfo->pLen );
				destKeyInfo->pLen = srcKeyInfo->pLen;
				if( srcKeyInfo->qLen > 0 )
					{
					memcpy( destKeyInfo->q, srcKeyInfo->q, srcKeyInfo->qLen );
					destKeyInfo->qLen = srcKeyInfo->qLen;
					}
				memcpy( destKeyInfo->g, srcKeyInfo->g, srcKeyInfo->gLen );
				destKeyInfo->gLen = srcKeyInfo->gLen;
				memcpy( destKeyInfo->y, srcKeyInfo->y, srcKeyInfo->yLen );
				destKeyInfo->yLen = srcKeyInfo->yLen;
				break;
				}
			}
		}

	return( CRYPT_OK );
#endif /* USE_OLD_INTERFACE */
	}

/* Delete an item held in the hardware, and delete all items held in the 
   hardware (used for an initialise/zeroise) */

int hwDeleteItem( const int keyHandle )
	{
	assert( keyHandle >= 0 && keyHandle < NO_PERSONALITIES );

	deletePersonality( keyHandle );
	return( CRYPT_OK );
	}

int hwDeleteAllItems( void )
	{
	int i;

	for( i = 0; i < NO_PERSONALITIES; i++ )
		deletePersonality( i );
	return( CRYPT_OK );
	}
#endif /* USE_HARDWARE */
