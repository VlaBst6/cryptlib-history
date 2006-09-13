/****************************************************************************
*																			*
*					cryptlib HMAC-RIPEMD-160 Hash Routines					*
*					  Copyright Peter Gutmann 1997-2005						*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "ripemd.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "crypt/ripemd.h"
#endif /* Compiler-specific includes */

/* A structure to hold the initial and current MAC state info.  Rather than
   redoing the key processing each time when we're calculating multiple MACs
   with the same key, we just copy the initial state into the current state */

typedef struct {
	RIPEMD160_CTX macState, initialMacState;
	} MAC_STATE;

#define MAC_STATE_SIZE		sizeof( MAC_STATE )

/****************************************************************************
*																			*
*						HMAC-RIPEMD-160 Self-test Routines					*
*																			*
****************************************************************************/

/* Test the HMAC-RIPEMD-160 output against the test vectors given in ???? */

static const struct {
	const char FAR_BSS *key;					/* HMAC key */
	const int keyLength;						/* Length of key */
	const char FAR_BSS *data;					/* Data to hash */
	const int length;							/* Length of data */
	const BYTE digest[ RIPEMD160_DIGEST_LENGTH ];	/* Digest of data */
	} FAR_BSS hmacValues[] = {
	/* No known test vectors for this algorithm */
	{ "", 0, NULL, 0, { 0 } }
	};

static int selfTest( void )
	{
	const CAPABILITY_INFO *capabilityInfo = getHmacRipemd160Capability();
	CONTEXT_INFO contextInfo;
	MAC_INFO contextData;
	BYTE keyData[ MAC_STATE_SIZE + 8 ];
	int i, status;

	/* Test HMAC-RIPEMD-160 against the test vectors given in RFC ???? */
	for( i = 0; hmacValues[ i ].data != NULL; i++ )
		{
		staticInitContext( &contextInfo, CONTEXT_MAC, capabilityInfo,
						   &contextData, sizeof( MAC_INFO ), keyData );
		status = capabilityInfo->initKeyFunction( &contextInfo, 
						hmacValues[ i ].key, hmacValues[ i ].keyLength );
		if( cryptStatusOK( status ) )
			status = capabilityInfo->encryptFunction( &contextInfo, 
						( BYTE * ) hmacValues[ i ].data, 
						hmacValues[ i ].length );
		contextInfo.flags |= CONTEXT_HASH_INITED;
		if( cryptStatusOK( status ) )
			status = capabilityInfo->encryptFunction( &contextInfo, NULL, 0 );
		if( cryptStatusOK( status ) && \
			memcmp( contextInfo.ctxMAC->mac, hmacValues[ i ].digest,
					RIPEMD160_DIGEST_LENGTH ) )
			status = CRYPT_ERROR;
		staticDestroyContext( &contextInfo );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Control Routines							*
*																			*
****************************************************************************/

/* Return context subtype-specific information */

static int getInfo( const CAPABILITY_INFO_TYPE type, void *varParam, 
					const int constParam )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		return( MAC_STATE_SIZE );

	return( getDefaultInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*							HMAC-RIPEMD-160 Hash Routines					*
*																			*
****************************************************************************/

/* Hash data using HMAC-RIPEMD-160 */

static int hash( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	MAC_INFO *macInfo = contextInfoPtr->ctxMAC;
	RIPEMD160_CTX *ripemdInfo = &( ( MAC_STATE * ) macInfo->macInfo )->macState;

	/* If the hash state was reset to allow another round of MAC'ing, copy 
	   the initial MAC state over into the current MAC state */
	if( !( contextInfoPtr->flags & CONTEXT_HASH_INITED ) )
		{
		MAC_STATE *macState = macInfo->macInfo;

		memcpy( &macState->macState, &macState->initialMacState, 
				sizeof( RIPEMD160_CTX ) );
		}

	if( noBytes > 0 )
		RIPEMD160_Update( ripemdInfo, buffer, noBytes );
	else
		{
		BYTE hashBuffer[ RIPEMD160_CBLOCK + 8 ];
		BYTE digestBuffer[ RIPEMD160_DIGEST_LENGTH + 8 ];
		int i;

		/* Complete the inner hash and extract the digest */
		RIPEMD160_Final( digestBuffer, ripemdInfo );

		/* Perform the of the outer hash using the zero-padded key XOR'd
		   with the opad value followed by the digest from the inner hash */
		memset( hashBuffer, HMAC_OPAD, RIPEMD160_CBLOCK );
		memcpy( hashBuffer, macInfo->userKey,
				macInfo->userKeyLength );
		for( i = 0; i < macInfo->userKeyLength; i++ )
			hashBuffer[ i ] ^= HMAC_OPAD;
		RIPEMD160_Init( ripemdInfo );
		RIPEMD160_Update( ripemdInfo, hashBuffer, RIPEMD160_CBLOCK );
		memset( hashBuffer, 0, RIPEMD160_CBLOCK );
		RIPEMD160_Update( ripemdInfo, digestBuffer, RIPEMD160_DIGEST_LENGTH );
		memset( digestBuffer, 0, RIPEMD160_DIGEST_LENGTH );
		RIPEMD160_Final( macInfo->mac, ripemdInfo );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						HMAC-RIPEMD-160 Key Management Routines				*
*																			*
****************************************************************************/

/* Set up an HMAC-RIPEMD-160 key */

static int initKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					const int keyLength )
	{
	MAC_INFO *macInfo = contextInfoPtr->ctxMAC;
	RIPEMD160_CTX *ripemdInfo = &( ( MAC_STATE * ) macInfo->macInfo )->macState;
	BYTE hashBuffer[ RIPEMD160_CBLOCK + 8 ];
	int i;

	RIPEMD160_Init( ripemdInfo );

	/* If the key size is larger than tha RIPEMD-160 data size, reduce it to
	   the RIPEMD-160 hash size before processing it (yuck.  You're required
	   to do this though) */
	if( keyLength > RIPEMD160_CBLOCK )
		{
		/* Hash the user key down to the hash size (RIPEMD160_Init() has
		   already been called when the context was created) */
		RIPEMD160_Update( ripemdInfo, ( BYTE * ) key, keyLength );
		RIPEMD160_Final( macInfo->userKey, ripemdInfo );
		macInfo->userKeyLength = RIPEMD160_DIGEST_LENGTH;

		/* Reset the RIPEMD-160 state */
		RIPEMD160_Init( ripemdInfo );
		}
	else
		{
		/* Copy the key to internal storage */
		memcpy( macInfo->userKey, key, keyLength );
		macInfo->userKeyLength = keyLength;
		}

	/* Perform the start of the inner hash using the zero-padded key XOR'd
	   with the ipad value */
	memset( hashBuffer, HMAC_IPAD, RIPEMD160_CBLOCK );
	memcpy( hashBuffer, macInfo->userKey,
			macInfo->userKeyLength );
	for( i = 0; i < macInfo->userKeyLength; i++ )
		hashBuffer[ i ] ^= HMAC_IPAD;
	RIPEMD160_Update( ripemdInfo, hashBuffer, RIPEMD160_CBLOCK );
	memset( hashBuffer, 0, RIPEMD160_CBLOCK );

	/* Save a copy of the initial state in case it's needed later */
	memcpy( &( ( MAC_STATE * ) macInfo->macInfo )->initialMacState, ripemdInfo, 
			sizeof( RIPEMD160_CTX ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO FAR_BSS capabilityInfo = {
	CRYPT_ALGO_HMAC_RIPEMD160, bitsToBytes( 160 ), "HMAC-RIPEMD160",
	bitsToBytes( 64 ), bitsToBytes( 128 ), CRYPT_MAX_KEYSIZE,
	selfTest, getInfo, NULL, NULL, initKey, NULL, hash, hash
	};

const CAPABILITY_INFO *getHmacRipemd160Capability( void )
	{
	return( &capabilityInfo );
	}
