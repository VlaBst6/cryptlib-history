/****************************************************************************
*																			*
*					  cryptlib Blowfish Encryption Routines					*
*						Copyright Peter Gutmann 1994-2003					*
*																			*
****************************************************************************/

#include <stdlib.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "libs.h"
  #include "blowfish.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "context.h"
  #include "libs.h"
  #include "../crypt/blowfish.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "context/libs.h"
  #include "crypt/blowfish.h"
#endif /* Compiler-specific includes */

/* The size of the expanded Blowfish keys */

#define BLOWFISH_EXPANDED_KEYSIZE		sizeof( BF_KEY )

/****************************************************************************
*																			*
*							Blowfish Self-test Routines						*
*																			*
****************************************************************************/

/* Test the Blowfish code against Bruce Schneiers test vectors (1 & 2) and
   Mike Morgans test vector (3) */

int blowfishSelfTest( void )
	{
	BYTE *plain1 = ( BYTE * ) "BLOWFISH";
	BYTE *key1 = ( BYTE * ) "abcdefghijklmnopqrstuvwxyz";
	BYTE cipher1[] = { 0x32, 0x4E, 0xD0, 0xFE, 0xF4, 0x13, 0xA2, 0x03 };
	BYTE plain2[] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	BYTE *key2 = ( BYTE * ) "Who is John Galt?";
	BYTE cipher2[] = { 0xCC, 0x91, 0x73, 0x2B, 0x80, 0x22, 0xF6, 0x84 };
	BYTE plain3[] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	BYTE key3[] = { 0x41, 0x79, 0x6E, 0xA0, 0x52, 0x61, 0x6E, 0xE4 };
	BYTE cipher3[] = { 0xE1, 0x13, 0xF4, 0x10, 0x2C, 0xFC, 0xCE, 0x43 };
#if defined( __WIN32__ ) && defined( NT_DRIVER )	/* Kernel stack is tiny */
	static BF_KEY bfKey;
#else
	BF_KEY bfKey;
#endif /* __WIN32__ && NT_DRIVER */
	BYTE buffer[ 8 ];

	/* Test the Blowfish implementation */
	memcpy( buffer, plain1, 8 );
	BF_set_key( &bfKey, strlen( ( char * ) key1 ), key1 );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_ENCRYPT );
	if( memcmp( buffer, cipher1, 8 ) )
		return( CRYPT_ERROR );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_DECRYPT );
	if( memcmp( buffer, plain1, 8 ) )
		return( CRYPT_ERROR );
	memcpy( buffer, plain2, 8 );
	BF_set_key( &bfKey, strlen( ( char * ) key2 ), key2 );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_ENCRYPT );
	if( memcmp( buffer, cipher2, 8 ) )
		return( CRYPT_ERROR );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_DECRYPT );
	if( memcmp( buffer, plain2, 8 ) )
		return( CRYPT_ERROR );
	memcpy( buffer, plain3, 8 );
	BF_set_key( &bfKey, 8, key3 );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_ENCRYPT );
	if( memcmp( buffer, cipher3, 8 ) )
		return( CRYPT_ERROR );
	BF_ecb_encrypt( buffer, buffer, &bfKey, BF_DECRYPT );
	if( memcmp( buffer, plain3, 8 ) )
		return( CRYPT_ERROR );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Control Routines							*
*																			*
****************************************************************************/

/* Return context subtype-specific information */

int blowfishGetInfo( const CAPABILITY_INFO_TYPE type, 
					 void *varParam, const int constParam )
	{
	if( type == CAPABILITY_INFO_STATESIZE )
		return( BLOWFISH_EXPANDED_KEYSIZE );

	return( getInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*							Blowfish En/Decryption Routines					*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int blowfishEncryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BF_KEY *blowfishKey = ( BF_KEY * ) convInfo->key;
	int blockCount = noBytes / BF_BLOCK;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		BF_ecb_encrypt( buffer, buffer, blowfishKey, BF_ENCRYPT );

		/* Move on to next block of data */
		buffer += BF_BLOCK;
		}

	return( CRYPT_OK );
	}

int blowfishDecryptECB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BF_KEY *blowfishKey = ( BF_KEY * ) convInfo->key;
	int blockCount = noBytes / BF_BLOCK;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		BF_ecb_encrypt( buffer, buffer, blowfishKey, BF_DECRYPT );

		/* Move on to next block of data */
		buffer += BF_BLOCK;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int blowfishEncryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	BF_cbc_encrypt( buffer, buffer, noBytes, convInfo->key,
					convInfo->currentIV, BF_ENCRYPT );

	return( CRYPT_OK );
	}

int blowfishDecryptCBC( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	BF_cbc_encrypt( buffer, buffer, noBytes, convInfo->key,
					convInfo->currentIV, BF_DECRYPT );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int blowfishEncryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BF_KEY *blowfishKey = ( BF_KEY * ) convInfo->key;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BF_BLOCK - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];
		memcpy( convInfo->currentIV + ivCount, buffer, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > BF_BLOCK ) ? BF_BLOCK : noBytes;

		/* Encrypt the IV */
		BF_ecb_encrypt( convInfo->currentIV, convInfo->currentIV, 
						blowfishKey, BF_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( convInfo->currentIV, buffer, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % BF_BLOCK );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int blowfishDecryptCFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BF_KEY *blowfishKey = ( BF_KEY * ) convInfo->key;
	BYTE temp[ BF_BLOCK ];
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BF_BLOCK - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		memcpy( temp, buffer, bytesToUse );
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];
		memcpy( convInfo->currentIV + ivCount, temp, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > BF_BLOCK ) ? BF_BLOCK : noBytes;

		/* Encrypt the IV */
		BF_ecb_encrypt( convInfo->currentIV, convInfo->currentIV, 
						blowfishKey, BF_ENCRYPT );

		/* Save the ciphertext */
		memcpy( temp, buffer, ivCount );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( convInfo->currentIV, temp, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % BF_BLOCK );

	/* Clear the temporary buffer */
	zeroise( temp, BF_BLOCK );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int blowfishEncryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BF_KEY *blowfishKey = ( BF_KEY * ) convInfo->key;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BF_BLOCK - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > BF_BLOCK ) ? BF_BLOCK : noBytes;

		/* Encrypt the IV */
		BF_ecb_encrypt( convInfo->currentIV, convInfo->currentIV, 
						blowfishKey, BF_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % BF_BLOCK );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int blowfishDecryptOFB( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;
	BF_KEY *blowfishKey = ( BF_KEY * ) convInfo->key;
	int i, ivCount = convInfo->ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = BF_BLOCK - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > BF_BLOCK ) ? BF_BLOCK : noBytes;

		/* Encrypt the IV */
		BF_ecb_encrypt( convInfo->currentIV, convInfo->currentIV, 
						blowfishKey, BF_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= convInfo->currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	convInfo->ivCount = ( ivCount % BF_BLOCK );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Blowfish Key Management Routines				*
*																			*
****************************************************************************/

/* Key schedule a Blowfish key */

int blowfishInitKey( CONTEXT_INFO *contextInfoPtr, const void *key, 
					 const int keyLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	/* Copy the key to internal storage */
	if( convInfo->userKey != key )
		memcpy( convInfo->userKey, key, keyLength );
	convInfo->userKeyLength = keyLength;

	BF_set_key( ( BF_KEY * ) convInfo->key, keyLength, ( void * ) key );
	return( CRYPT_OK );
	}
