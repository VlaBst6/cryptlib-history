/****************************************************************************
*																			*
*						cryptlib RC4 Encryption Routines					*
*						Copyright Peter Gutmann 1994-2005					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "rc4.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "crypt/rc4.h"
#endif /* Compiler-specific includes */

#ifdef USE_RC4

/* The size of the expanded RC4 keys */

#define RC4_EXPANDED_KEYSIZE	sizeof( RC4_KEY )

/****************************************************************************
*																			*
*								RC4 Self-test Routines						*
*																			*
****************************************************************************/

/* RC4 test vectors from the BSAFE implementation */

static const BYTE FAR_BSS testRC4key1[] =
	{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
static const BYTE FAR_BSS testRC4plaintext1[] =
	{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
static const BYTE FAR_BSS testRC4ciphertext1[] =
	{ 0x75, 0xB7, 0x87, 0x80, 0x99, 0xE0, 0xC5, 0x96 };

static const BYTE FAR_BSS testRC4key2[] =
	{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
static const BYTE FAR_BSS testRC4plaintext2[] =
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const BYTE FAR_BSS testRC4ciphertext2[] =
	{ 0x74, 0x94, 0xC2, 0xE7, 0x10, 0x4B, 0x08, 0x79 };

static const BYTE FAR_BSS testRC4key3[] =
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const BYTE FAR_BSS testRC4plaintext3[] =
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const BYTE FAR_BSS testRC4ciphertext3[] =
	{ 0xDE, 0x18, 0x89, 0x41, 0xA3, 0x37, 0x5D, 0x3A };

static const BYTE FAR_BSS testRC4key4[] =
	{ 0xEF, 0x01, 0x23, 0x45 };
static const BYTE FAR_BSS testRC4plaintext4[] =
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const BYTE FAR_BSS testRC4ciphertext4[] =
	{ 0xD6, 0xA1, 0x41, 0xA7, 0xEC, 0x3C, 0x38, 0xDF, 0xBD, 0x61 };

static const BYTE FAR_BSS testRC4key5[] =
	{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
static const BYTE FAR_BSS testRC4plaintext5[] =
	{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
static const BYTE FAR_BSS testRC4ciphertext5[] =
	{ 0x75, 0x95, 0xC3, 0xE6, 0x11, 0x4A, 0x09, 0x78,
	  0x0C, 0x4A, 0xD4, 0x52, 0x33, 0x8E, 0x1F, 0xFD,
	  0x9A, 0x1B, 0xE9, 0x49, 0x8F, 0x81, 0x3D, 0x76,
	  0x53, 0x34, 0x49, 0xB6, 0x77, 0x8D, 0xCA, 0xD8,
	  0xC7, 0x8A, 0x8D, 0x2B, 0xA9, 0xAC, 0x66, 0x08,
	  0x5D, 0x0E, 0x53, 0xD5, 0x9C, 0x26, 0xC2, 0xD1,
	  0xC4, 0x90, 0xC1, 0xEB, 0xBE, 0x0C, 0xE6, 0x6D,
	  0x1B, 0x6B, 0x1B, 0x13, 0xB6, 0xB9, 0x19, 0xB8,
	  0x47, 0xC2, 0x5A, 0x91, 0x44, 0x7A, 0x95, 0xE7,
	  0x5E, 0x4E, 0xF1, 0x67, 0x79, 0xCD, 0xE8, 0xBF,
	  0x0A, 0x95, 0x85, 0x0E, 0x32, 0xAF, 0x96, 0x89,
	  0x44, 0x4F, 0xD3, 0x77, 0x10, 0x8F, 0x98, 0xFD,
	  0xCB, 0xD4, 0xE7, 0x26, 0x56, 0x75, 0x00, 0x99,
	  0x0B, 0xCC, 0x7E, 0x0C, 0xA3, 0xC4, 0xAA, 0xA3,
	  0x04, 0xA3, 0x87, 0xD2, 0x0F, 0x3B, 0x8F, 0xBB,
	  0xCD, 0x42, 0xA1, 0xBD, 0x31, 0x1D, 0x7A, 0x43,
	  0x03, 0xDD, 0xA5, 0xAB, 0x07, 0x88, 0x96, 0xAE,
	  0x80, 0xC1, 0x8B, 0x0A, 0xF6, 0x6D, 0xFF, 0x31,
	  0x96, 0x16, 0xEB, 0x78, 0x4E, 0x49, 0x5A, 0xD2,
	  0xCE, 0x90, 0xD7, 0xF7, 0x72, 0xA8, 0x17, 0x47,
	  0xB6, 0x5F, 0x62, 0x09, 0x3B, 0x1E, 0x0D, 0xB9,
	  0xE5, 0xBA, 0x53, 0x2F, 0xAF, 0xEC, 0x47, 0x50,
	  0x83, 0x23, 0xE6, 0x71, 0x32, 0x7D, 0xF9, 0x44,
	  0x44, 0x32, 0xCB, 0x73, 0x67, 0xCE, 0xC8, 0x2F,
	  0x5D, 0x44, 0xC0, 0xD0, 0x0B, 0x67, 0xD6, 0x50,
	  0xA0, 0x75, 0xCD, 0x4B, 0x70, 0xDE, 0xDD, 0x77,
	  0xEB, 0x9B, 0x10, 0x23, 0x1B, 0x6B, 0x5B, 0x74,
	  0x13, 0x47, 0x39, 0x6D, 0x62, 0x89, 0x74, 0x21,
	  0xD4, 0x3D, 0xF9, 0xB4, 0x2E, 0x44, 0x6E, 0x35,
	  0x8E, 0x9C, 0x11, 0xA9, 0xB2, 0x18, 0x4E, 0xCB,
	  0xEF, 0x0C, 0xD8, 0xE7, 0xA8, 0x77, 0xEF, 0x96,
	  0x8F, 0x13, 0x90, 0xEC, 0x9B, 0x3D, 0x35, 0xA5,
	  0x58, 0x5C, 0xB0, 0x09, 0x29, 0x0E, 0x2F, 0xCD,
	  0xE7, 0xB5, 0xEC, 0x66, 0xD9, 0x08, 0x4B, 0xE4,
	  0x40, 0x55, 0xA6, 0x19, 0xD9, 0xDD, 0x7F, 0xC3,
	  0x16, 0x6F, 0x94, 0x87, 0xF7, 0xCB, 0x27, 0x29,
	  0x12, 0x42, 0x64, 0x45, 0x99, 0x85, 0x14, 0xC1,
	  0x5D, 0x53, 0xA1, 0x8C, 0x86, 0x4C, 0xE3, 0xA2,
	  0xB7, 0x55, 0x57, 0x93, 0x98, 0x81, 0x26, 0x52,
	  0x0E, 0xAC, 0xF2, 0xE3, 0x06, 0x6E, 0x23, 0x0C,
	  0x91, 0xBE, 0xE4, 0xDD, 0x53, 0x04, 0xF5, 0xFD,
	  0x04, 0x05, 0xB3, 0x5B, 0xD9, 0x9C, 0x73, 0x13,
	  0x5D, 0x3D, 0x9B, 0xC3, 0x35, 0xEE, 0x04, 0x9E,
	  0xF6, 0x9B, 0x38, 0x67, 0xBF, 0x2D, 0x7B, 0xD1,
	  0xEA, 0xA5, 0x95, 0xD8, 0xBF, 0xC0, 0x06, 0x6F,
	  0xF8, 0xD3, 0x15, 0x09, 0xEB, 0x0C, 0x6C, 0xAA,
	  0x00, 0x6C, 0x80, 0x7A, 0x62, 0x3E, 0xF8, 0x4C,
	  0x3D, 0x33, 0xC1, 0x95, 0xD2, 0x3E, 0xE3, 0x20,
	  0xC4, 0x0D, 0xE0, 0x55, 0x81, 0x57, 0xC8, 0x22,
	  0xD4, 0xB8, 0xC5, 0x69, 0xD8, 0x49, 0xAE, 0xD5,
	  0x9D, 0x4E, 0x0F, 0xD7, 0xF3, 0x79, 0x58, 0x6B,
	  0x4B, 0x7F, 0xF6, 0x84, 0xED, 0x6A, 0x18, 0x9F,
	  0x74, 0x86, 0xD4, 0x9B, 0x9C, 0x4B, 0xAD, 0x9B,
	  0xA2, 0x4B, 0x96, 0xAB, 0xF9, 0x24, 0x37, 0x2C,
	  0x8A, 0x8F, 0xFF, 0xB1, 0x0D, 0x55, 0x35, 0x49,
	  0x00, 0xA7, 0x7A, 0x3D, 0xB5, 0xF2, 0x05, 0xE1,
	  0xB9, 0x9F, 0xCD, 0x86, 0x60, 0x86, 0x3A, 0x15,
	  0x9A, 0xD4, 0xAB, 0xE4, 0x0F, 0xA4, 0x89, 0x34,
	  0x16, 0x3D, 0xDD, 0xE5, 0x42, 0xA6, 0x58, 0x55,
	  0x40, 0xFD, 0x68, 0x3C, 0xBF, 0xD8, 0xC0, 0x0F,
	  0x12, 0x12, 0x9A, 0x28, 0x4D, 0xEA, 0xCC, 0x4C,
	  0xDE, 0xFE, 0x58, 0xBE, 0x71, 0x37, 0x54, 0x1C,
	  0x04, 0x71, 0x26, 0xC8, 0xD4, 0x9E, 0x27, 0x55,
	  0xAB, 0x18, 0x1A, 0xB7, 0xE9, 0x40, 0xB0, 0xC0 };

/* Test vector from the State/Commerce Department */

static const BYTE FAR_BSS testRC4key6[] =
	{ 0x61, 0x8A, 0x63, 0xD2, 0xFB };
static const BYTE FAR_BSS testRC4plaintext6[] =
	{ 0xDC, 0xEE, 0x4C, 0xF9, 0x2C };
static const BYTE FAR_BSS testRC4ciphertext6[] =
	{ 0xF1, 0x38, 0x29, 0xC9, 0xDE };

/* Test the RC4 code against the test vectors from the BSAFE implementation */

static int rc4Test( const BYTE *key, const int keySize,
					const BYTE *plaintext, const BYTE *ciphertext,
					const int length )
	{
	const CAPABILITY_INFO *capabilityInfo = getRC4Capability();
	CONTEXT_INFO contextInfo;
	CONV_INFO contextData;
	BYTE keyData[ RC4_EXPANDED_KEYSIZE + 8 ];
	BYTE temp[ 512 + 8 ];
	int status;

	staticInitContext( &contextInfo, CONTEXT_CONV, capabilityInfo,
					   &contextData, sizeof( CONV_INFO ), keyData );
	memcpy( temp, plaintext, length );
	status = capabilityInfo->initKeyFunction( &contextInfo, key, keySize );
	if( cryptStatusOK( status ) )
		status = capabilityInfo->encryptOFBFunction( &contextInfo, temp,
													 length );
	staticDestroyContext( &contextInfo );
	if( cryptStatusError( status ) || \
		memcmp( ciphertext, temp, length ) )
		return( CRYPT_ERROR );

	return( CRYPT_OK );
	}

static int selfTest( void )
	{
	/* The testing gets somewhat messy here because of the variable-length
	   arrays, which isn't normally a problem with the fixed-length keys
	   and data used in the block ciphers */
	if( rc4Test( testRC4key1, sizeof( testRC4key1 ), testRC4plaintext1,
				 testRC4ciphertext1, sizeof( testRC4plaintext1 ) ) != CRYPT_OK ||
		rc4Test( testRC4key2, sizeof( testRC4key2 ), testRC4plaintext2,
				 testRC4ciphertext2, sizeof( testRC4plaintext2 ) ) != CRYPT_OK ||
		rc4Test( testRC4key3, sizeof( testRC4key3 ), testRC4plaintext3,
				 testRC4ciphertext3, sizeof( testRC4plaintext3 ) ) != CRYPT_OK ||
		rc4Test( testRC4key4, sizeof( testRC4key4 ), testRC4plaintext4,
				 testRC4ciphertext4, sizeof( testRC4plaintext4 ) ) != CRYPT_OK ||
		rc4Test( testRC4key5, sizeof( testRC4key5 ), testRC4plaintext5,
				 testRC4ciphertext5, sizeof( testRC4plaintext5 ) ) != CRYPT_OK ||
		rc4Test( testRC4key6, sizeof( testRC4key6 ), testRC4plaintext6,
				 testRC4ciphertext6, sizeof( testRC4plaintext6 ) ) != CRYPT_OK )
		return( CRYPT_ERROR );

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
		return( RC4_EXPANDED_KEYSIZE );

	return( getDefaultInfo( type, varParam, constParam ) );
	}

/****************************************************************************
*																			*
*							RC4 En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data.  Since RC4 is a stream cipher, encryption and
   decryption are the same operation.  We have to append the distinguisher
   'Fn' to the name since some systems already have 'encrypt' and 'decrypt'
   in their standard headers  */

static int encryptFn( CONTEXT_INFO *contextInfoPtr, BYTE *buffer,
					  int noBytes )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	RC4( ( RC4_KEY * ) convInfo->key, noBytes, buffer, buffer );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							RC4 Key Management Routines						*
*																			*
****************************************************************************/

/* Create an expanded RC4 key */

static int initKey( CONTEXT_INFO *contextInfoPtr, const void *key,
					const int keyLength )
	{
	CONV_INFO *convInfo = contextInfoPtr->ctxConv;

	/* Copy the key to internal storage */
	if( convInfo->userKey != key )
		memcpy( convInfo->userKey, key, keyLength );
	convInfo->userKeyLength = keyLength;

	RC4_set_key( ( RC4_KEY * ) convInfo->key, keyLength, ( BYTE * ) key );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO FAR_BSS capabilityInfo = {
	CRYPT_ALGO_RC4, bitsToBytes( 8 ), "RC4",
	bitsToBytes( MIN_KEYSIZE_BITS ), bitsToBytes( 128 ), 256,
	selfTest, getInfo, NULL, initKeyParams, initKey, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, encryptFn, encryptFn
	};

const CAPABILITY_INFO *getRC4Capability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_RC4 */
