/****************************************************************************
*																			*
*					cryptlib Generic Crypto HW Header						*
*					Copyright Peter Gutmann 1998-2008						*
*																			*
****************************************************************************/

/* A structure to pass back information from hwLookupItemInfo() */

typedef struct {
	/* Information for all item types */
	CRYPT_ALGO_TYPE cryptAlgo;	/* Algorithm type */
	char label[ CRYPT_MAX_TEXTSIZE ];
	int labelLength;			/* Label for this item */

	/* Information for public keys */
	BYTE keyID[ KEYID_SIZE ];	/* Key ID */
	BYTE pgpKeyID[ PGP_KEYID_SIZE ];	/* OpenPGP key ID */
	union {
		CRYPT_PKCINFO_RSA rsaKeyInfo;
		CRYPT_PKCINFO_DLP dlpKeyInfo;
		} publicKeyInfo;		/* Public-key components */
	} HW_KEYINFO;

/* The access functions that must be provided by each HAL module */

int hwGetCapabilities( const CAPABILITY_INFO **capabilityInfo,
					   int *noCapabilities );
int hwGetRandom( void *buffer, const int length );
int hwLookupItem( const CRYPT_KEYID_TYPE keyIDtype,
				  const void *keyID, const int keyIDlength,
				  int *keyHandle, HW_KEYINFO *keyInfo );
int hwDeleteItem( const int keyHandle );
int hwDeleteAllItems( void );

/* Helper functions in hardware.c that may be used by HAL modules */

int setPersonalityMapping( CONTEXT_INFO *contextInfoPtr, const int keyHandle,
						   void *storageID, const int storageIDlength );
int generatePKCcomponents( CONTEXT_INFO *contextInfoPtr, void *keyInfo, 
						   const int keySizeBits );
int setPKCinfo( CONTEXT_INFO *contextInfoPtr, 
				const CRYPT_ALGO_TYPE cryptAlgo, const void *keyInfo );
int setConvInfo( const CRYPT_CONTEXT iCryptContext, const int keySize );
int cleanupHardwareContext( const CONTEXT_INFO *contextInfoPtr );
