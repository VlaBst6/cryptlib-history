/****************************************************************************
*																			*
*					cryptlib ECDSA Encryption Routines						*
*			Copyright Matthias Bruestle and Peter Gutmann 2006-2007			*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC context */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
#else
  #include "crypt.h"
  #include "context/context.h"
#endif /* Compiler-specific includes */

#ifdef USE_ECC

/****************************************************************************
*																			*
*								Algorithm Self-test							*
*																			*
****************************************************************************/

/* Test the ECDSA implementation using the test vectors from ??? */

static BOOLEAN pairwiseConsistencyTest( CONTEXT_INFO *contextInfoPtr )
	{
	return( CRYPT_ERROR_NOTAVAIL );
	}

static int selfTest( void )
	{
	pairwiseConsistencyTest( NULL );	/* Keep compiler happy */
	return( CRYPT_ERROR_NOTAVAIL );
	}

/****************************************************************************
*																			*
*							Create/Check a Signature						*
*																			*
****************************************************************************/

/* Since ECDSA signature generation produces two values and the 
   cryptEncrypt() model only provides for passing a byte string in and out 
   (or, more specifically, the internal bignum data can't be exported to the 
   outside world), we need to encode the resulting data into a flat format.  
   This is done by encoding the output as an X9.31 Dss-Sig record, which is
   also used for ECDSA:

	Dss-Sig ::= SEQUENCE {
		r	INTEGER,
		s	INTEGER
		} */

/* Sign a single block of data  */

static int sign( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	return( CRYPT_ERROR_NOTAVAIL );
	}

/* Signature check a single block of data */

static int sigCheck( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	return( CRYPT_ERROR_NOTAVAIL );
	}

/****************************************************************************
*																			*
*								Key Management								*
*																			*
****************************************************************************/

/* Load key components into an encryption context */

static int initKey( CONTEXT_INFO *contextInfoPtr, const void *key,
					const int keyLength )
	{
	int status;

#ifndef USE_FIPS140
	/* Load the key component from the external representation into the
	   internal bignums unless we're doing an internal load */
	if( key != NULL )
		{
		PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
		const CRYPT_PKCINFO_ECC *eccKey = ( CRYPT_PKCINFO_ECC * ) key;
		int bnStatus = BN_STATUS;

		contextInfoPtr->flags |= ( eccKey->isPublicKey ) ? \
							CONTEXT_ISPUBLICKEY : CONTEXT_ISPRIVATEKEY;
		CKPTR( BN_bin2bn( eccKey->p, bitsToBytes( eccKey->pLen ),
						  &pkcInfo->eccParam_p ) );
		CKPTR( BN_bin2bn( eccKey->a, bitsToBytes( eccKey->aLen ),
						  &pkcInfo->eccParam_a ) );
		CKPTR( BN_bin2bn( eccKey->b, bitsToBytes( eccKey->bLen ),
						  &pkcInfo->eccParam_b ) );
		CKPTR( BN_bin2bn( eccKey->gx, bitsToBytes( eccKey->gxLen ),
						  &pkcInfo->eccParam_gx ) );
		CKPTR( BN_bin2bn( eccKey->gy, bitsToBytes( eccKey->gyLen ),
						  &pkcInfo->eccParam_gy ) );
		CKPTR( BN_bin2bn( eccKey->r, bitsToBytes( eccKey->rLen ),
						  &pkcInfo->eccParam_r ) );
		CKPTR( BN_bin2bn( eccKey->qx, bitsToBytes( eccKey->qxLen ),
						  &pkcInfo->eccParam_qx ) );
		CKPTR( BN_bin2bn( eccKey->qy, bitsToBytes( eccKey->qyLen ),
						  &pkcInfo->eccParam_qy ) );
		if( !eccKey->isPublicKey )
			CKPTR( BN_bin2bn( eccKey->d, bitsToBytes( eccKey->dLen ),
							  &pkcInfo->eccParam_d ) );
		contextInfoPtr->flags |= CONTEXT_PBO;
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		}
#endif /* USE_FIPS140 */

	/* Complete the key checking and setup */
	status = initECCkey( contextInfoPtr );
	if( cryptStatusOK( status ) )
		status = checkECCkey( contextInfoPtr );
	if( cryptStatusOK( status ) )
		status = contextInfoPtr->ctxPKC->calculateKeyIDFunction( contextInfoPtr );
	return( status );
	}

/* Generate a key into an encryption context */

static int generateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits )
	{
	int status;

	status = generateECCkey( contextInfoPtr, keySizeBits );
	if( cryptStatusOK( status ) &&
#ifndef USE_FIPS140
		( contextInfoPtr->flags & CONTEXT_SIDECHANNELPROTECTION ) &&
#endif /* USE_FIPS140 */
		!pairwiseConsistencyTest( contextInfoPtr ) )
		{
		assert( NOTREACHED );
		status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		status = contextInfoPtr->ctxPKC->calculateKeyIDFunction( contextInfoPtr );
	return( status );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO FAR_BSS capabilityInfo = {
	CRYPT_ALGO_ECDSA, bitsToBytes( 0 ), "ECDSA",
	MIN_PKCSIZE_ECC, bitsToBytes( 256 ), CRYPT_MAX_PKCSIZE_ECC,
	selfTest, getDefaultInfo, NULL, NULL, initKey, generateKey,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, sign, sigCheck
	};

const CAPABILITY_INFO *getECDSACapability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_ECC */
