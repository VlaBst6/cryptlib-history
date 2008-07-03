/****************************************************************************
*																			*
*					  Certificate Chain Management Routines					*
*						Copyright Peter Gutmann 1996-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL ) 
  #include "cert.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "misc_rw.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

/* When matching by subjectKeyIdentifier we don't use values less than 40
   bits because some CAs use monotonically increasing sequence numbers for 
   the sKID, which can clash with the same values when used by other CAs */

#define MIN_SKID_SIZE	5

/* A structure for storing pointers to parent and child (issuer and subject)
   names, key identifiers, and serial numbers (for finding a certificate by 
   issuerAndSerialNumber) and one for storing pointers to chaining info */

typedef struct {
	BUFFER_FIXED( issuerDNsize ) \
	const void *issuerDN;
	BUFFER_FIXED( subjectDNsize ) \
	const void *subjectDN;
	int issuerDNsize, subjectDNsize;
	BUFFER_OPT_FIXED( subjectKeyIDsize ) \
	const void *subjectKeyIdentifier;
	BUFFER_OPT_FIXED( issuerKeyIDsize ) \
	const void *issuerKeyIdentifier;
	int subjectKeyIDsize, issuerKeyIDsize;
	BUFFER_FIXED( serialNumberSize ) \
	const void *serialNumber;
	int serialNumberSize;
	} CHAIN_INFO;

typedef struct {
	BUFFER_FIXED( DNsize ) \
	const void *DN;
	BUFFER_FIXED( keyIDsize ) \
	const void *keyIdentifier;
	int DNsize, keyIDsize;
	} CHAINING_INFO;

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Copy subject or issuer chaining values from the chaining info */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void getSubjectChainingInfo( INOUT CHAINING_INFO *chainingInfo,
									const CHAIN_INFO *chainInfo )
	{
	assert( isWritePtr( chainingInfo, sizeof( CHAINING_INFO ) ) );
	assert( isReadPtr( chainInfo, sizeof( CHAIN_INFO ) ) );

	memset( chainingInfo, 0, sizeof( CHAINING_INFO ) );
	chainingInfo->DN = chainInfo->subjectDN;
	chainingInfo->DNsize = chainInfo->subjectDNsize;
	chainingInfo->keyIdentifier = chainInfo->subjectKeyIdentifier;
	chainingInfo->keyIDsize = chainInfo->subjectKeyIDsize;
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void getIssuerChainingInfo( INOUT CHAINING_INFO *chainingInfo,
								   const CHAIN_INFO *chainInfo )
	{
	assert( isWritePtr( chainingInfo, sizeof( CHAINING_INFO ) ) );
	assert( isReadPtr( chainInfo, sizeof( CHAIN_INFO ) ) );

	memset( chainingInfo, 0, sizeof( CHAINING_INFO ) );
	chainingInfo->DN = chainInfo->issuerDN;
	chainingInfo->DNsize = chainInfo->issuerDNsize;
	chainingInfo->keyIdentifier = chainInfo->issuerKeyIdentifier;
	chainingInfo->keyIDsize = chainInfo->issuerKeyIDsize;
	}

/* Determine whether a given certificate is the subject or issuer for the 
   requested certificate based on the chaining info.  We chain by issuer DN 
   if possible but if that fails we use the keyID.  This is somewhat dodgy 
   since it can lead to the situation where a certificate supposedly issued 
   by Verisign Class 1 Public Primary Certification Authority is actually 
   issued by Honest Joe's Used Cars but the standard requires this as a 
   fallback (PKIX section 4.2.1.1).
   
   There are actually two different interpretations of chaining by keyID, 
   the first says that the keyID is a non-DN identifier that can survive 
   operations such as cross-certification and re-parenting so that if a 
   straight chain by DN fails then a chain by keyID is possible as a 
   fallback option.  The second is that the keyID is a disambiguator if 
   multiple paths in a chain-by-DN scenario are present in a spaghetti PKI.  
   Since the latter is rather unlikely to occur in a standard PKCS #7/SSL 
   certificate chain (half the implementations around wouldn't be able to 
   assemble the chain any more) we use the former interpretation by default 
   but enable the latter if useStrictChaining is set.
   
   If useStrictChaining is enabled we require that the DN *and* the keyID 
   match, which (even without a spaghetti PKI being in effect) is required 
   to handle PKIX weirdness in which multiple potential issuers can be 
   present in a chain due to CA certificate renewals/reparenting.  We don't 
   do this by default because too many CAs get keyID chaining wrong, leading 
   to apparent breaks in the chain when the keyID fails to match.
   
   We don't have to worry about strict chaining for the issuer match because
   we only use it when we're walking down the chain looking for a leaf 
   certificate */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static BOOLEAN isSubject( const CHAINING_INFO *chainingInfo,
						  const CHAIN_INFO *chainInfo,
						  const BOOLEAN useStrictChaining )
	{
	BOOLEAN dnChains = FALSE, keyIDchains = FALSE;

	assert( isReadPtr( chainingInfo, sizeof( CHAINING_INFO ) ) );
	assert( isReadPtr( chainInfo, sizeof( CHAIN_INFO ) ) );

	/* Check for chaining by DN and keyID */
	if( chainingInfo->DNsize > 0 && \
		chainingInfo->DNsize == chainInfo->subjectDNsize && \
		!memcmp( chainingInfo->DN, chainInfo->subjectDN,
				 chainInfo->subjectDNsize ) )
		dnChains = TRUE;
	if( chainingInfo->keyIDsize > MIN_SKID_SIZE && \
		chainingInfo->keyIDsize == chainInfo->subjectKeyIDsize && \
		!memcmp( chainingInfo->keyIdentifier, 
				 chainInfo->subjectKeyIdentifier,
				 chainInfo->subjectKeyIDsize ) )
		keyIDchains = TRUE;

	/* If we're using strict chaining both the DN and keyID must chain */
	if( useStrictChaining )
		return( dnChains && keyIDchains );

	/* We're not using strict chaining, either can chain */
	return( dnChains || keyIDchains );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static BOOLEAN isIssuer( const CHAINING_INFO *chainingInfo,
						 const CHAIN_INFO *chainInfo )
	{
	assert( isReadPtr( chainingInfo, sizeof( CHAINING_INFO ) ) );
	assert( isReadPtr( chainInfo, sizeof( CHAIN_INFO ) ) );

	/* In the simplest case we chain by name.  This works for almost all
	   certificates */
	if( chainingInfo->DNsize > 0 && \
		chainingInfo->DNsize == chainInfo->issuerDNsize && \
		!memcmp( chainingInfo->DN, chainInfo->issuerDN,
				 chainInfo->issuerDNsize ) )
		return( TRUE );

	/* If that fails we chain by keyID */
	if( chainingInfo->keyIDsize > MIN_SKID_SIZE && \
		chainingInfo->keyIDsize == chainInfo->issuerKeyIDsize && \
		!memcmp( chainingInfo->keyIdentifier, 
				 chainInfo->issuerKeyIdentifier,
				 chainInfo->issuerKeyIDsize ) )
		return( TRUE );

	return( FALSE );
	}

/* Get the location and size of certificate attribute data required for
   chaining */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 3 ) ) \
static void *getChainingAttribute( INOUT CERT_INFO *certInfoPtr,
								   IN_ATTRIBUTE \
										const CRYPT_ATTRIBUTE_TYPE attributeType,
								   OUT_LENGTH_SHORT_Z int *attributeLength )
	{
	ATTRIBUTE_LIST *attributePtr;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( attributeLength, sizeof( int * ) ) );

	ENSURES_N( attributeType == CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER || \
			   attributeType == CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER );

	/* Clear return value */
	*attributeLength = 0;

	/* Find the requested attribute and return a pointer to it */
	attributePtr = findAttributeField( certInfoPtr->attributes,
									   attributeType, CRYPT_ATTRIBUTE_NONE );
	if( attributePtr == NULL )
		return( NULL );
	*attributeLength = attributePtr->valueLength;
	return( attributePtr->value );
	}

/* Free a certificate chain */

STDC_NONNULL_ARG( ( 1 ) ) \
static void freeCertChain( IN_ARRAY( certChainSize ) \
								CRYPT_CERTIFICATE *iCertChain,
						   IN_RANGE( 1, MAX_CHAINLENGTH ) \
								const int certChainSize )
	{
	int i;

	assert( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );
	assert( isWritePtr( iCertChain, sizeof( CRYPT_CERTIFICATE ) * certChainSize ) );

	REQUIRES_V( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );

	for( i = 0; i < certChainSize && i < MAX_CHAINLENGTH; i++ )
		{
		krnlSendNotifier( iCertChain[ i ], IMESSAGE_DESTROY );
		iCertChain[ i ] = CRYPT_ERROR;
		}
	}

/****************************************************************************
*																			*
*							Build a Certificate Chain						*
*																			*
****************************************************************************/

/* Build up the parent/child pointers for a certificate chain */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int buildChainInfo( INOUT CHAIN_INFO *chainInfo,
						   IN_ARRAY( certChainSize ) \
								const CRYPT_CERTIFICATE *iCertChain,
						   IN_RANGE( 1, MAX_CHAINLENGTH ) \
								const int certChainSize )
	{
	int i;

	assert( isWritePtr( chainInfo, sizeof( CHAIN_INFO ) * certChainSize ) );
	assert( isReadPtr( iCertChain, sizeof( CRYPT_CERTIFICATE ) * certChainSize ) );

	REQUIRES( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );

	/* Extract the subject and issuer DNs and key identifiers from each
	   certificate.  Maintaining an external pointer into the internal
	   structure is safe since the objects are reference-counted and won't be
	   destroyed until the encapsulating certificate is destroyed */
	for( i = 0; i < certChainSize && i < MAX_CHAINLENGTH; i++ )
		{
		CERT_INFO *certChainPtr;
		int status;

		status = krnlAcquireObject( iCertChain[ i ], OBJECT_TYPE_CERTIFICATE, 
									( void ** ) &certChainPtr, 
									CRYPT_ERROR_SIGNALLED );
		if( cryptStatusError( status ) )
			return( status );
		chainInfo[ i ].subjectDN = certChainPtr->subjectDNptr;
		chainInfo[ i ].issuerDN = certChainPtr->issuerDNptr;
		chainInfo[ i ].subjectDNsize = certChainPtr->subjectDNsize;
		chainInfo[ i ].issuerDNsize = certChainPtr->issuerDNsize;
		chainInfo[ i ].subjectKeyIdentifier = \
			getChainingAttribute( certChainPtr, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
								  &chainInfo[ i ].subjectKeyIDsize );
		chainInfo[ i ].issuerKeyIdentifier = \
			getChainingAttribute( certChainPtr, CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,
								  &chainInfo[ i ].issuerKeyIDsize );
		chainInfo[ i ].serialNumber = certChainPtr->cCertCert->serialNumber;
		chainInfo[ i ].serialNumberSize = certChainPtr->cCertCert->serialNumberLength;
		krnlReleaseObject( certChainPtr->objectHandle );
		}
	ENSURES( i < MAX_CHAINLENGTH );

	return( CRYPT_OK );
	}

/* Find the leaf node in a (possibly unordered) certificate chain by walking 
   down the chain as far as possible.  The strategy we use is to pick an 
   initial certificate (which is often the leaf cert anyway) and keep 
   looking for certificates it (or its successors) have issued until we 
   reach the end of the chain.  Returns the position of the leaf node in the 
   chain */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int findLeafNode( IN_ARRAY( certChainSize ) const CHAIN_INFO *chainInfo,
						 IN_RANGE( 1, MAX_CHAINLENGTH ) const int certChainSize )
	{
	CHAINING_INFO chainingInfo;
	BOOLEAN certUsed[ MAX_CHAINLENGTH + 8 ], moreMatches;
	int lastCertPos, iterationCount;

	assert( isReadPtr( chainInfo, sizeof( CHAIN_INFO ) * certChainSize ) );

	REQUIRES( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );

	/* We start our search at the first certificate, which is often the leaf 
	   certificate anyway */
	memset( certUsed, 0, MAX_CHAINLENGTH * sizeof( BOOLEAN ) );
	getSubjectChainingInfo( &chainingInfo, &chainInfo[ 0 ] );
	certUsed[ 0 ] = TRUE;
	lastCertPos = 0;

	/* Walk down the chain from the currently selected certificate checking 
	   for certificates issued by it until we can't go any further.  Note 
	   that this algorithm handles chains with PKIX path-kludge certificates 
	   as well as normal ones since it marks a certificate as used once it 
	   processes it for the first time, avoiding potential endless loops on 
	   subject == issuer path-kludge certificates */
	for( moreMatches = TRUE, iterationCount = 0;
		 moreMatches && iterationCount < FAILSAFE_ITERATIONS_MED;
		 iterationCount++ )
		{
		int i;

		/* Try and find a certificate issued by the current certificate */
		for( moreMatches = FALSE, i = 0; 
			 i < certChainSize && i < MAX_CHAINLENGTH; i++ )
			{
			if( !certUsed[ i ] && \
				isIssuer( &chainingInfo, &chainInfo[ i ] ) )
				{
				/* There's another certificate below the current one in the 
				   chain, mark the current one as used and move on to the next
				   one */
				getSubjectChainingInfo( &chainingInfo, &chainInfo[ i ] );
				certUsed[ i ] = TRUE;
				moreMatches = TRUE;
				lastCertPos = i;
				break;
				}
			}
		ENSURES( i < MAX_CHAINLENGTH );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( lastCertPos );
	}

/* Find a leaf node as identified by issuerAndSerialNumber.  Returns the 
   position of the leaf node in the chain */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
static int findIdentifiedLeafNode( IN_ARRAY( certChainSize ) \
										const CHAIN_INFO *chainInfo,
								   IN_RANGE( 1, MAX_CHAINLENGTH ) \
										const int certChainSize,
								   IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
								   IN_BUFFER( keyIDlength ) const void *keyID, 
								   IN_LENGTH_KEYID const int keyIDlength )
	{
	STREAM stream;
	void *serialNumber = DUMMY_INIT_PTR, *issuerDNptr = DUMMY_INIT_PTR;
	int issuerDNsize, serialNumberSize;
	int i, status;

	assert( isReadPtr( chainInfo, sizeof( CHAIN_INFO ) * certChainSize ) );
	assert( isReadPtr( keyID, keyIDlength ) );

	REQUIRES( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );
	REQUIRES( keyIDtype == CRYPT_IKEYID_KEYID || \
			  keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER );
	REQUIRES( keyID != NULL && \
			  keyIDlength >= MIN_SKID_SIZE && \
			  keyIDlength < MAX_ATTRIBUTE_SIZE );

	/* If it's a subjectKeyIdentifier, walk down the chain looking for a
	   match */
	if( keyIDtype == CRYPT_IKEYID_KEYID )
		{
		for( i = 0; i < certChainSize && i < MAX_CHAINLENGTH; i++ )
			{
			if( chainInfo[ i ].subjectKeyIDsize > MIN_SKID_SIZE && \
				chainInfo[ i ].subjectKeyIDsize == keyIDlength && \
				!memcmp( chainInfo[ i ].subjectKeyIdentifier, keyID,
						 keyIDlength ) )
				return( i );
			}
		ENSURES( i < MAX_CHAINLENGTH );
		return( CRYPT_ERROR_NOTFOUND );
		}

	/* It's an issuerAndSerialNumber, extract the issuer DN and serial 
	   number */
	sMemConnect( &stream, keyID, keyIDlength );
	readSequence( &stream, NULL );
	status = getStreamObjectLength( &stream, &issuerDNsize );
	if( cryptStatusOK( status ) )
		status = sMemGetDataBlock( &stream, &issuerDNptr, issuerDNsize );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( CRYPT_ERROR_NOTFOUND );
		}
	sSkip( &stream, issuerDNsize );				/* Issuer DN */
	status = readGenericHole( &stream, &serialNumberSize, 1, BER_INTEGER );
	if( cryptStatusOK( status ) )				/* Serial number */
		status = sMemGetDataBlock( &stream, &serialNumber, 
								   serialNumberSize );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_NOTFOUND );

	/* Walk down the chain looking for the one identified by the 
	   issuerAndSerialNumber */
	for( i = 0; i < certChainSize && i < MAX_CHAINLENGTH; i++ )
		{
		if( chainInfo[ i ].issuerDNsize > 0 && \
			chainInfo[ i ].issuerDNsize == issuerDNsize && \
			!memcmp( chainInfo[ i ].issuerDN, issuerDNptr,
					 issuerDNsize ) && \
			compareSerialNumber( chainInfo[ i ].serialNumber, 
								 chainInfo[ i ].serialNumberSize,
								 serialNumber, serialNumberSize ) )
			return( i );
		}
	ENSURES( i < MAX_CHAINLENGTH );

	return( CRYPT_ERROR_NOTFOUND );
	}

/* Sort the issuer certificates in a certificate chain, discarding any 
   unnecessary certificates.  If we're canonicalising an existing chain then 
   the start point in the chain is given by certChainStart and the -1th 
   certificate is the end user certificate and isn't part of the ordering 
   process.  If we're building a new chain from an arbitrary set of 
   certificates then the start point is given by the chaining info for the 
   leaf certificate.

   The canonicalisation of the chain can be handled in one of two ways, the 
   logical way and the PKIX way.  The latter allows apparently self-signed
   certificates in the middle of a chain due to certificate 
   renewals/reparenting, which completely breaks the standard certificate 
   convention that a self-signed cert is a root CA.  This means that without 
   special handling the chain will terminate at a certificate that appears 
   to be (but isn't) the CA root certificate.  A sample chain of this form 
   (in this case involving an oldWithNew certificate) is as follows:

	Issuer		Subject		Key/sKID	Sig/aKID
	------		-------		--------	----------
	Root		CA			ca_new		root
	CA			CA			ca_old		ca_new
	CA			EE			ee			ca_old

   In order to handle these chains we need to match by both DN *and* keyID,
   however since so many CAs get keyIDs wrong enabling this by default 
   would break many certificate chains.  To handle this we only enable the 
   extra-match behaviour if the compliance level is 
   CRYPT_COMPLIANCELEVEL_PKIX_FULL, for which people should be expecting all 
   sorts of weird behaviour anyway.
   
   Returns the length of the ordered chain */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int sortCertChain( IN_ARRAY( certChainSize ) CRYPT_CERTIFICATE *iCertChain,
						  IN_ARRAY( certChainSize ) CHAIN_INFO *chainInfo,
						  IN_RANGE( 1, MAX_CHAINLENGTH ) const int certChainSize,
						  IN_HANDLE_OPT const CRYPT_CERTIFICATE certChainStart,
						  IN_OPT CHAINING_INFO *chainingInfo,
						  const BOOLEAN useStrictChaining )
	{
	CRYPT_CERTIFICATE orderedChain[ MAX_CHAINLENGTH + 8 ];
	CHAINING_INFO localChainingInfo, *chainingInfoPtr = &localChainingInfo;
	BOOLEAN moreMatches;
	const int maxMatchLevel = useStrictChaining ? 1 : 0;
	int orderedChainIndex = 0, iterationCount, i;

	assert( isWritePtr( iCertChain, sizeof( CRYPT_CERTIFICATE ) * certChainSize ) );
	assert( isWritePtr( chainInfo, sizeof( CHAIN_INFO ) * certChainSize ) );
	assert( ( isHandleRangeValid( certChainStart ) && \
			  chainingInfo == NULL ) || \
			( certChainStart == CRYPT_UNUSED && \
			  isWritePtr( chainingInfo, sizeof( CHAINING_INFO ) ) ) );

	REQUIRES( certChainSize > 0 && certChainSize < MAX_CHAINLENGTH );
	REQUIRES( ( isHandleRangeValid( certChainStart ) && \
				chainingInfo == NULL ) || \
			  ( certChainStart == CRYPT_UNUSED && \
				chainingInfo != NULL ) );

	/* If we're canonicalising an existing chain there's a predefined chain
	   start that we copy over and prepare to look for the next certificate 
	   up the chain */
	if( certChainStart != CRYPT_UNUSED )
		{
		orderedChain[ orderedChainIndex++ ] = certChainStart;
		getIssuerChainingInfo( chainingInfoPtr, &chainInfo[ 0 ] );
		memset( &chainInfo[ 0 ], 0, sizeof( CHAIN_INFO ) );
		}
	else
		{
		/* We're building a new chain, the caller has supplied the chaining
		   info */
		chainingInfoPtr = chainingInfo;
		}

	/* Build an ordered chain of certificates from the leaf to the root */
	for( moreMatches = TRUE, iterationCount = 0;
		 moreMatches && iterationCount < FAILSAFE_ITERATIONS_MED;
		 iterationCount++ )
		{
		int matchLevel;

		/* Find the certificate with the current issuer as its subject.  If 
		   we're using strict chaining we first try a strict match 
		   (matchLevel = TRUE), if that fails we fall back to a standard 
		   match (matchLevel = FALSE).  This is required to handle the
		   significant number of CAs that don't get chaining by keyID 
		   right */
		for( moreMatches = FALSE, matchLevel = maxMatchLevel; \
			 !moreMatches && matchLevel >= 0; matchLevel-- )
			{
			for( i = 0; i < certChainSize && i < MAX_CHAINLENGTH; i++ )
				{
				if( chainInfo[ i ].subjectDN != NULL && \
					isSubject( chainingInfoPtr, &chainInfo[ i ], 
							   matchLevel ) )
					{
					/* We've found the issuer, move the certificates to the 
					   ordered chain and prepare to find the issuer of this 
					   certificate */
					orderedChain[ orderedChainIndex++ ] = iCertChain[ i ];
					ENSURES( orderedChainIndex < MAX_CHAINLENGTH );
					getIssuerChainingInfo( chainingInfoPtr, &chainInfo[ i ] );
					memset( &chainInfo[ i ], 0, sizeof( CHAIN_INFO ) );
					moreMatches = TRUE;
					break;
					}
				}
			ENSURES( i < MAX_CHAINLENGTH );
			}
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	/* If there are any certificates left they're not needed for anything 
	   so we can free the resources */
	for( i = 0; i < certChainSize && i < MAX_CHAINLENGTH; i++ )
		{
		if( chainInfo[ i ].subjectDN != NULL )
			krnlSendNotifier( iCertChain[ i ], IMESSAGE_DECREFCOUNT );
		}
	ENSURES( i < MAX_CHAINLENGTH );

	/* Replace the existing chain with the ordered version */
	memset( iCertChain, 0, sizeof( CRYPT_CERTIFICATE ) * MAX_CHAINLENGTH );
	if( orderedChainIndex > 0 )
		{
		memcpy( iCertChain, orderedChain,
				sizeof( CRYPT_CERTIFICATE ) * orderedChainIndex );
		}

	return( orderedChainIndex );
	}

/* Read a collection of certificates in a certificate chain into a cert 
   object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int buildCertChain( IN_ARRAY( certChainEnd ) CRYPT_CERTIFICATE *iLeafCert, 
						   IN_ARRAY( certChainEnd ) CRYPT_CERTIFICATE *iCertChain, 
						   IN_RANGE( 1, MAX_CHAINLENGTH ) const int certChainEnd,
						   IN_KEYID_OPT const CRYPT_KEYID_TYPE keyIDtype,
						   IN_BUFFER_OPT( keyIDlength ) const void *keyID, 
						   IN_LENGTH_KEYID_Z const int keyIDlength )
	{
	CHAIN_INFO chainInfo[ MAX_CHAINLENGTH + 8 ];
	CERT_INFO *certChainPtr;
	CHAINING_INFO chainingInfo;
	int leafNodePos, newCertChainEnd, complianceLevel, status;

	assert( isWritePtr( iLeafCert, \
			sizeof( CRYPT_CERTIFICATE ) * certChainEnd ) );
	assert( isReadPtr( iCertChain, \
			sizeof( CRYPT_CERTIFICATE ) * certChainEnd ) );
	assert( ( keyIDtype == CRYPT_KEYID_NONE && \
			  keyID == NULL && keyIDlength == 0 ) || \
			( ( keyIDtype == CRYPT_IKEYID_KEYID || \
				keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER ) && \
			  isReadPtr( keyID, keyIDlength ) ) );

	REQUIRES( certChainEnd > 0 && certChainEnd < MAX_CHAINLENGTH );
	REQUIRES( ( keyIDtype == CRYPT_KEYID_NONE && \
				keyID == NULL && keyIDlength == 0 ) || \
			  ( ( keyIDtype == CRYPT_IKEYID_KEYID || \
				  keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER ) && \
				keyID != NULL && \
				keyIDlength >= MIN_SKID_SIZE && \
				keyIDlength < MAX_ATTRIBUTE_SIZE ) );

	status = krnlSendMessage( iCertChain[ 0 ], IMESSAGE_GETATTRIBUTE, 
							  &complianceLevel, 
							  CRYPT_OPTION_CERT_COMPLIANCELEVEL );
	if( cryptStatusError( status ) )
		return( status );

	/* We've now got a collection of certificates in unknown order (although 
	   it's common for the first certificate to be the leaf).  Extract the 
	   chaining info and search the chain for the leaf node */
	status = buildChainInfo( chainInfo, iCertChain, certChainEnd );
	if( cryptStatusError( status ) )
		{
		freeCertChain( iCertChain, certChainEnd );
		return( status );
		}
	if( keyID != NULL )
		{
		leafNodePos = findIdentifiedLeafNode( chainInfo, certChainEnd,
											  keyIDtype, keyID, keyIDlength );
		}
	else
		leafNodePos = findLeafNode( chainInfo, certChainEnd );
	if( cryptStatusError( leafNodePos ) )
		{
		freeCertChain( iCertChain, certChainEnd );
		return( leafNodePos );
		}

	/* Now that we have the leaf node, clear its entry in the chain to make
	   sure that it isn't used for further processing, order the remaining 
	   certificates up to the root, and discard any unneeded certificates */
	*iLeafCert = iCertChain[ leafNodePos ];
	getIssuerChainingInfo( &chainingInfo, &chainInfo[ leafNodePos ] );
	memset( &chainInfo[ leafNodePos ], 0, sizeof( CHAIN_INFO ) );
	status = newCertChainEnd = sortCertChain( iCertChain, chainInfo, 
					certChainEnd, CRYPT_UNUSED, &chainingInfo,
					( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_FULL ) ? \
					TRUE : FALSE );
	if( cryptStatusError( status ) )
		{
		/* We've cleared the leaf node entry in the chain so we have to 
		   explicitly clean up the corresponding certificate */
		krnlSendNotifier( *iLeafCert, IMESSAGE_DECREFCOUNT );
		freeCertChain( iCertChain, certChainEnd );
		return( status );
		}
	newCertChainEnd = status;
	if( newCertChainEnd <= 0 )
		{
		/* There's only one certificate in the chain either due to the 
		   chain containing only a single certificate or due to all other 
		   certificates being discarded, leave it as a standalone 
		   certificate rather than turning it into a chain */
		return( CRYPT_OK );
		}

	/* Walk up the chain re-setting the pseudo-selfsigned flag on any
	   chain-internal path-kludge certificates if necessary.  This means 
	   that if the chain contains n certificates we reset the flag on 
	   certificates 0...n-1.  This is required when there's a re-issued 
	   certificate kludged into the middle of the path to connect a new CA 
	   signing key with a certificate signed with the old key.  Note that 
	   this can't detect the case where the first certificate in the chain 
	   is a path kludge certificate with further certificates held 
	   externally, e.g. in the trusted certificate store, since it appears 
	   as a self-signed CA root certificate */
	if( complianceLevel >= CRYPT_COMPLIANCELEVEL_PKIX_FULL )
		{
		int i;

		for( i = 0; i < newCertChainEnd - 1 && i < MAX_CHAINLENGTH; i++ )
			{
			CERT_INFO *certInfoPtr;
			int value;

			/* Check whether this is a self-signed certificate */
			status = krnlSendMessage( iCertChain[ i ], IMESSAGE_GETATTRIBUTE,
									  &value, CRYPT_CERTINFO_SELFSIGNED );
			if( cryptStatusError( status ) || !value )
				continue;

			/* Convert the self-signed flag into the pseudo self-signed/path
			   kludge flag */
			status = krnlAcquireObject( iCertChain[ i ], OBJECT_TYPE_CERTIFICATE, 
										( void ** ) &certInfoPtr, 
										CRYPT_ERROR_SIGNALLED );
			if( cryptStatusError( status ) )
				continue;
			certInfoPtr->flags &= ~CERT_FLAG_SELFSIGNED;
			certInfoPtr->flags |= CERT_FLAG_PATHKLUDGE;
			krnlReleaseObject( certInfoPtr->objectHandle );
			}
		ENSURES( i < MAX_CHAINLENGTH );
		}

	/* Finally, we've got the leaf certificate and a chain up to the root.  
	   Make the leaf a certificate-chain type and copy in the chain */
	status = krnlAcquireObject( *iLeafCert, OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &certChainPtr, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		{
		/* We've cleared the leaf node entry in the chain so we have to 
		   explicitly clean up the corresponding certificate */
		krnlSendNotifier( *iLeafCert, IMESSAGE_DECREFCOUNT );
		freeCertChain( iCertChain, newCertChainEnd );
		return( status );
		}
	memcpy( certChainPtr->cCertCert->chain, iCertChain,
			newCertChainEnd * sizeof( CRYPT_CERTIFICATE ) );
	certChainPtr->cCertCert->chainEnd = newCertChainEnd;
	certChainPtr->type = CRYPT_CERTTYPE_CERTCHAIN;
	krnlReleaseObject( certChainPtr->objectHandle );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Copy a Certificate Chain						*
*																			*
****************************************************************************/

/* Determine whether a certificate is present in a cert collection based on 
   its fingerprint */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN certPresent( BYTE certChainHashes[][ CRYPT_MAX_HASHSIZE + 8 ],
							IN_RANGE( 0, MAX_CHAINLENGTH ) const int certChainLen, 
							IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	MESSAGE_DATA msgData;
	int i, status;

	assert( isWritePtr( certChainHashes, \
						MAX_CHAINLENGTH * CRYPT_MAX_HASHSIZE ) );

	REQUIRES_B( certChainLen >= 0 && certChainLen < MAX_CHAINLENGTH );
				/* Apparent length may be zero for a chain of size 1 since
				   the leaf cert has effective index value -1 */
	REQUIRES_B( isHandleRangeValid( iCryptCert ) );

	/* Get the fingerprint of the (potential) next certificate in the 
	   collection.  This leaves it at the end of the existing collection of 
	   hashes so that if the certificate is then added to the chain its hash 
	   will also be present */
	setMessageData( &msgData, certChainHashes[ certChainLen ], 
					CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_FINGERPRINT );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that it isn't already present in the collection */
	for( i = 0; i < certChainLen && i < MAX_CHAINLENGTH; i++ )
		{
		if( !memcmp( certChainHashes[ i ], 
					 certChainHashes[ certChainLen ], msgData.length ) )
			return( TRUE );
		}
	return( FALSE );
	}

/* Copy a certificate chain into a certificate object and canonicalise the 
   chain by ordering the certificates from the leaf certificate up to the 
   root.  This function is used when signing a certificate with a cert 
   chain and takes as input ( oldCert, oldCert.chain[ ... ] ) and produces 
   as output ( newCert, chain[ oldCert, oldCert.chain[ ... ] ], i.e. the 
   chain for the new certificate contains the old certificate and its 
   attached certificate chain */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int copyCertChain( INOUT CERT_INFO *certInfoPtr, 
				   IN_HANDLE const CRYPT_HANDLE certChain,
				   const BOOLEAN isCertCollection )
	{
	CRYPT_CERTIFICATE iChainCert;
	CERT_INFO *chainCertInfoPtr;
	CERT_CERT_INFO *certChainInfo = certInfoPtr->cCertCert;
	CHAIN_INFO chainInfo[ MAX_CHAINLENGTH + 8 ];
	BYTE certChainHashes[ MAX_CHAINLENGTH + 1 + 8 ][ CRYPT_MAX_HASHSIZE + 8 ];
	const int oldChainEnd = certChainInfo->chainEnd;
	int i, status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( isHandleRangeValid( certChain ) );

	status = krnlSendMessage( certChain, IMESSAGE_GETDEPENDENT, &iChainCert, 
							  OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're building a certificate collection all that we need to ensure 
	   is non-duplicate certificates rather than a strict chain.  To handle 
	   duplicate-checking we build a list of the fingerprints for each 
	   certificate in the chain */
	if( isCertCollection )
		{
		for( i = 0; i < certChainInfo->chainEnd && i < MAX_CHAINLENGTH; i++ )
			{
			MESSAGE_DATA msgData;

			setMessageData( &msgData, certChainHashes[ i ], 
							CRYPT_MAX_HASHSIZE );
			status = krnlSendMessage( certChainInfo->chain[ i ], 
									  IMESSAGE_GETATTRIBUTE_S, &msgData, 
									  CRYPT_CERTINFO_FINGERPRINT );
			if( cryptStatusError( status ) )
				return( status );
			}
		ENSURES( i < MAX_CHAINLENGTH );
		}

	/* Extract the base certificate from the chain and copy it over (the
	   certPresent() check also sets up the hash for the new certificate in 
	   the certChainHashes array) */
	status = krnlAcquireObject( iChainCert, OBJECT_TYPE_CERTIFICATE, 
								( void ** ) &chainCertInfoPtr, 
								CRYPT_ERROR_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	if( !isCertCollection || \
		!certPresent( certChainHashes, certChainInfo->chainEnd, iChainCert ) )
		{
		if( certChainInfo->chainEnd >= MAX_CHAINLENGTH )
			status = CRYPT_ERROR_OVERFLOW;
		else
			{
			krnlSendNotifier( iChainCert, IMESSAGE_INCREFCOUNT );
			certChainInfo->chain[ certChainInfo->chainEnd++ ] = iChainCert;
			}
		}

	/* Copy the rest of the chain.  Because we're about to canonicalise it
	   (which re-orders the certificates and deletes unused ones) we copy 
	   individual certificates over rather than copying only the base 
	   certificate and relying on the chain held in that */
	for( i = 0; cryptStatusOK( status ) && \
				i < chainCertInfoPtr->cCertCert->chainEnd && \
				i < MAX_CHAINLENGTH; i++ )
		{
		if( !isCertCollection || \
			!certPresent( certChainHashes, certChainInfo->chainEnd,
						  chainCertInfoPtr->cCertCert->chain[ i ] ) )
			{
			const CRYPT_CERTIFICATE iCopyCert = \
								chainCertInfoPtr->cCertCert->chain[ i ];

			if( certChainInfo->chainEnd >= MAX_CHAINLENGTH )
				{
				status = CRYPT_ERROR_OVERFLOW;
				break;
				}
			krnlSendNotifier( iCopyCert, IMESSAGE_INCREFCOUNT );
			certChainInfo->chain[ certChainInfo->chainEnd++ ] = iCopyCert;
			}
		}
	ENSURES( i < MAX_CHAINLENGTH );
	krnlReleaseObject( chainCertInfoPtr->objectHandle );
	if( cryptStatusError( status ) )
		{
		/* An error at this point indicates that the upper limit on chain
		   length isn't sufficient so we throw a (debug) exception if we 
		   get here */
		assert( DEBUG_WARN );

		/* Clean up the newly-copied certificates if necessary */
		if( certChainInfo->chainEnd > oldChainEnd )
			{
			freeCertChain( &certChainInfo->chain[ oldChainEnd ],
						   certChainInfo->chainEnd - oldChainEnd );
			}

		return( status );
		}

	/* If we're building an unordered certificate collection, mark the 
	   certificate chain object as a certificate collection only and exit.  
	   This is a pure container object for which only the certificate chain 
	   member contains certificates, the base certificate object doesn't 
	   correspond to an actual certificate */
	if( isCertCollection )
		{
		certInfoPtr->flags |= CERT_FLAG_CERTCOLLECTION;
		return( CRYPT_OK );
		}

	/* If the chain being attached consists of a single certificate (which 
	   occurs when we're building a new chain by signing a certificate with 
	   a CA certificate) we don't have to bother doing anything else */
	if( chainCertInfoPtr->cCertCert->chainEnd <= 0 )
		return( CRYPT_OK );

	/* Extract the chaining info from each certificate and use it to sort 
	   the chain.  Since we know what the leaf certificate is and since 
	   chaining info such as the encoded DN data in the certinfo structure 
	   may not have been set up yet if it contains an unsigned certificate 
	   we feed in the leaf certificate and omit the chaining information.  
	   Since sortCertChain() deletes unused certificates (and never returns 
	   an error status, all it does is shuffle existing certificates around) 
	   we only perform a cleanup if the chain-build fails */
	status = buildChainInfo( chainInfo, certChainInfo->chain,
							 certChainInfo->chainEnd );
	if( cryptStatusError( status ) )
		{
		/* Clean up the newly-copied certificates if necessary */
		if( certChainInfo->chainEnd > oldChainEnd )
			{
			freeCertChain( &certChainInfo->chain[ oldChainEnd ],
						   certChainInfo->chainEnd - oldChainEnd );
			}

		return( status );
		}
	certChainInfo->chainEnd = sortCertChain( certChainInfo->chain, chainInfo,
											 certChainInfo->chainEnd, 
											 iChainCert, NULL, FALSE );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Read Certificate-bagging Records					*
*																			*
****************************************************************************/

/* Read certificate chain/sequence information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCertChain( INOUT STREAM *stream, 
				   OUT CRYPT_CERTIFICATE *iCryptCert,
				   IN_HANDLE const CRYPT_USER iCryptOwner,
				   IN_ENUM( CRYPT_CERTTYPE ) const CRYPT_CERTTYPE_TYPE type,
				   IN_KEYID_OPT const CRYPT_KEYID_TYPE keyIDtype,
				   IN_BUFFER_OPT( keyIDlength ) const void *keyID, 
				   IN_LENGTH_KEYID_Z const int keyIDlength,
				   const BOOLEAN dataOnlyCert )
	{
	CRYPT_CERTIFICATE iCertChain[ MAX_CHAINLENGTH + 8 ];
	int certSequenceLength, endPos = 0, certChainEnd = 0;
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( iCryptCert, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( ( keyIDtype == CRYPT_KEYID_NONE && keyID == NULL && \
			  keyIDlength == 0 ) || \
			( ( keyIDtype == CRYPT_IKEYID_KEYID || \
				keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER ) && \
			  isReadPtr( keyID, keyIDlength ) && \
			  keyIDlength >= MIN_SKID_SIZE ) );

	REQUIRES( iCryptOwner == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( iCryptOwner ) );
	REQUIRES( type == CRYPT_CERTTYPE_CERTCHAIN || \
			  type == CRYPT_ICERTTYPE_CMS_CERTSET || \
			  type == CRYPT_ICERTTYPE_SSL_CERTCHAIN );
	REQUIRES( ( keyIDtype == CRYPT_KEYID_NONE && \
				keyID == NULL && keyIDlength == 0 ) || \
			  ( ( keyIDtype == CRYPT_IKEYID_KEYID || \
				  keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER ) && \
				keyID != NULL && \
				keyIDlength >= MIN_SKID_SIZE && \
				keyIDlength < MAX_ATTRIBUTE_SIZE ) );

	switch( type )
		{
		case CRYPT_CERTTYPE_CERTCHAIN:
			{
			BYTE oid[ MAX_OID_SIZE + 8 ];
			long integer;
			int length, oidLength;

			/* Skip the contentType OID, read the content encapsulation and 
			   header if necessary, and burrow down into the PKCS #7 content.  
			   First we read the wrapper.  We use readEncodedOID() rather 
			   than readUniversal() to make sure that we're at least getting 
			   an OID at this point */
			status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
									 BER_OBJECT_IDENTIFIER );
			if( cryptStatusError( status ) )
				return( status );
			readConstructed( stream, NULL, 0 );
			readSequence( stream, NULL );

			/* Read the version number (1 = PKCS #7 v1.5, 2 = PKCS #7 v1.6,
			   3 = S/MIME with attribute certificate(s)), and (should be 
			   empty) SET OF DigestAlgorithmIdentifier */
			readShortInteger( stream, &integer );
			status = readSet( stream, &length );
			if( cryptStatusOK( status ) && ( integer < 1 || integer > 3 ) )
				status = CRYPT_ERROR_BADDATA;
			if( cryptStatusError( status ) )
				return( status );
			if( length > 0 )
				sSkip( stream, length );

			/* Read the ContentInfo header, contentType OID (ignored) and 
			   the inner content encapsulation.  We use readEncodedOID()
			   rather than readUniversal() to make sure that we're at least
			   getting an OID at this point.

			   Sometimes we may (incorrectly) get passed actual signed data 
			   (rather than degenerate zero-length data signifying a pure 
			   certificate chain), if there's data present then we skip it */
			readSequenceI( stream, &length );
			status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
									 BER_OBJECT_IDENTIFIER );
			if( cryptStatusError( status ) )
				return( status );
			if( length == CRYPT_UNUSED )
				{
				/* It's an indefinite-length ContentInfo, check for the 
				   EOC.  If there's no EOC present that means there's 
				   indefinite-length inner data present and we have to dig 
				   down further */
				status = checkEOC( stream );
				if( cryptStatusError( status ) )
					return( status );
				if( status == FALSE )
					{
					int innerLength;

					/* Try and get the length from the ContentInfo.  We're
					   really reaching the point of diminishing return here,
					   if we can't get a length at this point we bail out
					   since we're not even supposed to be getting down to
					   this level */
					status = readConstructedI( stream, &innerLength, 0 );
					if( cryptStatusError( status ) )
						return( status );
					if( innerLength == CRYPT_UNUSED )
						return( CRYPT_ERROR_BADDATA );
					status = sSkip( stream, innerLength );
					}
				}
			else
				{
				/* If we've been fed signed data (i.e. the ContentInfo has 
				   the content field present) skip the content to get to the 
				   certificate chain */
				if( length > sizeofObject( oidLength ) )
					status = readUniversal( stream );
				}
			status = readConstructedI( stream, &certSequenceLength, 0 );
			break;
			}

		case CRYPT_ICERTTYPE_CMS_CERTSET:
			status = readConstructedI( stream, &certSequenceLength, 0 );
			break;

		case CRYPT_ICERTTYPE_SSL_CERTCHAIN:
			/* There's no outer wrapper to give us length information for an 
			   SSL certificate chain however the length will be equal to the 
			   total remaining stream size */
			certSequenceLength = sMemDataLeft( stream );
			status = CRYPT_OK;
			break;

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If it's a definite-length chain, determine where it ends */
	if( certSequenceLength != CRYPT_UNUSED )
		endPos = stell( stream ) + certSequenceLength;

	/* We've finally reached the certificate(s), read the collection of 
	   certificates into certificate objects.  We allow for a bit of slop 
	   for software that gets the length encoding wrong by a few bytes.  
	   Note that the limit is given as FAILSAFE_ITERATIONS_MED since we're 
	   using it as a fallback check on the existing MAX_CHAINLENGTH check.  
	   In other words anything over MAX_CHAINLENGTH is handled as a normal 
	   error and it's only if we exceed this that we have an internal 
	   error */
	for( iterationCount = 0;
		 ( certSequenceLength == CRYPT_UNUSED || \
		   stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE ) && \
			iterationCount < FAILSAFE_ITERATIONS_MED; 
		 iterationCount++ )
		{
		CRYPT_CERTIFICATE iNewCert = DUMMY_INIT;
		void *dataPtr;
		int length;

		/* Make sure that we don't overflow the chain */
		if( certChainEnd >= MAX_CHAINLENGTH )
			{
			freeCertChain( iCertChain, certChainEnd );
			return( CRYPT_ERROR_OVERFLOW );
			}

		/* If it's an SSL certificate chain then there's a 24-bit length 
		   field between certificates */
		if( type == CRYPT_ICERTTYPE_SSL_CERTCHAIN )
			sSkip( stream, 3 );

		/* Read the next certificate and add it to the chain.  When 
		   importing the chain from an external (untrusted) source we create 
		   standard certificates so that we can check the signatures on each 
		   link in the chain.  When importing from a trusted source we 
		   create data-only certificates, once we've got all of the 
		   certificates and know which certificate is the leaf we can go 
		   back and decode the public key information for it */
		status = sMemGetDataBlockRemaining( stream, &dataPtr, &length );
		if( cryptStatusOK( status ) )
			{
			status = importCert( dataPtr, length, &iNewCert, iCryptOwner, 
								 CRYPT_KEYID_NONE, NULL, 0, 
								 dataOnlyCert ? \
									CRYPT_ICERTTYPE_DATAONLY : \
									CRYPT_CERTTYPE_CERTIFICATE );
			}
		if( cryptStatusOK( status ) )
			{
			MESSAGE_DATA msgData;

			/* Add the newly-read certificate to the chain and skip over its 
			   encoded data.  Unfortunately due to the mixing of stream and 
			   non-stream functions we have to do this in a somewhat 
			   roundabout manner by getting the length of the data in the 
			   newly-created certificate object and then skipping that far 
			   ahead in the input stream */
			iCertChain[ certChainEnd++ ] = iNewCert;
			setMessageData( &msgData, NULL, 0 );
			status = krnlSendMessage( iNewCert, IMESSAGE_CRT_EXPORT, 
									  &msgData, CRYPT_CERTFORMAT_CERTIFICATE );
			if( cryptStatusOK( status ) )
				status = sSkip( stream, msgData.length );
			}
		if( cryptStatusError( status ) )
			{
			if( certChainEnd > 0 )
				freeCertChain( iCertChain, certChainEnd );
			return( status );
			}

		/* If it's encoded using the indefinite form and we find the EOC
		   octets, exit */
		if( certSequenceLength == CRYPT_UNUSED )
			{
			status = checkEOC( stream );
			if( cryptStatusError( status ) )
				return( status );
			if( status == TRUE )
				{
				/* We've seen EOC octets, we're done */
				break;
				}
			}
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	/* We must have read at least one certificate in order to create a 
	   chain */
	if( certChainEnd <= 0 )
		return( CRYPT_ERROR_BADDATA );

	/* Build the complete chain from the individual certificates */
	return( buildCertChain( iCryptCert, iCertChain, certChainEnd, 
							keyIDtype, keyID, keyIDlength ) );
	}

/* Fetch a sequence of certificates from an object to create a certificate 
   chain */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
int assembleCertChain( OUT CRYPT_CERTIFICATE *iCertificate,
					   IN_HANDLE const CRYPT_HANDLE iCertSource,
					   IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
					   IN_BUFFER( keyIDlength ) const void *keyID, 
					   IN_LENGTH_KEYID const int keyIDlength,
					   IN_FLAGS( KEYMGMT ) const int options )
	{
	CRYPT_CERTIFICATE iCertChain[ MAX_CHAINLENGTH + 8 ], lastCert;
	MESSAGE_KEYMGMT_INFO getnextcertInfo;
	const int chainOptions = options & KEYMGMT_FLAG_DATAONLY_CERT;
	int stateInfo = CRYPT_ERROR, certChainEnd = 1;
	int iterationCount, status;

	assert( isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isReadPtr( keyID, keyIDlength ) && \
			keyIDlength >= MIN_NAME_LENGTH );

	REQUIRES( isHandleRangeValid( iCertSource ) );
	REQUIRES( keyIDtype > CRYPT_KEYID_NONE && \
			  keyIDtype < CRYPT_KEYID_LAST );
	REQUIRES( keyIDlength >= MIN_NAME_LENGTH && \
			  keyIDlength < MAX_ATTRIBUTE_SIZE );
	REQUIRES( options >= KEYMGMT_FLAG_NONE && options < KEYMGMT_FLAG_MAX && \
			  ( options & ~KEYMGMT_MASK_CERTOPTIONS ) == 0 );

	/* Get the initial certificate based on the key ID */
	setMessageKeymgmtInfo( &getnextcertInfo, keyIDtype, keyID, keyIDlength, 
						   &stateInfo, sizeof( int ), 
						   options & KEYMGMT_MASK_CERTOPTIONS );
	status = krnlSendMessage( iCertSource, IMESSAGE_KEY_GETFIRSTCERT,
							  &getnextcertInfo, KEYMGMT_ITEM_PUBLICKEY );
	if( cryptStatusError( status ) )
		return( status );
	iCertChain[ 0 ] = lastCert = getnextcertInfo.cryptHandle;

	/* Fetch subsequent certificates that make up the chain based on the 
	   state information.  Since the basic options apply only to the leaf 
	   certificate we only allow the data-only-cert flag at this point.  See 
	   the comment in readCertChain() for the use of FAILSAFE_ITERATIONS_MED
	   for the bounds check */
	setMessageKeymgmtInfo( &getnextcertInfo, CRYPT_KEYID_NONE, NULL, 0, 
						   &stateInfo, sizeof( int ), chainOptions );
	for( iterationCount = 0;
		 cryptStatusOK( status ) && \
			iterationCount < FAILSAFE_ITERATIONS_MED; 
		 iterationCount++ )
		{
		int selfSigned;

		/* If we've reached a self-signed (CA root) certificate, stop.  Note 
		   that this can't detect PKIX path-kludge certificates which look 
		   identical to CA root certificates and can only be reliably 
		   identified if they're present in the middle of a pre-built 
		   chain */
		status = krnlSendMessage( lastCert, IMESSAGE_GETATTRIBUTE, 
								  &selfSigned, CRYPT_CERTINFO_SELFSIGNED );
		if( cryptStatusError( status ) || selfSigned > 0 )
			break;

		/* Get the next certificate in the chain from the source, import it,
		   and add it to the collection */
		getnextcertInfo.cryptHandle = CRYPT_ERROR;	/* Reset result handle */
		status = krnlSendMessage( iCertSource, IMESSAGE_KEY_GETNEXTCERT,
								  &getnextcertInfo, KEYMGMT_ITEM_PUBLICKEY );
		if( cryptStatusError( status ) )
			break;

		/* Make sure that we don't overflow the chain */
		if( certChainEnd >= MAX_CHAINLENGTH )
			{
			krnlSendNotifier( getnextcertInfo.cryptHandle,
							  IMESSAGE_DECREFCOUNT );
			status = CRYPT_ERROR_OVERFLOW;
			break;
			}

		iCertChain[ certChainEnd++ ] = lastCert = getnextcertInfo.cryptHandle;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_NOTFOUND )
		{
		freeCertChain( iCertChain, certChainEnd );
		return( status );
		}

	/* Build the complete chain from the individual certificates */
	return( buildCertChain( iCertificate, iCertChain, certChainEnd, 
							CRYPT_KEYID_NONE, NULL, 0 ) );
	}

/****************************************************************************
*																			*
*						Write Certificate-bagging Records					*
*																			*
****************************************************************************/

/* Determine the size of and write a certificate path from a base 
   certificate up to the root */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int sizeofCertPath( const CERT_INFO *certInfoPtr,
						   OUT_ARRAY_OPT( MAX_CHAINLENGTH ) int *certSizeInfo )
	{
	int length = 0, i;

	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( certSizeInfo == NULL || \
			isWritePtr( certSizeInfo, sizeof( int ) * MAX_CHAINLENGTH ) );

	/* Clear return value */
	if( certSizeInfo != NULL )
		memset( certSizeInfo, 0, sizeof( int ) * MAX_CHAINLENGTH );

	/* Evaluate the size of the current certificate and the issuer 
	   certificates in the chain.  If it's a certificate collection it's 
	   just a container for random certificates but not a certificate in its 
	   own right so we skip the leaf certificate */
	if( !( certInfoPtr->flags & CERT_FLAG_CERTCOLLECTION ) )
		{
		length = certInfoPtr->certificateSize;
		if( certSizeInfo != NULL )
			length += 3;
		}
	for( i = 0; i < certInfoPtr->cCertCert->chainEnd && \
				i < MAX_CHAINLENGTH; i++ )
		{
		MESSAGE_DATA msgData;
		int status;

		setMessageData( &msgData, NULL, 0 );
		status = krnlSendMessage( certInfoPtr->cCertCert->chain[ i ], 
								  IMESSAGE_CRT_EXPORT, &msgData, 
								  CRYPT_CERTFORMAT_CERTIFICATE );
		if( cryptStatusError( status ) )
			return( status );
		length += msgData.length;
		if( certSizeInfo != NULL )
			{
			certSizeInfo[ i ] = msgData.length;
			length += 3;
			}
		}
	ENSURES( i < MAX_CHAINLENGTH );

	return( length );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeCertPath( INOUT STREAM *stream, 
						  const CERT_INFO *certInfoPtr,
						  IN_ARRAY_OPT( MAX_CHAINLENGTH ) \
								const int *certSizeInfo )

	{
	int i, status = CRYPT_OK;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( certSizeInfo == NULL || \
			isReadPtr( certSizeInfo, sizeof( int ) * MAX_CHAINLENGTH ) );

	/* Write the current certificate and the associated certificate chain up 
	   to the root.  If it's a certificate collection it's just a container 
	   for random certificates but not a certificate in its own right so we 
	   skip the leaf certificate */
	if( !( certInfoPtr->flags & CERT_FLAG_CERTCOLLECTION ) )
		{
		if( certSizeInfo != NULL )
			{
			sputc( stream, 0 );
			writeUint16( stream, certInfoPtr->certificateSize );
			}
		status = swrite( stream, certInfoPtr->certificate, 
						 certInfoPtr->certificateSize );
		}
	for( i = 0; cryptStatusOK( status ) && \
				i < certInfoPtr->cCertCert->chainEnd && \
				i < MAX_CHAINLENGTH; i++ )
		{
		if( certSizeInfo != NULL )
			{
			sputc( stream, 0 );
			writeUint16( stream, certSizeInfo[ i ] );
			}
		status = exportCertToStream( stream,
									 certInfoPtr->cCertCert->chain[ i ], 
									 CRYPT_CERTFORMAT_CERTIFICATE );
		}
	ENSURES( i < MAX_CHAINLENGTH );

	return( status );
	}

/* Write certificate chain/sequence information:

	CertChain ::= SEQUENCE {
		contentType				OBJECT IDENTIFIER,	-- signedData
		content			  [ 0 ]	EXPLICIT SEQUENCE {
			version				INTEGER (1),
			digestAlgorithms	SET OF AlgorithmIdentifier,	-- SIZE(0)
			contentInfo			SEQUENCE {
				signedData		OBJECT IDENTIFIER	-- data
				}
			certificates  [ 0 ]	SET OF {
									Certificate
				}
			}
		signerInfos				SET OF SignerInfo			-- SIZE(0)
		} */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofCertCollection( const CERT_INFO *certInfoPtr,
						  IN_ENUM( CRYPT_CERTFORMAT ) \
							const CRYPT_CERTFORMAT_TYPE certFormatType )
	{
	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	REQUIRES( certFormatType == CRYPT_ICERTFORMAT_CERTSET || \
			  certFormatType == CRYPT_ICERTFORMAT_CERTSEQUENCE || \
			  certFormatType == CRYPT_ICERTFORMAT_SSL_CERTCHAIN );

	if( certFormatType == CRYPT_ICERTFORMAT_SSL_CERTCHAIN )
		{
		int certSizeInfo[ MAX_CHAINLENGTH + 8 ];

		return( sizeofCertPath( certInfoPtr, certSizeInfo ) );
		}
	return( sizeofObject( sizeofCertPath( certInfoPtr, NULL ) ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCertCollection( INOUT STREAM *stream, 
						 const CERT_INFO *certInfoPtr,
						 IN_ENUM( CRYPT_CERTFORMAT ) \
							const CRYPT_CERTFORMAT_TYPE certFormatType )
	{
	int certSizeInfo[ MAX_CHAINLENGTH + 8 ];
	int *certSizePtr = \
			( certFormatType == CRYPT_ICERTFORMAT_SSL_CERTCHAIN ) ? \
			certSizeInfo : NULL;
	const int certCollectionLength = sizeofCertPath( certInfoPtr, \
													 certSizePtr );

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	
	REQUIRES( certFormatType == CRYPT_ICERTFORMAT_CERTSET || \
			  certFormatType == CRYPT_ICERTFORMAT_CERTSEQUENCE || \
			  certFormatType == CRYPT_ICERTFORMAT_SSL_CERTCHAIN );

	if( cryptStatusError( certCollectionLength ) )
		return( certCollectionLength );
	switch( certFormatType )
		{
		case CRYPT_ICERTFORMAT_CERTSET:
			writeConstructed( stream, certCollectionLength, 0 );
			break;

		case CRYPT_ICERTFORMAT_CERTSEQUENCE:
			writeSequence( stream, certCollectionLength );
			break;

		case CRYPT_ICERTFORMAT_SSL_CERTCHAIN:
			break;

		default:
			retIntError();
		}
	return( writeCertPath( stream, certInfoPtr, certSizePtr ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCertChain( INOUT STREAM *stream, 
					const CERT_INFO *certInfoPtr )
	{
	const int certSetLength = sizeofCertPath( certInfoPtr, NULL );
	int innerLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( certInfoPtr, sizeof( CERT_INFO ) ) );

	if( cryptStatusError( certSetLength ) )
		return( certSetLength );

	/* Determine how big the encoded certificate chain/sequence will be */
	innerLength = sizeofShortInteger( 1 ) + ( int ) sizeofObject( 0 ) + \
					  ( int ) sizeofObject( sizeofOID( OID_CMS_DATA ) ) + \
					  ( int ) sizeofObject( certSetLength ) + \
					  ( int ) sizeofObject( 0 );

	/* Write the outer SEQUENCE wrapper and contentType and content wrapper */
	writeSequence( stream, 
				   sizeofOID( OID_CMS_SIGNEDDATA ) + \
					( int ) sizeofObject( sizeofObject( innerLength ) ) );
	swrite( stream, OID_CMS_SIGNEDDATA, sizeofOID( OID_CMS_SIGNEDDATA ) );
	writeConstructed( stream, sizeofObject( innerLength ), 0 );
	writeSequence( stream, innerLength );

	/* Write the inner content */
	writeShortInteger( stream, 1, DEFAULT_TAG );
	writeSet( stream, 0 );
	writeSequence( stream, sizeofOID( OID_CMS_DATA ) );
	swrite( stream, OID_CMS_DATA, sizeofOID( OID_CMS_DATA ) );
	writeConstructed( stream, certSetLength, 0 );
	status = writeCertPath( stream, certInfoPtr, NULL );
	if( cryptStatusOK( status ) )
		status = writeSet( stream, 0 );
	return( status );
	}
