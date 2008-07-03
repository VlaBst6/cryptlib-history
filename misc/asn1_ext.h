/****************************************************************************
*																			*
*				ASN.1 Supplementary Constants and Structures				*
*						Copyright Peter Gutmann 1992-2007					*
*																			*
****************************************************************************/

#ifndef _ASN1OID_DEFINED

#define _ASN1OID_DEFINED

/* The cryptlib (strictly speaking DDS) OID arc is as follows:

	1 3 6 1 4 1 3029 = dds
					 1 = algorithm
					   1 = symmetric encryption
						 1 = blowfishECB
						 2 = blowfishCBC
						 3 = blowfishCFB
						 4 = blowfishOFB
					   2 = public-key encryption
						 1 = elgamal
						   1 = elgamalWithSHA-1
						   2 = elgamalWithRIPEMD-160
					   3 = hash
					 2 = mechanism
					 3 = attribute
					   1 = PKIX fixes
						 1 = cryptlibPresenceCheck
						 2 = pkiBoot
						 (3 unused)
						 4 = cRLExtReason
						 5 = keyFeatures
					 4 = content-type
					   1 = cryptlib
						 1 = cryptlibConfigData
						 2 = cryptlibUserIndex
						 3 = cryptlibUserInfo
						 4 = cryptlibRtcsRequest
						 5 = cryptlibRtcsResponse
						 6 = cryptlibRtcsResponseExt
					 x58 x59 x5A x5A x59 = XYZZY cert policy */

/* Attribute OIDs */

#define OID_CRYPTLIB_PRESENCECHECK	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x01" )
#define OID_ESS_CERTID			MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0C" )
#define OID_TSP_TSTOKEN			MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0E" )
#define OID_PKCS9_FRIENDLYNAME	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x14" )
#define OID_PKCS9_LOCALKEYID	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x15" )
#define OID_PKCS9_X509CERTIFICATE MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x16\x01" )

/* The PKCS #9 OID for cert extensions in a certification request, from the
   CMMF draft.  Naturally MS had to define their own incompatible OID for
   this, so we check for this as well */

#define OID_PKCS9_EXTREQ		MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0E" )
#define OID_MS_EXTREQ			MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0E" )

/* Content-type OIDs */

#define OID_CMS_DATA			MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01" )
#define OID_CMS_SIGNEDDATA		MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02" )
#define OID_CMS_ENVELOPEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03" )
#define OID_CMS_DIGESTEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x05" )
#define OID_CMS_ENCRYPTEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06" )
#define OID_CMS_AUTHDATA		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x02" )
#define OID_CMS_TSTOKEN			MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x04" )
#define OID_CMS_COMPRESSEDDATA	MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x09" )
#define OID_CMS_AUTHENVDATA		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x17" )
#define OID_CRYPTLIB_CONTENTTYPE MKOID( "\x06\x09\x2B\x06\x01\x04\x01\x97\x55\x04\x01" )
#define OID_CRYPTLIB_CONFIGDATA	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x01" )
#define OID_CRYPTLIB_USERINDEX	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x02" )
#define OID_CRYPTLIB_USERINFO	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x03" )
#define OID_CRYPTLIB_RTCSREQ	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x04" )
#define OID_CRYPTLIB_RTCSRESP	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x05" )
#define OID_CRYPTLIB_RTCSRESP_EXT	MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x04\x01\x06" )
#define OID_MS_SPCINDIRECTDATACONTEXT MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x04" )
#define OID_NS_CERTSEQ			MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x02\x05" )
#define OID_OCSP_RESPONSE_OCSP MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01" )
#define OID_PKIBOOT				MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x02" )
#define OID_PKCS12_SHROUDEDKEYBAG MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x02" )
#define OID_PKCS12_CERTBAG		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x0A\x01\x03" )
#define OID_PKCS15_CONTENTTYPE	MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0F\x03\x01" )

/* Misc OIDs */

#define OID_ANYPOLICY			MKOID( "\x06\x04\x55\x1D\x20\x00" )
#define OID_CRYPTLIB_XYZZYCERT	MKOID( "\x06\x0C\x2B\x06\x01\x04\x01\x97\x55\x58\x59\x5A\x5A\x59" )
#define OID_PKCS12_PBEWITHSHAAND3KEYTRIPLEDESCBC MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x03" )
#define OID_PKCS12_PBEWITHSHAAND2KEYTRIPLEDESCBC MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0C\x01\x04" )
#define OID_ZLIB				MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x08" )

/* AlgorithmIdentifiers that are used in various places.  The Fortezza key
   wrap one is keyExchangeAlgorithm { fortezzaWrap80Algorithm } */

#define ALGOID_FORTEZZA_KEYWRAP	MKOID( "\x30\x18" \
									   "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x16" \
									   "\x30\x0B" \
									   "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x17" )

/* Additional information required when reading a CMS header.  This is
   pointed to by the extraInfo member of the ASN.1 OID_INFO structure and
   contains CMS version number information */

typedef struct {
	const int minVersion;	/* Minimum version number for content type */
	const int maxVersion;	/* Maximum version number for content type */
	} CMS_CONTENT_INFO;

/* AlgorithmIdentifier routines.  The reason for the apparently redundant 
   CHECK_RETVAL specifiers on some of the write functions is because they 
   won't necessarily set the stream error state if they encounter an error
   obtaining algorithm parameters or during some other non-stream-related
   operation */

CHECK_RETVAL_BOOL \
BOOLEAN checkAlgoID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					 IN_MODE const CRYPT_MODE_TYPE cryptMode );
CHECK_RETVAL \
int sizeofAlgoID( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo );
CHECK_RETVAL \
int sizeofAlgoIDex( IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
					IN_RANGE( 0, 999 ) const int parameter, 
					IN_LENGTH_SHORT_Z const int extraLength );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeAlgoID( INOUT STREAM *stream, 
				 IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeAlgoIDex( INOUT STREAM *stream, 
				   IN_ALGO const CRYPT_ALGO_TYPE cryptAlgo,
				   IN_RANGE( 0, 999 ) const int parameter, 
				   IN_LENGTH_SHORT_Z const int extraLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2) ) \
int readAlgoID( INOUT STREAM *stream, 
				OUT_OPT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readAlgoIDext( INOUT STREAM *stream, OUT CRYPT_ALGO_TYPE *cryptAlgo,
				   OUT CRYPT_ALGO_TYPE *altCryptAlgo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readAlgoIDparams( INOUT STREAM *stream, 
					  OUT_ALGO_Z CRYPT_ALGO_TYPE *cryptAlgo, 
					  OUT_LENGTH_SHORT_Z int *extraLength );

/* Alternative versions that read/write various algorithm ID types (algo and
   mode only or full details depending on the option parameter) from contexts */

CHECK_RETVAL \
int sizeofContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						 IN_RANGE( 0, 999 ) const int parameter );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int readContextAlgoID( INOUT STREAM *stream, 
					   OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext,
					   INOUT_OPT QUERY_INFO *queryInfo, 
					   IN_TAG const int tag );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeContextAlgoID( INOUT STREAM *stream, 
						IN_HANDLE const CRYPT_CONTEXT iCryptContext,
						IN_RANGE( 0, 999 ) const int parameter );
CHECK_RETVAL \
int sizeofCryptContextAlgoID( IN_HANDLE const CRYPT_CONTEXT iCryptContext );
RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeCryptContextAlgoID( INOUT STREAM *stream,
							 IN_HANDLE const CRYPT_CONTEXT iCryptContext );

/* Another alternative that reads/writes a non-crypto algorithm identifier,
   used for things like content types.  This just wraps the given OID up
   in the AlgorithmIdentifier and writes it */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readGenericAlgoID( INOUT STREAM *stream, 
					   IN_BUFFER( oidLength ) \
					   const BYTE *oid, 
					   IN_LENGTH_OID const int oidLength );
RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeGenericAlgoID( INOUT STREAM *stream, 
						IN_BUFFER( oidLength ) \
						const BYTE *oid, 
						IN_LENGTH_OID const int oidLength );

/* Read/write a message digest */

CHECK_RETVAL \
int sizeofMessageDigest( IN_ALGO const CRYPT_ALGO_TYPE hashAlgo, 
						 IN_LENGTH_HASH const int hashSize );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int readMessageDigest( INOUT STREAM *stream, 
					   OUT_ALGO_Z CRYPT_ALGO_TYPE *hashAlgo,
					   OUT_BUFFER( hashMaxLen, hashSize ) \
					   void *hash, IN_LENGTH_HASH const int hashMaxLen, 
					   OUT_LENGTH_SHORT_Z int *hashSize );
RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int writeMessageDigest( INOUT STREAM *stream, 
						IN_ALGO const CRYPT_ALGO_TYPE hashAlgo,
						IN_BUFFER( hashSize ) \
						const void *hash, IN_LENGTH_HASH const int hashSize );

/* Read/write CMS headers */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCMSheader( INOUT STREAM *stream, 
				   IN_ARRAY( noOidInfoEntries ) \
				   const OID_INFO *oidInfo, 
				   IN_RANGE( 1, 50 ) const int noOidInfoEntries, 
				   OUT_OPT_LENGTH_INDEF long *dataSize, 
				   const BOOLEAN isInnerHeader );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCMSheader( INOUT STREAM *stream, 
					IN_BUFFER( contentOIDlength ) \
					const BYTE *contentOID, 
					IN_LENGTH_OID const int contentOIDlength,
					IN_LENGTH_INDEF const long dataSize, 
					const BOOLEAN isInnerHeader );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofCMSencrHeader( IN_BUFFER( contentOIDlength ) \
						 const BYTE *contentOID, 
						 IN_LENGTH_OID const int contentOIDlength,
						 IN_LENGTH_INDEF const long dataSize, 
						 IN_HANDLE const CRYPT_CONTEXT iCryptContext );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCMSencrHeader( INOUT STREAM *stream, 
					   IN_ARRAY( noOidInfoEntries ) \
					   const OID_INFO *oidInfo,
					   IN_RANGE( 1, 50 ) const int noOidInfoEntries, 
					   OUT_OPT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
					   INOUT_OPT QUERY_INFO *queryInfo );
RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCMSencrHeader( INOUT STREAM *stream, 
						IN_BUFFER( contentOIDlength ) \
						const BYTE *contentOID, 
						IN_LENGTH_OID const int contentOIDlength,
						IN_LENGTH_INDEF const long dataSize,
						IN_HANDLE const CRYPT_CONTEXT iCryptContext );

#endif /* _ASN1OID_DEFINED */
