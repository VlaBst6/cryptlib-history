/****************************************************************************
*																			*
*						Certificate Attribute Definitions					*
*						Copyright Peter Gutmann 1996-2008					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "certattr.h"
  #include "asn1.h"
  #include "asn1_ext.h"
#else
  #include "cert/cert.h"
  #include "cert/certattr.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
#endif /* Compiler-specific includes */

/* The following certificate extensions are currently supported.  If
   'Enforced' is set to 'Yes', this means that they are constraint extensions
   that are enforced by the certificate checking code; if set to '-', they 
   are informational extensions for which enforcement doesn't apply; if set 
   to 'No', they need to be handled by the user (this only applies for
   certificate policies, where the user has to decide whether a given 
   certificate policy is acceptable or not).  The Yes/No in policyConstraints 
   means that everything except the policy mapping constraint is enforced 
   (because policyMappings itself isn't enforced).

									Enforced
									--------
	authorityInfoAccess				   -
	authorityKeyIdentifier			   -
	basicConstraints				  Yes
	biometricInfo (QualifiedCert)	  -
	certCardRequired (SET)			  -
	certificateIssuer				   -
	certificatePolicies				  Yes
	certificateType (SET)			   -
	challengePassword (SCEP)		   -
	cRLDistributionPoints			   -
	cRLNumber						   -
	cRLReason						   -
	cRLExtReason					   -
	dateOfCertGen (SigG)			   -
	deltaCRLIndicator				   -
	extKeyUsage						  Yes
	freshestCRL						   -
	hashedRootKey (SET)				   -
	holdInstructionCode				   -
	inhibitAnyPolicy				  Yes
	invalidityDate					   -
	issuerAltName					   -
	issuingDistributionPoint		   -
	keyFeatures						   -
	keyUsage						  Yes
	monetaryLimit (SigG)			   -
	nameConstraints					  Yes
	netscape-cert-type				  Yes
	netscape-base-url				   -
	netscape-revocation-url			   -
	netscape-ca-revocation-url		   -
	netscape-cert-renewal-url		   -
	netscape-ca-policy-url			   -
	netscape-ssl-server-name		   -
	netscape-comment				   -
	merchantData (SET)				   -
	ocspAcceptableResponse (OCSP)	  -
	ocspArchiveCutoff (OCSP)		   -
	ocspNoCheck (OCSP)				   -
	ocspNonce (OCSP)				   -
	policyConstraints				 Yes/No
	policyMappings					  No
	privateKeyUsagePeriod			  Yes
	procuration (SigG)				   -
	qcStatements (QualifiedCert)	   -
	restriction (SigG)				   -
	strongExtranet (Thawte)			   -
	subjectAltName					   -
	subjectDirectoryAttributes		   -
	subjectInfoAccess				   -
	subjectKeyIdentifier			   -
	tunneling (SET)					   -

   Some extensions are specified as a SEQUENCE OF thing, to make it possible
   to process these automatically we rewrite them as a SEQUENCE OF
   thingInstance1 OPTIONAL, thingInstance2 OPTIONAL, ... thingInstanceN
   OPTIONAL.  Examples of this are extKeyUsage and the altNames.

   Since some extensions fields are tagged, the fields as encoded differ from
   the fields as defined by the tagging, the following macro is used to turn
   a small integer into a context-specific tag.  By default the tag is
   implicit as per X.509v3, to make it an explicit tag we need to set the
   FL_EXPLICIT flag for the field */

#define CTAG( x )		( x | BER_CONTEXT_SPECIFIC )

/* A symbolic define for use when there's no explicit tagging or other form
   of encapsulation being used */

#define ENCODING( tag )		tag, CRYPT_UNUSED
#define ENCODING_ALIAS( tag, aliasTag ) \
							tag, aliasTag
#define ENCODING_TAGGED( tag, outerTag ) \
							tag, outerTag
#define RANGE( min, max )	min, max, 0, NULL
#define RANGE_ATTRIBUTEBLOB	1, MAX_ATTRIBUTE_SIZE, 0, NULL
#define RANGE_BLOB			32, MAX_ATTRIBUTE_SIZE, 0, NULL
#define RANGE_BOOLEAN		FALSE, TRUE, FALSE, NULL 
#define RANGE_NONE			0, 0, 0, NULL
#define RANGE_OID			MIN_OID_SIZE, MAX_OID_SIZE, 0, NULL
#define RANGE_TEXTSTRING	1, CRYPT_MAX_TEXTSIZE, 0, NULL
#define RANGE_TIME			sizeof( time_t ), sizeof( time_t ), 0, NULL
#define RANGE_UNUSED		CRYPT_UNUSED, CRYPT_UNUSED, 0, NULL
#define ENCODED_OBJECT( altEncodingTable ) \
							0, 0, 0, ( void * ) altEncodingTable
#define CHECK_DNS			MIN_DNS_SIZE, MAX_DNS_SIZE, 0, ( void * ) checkDNS
#define CHECK_HTTP			MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP
#define CHECK_RFC822		MIN_RFC822_SIZE, MAX_RFC822_SIZE, 0, ( void * ) checkRFC822
#define CHECK_URL			MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkURL
#define CHECK_X500			0, 0, 0, ( void * ) checkDirectoryName

/* Extended checking functions */

CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkRFC822( const ATTRIBUTE_LIST *attributeListPtr );
CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkDNS( const ATTRIBUTE_LIST *attributeListPtr );
CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkURL( const ATTRIBUTE_LIST *attributeListPtr );
CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkHTTP( const ATTRIBUTE_LIST *attributeListPtr );
CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkDirectoryName( const ATTRIBUTE_LIST *attributeListPtr );

/* Forward declarations for alternative encoding tables used by the main
   tables.  These are declared in a somewhat peculiar manner because there's
   no clean way in C to forward declare a static array.  Under VC++ with the
   highest warning level enabled this produces a compiler warning, so we
   turn the warning off for this module.  In addition there are problems with
   some versions of gcc 4.x, these first cropped up in 4.0.0 (which only
   Apple, with their penchant for running with buggy bleeding-edge releases 
   really went with) but they're they're still in 4.1.x so we have to add a 
   special case for this */

#if defined( __GNUC__ ) && ( __GNUC__ == 4 )
  static const ATTRIBUTE_INFO FAR_BSS generalNameInfo[];
  static const ATTRIBUTE_INFO FAR_BSS holdInstructionInfo[];
  static const ATTRIBUTE_INFO FAR_BSS contentTypeInfo[];
#else
  extern const ATTRIBUTE_INFO FAR_BSS generalNameInfo[];
  extern const ATTRIBUTE_INFO FAR_BSS holdInstructionInfo[];
  extern const ATTRIBUTE_INFO FAR_BSS contentTypeInfo[];
#endif /* Some gcc 4 versions */

#if defined( _MSC_VER )
  #pragma warning( disable: 4211 )
#endif /* VC++ */

/****************************************************************************
*																			*
*						Certificate Extension Definitions					*
*																			*
****************************************************************************/

/* Certificate extensions are encoded using the following table */

static const ATTRIBUTE_INFO FAR_BSS extensionInfo[] = {
	/* challengePassword.  This is here even though it's a CMS attribute
	   because SCEP stuffs it into PKCS #10 requests:

		OID = 1 2 840 113549 1 9 7
		PrintableString */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x07" ), CRYPT_CERTINFO_CHALLENGEPASSWORD,
	  MKDESC( "challengePassword" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  FL_LEVEL_STANDARD | FL_NOCOPY | FL_VALID_CERTREQ, RANGE_TEXTSTRING },

	/* signingCertificate.  This is here even though it's a CMS attribute
	   because it's required in order to make OCSP work.  Since OCSP breaks 
	   up the certificate identification information into bits and pieces 
	   and hashes some while leaving others intact, there's no way to map 
	   what arrives at the responder back into a certificate without 
	   breaking the hash function.  To work around this, we include an 
	   ESSCertID in the request that properly identifies the certificate 
	   being queried.  Since it's a limited-use version that only identifies 
	   the certificate, we don't allow a full signingCertificate extension 
	   but only a single ESSCertID:

		OID = 1 2 840 113549 1 9 16 2 12
		SEQUENCE {
			SEQUENCE OF ESSCertID,			-- SIZE(1)
			SEQUENCE OF { ... } OPTIONAL	-- ABSENT
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0C" ), CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE,
	  MKDESC( "signingCertificate" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_OCSPREQ /*Per-entry*/, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "signingCertificate.certs" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID,
	  MKDESC( "signingCertificate.certs.essCertID" )
	  ENCODING( FIELDTYPE_BLOB ),
	  FL_SEQEND_2 /*FL_SEQEND*/, RANGE_BLOB },

	/* cRLExtReason:

		OID = 1 3 6 1 4 1 3029 3 1 4
		ENUMERATED */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x04" ), CRYPT_CERTINFO_CRLEXTREASON,
	  MKDESC( "cRLExtReason" )
	  ENCODING( BER_ENUMERATED ),
	  FL_LEVEL_STANDARD | FL_VALID_CRL | FL_VALID_REVREQ /*Per-entry*/, RANGE( 0, CRYPT_CRLEXTREASON_LAST ) },

	/* keyFeatures:

		OID = 1 3 6 1 4 1 3029 3 1 5
		BITSTRING */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x05" ), CRYPT_CERTINFO_KEYFEATURES,
	  MKDESC( "keyFeatures" )
	  ENCODING( BER_BITSTRING ),
	  FL_LEVEL_STANDARD | FL_VALID_CERT | FL_VALID_CERTREQ, RANGE( 0, 7 ) },

	/* authorityInfoAccess:

		OID = 1 3 6 1 5 5 7 1 1
		SEQUENCE SIZE (1...MAX) OF {
			SEQUENCE {
				accessMethod	OBJECT IDENTIFIER,
				accessLocation	GeneralName
				}
			} */
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x01" ), CRYPT_CERTINFO_AUTHORITYINFOACCESS,
	  MKDESC( "authorityInfoAccess" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERT | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (rtcs)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x03\x01\x07" ), 0,
	  MKDESC( "authorityInfoAccess.rtcs (1 3 6 1 4 1 3029 3 1 7)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_RTCS,
	  MKDESC( "authorityInfoAccess.accessDescription.accessLocation (rtcs)" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (ocsp)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x01" ), 0,
	  MKDESC( "authorityInfoAccess.ocsp (1 3 6 1 5 5 7 48 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_OCSP,
	  MKDESC( "authorityInfoAccess.accessDescription.accessLocation (ocsp)" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (caIssuers)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x02" ), 0,
	  MKDESC( "authorityInfoAccess.caIssuers (1 3 6 1 5 5 7 48 2)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS,
	  MKDESC( "authorityInfoAccess.accessDescription.accessLocation (caIssuers)" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (httpCerts)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x06" ), 0,
	  MKDESC( "authorityInfoAccess.httpCerts (1 3 6 1 5 5 7 48 6)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_CERTSTORE,
	  MKDESC( "authorityInfoAccess.accessDescription.accessLocation (httpCerts)" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (httpCRLs)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x07" ), 0,
	  MKDESC( "authorityInfoAccess.httpCRLs (1 3 6 1 5 5 7 48 7)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_CRLS,
	  MKDESC( "authorityInfoAccess.accessDescription.accessLocation (httpCRLs)" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.accessDescription (catchAll)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "authorityInfoAccess.catchAll" )
	  ENCODING( FIELDTYPE_BLOB ),	/* Match anything and ignore it */
	  FL_OPTIONAL | FL_NONENCODING | FL_SEQEND_2 /*FL_SEQEND*/, RANGE_NONE },

	/* biometricInfo

		OID = 1 3 6 1 5 5 7 1 2
		SEQUENCE OF {
			SEQUENCE {
				typeOfData		INTEGER,
				hashAlgorithm	OBJECT IDENTIFIER,
				dataHash		OCTET STRING,
				sourceDataUri	IA5String OPTIONAL
				}
			} */
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x02" ), CRYPT_CERTINFO_BIOMETRICINFO,
	  MKDESC( "biometricInfo" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "biometricInfo.biometricData" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_BIOMETRICINFO_TYPE,
	  MKDESC( "biometricInfo.biometricData.typeOfData" )
	  ENCODING( BER_INTEGER ),
	  FL_MORE | FL_MULTIVALUED, RANGE( 0, 1 ) },
	{ NULL, CRYPT_CERTINFO_BIOMETRICINFO_HASHALGO,
	  MKDESC( "biometricInfo.biometricData.hashAlgorithm" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MORE | FL_MULTIVALUED, RANGE_OID },
	{ NULL, CRYPT_CERTINFO_BIOMETRICINFO_HASH,
	  MKDESC( "biometricInfo.biometricData.dataHash" )
	  ENCODING( BER_OCTETSTRING ),
	  FL_MORE | FL_MULTIVALUED, RANGE( 16, CRYPT_MAX_HASHSIZE ) },
	{ NULL, CRYPT_CERTINFO_BIOMETRICINFO_URL,
	  MKDESC( "biometricInfo.biometricData.sourceDataUri" )
	  ENCODING( BER_STRING_IA5 ),
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_2 /*FL_SEQEND*/, CHECK_URL },

	/* qcStatements

		OID = 1 3 6 1 5 5 7 1 3
		critical = TRUE
		SEQUENCE OF {
			SEQUENCE {
				statementID		OBJECT IDENTIFIER,
				statementInfo	SEQUENCE {
					semanticsIdentifier	OBJECT IDENTIFIER OPTIONAL,
					nameRegistrationAuthorities SEQUENCE OF GeneralName
				}
			}
		There are two versions of the statementID OID, one for RFC 3039 and
		the other for RFC 3739 (which are actually identical except where
		they're not).  To handle this we preferentially encode the RFC 3739
		(v2) OID but allow the v1 OID as a fallback by marking both as
		optional */
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x03" ), CRYPT_CERTINFO_QCSTATEMENT,
	  MKDESC( "qcStatements" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_CRITICAL | FL_VALID_CERT | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "qcStatements.qcStatement (statementID)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x0B\x02" ), 0,
	  MKDESC( "qcStatements.qcStatement.statementID (1 3 6 1 5 5 7 11 2)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x0B\x01" ), 0,
	  MKDESC( "qcStatements.qcStatement.statementID (Backwards-compat.) (1 3 6 1 5 5 7 11 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "qcStatements.qcStatement.statementInfo (statementID)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_QCSTATEMENT_SEMANTICS,
	  MKDESC( "qcStatements.qcStatement.statementInfo.semanticsIdentifier (statementID)" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, RANGE_OID },
	{ NULL, 0,
	  MKDESC( "qcStatements.qcStatement.statementInfo.nameRegistrationAuthorities (statementID)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_SETOF, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_QCSTATEMENT_REGISTRATIONAUTHORITY,
	  MKDESC( "qcStatements.qcStatement.statementInfo.nameRegistrationAuthorities.generalNames" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MULTIVALUED | FL_NONEMPTY | FL_SEQEND_3 /* Really _4*/, ENCODED_OBJECT( generalNameInfo ) },

	/* subjectInfoAccess:

		OID = 1 3 6 1 5 5 7 1 11
		SEQUENCE SIZE (1...MAX) OF {
			SEQUENCE {
				accessMethod	OBJECT IDENTIFIER,
				accessLocation	GeneralName
				}
			} */
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x0B" ), CRYPT_CERTINFO_SUBJECTINFOACCESS,
	  MKDESC( "subjectInfoAccess" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERT | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "subjectInfoAccess.accessDescription (timeStamping)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x03" ), 0,
	  MKDESC( "subjectInfoAccess.timeStamping (1 3 6 1 5 5 7 48 3)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING,
	  MKDESC( "subjectInfoAccess.accessDescription.accessLocation (timeStamping)" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, 0,
	  MKDESC( "subjectInfoAccess.accessDescription (caRepository)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x05" ), 0,
	  MKDESC( "subjectInfoAccess.caRepository (1 3 6 1 5 5 7 48 5)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING,
	  MKDESC( "subjectInfoAccess.accessDescription.accessLocation (timeStamping)" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, 0,
	  MKDESC( "subjectInfoAccess.accessDescription (catchAll)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "subjectInfoAccess.catchAll" )
	  ENCODING( FIELDTYPE_BLOB ),	/* Match anything and ignore it */
	  FL_OPTIONAL | FL_NONENCODING | FL_SEQEND_2 /*FL_SEQEND*/, RANGE_NONE },

	/* ocspNonce:

		OID = 1 3 6 1 5 5 7 48 1 2
		nonce		INTEGER

	   This value was supposed to be an INTEGER, however while specifying a 
	   million pieces of uneecessary braindamage OCSP forgot to actually 
	   define this anywhere in the spec.  Because of this it's possible to 
	   get other stuff here as well, the worst-case being OpenSSL 0.9.6/
	   0.9.7a-c which just dumps a raw blob (not even valid ASN.1 data) in 
	   here.  We can't do anything with this since we need at least 
	   something DER-encoded to be able to read it.  OpenSSL 0.9.7d and 
	   later used an OCTET STRING so we use the same trick as we do for the 
	   certPolicy IA5String/VisibleString duality where we define the field 
	   as if it were a CHOICE { INTEGER, OCTET STRING } with the INTEGER 
	   first to make sure that we encode that preferentially.
	   
	   In addition although the nonce should be an INTEGER data value it's 
	   really an INTEGER equivalent of an OCTET STRING hole so we call it an 
	   octet string to make sure that it gets handled appropriately.
	   
	   Finally, we set the en/decoding level to FL_LEVEL_OBLIVIOUS to make 
	   sure that it's still encoded even in oblivious mode, if we don't do 
	   this then a nonce in a request won't be returned in the response if 
	   the user is running at a reduced compliance level */
	{ MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x02" ), CRYPT_CERTINFO_OCSP_NONCE,
	  MKDESC( "ocspNonce" )
	  ENCODING_ALIAS( BER_OCTETSTRING, BER_INTEGER ),	/* Actually an INTEGER hole */
	  FL_MORE | FL_LEVEL_OBLIVIOUS | FL_VALID_OCSPREQ | FL_VALID_OCSPRESP | FL_OPTIONAL | FL_ALIAS, RANGE( 1, 64 ) },
	{ NULL, CRYPT_CERTINFO_OCSP_NONCE,
	  MKDESC( "ocspNonce (Kludge)" )
	  ENCODING( BER_OCTETSTRING ),
	  FL_OPTIONAL, RANGE( 1, 64 ) },

	/* ocspAcceptableResponses:

		OID = 1 3 6 1 5 5 7 48 1 4
		SEQUENCE {
			oidInstance1 OPTIONAL,
			oidInstance2 OPTIONAL,
				...
			oidInstanceN OPTIONAL
			} */
	{ MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x04" ), CRYPT_CERTINFO_OCSP_RESPONSE,
	  MKDESC( "ocspAcceptableResponses" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY | FL_LEVEL_STANDARD | FL_VALID_CERTREQ | FL_VALID_CERT, RANGE_NONE },
	{ MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01" ), CRYPT_CERTINFO_OCSP_RESPONSE_OCSP,
	  MKDESC( "ocspAcceptableResponses.ocsp (1 3 6 1 5 5 7 48 1 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_OPTIONAL | FL_SEQEND /*NONE*/, RANGE_NONE },

	/* ocspNoCheck:
		OID = 1 3 6 1 5 5 7 48 1 5
		critical = FALSE
		NULL
	   This value is treated as a pseudo-numeric value that must be
	   CRYPT_UNUSED when written and is explicitly set to CRYPT_UNUSED when
	   read */
	{ MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x05" ), CRYPT_CERTINFO_OCSP_NOCHECK,
	  MKDESC( "ocspNoCheck" )
	  ENCODING( BER_NULL ),
	  FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERT | FL_VALID_CERTREQ | FL_NONENCODING, RANGE_UNUSED },

	/* ocspArchiveCutoff:
		OID = 1 3 6 1 5 5 7 48 1 6
		archiveCutoff	GeneralizedTime */
	{ MKOID( "\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x06" ), CRYPT_CERTINFO_OCSP_ARCHIVECUTOFF,
	  MKDESC( "ocspArchiveCutoff" )
	  ENCODING( BER_TIME_GENERALIZED ),
	  FL_LEVEL_PKIX_PARTIAL | FL_VALID_OCSPRESP, RANGE_TIME },

	/* dateOfCertGen
		OID = 1 3 36 8 3 1
		dateOfCertGen	GeneralizedTime */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x01" ), CRYPT_CERTINFO_SIGG_DATEOFCERTGEN,
	  MKDESC( "dateOfCertGen" )
	  ENCODING( BER_TIME_GENERALIZED ),
	  FL_LEVEL_PKIX_FULL | FL_VALID_CERT, RANGE_TIME },

	/* procuration
		OID = 1 3 36 8 3 2
		SEQUENCE OF {
			country					PrintableString SIZE(2) OPTIONAL,
			typeOfSubstitution  [0]	PrintableString OPTIONAL,
			signingFor				GeneralName
			} */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x02" ), CRYPT_CERTINFO_SIGG_PROCURATION,
	  MKDESC( "procuration" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_VALID_CERTREQ | FL_VALID_CERT | FL_SETOF, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SIGG_PROCURE_COUNTRY,
	  MKDESC( "procuration.country" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, RANGE( 2, 2 ) },
	{ NULL, CRYPT_CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION,
	  MKDESC( "procuration.typeOfSubstitution" )
	  ENCODING_TAGGED( BER_STRING_PRINTABLE, 0 ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, RANGE( 1, 128 ) },
	{ NULL, CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR,
	  MKDESC( "procuration.signingFor.thirdPerson" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MULTIVALUED | FL_SEQEND /*NONE*/ | FL_NONEMPTY, ENCODED_OBJECT( generalNameInfo ) },

	/* monetaryLimit
		OID = 1 3 36 8 3 4
		SEQUENCE {
			currency	PrintableString SIZE(3),
			amount		INTEGER,
			exponent	INTEGER
			} */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x04" ), CRYPT_CERTINFO_SIGG_MONETARYLIMIT,
	  MKDESC( "monetaryLimit" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERTREQ | FL_VALID_CERT, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SIGG_MONETARY_CURRENCY,
	  MKDESC( "monetaryLimit.currency" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  FL_MORE, RANGE( 3, 3 ) },
	{ NULL, CRYPT_CERTINFO_SIGG_MONETARY_AMOUNT,
	  MKDESC( "monetaryLimit.amount" )
	  ENCODING( BER_INTEGER ),
	  FL_MORE, RANGE( 1, 255 ) },	/* That's what the spec says */
	{ NULL, CRYPT_CERTINFO_SIGG_MONETARY_EXPONENT,
	  MKDESC( "monetaryLimit.exponent" )
	  ENCODING( BER_INTEGER ),
	  FL_SEQEND /*NONE*/, RANGE( 0, 255 ) },

	/* restriction
		OID = 1 3 36 8 3 8
		restriction		PrintableString */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x08" ), CRYPT_CERTINFO_SIGG_RESTRICTION,
	  MKDESC( "restriction" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  FL_LEVEL_PKIX_FULL | FL_VALID_CERT, RANGE( 1, 128 ) },

	/* strongExtranet:
		OID = 1 3 101 1 4 1
		SEQUENCE {
			version		INTEGER (0),
			SEQUENCE OF {
				SEQUENCE {
					zone	INTEGER,
					id		OCTET STRING (SIZE(1..64))
					}
				}
			} */
	{ MKOID( "\x06\x05\x2B\x65\x01\x04\x01" ), CRYPT_CERTINFO_STRONGEXTRANET,
	  MKDESC( "strongExtranet" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERTREQ | FL_VALID_CERT, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "strongExtranet.version" )
	  ENCODING( FIELDTYPE_BLOB ),	/* Always 0 */
	  FL_MORE | FL_NONENCODING, 0, 0, 3, "\x02\x01\x00" },
	{ NULL, 0,
	  MKDESC( "strongExtranet.sxNetIDList" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "strongExtranet.sxNetIDList.sxNetID" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_STRONGEXTRANET_ZONE,
	  MKDESC( "strongExtranet.sxNetIDList.sxNetID.zone" )
	  ENCODING( BER_INTEGER ),
	  FL_MORE, RANGE( 0, MAX_INTLENGTH ) },
	{ NULL, CRYPT_CERTINFO_STRONGEXTRANET_ID,
	  MKDESC( "strongExtranet.sxNetIDList.sxnetID.id" )
	  ENCODING( BER_OCTETSTRING ),
	  FL_SEQEND_3 /*FL_SEQEND_2*/, RANGE( 1, 64 ) },

	/* subjectDirectoryAttributes:
		OID = 2 5 29 9
		SEQUENCE SIZE (1..MAX) OF {
			SEQUENCE {
				type	OBJECT IDENTIFIER,
				values	SET OF ANY					-- SIZE (1)
				} */
	{ MKOID( "\x06\x03\x55\x1D\x09" ), CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES,
	  MKDESC( "subjectDirectoryAttributes" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERT | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "subjectDirectoryAttributes.attribute" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SUBJECTDIR_TYPE,
	  MKDESC( "subjectDirectoryAttributes.attribute.type" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MORE | FL_MULTIVALUED, RANGE_OID },
	{ NULL, 0,
	  MKDESC( "subjectDirectoryAttributes.attribute.values" )
	  ENCODING( BER_SET ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SUBJECTDIR_VALUES,
	  MKDESC( "subjectDirectoryAttributes.attribute.values.value" )
	  ENCODING( FIELDTYPE_BLOB ),
	  FL_MULTIVALUED | FL_SEQEND_2 /*SEQEND*/, RANGE_ATTRIBUTEBLOB },

	/* subjectKeyIdentifier:
		OID = 2 5 29 14
		OCTET STRING */
	{ MKOID( "\x06\x03\x55\x1D\x0E" ), CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
	  MKDESC( "subjectKeyIdentifier" )
	  ENCODING( BER_OCTETSTRING ),
	  FL_LEVEL_STANDARD | FL_VALID_CERT, RANGE( 1, 64 ) },

	/* keyUsage:
		OID = 2 5 29 15
		critical = TRUE
		BITSTRING */
	{ MKOID( "\x06\x03\x55\x1D\x0F" ), CRYPT_CERTINFO_KEYUSAGE,
	  MKDESC( "keyUsage" )
	  ENCODING( BER_BITSTRING ),
	  FL_CRITICAL | FL_LEVEL_REDUCED | FL_VALID_CERTREQ | FL_VALID_CERT, 0, CRYPT_KEYUSAGE_LAST, 0, NULL },

	/* privateKeyUsagePeriod:
		OID = 2 5 29 16
		SEQUENCE {
			notBefore	  [ 0 ]	GeneralizedTime OPTIONAL,
			notAfter	  [ 1 ]	GeneralizedTime OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x10" ), CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD,
	  MKDESC( "privateKeyUsagePeriod" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERT, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE,
	  MKDESC( "privateKeyUsagePeriod.notBefore" )
	  ENCODING_TAGGED( BER_TIME_GENERALIZED, 0 ),
	  FL_MORE | FL_OPTIONAL, RANGE_TIME },
	{ NULL, CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER,
	  MKDESC( "privateKeyUsagePeriod.notAfter" )
	  ENCODING_TAGGED( BER_TIME_GENERALIZED, 1 ),
	  FL_OPTIONAL | FL_SEQEND /*NONE*/, RANGE_TIME },

	/* subjectAltName:
		OID = 2 5 29 17
		SEQUENCE OF GeneralName */
	{ MKOID( "\x06\x03\x55\x1D\x11" ), FIELDID_FOLLOWS,
	  MKDESC( "subjectAltName" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERTREQ | FL_VALID_CERT | FL_SETOF, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SUBJECTALTNAME,
	  MKDESC( "subjectAltName.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MULTIVALUED | FL_NONEMPTY | FL_SEQEND /*NONE*/, ENCODED_OBJECT( generalNameInfo ) },

	/* issuerAltName:
		OID = 2 5 29 18
		SEQUENCE OF GeneralName */
	{ MKOID( "\x06\x03\x55\x1D\x12" ), FIELDID_FOLLOWS,
	  MKDESC( "issuerAltName" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERT | FL_VALID_CRL | FL_SETOF, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_ISSUERALTNAME,
	  MKDESC( "issuerAltName.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MULTIVALUED | FL_NONEMPTY | FL_SEQEND /*NONE*/, ENCODED_OBJECT( generalNameInfo ) },

	/* basicConstraints:
		OID = 2 5 29 19
		critical = TRUE
		SEQUENCE {
			cA					BOOLEAN DEFAULT FALSE,
			pathLenConstraint	INTEGER (0..64) OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x13" ), CRYPT_CERTINFO_BASICCONSTRAINTS,
	  MKDESC( "basicConstraints" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_CRITICAL | FL_LEVEL_REDUCED | FL_VALID_CERTREQ | FL_VALID_CERT | FL_VALID_ATTRCERT, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CA,
	  MKDESC( "basicConstraints.cA" )
	  ENCODING( BER_BOOLEAN ),
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, RANGE_BOOLEAN },
	{ NULL, CRYPT_CERTINFO_PATHLENCONSTRAINT,
	  MKDESC( "basicConstraints.pathLenConstraint" )
	  ENCODING( BER_INTEGER ),
	  FL_OPTIONAL | FL_SEQEND /*NONE*/, RANGE( 0, 64 ) },

	/* cRLNumber:
		OID = 2 5 29 20
		INTEGER */
	{ MKOID( "\x06\x03\x55\x1D\x14" ), CRYPT_CERTINFO_CRLNUMBER,
	  MKDESC( "cRLNumber" )
	  ENCODING( BER_INTEGER ),
	  FL_LEVEL_PKIX_PARTIAL | FL_VALID_CRL, RANGE( 0, MAX_INTLENGTH ) },

	/* cRLReason:
		OID = 2 5 29 21
		ENUMERATED */
	{ MKOID( "\x06\x03\x55\x1D\x15" ), CRYPT_CERTINFO_CRLREASON,
	  MKDESC( "cRLReason" )
	  ENCODING( BER_ENUMERATED ),
	  FL_LEVEL_REDUCED | FL_VALID_CRL | FL_VALID_REVREQ /*Per-entry*/, RANGE( 0, CRYPT_CRLREASON_LAST ) },

	/* holdInstructionCode:
		OID = 2 5 29 23
		OBJECT IDENTIFIER */
	{ MKOID( "\x06\x03\x55\x1D\x17" ), CRYPT_CERTINFO_HOLDINSTRUCTIONCODE,
	  MKDESC( "holdInstructionCode" )
	  ENCODING( FIELDTYPE_CHOICE ),
	  FL_LEVEL_PKIX_PARTIAL | FL_VALID_CRL | FL_VALID_REVREQ /*Per-entry*/, CRYPT_HOLDINSTRUCTION_NONE, CRYPT_HOLDINSTRUCTION_LAST, 0, ( void * ) holdInstructionInfo },

	/* invalidityDate:
		OID = 2 5 29 24
		GeneralizedTime */
	{ MKOID( "\x06\x03\x55\x1D\x18" ), CRYPT_CERTINFO_INVALIDITYDATE,
	  MKDESC( "invalidityDate" )
	  ENCODING( BER_TIME_GENERALIZED ),
	  FL_LEVEL_STANDARD | FL_VALID_CRL | FL_VALID_REVREQ /*Per-entry*/, RANGE_TIME },

	/* deltaCRLIndicator:
		OID = 2 5 29 27
		critical = TRUE
		INTEGER */
	{ MKOID( "\x06\x03\x55\x1D\x1B" ), CRYPT_CERTINFO_DELTACRLINDICATOR,
	  MKDESC( "deltaCRLIndicator" )
	  ENCODING( BER_INTEGER ),
	  FL_CRITICAL | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CRL, RANGE( 0, MAX_INTLENGTH ) },

	/* issuingDistributionPoint:
		OID = 2 5 29 28
		critical = TRUE
		SEQUENCE {
			distributionPoint [ 0 ]	{
				fullName	  [ 0 ]	{				-- CHOICE { ... }
					SEQUENCE OF GeneralName			-- GeneralNames
					}
				} OPTIONAL,
			onlyContainsUserCerts
							  [ 1 ]	BOOLEAN DEFAULT FALSE,
			onlyContainsCACerts
							  [ 2 ]	BOOLEAN DEFAULT FALSE,
			onlySomeReasons	  [ 3 ]	BITSTRING OPTIONAL,
			indirectCRL		  [ 4 ]	BOOLEAN DEFAULT FALSE
		} */
	{ MKOID( "\x06\x03\x55\x1D\x1C" ), CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT,
	  MKDESC( "issuingDistributionPoint" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_CRITICAL | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CRL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "issuingDistributionPoint.distributionPoint" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "issuingDistributionPoint.distributionPoint.fullName" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE | FL_NONEMPTY, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "issuingDistributionPoint.distributionPoint.fullName.generalNames" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_FULLNAME,
	  MKDESC( "issuingDistributionPoint.distributionPoint.fullName.generalNames.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_3, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY,
	  MKDESC( "issuingDistributionPoint.onlyContainsUserCerts" )
	  ENCODING_TAGGED( BER_BOOLEAN, 1 ),
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, RANGE_BOOLEAN },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY,
	  MKDESC( "issuingDistributionPoint.onlyContainsCACerts" )
	  ENCODING_TAGGED( BER_BOOLEAN, 2 ),
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, RANGE_BOOLEAN },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY,
	  MKDESC( "issuingDistributionPoint.onlySomeReasons" )
	  ENCODING_TAGGED( BER_BITSTRING, 3 ),
	  FL_MORE | FL_OPTIONAL, RANGE( 0, CRYPT_CRLREASONFLAG_LAST ) },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL,
	  MKDESC( "issuingDistributionPoint.indirectCRL" )
	  ENCODING_TAGGED( BER_BOOLEAN, 4 ),
	  FL_OPTIONAL | FL_DEFAULT | FL_SEQEND /*NONE*/, RANGE_BOOLEAN },

	/* certificateIssuer:
		OID = 2 5 29 29
		critical = TRUE
		certificateIssuer SEQUENCE OF GeneralName */
	{ MKOID( "\x06\x03\x55\x1D\x1D" ), FIELDID_FOLLOWS,
	  MKDESC( "certificateIssuer" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_CRITICAL | FL_LEVEL_PKIX_FULL | FL_VALID_CRL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CERTIFICATEISSUER,
	  MKDESC( "certificateIssuer.generalNames" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MULTIVALUED | FL_NONEMPTY, ENCODED_OBJECT( generalNameInfo ) },

	/* nameConstraints
		OID = 2 5 29 30
		critical = TRUE
		SEQUENCE {
			permittedSubtrees [ 0 ]	SEQUENCE OF {
				SEQUENCE { GeneralName }
				} OPTIONAL,
			excludedSubtrees  [ 1 ]	SEQUENCE OF {
				SEQUENCE { GeneralName }
				} OPTIONAL,
			}

		RFC 3280 extended this by adding two additional fields after the
		GeneralName (probably from X.509v4) but mitigated it by requiring
		that they never be used, so we leave the definition as is */
	{ MKOID( "\x06\x03\x55\x1D\x1E" ), CRYPT_CERTINFO_NAMECONSTRAINTS,
	  MKDESC( "nameConstraints" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_VALID_ATTRCERT, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "nameConstraints.permittedSubtrees" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "nameConstraints.permittedSubtrees.sequenceOf" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_PERMITTEDSUBTREES,
	  MKDESC( "nameConstraints.permittedSubtrees.sequenceOf.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_2, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, 0,
	  MKDESC( "nameConstraints.excludedSubtrees" )
	  ENCODING_TAGGED( BER_SEQUENCE, 1 ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "nameConstraints.excludedSubtrees.sequenceOf" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_EXCLUDEDSUBTREES,
	  MKDESC( "nameConstraints.excludedSubtrees.sequenceOf.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_OPTIONAL | FL_NONEMPTY | FL_MULTIVALUED | FL_SEQEND_2 /*or _3*/, ENCODED_OBJECT( generalNameInfo ) },

	/* cRLDistributionPoints:
		OID = 2 5 29 31
		SEQUENCE OF {
			SEQUENCE {
				distributionPoint
							  [ 0 ]	{				-- CHOICE { ... }
					fullName  [ 0 ]	SEQUENCE OF GeneralName
					} OPTIONAL,
				reasons		  [ 1 ]	BIT STRING OPTIONAL,
				cRLIssuer	  [ 2 ]	SEQUENCE OF GeneralName OPTIONAL
				}
			} */
	{ MKOID( "\x06\x03\x55\x1D\x1F" ), CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT,
	  MKDESC( "cRLDistributionPoints" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERT | FL_VALID_ATTRCERT | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "cRLDistributionPoints.distPoint" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "cRLDistributionPoints.distPoint.distPoint" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "cRLDistributionPoints.distPoint.distPoint.fullName" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE | FL_NONEMPTY | FL_SETOF, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CRLDIST_FULLNAME,
	  MKDESC( "cRLDistributionPoints.distPoint.distPoint.fullName.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_2, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, CRYPT_CERTINFO_CRLDIST_REASONS,
	  MKDESC( "cRLDistributionPoints.distPoint.reasons" )
	  ENCODING_TAGGED( BER_BITSTRING, 1 ),
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED, RANGE( 0, CRYPT_CRLREASONFLAG_LAST ) },
	{ NULL, 0,
	  MKDESC( "cRLDistributionPoints.distPoint.cRLIssuer" )
	  ENCODING_TAGGED( BER_SEQUENCE, 2 ),
	  FL_MORE | FL_NONEMPTY | FL_SETOF | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CRLDIST_CRLISSUER,
	  MKDESC( "cRLDistributionPoints.distPoint.cRLIssuer.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_OPTIONAL | FL_NONEMPTY | FL_MULTIVALUED | FL_SEQEND_2 /*or _3*/, ENCODED_OBJECT( generalNameInfo ) },

	/* certificatePolicies:
		OID = 2 5 29 32
		SEQUENCE SIZE (1..64) OF {
			SEQUENCE {
				policyIdentifier	OBJECT IDENTIFIER,
				policyQualifiers	SEQUENCE SIZE (1..64) OF {
									SEQUENCE {
					policyQualifierId
									OBJECT IDENTIFIER,
					qualifier		ANY DEFINED BY policyQualifierID
						} OPTIONAL
					}
				}
			}

		CPSuri ::= IA5String						-- OID = cps

		UserNotice ::= SEQUENCE {					-- OID = unotice
			noticeRef		SEQUENCE {
				organization	DisplayText,
				noticeNumbers	SEQUENCE OF INTEGER	-- SIZE (1)
				} OPTIONAL,
			explicitText	DisplayText OPTIONAL
			}

	   Note that although this extension is decoded at
	   CRYPT_COMPLIANCELEVEL_STANDARD, policy constraints are only enforced
	   at CRYPT_COMPLIANCELEVEL_PKIX_FULL due to the totally bizarre
	   requirements that some of them have (see comments in chk_*.c for more
	   on this) */
	{ MKOID( "\x06\x03\x55\x1D\x20" ), CRYPT_CERTINFO_CERTIFICATEPOLICIES,
	  MKDESC( "certPolicies" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_STANDARD | FL_VALID_CERT | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "certPolicies.policyInfo" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CERTPOLICYID,
	  MKDESC( "certPolicies.policyInfo.policyIdentifier" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MORE | FL_MULTIVALUED, RANGE_OID },
	{ NULL, 0,
	  MKDESC( "certPolicies.policyInfo.policyQualifiers" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY | FL_SETOF | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "certPolicies.policyInfo.policyQual" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x02\x01" ), 0,
	  MKDESC( "certPolicies.policyInfo.policyQual.cps (1 3 6 1 5 5 7 2 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_CPSURI,
	  MKDESC( "certPolicies.policyInfo.policyQuals.qualifier.cPSuri" )
	  ENCODING( BER_STRING_IA5 ),
	  FL_MORE | FL_MULTIVALUED | FL_SEQEND /*FL_SEQEND_2*/, CHECK_URL },
	{ NULL, 0,
	  MKDESC( "certPolicies.policyInfo.policyQual" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x02\x02" ), 0,
	  MKDESC( "certPolicies.policyInfo.policyQual.unotice (1 3 6 1 5 5 7 2 2)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "certPolicies.policyInfo.policyQual.userNotice" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "certPolicies.policyInfo.policyQual.userNotice.noticeRef" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION,
	  MKDESC( "certPolicies.policyInfo.policyQual.userNotice.noticeRef.organization" )
	  ENCODING( FIELDTYPE_DISPLAYSTRING ),
	  FL_MORE | FL_MULTIVALUED, RANGE( 1, 200 ) },
	{ NULL, 0,
	  MKDESC( "certPolicies.policyInfo.policyQual.userNotice.noticeRef.noticeNumbers" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS,
	  MKDESC( "certPolicies.policyInfo.policyQual.userNotice.noticeRef.noticeNumbers" )
	  ENCODING( BER_INTEGER ),
	  FL_MORE | FL_MULTIVALUED | FL_SEQEND_2, RANGE( 1, 1000 ) },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT,
	  MKDESC( "certPolicies.policyInfo.policyQual.userNotice.explicitText" )
	  ENCODING( FIELDTYPE_DISPLAYSTRING ),
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_3 /*FL_SEQEND, or _4 (CPS) or _5 or _7 (uNotice), */, RANGE( 1, 200 ) },

	/* policyMappings:
		OID = 2 5 29 33
		SEQUENCE SIZE (1..MAX) OF {
			SEQUENCE {
				issuerDomainPolicy	OBJECT IDENTIFIER,
				subjectDomainPolicy	OBJECT IDENTIFIER
				}
			} */
	{ MKOID( "\x06\x03\x55\x1D\x21" ), CRYPT_CERTINFO_POLICYMAPPINGS,
	  MKDESC( "policyMappings" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "policyMappings.sequenceOf" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_ISSUERDOMAINPOLICY,
	  MKDESC( "policyMappings.sequenceOf.issuerDomainPolicy" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MORE | FL_MULTIVALUED, RANGE_OID },
	{ NULL, CRYPT_CERTINFO_SUBJECTDOMAINPOLICY,
	  MKDESC( "policyMappings.sequenceOf.subjectDomainPolicy" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MULTIVALUED | FL_SEQEND_2 /*FL_SEQEND_3*/, RANGE_OID },

	/* authorityKeyIdentifier:
		OID = 2 5 29 35
		SEQUENCE {
			keyIdentifier [ 0 ]	OCTET STRING OPTIONAL,
			authorityCertIssuer						-- Neither or both
						  [ 1 ] SEQUENCE OF GeneralName OPTIONAL
			authorityCertSerialNumber				-- of these must
						  [ 2 ] INTEGER OPTIONAL	-- be present
			}
	   Although the serialNumber should be an integer it's really an integer 
	   equivalent of an octet string hole so we call it an octet string to 
	   make sure that it gets handled appropriately */
	{ MKOID( "\x06\x03\x55\x1D\x23" ), CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER,
	  MKDESC( "authorityKeyIdentifier" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY | FL_LEVEL_PKIX_PARTIAL | FL_VALID_CERT | FL_VALID_CRL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,
	  MKDESC( "authorityKeyIdentifier.keyIdentifier" )
	  ENCODING_TAGGED( BER_OCTETSTRING, 0 ),
	  FL_MORE | FL_OPTIONAL, RANGE( 1, 64 ) },
	{ NULL, 0,
	  MKDESC( "authorityKeyIdentifier.authorityCertIssuer" )
	  ENCODING_TAGGED( BER_SEQUENCE, 1 ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_AUTHORITY_CERTISSUER,
	  MKDESC( "authorityKeyIdentifier.authorityCertIssuer.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER,
	  MKDESC( "authorityKeyIdentifier.authorityCertSerialNumber" )
	  ENCODING_TAGGED( BER_OCTETSTRING, 2 ),	/* Actually an INTEGER hole */
	  FL_OPTIONAL | FL_SEQEND /*NONE*/, RANGE( 1, 64 ) },

	/* policyConstraints:
		OID = 2 5 29 36
		SEQUENCE {
			requireExplicitPolicy [ 0 ]	INTEGER OPTIONAL,
			inhibitPolicyMapping  [ 1 ]	INTEGER OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x24" ), CRYPT_CERTINFO_POLICYCONSTRAINTS,
	  MKDESC( "policyConstraints" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY | FL_LEVEL_PKIX_FULL | FL_VALID_CERT, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,
	  MKDESC( "policyConstraints.requireExplicitPolicy" )
	  ENCODING_TAGGED( BER_INTEGER, 0 ),
	  FL_MORE | FL_OPTIONAL, RANGE( 0, 64 ) },
	{ NULL, CRYPT_CERTINFO_INHIBITPOLICYMAPPING,
	  MKDESC( "policyConstraints.inhibitPolicyMapping" )
	  ENCODING_TAGGED( BER_INTEGER, 1 ),
	  FL_OPTIONAL | FL_SEQEND /*NONE*/, RANGE( 0, 64 ) },

	/* extKeyUsage:
		OID = 2 5 29 37
		SEQUENCE {
			oidInstance1 OPTIONAL,
			oidInstance2 OPTIONAL,
				...
			oidInstanceN OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x25" ), CRYPT_CERTINFO_EXTKEYUSAGE,
	  MKDESC( "extKeyUsage" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY | FL_LEVEL_STANDARD | FL_VALID_CERTREQ | FL_VALID_CERT, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x15" ), CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING,
	  MKDESC( "extKeyUsage.individualCodeSigning (1 3 6 1 4 1 311 2 1 21)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x16" ), CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING,
	  MKDESC( "extKeyUsage.commercialCodeSigning (1 3 6 1 4 1 311 2 1 22)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x01" ), CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING,
	  MKDESC( "extKeyUsage.certTrustListSigning (1 3 6 1 4 1 311 10 3 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x02" ), CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING,
	  MKDESC( "extKeyUsage.timeStampSigning (1 3 6 1 4 1 311 10 3 2)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x03" ), CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO,
	  MKDESC( "extKeyUsage.serverGatedCrypto (1 3 6 1 4 1 311 10 3 3)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x04" ), CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM,
	  MKDESC( "extKeyUsage.encrypedFileSystem (1 3 6 1 4 1 311 10 3 4)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x01" ), CRYPT_CERTINFO_EXTKEY_SERVERAUTH,
	  MKDESC( "extKeyUsage.serverAuth (1 3 6 1 5 5 7 3 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x02" ), CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,
	  MKDESC( "extKeyUsage.clientAuth (1 3 6 1 5 5 7 3 2)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x03" ), CRYPT_CERTINFO_EXTKEY_CODESIGNING,
	  MKDESC( "extKeyUsage.codeSigning (1 3 6 1 5 5 7 3 3)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x04" ), CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,
	  MKDESC( "extKeyUsage.emailProtection (1 3 6 1 5 5 7 3 4)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x05" ), CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM,
	  MKDESC( "extKeyUsage.ipsecEndSystem (1 3 6 1 5 5 7 3 5)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x06" ), CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL,
	  MKDESC( "extKeyUsage.ipsecTunnel (1 3 6 1 5 5 7 3 6)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x07" ), CRYPT_CERTINFO_EXTKEY_IPSECUSER,
	  MKDESC( "extKeyUsage.ipsecUser (1 3 6 1 5 5 7 3 7)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x08" ), CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,
	  MKDESC( "extKeyUsage.timeStamping (1 3 6 1 5 5 7 3 8)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x09" ), CRYPT_CERTINFO_EXTKEY_OCSPSIGNING,
	  MKDESC( "extKeyUsage.ocspSigning (1 3 6 1 5 5 7 3 9)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x05\x2B\x24\x08\x02\x01" ), CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE,
	  MKDESC( "extKeyUsage.directoryService (1 3 36 8 2 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x04\x55\x1D\x25\x00" ), CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE,
	  MKDESC( "extKeyUsage.anyExtendedKeyUsage(2 5 29 37 0)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x04\x01" ), CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO,
	  MKDESC( "extKeyUsage.serverGatedCrypto (2 16 840 1 113730 4 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x08\x01" ), CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA,
	  MKDESC( "extKeyUsage.serverGatedCryptoCA (2 16 840 1 113733 1 8 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "extKeyUsage.catchAll" )
	  ENCODING( FIELDTYPE_BLOB ),	/* Match anything and ignore it */
	  FL_OPTIONAL | FL_NONENCODING | FL_SEQEND /*NONE*/, RANGE_NONE },

	/* freshestCRL:
		OID = 2 5 29 46
		SEQUENCE OF {
			SEQUENCE {
				distributionPoint
							  [ 0 ]	{				-- CHOICE { ... }
					fullName  [ 0 ]	SEQUENCE OF GeneralName
					} OPTIONAL,
				reasons		  [ 1 ]	BIT STRING OPTIONAL,
				cRLIssuer	  [ 2 ]	SEQUENCE OF GeneralName OPTIONAL
				}
			} */
	{ MKOID( "\x06\x03\x55\x1D\x2E" ), CRYPT_CERTINFO_FRESHESTCRL,
	  MKDESC( "freshestCRL" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_VALID_ATTRCERT | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "freshestCRL.distributionPoint" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "freshestCRL.distributionPoint.distributionPoint" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "freshestCRL.distributionPoint.distributionPoint.fullName" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE | FL_NONEMPTY | FL_SETOF, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_FRESHESTCRL_FULLNAME,
	  MKDESC( "freshestCRL.distributionPoint.distributionPoint.fullName.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MORE | FL_NONEMPTY | FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND_2, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, CRYPT_CERTINFO_FRESHESTCRL_REASONS,
	  MKDESC( "freshestCRL.distributionPoint.reasons" )
	  ENCODING_TAGGED( BER_BITSTRING, 1 ),
	  FL_MORE | FL_OPTIONAL | FL_MULTIVALUED, RANGE( 0, CRYPT_CRLREASONFLAG_LAST ) },
	{ NULL, 0,
	  MKDESC( "freshestCRL.distributionPoint.cRLIssuer" )
	  ENCODING_TAGGED( BER_SEQUENCE, 2 ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_FRESHESTCRL_CRLISSUER,
	  MKDESC( "freshestCRL.distributionPoint.cRLIssuer.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_OPTIONAL | FL_NONEMPTY | FL_MULTIVALUED | FL_SEQEND_2 /*or _3*/, ENCODED_OBJECT( generalNameInfo ) },

	/* inhibitAnyPolicy:
		OID = 2 5 29 54
		INTEGER */
	{ MKOID( "\x06\x03\x55\x1D\x36" ), CRYPT_CERTINFO_INHIBITANYPOLICY,
	  MKDESC( "inhibitAnyPolicy" )
	  ENCODING( BER_INTEGER ),
	  FL_LEVEL_PKIX_FULL | FL_VALID_CERTREQ | FL_VALID_CERT, RANGE( 0, 64 ) },

	/* netscape-cert-type:
		OID = 2 16 840 1 113730 1 1
		BITSTRING */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x01" ), CRYPT_CERTINFO_NS_CERTTYPE,
	  MKDESC( "netscape-cert-type" )
	  ENCODING( BER_BITSTRING ),
	  FL_LEVEL_REDUCED | FL_VALID_CERTREQ | FL_VALID_CERT, RANGE( 0, CRYPT_NS_CERTTYPE_LAST ) },

	/* netscape-base-url:
		OID = 2 16 840 1 113730 1 2
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x02" ), CRYPT_CERTINFO_NS_BASEURL,
	  MKDESC( "netscape-base-url" )
	  ENCODING( BER_STRING_IA5 ),
	  FL_LEVEL_STANDARD | FL_VALID_CERT, CHECK_HTTP },

	/* netscape-revocation-url:
		OID = 2 16 840 1 113730 1 3
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x03" ), CRYPT_CERTINFO_NS_REVOCATIONURL,
	  MKDESC( "netscape-revocation-url" )
	  ENCODING( BER_STRING_IA5 ),
	  FL_LEVEL_STANDARD | FL_VALID_CERT, CHECK_HTTP },

	/* netscape-ca-revocation-url:
		OID = 2 16 840 1 113730 1 3
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x04" ), CRYPT_CERTINFO_NS_CAREVOCATIONURL,
	  MKDESC( "netscape-ca-revocation-url" )
	  ENCODING( BER_STRING_IA5 ),
	  FL_LEVEL_STANDARD | FL_VALID_CERT, CHECK_HTTP },

	/* netscape-ca-revocation-url:
		OID = 2 16 840 1 113730 11 7
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x07" ), CRYPT_CERTINFO_NS_CERTRENEWALURL,
	  MKDESC( "netscape-ca-revocation-url" )
	  ENCODING( BER_STRING_IA5 ),
	  FL_LEVEL_STANDARD | FL_VALID_CERT, CHECK_HTTP },

	/* netscape-ca-policy-url:
		OID = 2 16 840 1 113730 1 8
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x08" ), CRYPT_CERTINFO_NS_CAPOLICYURL,
	  MKDESC( "netscape-ca-policy-url" )
	  ENCODING( BER_STRING_IA5 ),
	  FL_LEVEL_STANDARD | FL_VALID_CERT, CHECK_HTTP },

	/* netscape-ssl-server-name:
		OID = 2 16 840 1 113730 1 12
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x0C" ), CRYPT_CERTINFO_NS_SSLSERVERNAME,
	  MKDESC( "netscape-ssl-server-name" )
	  ENCODING( BER_STRING_IA5 ),
	  FL_LEVEL_STANDARD | FL_VALID_CERTREQ | FL_VALID_CERT, CHECK_DNS },

	/* netscape-comment:
		OID = 2 16 840 1 113730 1 13
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x0D" ), CRYPT_CERTINFO_NS_COMMENT,
	  MKDESC( "netscape-comment" )
	  ENCODING( BER_STRING_IA5 ),
	  FL_LEVEL_STANDARD | FL_VALID_CERTREQ | FL_VALID_CERT, RANGE_ATTRIBUTEBLOB },

	/* hashedRootKey:
		OID = 2 23 42 7 0
		critical = TRUE
		SEQUENCE {
			rootKeyThumbprint	DigestedData		-- PKCS #7-type wrapper
			} */
	{ MKOID( "\x06\x04\x67\x2A\x07\x00" ), CRYPT_CERTINFO_SET_HASHEDROOTKEY,
	  MKDESC( "hashedRootKey" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_CRITICAL | FL_LEVEL_PKIX_FULL | FL_VALID_CERT, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "hashedRootKey.rootKeyThumbprint" )
	  ENCODING( FIELDTYPE_BLOB ),		/* PKCS #7-type wrapper */
	  FL_MORE | FL_NONENCODING, 0, 0, 25,
	  "\x30\x2D\x02\x01\x00\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x30\x07\x06\x05\x67\x2A\x03\x00\x00" },
	{ NULL, CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT,
	  MKDESC( "hashedRootKey.rootKeyThumbprint.hashData" )
	  ENCODING( BER_OCTETSTRING ),
	  FL_SEQEND /*NONE*/, RANGE( 20, 20 ) },

	/* certificateType:
		OID = 2 23 42 7 1
		critical = TRUE
		BIT STRING */
	{ MKOID( "\x06\x04\x67\x2A\x07\x01" ), CRYPT_CERTINFO_SET_CERTIFICATETYPE,
	  MKDESC( "certificateType" )
	  ENCODING( BER_BITSTRING ),
	  FL_CRITICAL | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_VALID_CERTREQ, RANGE( 0, CRYPT_SET_CERTTYPE_LAST ) },

	/* merchantData:
		OID = 2 23 42 7 2
		SEQUENCE {
			merID				SETString SIZE(1..30),
			merAcquirerBIN		NumericString SIZE(6),
			merNameSeq			SEQUENCE OF MerNames,
			merCountry			INTEGER (1..999),
			merAuthFlag			BOOLEAN DEFAULT TRUE
			}

		MerNames ::= SEQUENCE {
			language	  [ 0 ] VisibleString SIZE(1..35),
			name		  [ 1 ]	EXPLICIT SETString SIZE(1..50),
			city		  [ 2 ]	EXPLICIT SETString SIZE(1..50),
			stateProvince [ 3 ] EXPLICIT SETString SIZE(1..50) OPTIONAL,
			postalCode	  [ 4 ] EXPLICIT SETString SIZE(1..14) OPTIONAL,
			countryName	  [ 5 ]	EXPLICIT SETString SIZE(1..50)
			} */
	{ MKOID( "\x06\x04\x67\x2A\x07\x02" ), CRYPT_CERTINFO_SET_MERCHANTDATA,
	  MKDESC( "merchantData" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SET_MERID,
	  MKDESC( "merchantData.merID" )
	  ENCODING( BER_STRING_ISO646 ),
	  FL_MORE, RANGE( 1, 30 ) },
	{ NULL, CRYPT_CERTINFO_SET_MERACQUIRERBIN,
	  MKDESC( "merchantData.merAcquirerBIN" )
	  ENCODING( BER_STRING_NUMERIC ),
	  FL_MORE, RANGE( 6, 6 ) },
	{ NULL, 0,
	  MKDESC( "merchantData.merNameSeq" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "merchantData.merNameSeq.merNames" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTLANGUAGE,
	  MKDESC( "merchantData.merNameSeq.merNames.language" )
	  ENCODING_TAGGED( BER_STRING_ISO646, 0 ),
	  FL_MORE | FL_MULTIVALUED, RANGE( 1, 35 ) },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTNAME,
	  MKDESC( "merchantData.merNameSeq.merNames.name" )
	  ENCODING_TAGGED( BER_STRING_ISO646, 1 ),
	  FL_MORE | FL_MULTIVALUED | FL_EXPLICIT, RANGE( 1, 50 ) },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTCITY,
	  MKDESC( "merchantData.merNameSeq.merNames.city" )
	  ENCODING_TAGGED( BER_STRING_ISO646, 2 ),
	  FL_MORE | FL_MULTIVALUED | FL_EXPLICIT, RANGE( 1, 50 ) },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE,
	  MKDESC( "merchantData.merNameSeq.merNames.stateProvince" )
	  ENCODING_TAGGED( BER_STRING_ISO646, 3 ),
	  FL_MORE | FL_MULTIVALUED | FL_EXPLICIT | FL_OPTIONAL, RANGE( 1, 50 ) },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE,
	  MKDESC( "merchantData.merNameSeq.merNames.postalCode" )
	  ENCODING_TAGGED( BER_STRING_ISO646, 4 ),
	  FL_MORE | FL_MULTIVALUED | FL_EXPLICIT | FL_OPTIONAL, RANGE( 1, 50 ) },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME,
	  MKDESC( "merchantData.merNameSeq.merNames.countryName" )
	  ENCODING_TAGGED( BER_STRING_ISO646, 5 ),
	  FL_MORE | FL_MULTIVALUED | FL_EXPLICIT | FL_SEQEND_2, RANGE( 1, 50 ) },
	{ NULL, CRYPT_CERTINFO_SET_MERCOUNTRY,
	  MKDESC( "merchantData.merCountry" )
	  ENCODING( BER_INTEGER ),
	  FL_MORE, RANGE( 1, 999 ) },
	{ NULL, CRYPT_CERTINFO_SET_MERAUTHFLAG,
	  MKDESC( "merchantData.merAuthFlag" )
	  ENCODING( BER_BOOLEAN ),
	  FL_OPTIONAL | FL_DEFAULT | FL_SEQEND /*NONE*/, RANGE_BOOLEAN },

	/* certCardRequired
		OID = 2 23 42 7 3
		BOOLEAN */
	{ MKOID( "\x06\x04\x67\x2A\x07\x03" ), CRYPT_CERTINFO_SET_CERTCARDREQUIRED,
	  MKDESC( "certCardRequired" )
	  ENCODING( BER_BOOLEAN ),
	  FL_LEVEL_PKIX_FULL | FL_VALID_CERT, RANGE_BOOLEAN },

	/* tunneling:
		OID = 2 23 42 7 4
		SEQUENCE {
			tunneling 		DEFAULT TRUE,
			tunnelAlgIDs	SEQUENCE OF OBJECT IDENTIFIER
			} */
	{ MKOID( "\x06\x04\x67\x2A\x07\x04" ), CRYPT_CERTINFO_SET_TUNNELING,
	  MKDESC( "tunneling" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_LEVEL_PKIX_FULL | FL_VALID_CERT | FL_VALID_CERTREQ, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SET_TUNNELINGFLAG,
	  MKDESC( "tunneling.tunneling" )
	  ENCODING( BER_BOOLEAN ),
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, TRUE, NULL },
	{ NULL, 0,
	  MKDESC( "tunneling.tunnelingAlgIDs" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_SETOF, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_SET_TUNNELINGALGID,
	  MKDESC( "tunneling.tunnelingAlgIDs.tunnelingAlgID" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MULTIVALUED | FL_SEQEND, RANGE_OID },

	{ NULL, CRYPT_ERROR }, { NULL, CRYPT_ERROR }
	};

/* Subtable for encoding the holdInstructionCode */

STATIC_DATA const ATTRIBUTE_INFO FAR_BSS holdInstructionInfo[] = {
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x01" ), CRYPT_HOLDINSTRUCTION_NONE,
	  MKDESC( "holdInstructionCode.holdinstruction-none (1 2 840 10040 2 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x02" ), CRYPT_HOLDINSTRUCTION_CALLISSUER,
	  MKDESC( "holdInstructionCode.holdinstruction-callissuer (1 2 840 10040 2 2)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x03" ), CRYPT_HOLDINSTRUCTION_REJECT,
	  MKDESC( "holdInstructionCode.holdinstruction-reject (1 2 840 10040 2 3)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x04" ), CRYPT_HOLDINSTRUCTION_PICKUPTOKEN,
	  MKDESC( "holdInstructionCode.holdinstruction-pickupToken (1 2 840 10040 2 4)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_OPTIONAL, RANGE_NONE },

	{ NULL, CRYPT_ERROR }, { NULL, CRYPT_ERROR }
	};

/****************************************************************************
*																			*
*								GeneralName Definition						*
*																			*
****************************************************************************/

/* Encoding and decoding of GeneralNames is performed with the following
   subtable:

	otherName		  [ 0 ]	SEQUENCE {
		type-id				OBJECT IDENTIFIER,
		value		  [ 0 ]	EXPLICIT ANY DEFINED BY type-id
		} OPTIONAL,
	rfc822Name		  [ 1 ]	IA5String OPTIONAL,
	dNSName			  [ 2 ]	IA5String OPTIONAL,
	x400Address		  [ 3 ] ITU-BrainDamage OPTIONAL
	directoryName	  [ 4 ]	EXPLICIT Name OPTIONAL,
	ediPartyName 	  [ 5 ]	SEQUENCE {
		nameAssigner  [ 0 ]	EXPLICIT DirectoryString OPTIONAL,
		partyName	  [ 1 ]	EXPLICIT DirectoryString
		} OPTIONAL,
	uniformResourceIdentifier
					  [ 6 ]	IA5String OPTIONAL,
	iPAddress		  [ 7 ]	OCTET STRING OPTIONAL,
	registeredID	  [ 8 ]	OBJECT IDENTIFIER OPTIONAL

	ITU-Braindamge ::= SEQUENCE {
		built-in-standard-attributes		SEQUENCE {
			country-name  [ APPLICATION 1 ]	CHOICE {
				x121-dcc-code				NumericString,
				iso-3166-alpha2-code		PrintableString
				},
			administration-domain-name
						  [ APPLICATION 2 ]	CHOICE {
				numeric						NumericString,
				printable					PrintableString
				},
			network-address			  [ 0 ]	NumericString OPTIONAL,
			terminal-identifier		  [ 1 ]	PrintableString OPTIONAL,
			private-domain-name		  [ 2 ]	CHOICE {
				numeric						NumericString,
				printable					PrintableString
				} OPTIONAL,
			organization-name		  [ 3 ]	PrintableString OPTIONAL,
			numeric-use-identifier	  [ 4 ]	NumericString OPTIONAL,
			personal-name			  [ 5 ]	SET {
				surname				  [ 0 ]	PrintableString,
				given-name			  [ 1 ]	PrintableString,
				initials			  [ 2 ]	PrintableString,
				generation-qualifier  [ 3 ]	PrintableString
				} OPTIONAL,
			organizational-unit-name  [ 6 ]	PrintableString OPTIONAL,
			}
		built-in-domain-defined-attributes	SEQUENCE OF {
			type							PrintableString SIZE(1..64),
			value							PrintableString SIZE(1..64)
			} OPTIONAL
		extensionAttributes					SET OF SEQUENCE {
			extension-attribute-type  [ 0 ]	INTEGER,
			extension-attribute-value [ 1 ]	ANY DEFINED BY extension-attribute-type
			} OPTIONAL
		}

   Needless to say, X.400 addresses aren't supported (for readers who've
   never seen one before, now you know why they've been so enormously
   successful).

   Note the special-case encoding of the DirectoryName and EDIPartyName.
   This is required because (for the DirectoryName) a Name is actually a
   CHOICE { RDNSequence } and if the tagging were implicit then there'd be
   no way to tell which of the CHOICE options was being used:

	directoryName	  [ 4 ]	Name OPTIONAL

   becomes:

	directoryName	  [ 4 ]	CHOICE { RDNSequence } OPTIONAL

   which, if implicit tagging is used, would replace the RDNSequence tag with
   the [4] tag, making it impossible to determine which of the Name choices
   was used (actually there's only one possibility and it's unlikely that
   there'll ever be more but that's what the encoding rules require - X.208,
   section 26.7c).

   The same applies to the EDIPartyName, this is a DirectoryString which is
   a CHOICE of several possible string types.  The end result is that:

	[ 0 ] DirectoryString

   ends up looking like:

	[ 0 ] SEQUENCE {
		option1				PrintableString	OPTIONAL,
		option2				T61String OPTIONAL,
		option3				UTF8String OPTIONAL,
		option4				BMPString OPTIONAL
		}

   Newer versions of the PKIX core RFC allow the use of 8- and 32-byte CIDR
   forms for 4- and 16-byte IP addresses in some instances when they're
   being used as constraints.  We'll add support for this if anyone ever
   asks for it */

STATIC_DATA const ATTRIBUTE_INFO FAR_BSS generalNameInfo[] = {
	/* otherName */
	{ NULL, 0,
	  MKDESC( "generalName.otherName" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_OTHERNAME_TYPEID,
	  MKDESC( "generalName.otherName.type-id" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_OID },
	{ NULL, CRYPT_CERTINFO_OTHERNAME_VALUE,
	  MKDESC( "generalName.otherName.value" )
	  ENCODING_TAGGED( FIELDTYPE_BLOB, 0 ),
	  FL_MORE | FL_OPTIONAL | FL_EXPLICIT | FL_SEQEND, RANGE( 3, MAX_ATTRIBUTE_SIZE ) },
	
	/* rfc822Name */
	{ NULL, CRYPT_CERTINFO_RFC822NAME,
	  MKDESC( "generalName.rfc822Name" )
	  ENCODING_TAGGED( BER_STRING_IA5, 1 ),
	  FL_MORE | FL_OPTIONAL, CHECK_RFC822 },
	
	/* dNSName */
	{ NULL, CRYPT_CERTINFO_DNSNAME,
	  MKDESC( "generalName.dNSName" )
	  ENCODING_TAGGED( BER_STRING_IA5, 2 ),
	  FL_MORE | FL_OPTIONAL, CHECK_DNS },
	
	/* directoryName */
#if 0	/* 28/4/08 This form seems to have worked by coincidence... */
	{ NULL, 0,
	  MKDESC( "generalName.directoryName" )
	  ENCODING_TAGGED( BER_SEQUENCE, 4 ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_DIRECTORYNAME,
	  MKDESC( "generalName.directoryName.name" )
	  ENCODING_ALIAS( FIELDTYPE_DN, BER_SEQUENCE ),
	  FL_MORE | FL_OPTIONAL | FL_ALIAS | FL_SEQEND_1, CHECK_X500 },
#else
	{ NULL, CRYPT_CERTINFO_DIRECTORYNAME,
	  MKDESC( "generalName.directoryName" )
	  ENCODING_TAGGED( FIELDTYPE_DN, 4 ),
	  FL_MORE | FL_OPTIONAL | FL_EXPLICIT, CHECK_X500 },
#endif /* 0 */

	/* ediPartyName */
	{ NULL, 0,
	  MKDESC( "generalName.ediPartyName" )
	  ENCODING_TAGGED( BER_SEQUENCE, 5 ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "generalName.ediPartyName.nameAssigner" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE | FL_OPTIONAL, RANGE_TEXTSTRING },
	  /* See note above on why the extra SEQUENCE is present */
	{ NULL, CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER,
	  MKDESC( "generalName.ediPartyName.nameAssigner.directoryName" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  FL_MORE | FL_OPTIONAL, RANGE_TEXTSTRING },
	{ NULL, CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER,
	  MKDESC( "generalName.ediPartyName.nameAssigner.directoryName" )
	  ENCODING( BER_STRING_T61 ),
	  FL_MORE | FL_OPTIONAL | FL_SEQEND, RANGE_TEXTSTRING },
	{ NULL, 0,
	  MKDESC( "generalName.ediPartyName.partyName" )
	  ENCODING_TAGGED( BER_SEQUENCE, 1 ),
	  FL_MORE, RANGE_TEXTSTRING },
	{ NULL, CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME,
	  MKDESC( "generalName.ediPartyName.partyName.directoryName" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  FL_MORE | FL_OPTIONAL, RANGE_TEXTSTRING },
	{ NULL, CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME,
	  MKDESC( "generalName.ediPartyName.partyName.directoryName" )
	  ENCODING( BER_STRING_T61 ),
	  FL_MORE | FL_OPTIONAL | FL_SEQEND_2, RANGE_TEXTSTRING },
	
	/* uniformResourceIdentifier */
	{ NULL, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
	  MKDESC( "generalName.uniformResourceIdentifier" )
	  ENCODING_TAGGED( BER_STRING_IA5, 6 ),
	  FL_MORE | FL_OPTIONAL, CHECK_URL },
	
	/* iPAddress */
	{ NULL, CRYPT_CERTINFO_IPADDRESS,
	  MKDESC( "generalName.iPAddress" )
	  ENCODING_TAGGED( BER_OCTETSTRING, 7 ),
	  FL_MORE | FL_OPTIONAL, RANGE( 4, 16 ) },

	/* registeredID */
	{ NULL, CRYPT_CERTINFO_REGISTEREDID,
	  MKDESC( "generalName.registeredID" )
	  ENCODING_TAGGED( BER_OBJECT_IDENTIFIER, 8 ),
	  FL_OPTIONAL, RANGE_OID },

	{ NULL, CRYPT_ERROR }, { NULL, CRYPT_ERROR }
	};

/****************************************************************************
*																			*
*							CMS Attribute Definitions						*
*																			*
****************************************************************************/

/* CMS attributes are encoded using the following table */

static const ATTRIBUTE_INFO FAR_BSS cmsAttributeInfo[] = {
	/* contentType:
		OID = 1 2 840 113549 1 9 3
		OBJECT IDENTIFIER */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x03" ), CRYPT_CERTINFO_CMS_CONTENTTYPE,
	  MKDESC( "contentType" )
	  ENCODING( FIELDTYPE_CHOICE ),
	  0, CRYPT_CONTENT_DATA, CRYPT_CONTENT_LAST, 0, ( void * ) contentTypeInfo },

	/* messageDigest:
		OID = 1 2 840 113549 1 9 4
		OCTET STRING */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x04" ), CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
	  MKDESC( "messageDigest" )
	  ENCODING( BER_OCTETSTRING ),
	  0, RANGE( 16, CRYPT_MAX_HASHSIZE ) },

	/* signingTime:
		OID = 1 2 840 113549 1 9 5
		CHOICE {
			utcTime			UTCTime,				-- Up to 2049
			generalizedTime	GeneralizedTime
			} */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x05" ), CRYPT_CERTINFO_CMS_SIGNINGTIME,
	  MKDESC( "signingTime" )
	  ENCODING( BER_TIME_UTC ),
	  0, RANGE_TIME },

	/* counterSignature:
		OID = 1 2 840 113549 1 9 6
		CHOICE {
			utcTime			UTCTime,				-- Up to 2049
			generalizedTime	GeneralizedTime
			}
	   This field isn't an authenticated attribute so it isn't used */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x06" ), CRYPT_CERTINFO_CMS_COUNTERSIGNATURE,
	  MKDESC( "counterSignature" )
	  ENCODING( -1 ),
	  0, RANGE_NONE },

  	/* signingDescription:
		OID = 1 2 840 113549 1 9 13
		UTF8String */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0D" ), CRYPT_CERTINFO_CMS_SIGNINGDESCRIPTION,
	  MKDESC( "signingDescription" )
	  ENCODING( BER_STRING_UTF8 ),
	  0, RANGE_ATTRIBUTEBLOB },

	/* sMIMECapabilities:
		OID = 1 2 840 113549 1 9 15
		SEQUENCE OF {
			SEQUENCE {
				capabilityID	OBJECT IDENTIFIER,
				parameters		ANY DEFINED BY capabilityID
				}
			} */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0F" ), CRYPT_CERTINFO_CMS_SMIMECAPABILITIES,
	  MKDESC( "sMIMECapabilities" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (des-EDE3-CBC)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x07" ), CRYPT_CERTINFO_CMS_SMIMECAP_3DES,
	  MKDESC( "sMIMECapabilities.capability.des-EDE3-CBC" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_NONENCODING | FL_SEQEND, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (aes128-CBC)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_AES,
	  MKDESC( "sMIMECapabilities.capability.aes128-CBC" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_NONENCODING | FL_SEQEND, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (cast5CBC)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF6\x7D\x07\x42\x0A" ), CRYPT_CERTINFO_CMS_SMIMECAP_CAST128,
	  MKDESC( "sMIMECapabilities.capability.cast5CBC" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_NONENCODING, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability.cast5CBC.parameter" )
	  ENCODING( FIELDTYPE_BLOB ),	/* 128-bit key */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 4, "\x02\x02\x00\x80" },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (ideaCBC)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_IDEA,
	  MKDESC( "sMIMECapabilities.capability.ideaCBC (Ascom Tech variant)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_NONENCODING | FL_SEQEND, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (rc2CBC)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_RC2,
	  MKDESC( "sMIMECapabilities.capability.rc2CBC" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_NONENCODING, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability.rc2CBC.parameters" )
	  ENCODING( FIELDTYPE_BLOB ),	/* 128-bit key */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 4, "\x02\x02\x00\x80" },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (rC5-CBCPad)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x09" ), CRYPT_CERTINFO_CMS_SMIMECAP_RC5,
	  MKDESC( "sMIMECapabilities.capability.rC5-CBCPad" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_NONENCODING, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability.rC5-CBCPad.parameters" )
	  ENCODING( FIELDTYPE_BLOB ),	/* 16-byte key, 12 rounds, 64-bit blocks */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 11, "\x30\x09\x02\x01\x10\x02\x01\x0C\x02\x01\x40" },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (fortezzaConfidentialityAlgorithm)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x04" ), CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK,
	  MKDESC( "sMIMECapabilities.capability.fortezzaConfidentialityAlgorithm" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_NONENCODING | FL_SEQEND, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (desCBC)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x05\x2B\x0E\x03\x02\x07" ), CRYPT_CERTINFO_CMS_SMIMECAP_DES,
	  MKDESC( "sMIMECapabilities.capability.desCBC" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_NONENCODING | FL_SEQEND, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (preferSignedData)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0F\x01" ), CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA,
	  MKDESC( "sMIMECapabilities.capability.preferSignedData" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_NONENCODING | FL_SEQEND, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (canNotDecryptAny)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0F\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY,
	  MKDESC( "sMIMECapabilities.capability.canNotDecryptAny" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_NONENCODING | FL_SEQEND, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "sMIMECapabilities.capability (catchAll)" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ NULL, 10000,
	  MKDESC( "sMIMECapabilities.capability.catchAll" )
	  ENCODING( FIELDTYPE_BLOB ),	/* Match anything and ignore it */
	  FL_NONENCODING | FL_SEQEND_2 /*FL_SEQEND*/, RANGE_NONE },

	/* receiptRequest:
		OID = 1 2 840 113549 1 9 16 2 1
		SEQUENCE {
			contentIdentifier	OCTET STRING,
			receiptsFrom  [ 0 ]	INTEGER (0..1),
			receiptsTo			SEQUENCE {
				SEQUENCE OF GeneralName
				}
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x01" ), CRYPT_CERTINFO_CMS_RECEIPTREQUEST,
	  MKDESC( "receiptRequest" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER,
	  MKDESC( "receiptRequest.contentIdentifier" )
	  ENCODING( BER_OCTETSTRING ),
	  FL_MORE, RANGE( 16, 64 ) },
	{ NULL, CRYPT_CERTINFO_CMS_RECEIPT_FROM,
	  MKDESC( "receiptRequest.receiptsFrom" )
	  ENCODING_TAGGED( BER_INTEGER, 0 ),
	  FL_MORE, RANGE( 0, 1 ) },
	{ NULL, 0,
	  MKDESC( "receiptRequest.receiptsTo" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "receiptRequest.receiptsTo.generalNames" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_RECEIPT_TO,
	  MKDESC( "receiptRequest.receiptsTo.generalNames.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_MULTIVALUED | FL_SEQEND_3 /*FL_SEQEND_2*/, ENCODED_OBJECT( generalNameInfo ) },

	/* essSecurityLabel:
		OID = 1 2 840 113549 1 9 16 2 2
		SET {
			policyIdentifier	OBJECT IDENTIFIER,
			classification		INTEGER (0..5+6..255) OPTIONAL,
			privacyMark			PrintableString OPTIONAL,
			categories			SET OF {
				SEQUENCE {
					type  [ 0 ]	OBJECT IDENTIFIER,
					value [ 1 ]	ANY DEFINED BY type
					}
				} OPTIONAL
			}
		Because this is a SET we don't order the fields in the sequence
		given in the above ASN.1 but in the order of encoded size to follow
		the DER SET encoding rules */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x02" ), CRYPT_CERTINFO_CMS_SECURITYLABEL,
	  MKDESC( "essSecurityLabel" )
	  ENCODING( BER_SET ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_POLICY,
	  MKDESC( "essSecurityLabel.securityPolicyIdentifier" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MORE, RANGE_OID },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION,
	  MKDESC( "essSecurityLabel.securityClassification" )
	  ENCODING( BER_INTEGER ),
	  FL_MORE | FL_OPTIONAL, RANGE( CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST ) },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK,
	  MKDESC( "essSecurityLabel.privacyMark" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  FL_MORE | FL_OPTIONAL, RANGE( 1, 64 ) },
	{ NULL, 0,
	  MKDESC( "essSecurityLabel.securityCategories" )
	  ENCODING( BER_SET ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "essSecurityLabel.securityCategories.securityCategory" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE,
	  MKDESC( "essSecurityLabel.securityCategories.securityCategory.type" )
	  ENCODING_TAGGED( BER_OBJECT_IDENTIFIER, 0 ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, RANGE_OID },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE,
	  MKDESC( "essSecurityLabel.securityCategories.securityCategory.value" )
	  ENCODING_TAGGED( FIELDTYPE_BLOB, 1 ),
	  FL_MULTIVALUED | FL_SEQEND /*FL_SEQEND_2, or _3*/ | FL_OPTIONAL, RANGE_ATTRIBUTEBLOB },

	/* mlExpansionHistory:
		OID = 1 2 840 113549 1 9 16 2 3
		SEQUENCE OF {
			SEQUENCE {
				entityIdentifier IssuerAndSerialNumber,	-- Treated as blob
				expansionTime	GeneralizedTime,
				mlReceiptPolicy	CHOICE {
					none		  [ 0 ]	NULL,
					insteadOf	  [ 1 ]	SEQUENCE OF {
						SEQUENCE OF GeneralName		-- GeneralNames
						}
					inAdditionTo  [ 2 ]	SEQUENCE OF {
						SEQUENCE OF GeneralName		-- GeneralNames
						}
					}
				}
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x03" ), CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY,
	  MKDESC( "mlExpansionHistory" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "mlExpansionHistory.mlData" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER,
	  MKDESC( "mlExpansionHistory.mlData.mailListIdentifier.issuerAndSerialNumber" )
	  ENCODING( FIELDTYPE_BLOB ),
	  FL_MORE | FL_MULTIVALUED, RANGE_ATTRIBUTEBLOB },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_TIME,
	  MKDESC( "mlExpansionHistory.mlData.expansionTime" )
	  ENCODING( BER_TIME_GENERALIZED ),
	  FL_MORE | FL_MULTIVALUED, RANGE_TIME },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_NONE,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.none" )
	  ENCODING_TAGGED( BER_NULL, 0 ),
	  FL_MORE | FL_MULTIVALUED, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.insteadOf" )
	  ENCODING_TAGGED( BER_SEQUENCE, 1 ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.insteadOf.generalNames" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.insteadOf.generalNames.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_SEQEND_2 | FL_MULTIVALUED | FL_OPTIONAL, ENCODED_OBJECT( generalNameInfo ) },
	{ NULL, 0,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.inAdditionTo" )
	  ENCODING_TAGGED( BER_SEQUENCE, 2 ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.inAdditionTo.generalNames" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO,
	  MKDESC( "mlExpansionHistory.mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName" )
	  ENCODING( FIELDTYPE_SUBTYPED ),
	  FL_SEQEND_2 /*FL_SEQEND_3, or _4*/ | FL_MULTIVALUED | FL_OPTIONAL, ENCODED_OBJECT( generalNameInfo ) },

	/* contentHints:
		OID = 1 2 840 113549 1 9 16 2 4
		SEQUENCE {
			contentDescription	UTF8String,
			contentType			OBJECT IDENTIFIER
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x04" ), CRYPT_CERTINFO_CMS_CONTENTHINTS,
	  MKDESC( "contentHints" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION,
	  MKDESC( "contentHints.contentDescription" )
	  ENCODING( BER_STRING_UTF8 ),
	  FL_MORE | FL_OPTIONAL, RANGE_TEXTSTRING },
	{ NULL, CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE,
	  MKDESC( "contentHints.contentType" )
	  ENCODING( FIELDTYPE_CHOICE ),
	  FL_SEQEND /*NONE*/, CRYPT_CONTENT_DATA, CRYPT_CONTENT_LAST, 0, ( void * ) contentTypeInfo },

	/* equivalentLabels:
		OID = 1 2 840 113549 1 9 16 2 9
		SEQUENCE OF {
			SET {
				policyIdentifier OBJECT IDENTIFIER,
				classification	INTEGER (0..5) OPTIONAL,
				privacyMark		PrintableString OPTIONAL,
				categories		SET OF {
					SEQUENCE {
						type  [ 0 ]	OBJECT IDENTIFIER,
						value [ 1 ]	ANY DEFINED BY type
						}
					} OPTIONAL
				}
			}
		Because this is a SET, we don't order the fields in the sequence
		given in the above ASN.1 but in the order of encoded size to follow
		the DER SET encoding rules */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x09" ), CRYPT_CERTINFO_CMS_EQUIVALENTLABEL,
	  MKDESC( "equivalentLabels" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_SETOF, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "equivalentLabels.set" )
	  ENCODING( BER_SET ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION,
	  MKDESC( "equivalentLabels.set.securityClassification" )
	  ENCODING( BER_INTEGER ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_POLICY,
	  MKDESC( "equivalentLabels.set.securityPolicyIdentifier" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MORE | FL_MULTIVALUED, RANGE_OID },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK,
	  MKDESC( "equivalentLabels.set.privacyMark" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, RANGE_TEXTSTRING },
	{ NULL, 0,
	  MKDESC( "equivalentLabels.set.securityCategories" )
	  ENCODING( BER_SET ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "equivalentLabels.set.securityCategories.securityCategory" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE,
	  MKDESC( "equivalentLabels.set.securityCategories.securityCategory.type" )
	  ENCODING_TAGGED( BER_OBJECT_IDENTIFIER, 0 ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, RANGE_OID },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE,
	  MKDESC( "equivalentLabels.set.securityCategories.securityCategory.value" )
	  ENCODING_TAGGED( FIELDTYPE_BLOB, 1 ),
	  FL_MULTIVALUED | FL_SEQEND_2 /*or _4*/ | FL_OPTIONAL, RANGE_ATTRIBUTEBLOB },

	/* signingCertificate:
		OID = 1 2 840 113549 1 9 16 2 12
		SEQUENCE {
			SEQUENCE OF ESSCertID
			SEQUENCE OF {
				SEQUENCE {
					policyIdentifier	OBJECT IDENTIFIER
					}
				} OPTIONAL
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0C" ), CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE,
	  MKDESC( "signingCertificate" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "signingCertificate.certs" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_SETOF, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID,
	  MKDESC( "signingCertificate.certs.essCertID" )
	  ENCODING( FIELDTYPE_BLOB ),
	  FL_MORE | FL_MULTIVALUED | FL_SEQEND, RANGE_BLOB },
	{ NULL, 0,
	  MKDESC( "signingCertificate.policies" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "signingCertificate.policies.policyInfo" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES,
	  MKDESC( "signingCertificate.policies.policyInfo.policyIdentifier" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND /*or _3*/, RANGE_OID },

	/* signaturePolicyID:
		OID = 1 2 840 113549 1 9 16 2 15
		SEQUENCE {
			sigPolicyID					OBJECT IDENTIFIER,
			sigPolicyHash				OtherHashAlgAndValue,
			sigPolicyQualifiers			SEQUENCE OF {
										SEQUENCE {
				sigPolicyQualifierID	OBJECT IDENTIFIER,
				sigPolicyQualifier		ANY DEFINED BY sigPolicyQualifierID
					}
				} OPTIONAL
			}

		CPSuri ::= IA5String						-- OID = cps

		UserNotice ::= SEQUENCE {					-- OID = unotice
			noticeRef		SEQUENCE {
				organization	UTF8String,
				noticeNumbers	SEQUENCE OF INTEGER	-- SIZE (1)
				} OPTIONAL,
			explicitText	UTF8String OPTIONAL
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0F" ), CRYPT_CERTINFO_CMS_SIGNATUREPOLICYID,
	  MKDESC( "signaturePolicyID" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICYID,
	  MKDESC( "signaturePolicyID.sigPolicyID" )
	  ENCODING( BER_OBJECT_IDENTIFIER ),
	  FL_MORE, RANGE_OID },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICYHASH,
	  MKDESC( "signaturePolicyID.sigPolicyHash" )
	  ENCODING( FIELDTYPE_BLOB ),
	  FL_MORE, RANGE_BLOB },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_SETOF | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x05\x01" ), 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.cps (1 2 840 113549 1 9 16 5 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_CPSURI,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.cPSuri" )
	  ENCODING( BER_STRING_IA5 ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND_2, CHECK_URL },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_IDENTIFIER, RANGE_NONE },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x05\x02" ), 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.unotice (1 2 840 113549 1 9 16 5 2)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY | FL_OPTIONAL, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_ORGANIZATION,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.organization" )
	  ENCODING( BER_STRING_UTF8 ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, RANGE( 1, 200 ) },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_ORGANIZATION,	/* Backwards-compat.handling for VisibleString */
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.organization" )
	  ENCODING( BER_STRING_ISO646 ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL, RANGE( 1, 200 ) },
	{ NULL, 0,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.noticeNumbers" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_NOTICENUMBERS,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.noticeNumbers" )
	  ENCODING( BER_INTEGER ),
	  FL_MORE | FL_MULTIVALUED | FL_OPTIONAL | FL_SEQEND_2, RANGE( 1, 1000 ) },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT,
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.explicitText" )
	  ENCODING( BER_STRING_UTF8 ),
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND, RANGE( 1, 200 ) },
	{ NULL, CRYPT_CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT,	/* Backwards-compat.handling for VisibleString */
	  MKDESC( "signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.explicitText" )
	  ENCODING( BER_STRING_ISO646 ),
	  FL_OPTIONAL | FL_MULTIVALUED | FL_SEQEND /* or ... _5 */, RANGE( 1, 200 ) },

	/* signatureTypeIdentifier:
		OID = 1 2 840 113549 1 9 16 9
		SEQUENCE {
			oidInstance1 OPTIONAL,
			oidInstance2 OPTIONAL,
				...
			oidInstanceN OPTIONAL
			} */
	{ MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x09" ), CRYPT_CERTINFO_CMS_SIGTYPEIDENTIFIER,
	  MKDESC( "signatureTypeIdentifier" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY, RANGE_NONE },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x09\x01" ), CRYPT_CERTINFO_CMS_SIGTYPEID_ORIGINATORSIG,
	  MKDESC( "signatureTypeIdentifier.originatorSig (1 2 840 113549 1 9 16 9 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x09\x02" ), CRYPT_CERTINFO_CMS_SIGTYPEID_DOMAINSIG,
	  MKDESC( "signatureTypeIdentifier.domainSig (1 2 840 113549 1 9 16 9 2)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x09\x03" ), CRYPT_CERTINFO_CMS_SIGTYPEID_ADDITIONALATTRIBUTES,
	  MKDESC( "signatureTypeIdentifier.additionalAttributesSig (1 2 840 113549 1 9 16 9 3)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x09\x04" ), CRYPT_CERTINFO_CMS_SIGTYPEID_REVIEWSIG,
	  MKDESC( "signatureTypeIdentifier.reviewSig (1 2 840 113549 1 9 16 9 4)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_OPTIONAL | FL_SEQEND /*NONE*/, RANGE_NONE },

	/* randomNonce:
		OID = 1 2 840 113549 1 9 25 3
		OCTET STRING */
	{ MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x19\x03" ), CRYPT_CERTINFO_CMS_NONCE,
	  MKDESC( "randomNonce" )
	  ENCODING( BER_OCTETSTRING ),
	  0, RANGE( 4, CRYPT_MAX_HASHSIZE ) },

	/* SCEP attributes:
		messageType:
			OID = 2 16 840 1 113733 1 9 2
			PrintableString
		pkiStatus
			OID = 2 16 840 1 113733 1 9 3
			PrintableString
		failInfo
			OID = 2 16 840 1 113733 1 9 4
			PrintableString
		senderNonce
			OID = 2 16 840 1 113733 1 9 5
			OCTET STRING
		recipientNonce
			OID = 2 16 840 1 113733 1 9 6
			OCTET STRING
		transID
			OID = 2 16 840 1 113733 1 9 7
			PrintableString */
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x02" ), CRYPT_CERTINFO_SCEP_MESSAGETYPE,
	  MKDESC( "messageType" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  0, RANGE( 1, 2 ) },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x03" ), CRYPT_CERTINFO_SCEP_PKISTATUS,
	  MKDESC( "pkiStatus" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  0, RANGE( 1, 1 ) },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x04" ), CRYPT_CERTINFO_SCEP_FAILINFO,
	  MKDESC( "failInfo" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  0, RANGE( 1, 1 ) },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x05" ), CRYPT_CERTINFO_SCEP_SENDERNONCE,
	  MKDESC( "senderNonce" )
	  ENCODING( BER_OCTETSTRING ),
	  0, RANGE( 8, CRYPT_MAX_HASHSIZE ) },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x06" ), CRYPT_CERTINFO_SCEP_RECIPIENTNONCE,
	  MKDESC( "recipientNonce" )
	  ENCODING( BER_OCTETSTRING ),
	  0, RANGE( 8, CRYPT_MAX_HASHSIZE ) },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x09\x07" ), CRYPT_CERTINFO_SCEP_TRANSACTIONID,
	  MKDESC( "transID" )
	  ENCODING( BER_STRING_PRINTABLE ),
	  0, RANGE( 2, CRYPT_MAX_TEXTSIZE ) },

	/* spcAgencyInfo:
		OID = 1 3 6 1 4 1 311 2 1 10
		SEQUENCE {
			[ 0 ] {
				??? (= [ 0 ] IA5String )
				}
			}
	   The format for this attribute is unknown but it seems to be an
	   unnecessarily nested URL which is probably an IA5String */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0A" ), CRYPT_CERTINFO_CMS_SPCAGENCYINFO,
	  MKDESC( "spcAgencyInfo" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "spcAgencyInfo.vendorInfo" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SPCAGENCYURL,
	  MKDESC( "spcAgencyInfo..vendorInfo.url" )
	  ENCODING_TAGGED( BER_STRING_IA5, 0 ),
	  FL_SEQEND /*NONE*/, CHECK_HTTP },

	/* spcStatementType:
		OID = 1 3 6 1 4 1 311 2 1 11
		SEQUENCE {
			oidInstance1 OPTIONAL,
			oidInstance2 OPTIONAL,
				...
			oidInstanceN OPTIONAL
			} */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0B" ), CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE,
	  MKDESC( "spcStatementType" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY | FL_SETOF, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x15" ), CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING,
	  MKDESC( "spcStatementType.individualCodeSigning (1 3 6 1 4 1 311 2 1 21)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x16" ), CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING,
	  MKDESC( "spcStatementType.commercialCodeSigning (1 3 6 1 4 1 311 2 1 22)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_OPTIONAL | FL_SEQEND /*NONE*/, RANGE_NONE },

	/* spcOpusInfo:
		OID = 1 3 6 1 4 1 311 2 1 12
		SEQUENCE {
			[ 0 ] {
				??? (= [ 0 ] BMPString )
				}
			[ 1 ] {
				??? (= [ 0 ] IA5String )
				}
			}
	   The format for this attribute is unknown but it seems to be either an
	   empty sequence or some nested set of tagged fields that eventually
	   end up as text strings */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0C" ), CRYPT_CERTINFO_CMS_SPCOPUSINFO,
	  MKDESC( "spcOpusInfo" )
	  ENCODING( BER_SEQUENCE ),
	  FL_MORE | FL_NONEMPTY, RANGE_NONE },
	{ NULL, 0,
	  MKDESC( "spcOpusInfo.programInfo" )
	  ENCODING_TAGGED( BER_SEQUENCE, 0 ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SPCOPUSINFO_NAME,
	  MKDESC( "spcOpusInfo.programInfo.name" )
	  ENCODING_TAGGED( BER_STRING_BMP, 0 ),
	  FL_MORE | FL_OPTIONAL | FL_SEQEND, RANGE( 2, 128 ) },
	{ NULL, 0,
	  MKDESC( "spcOpusInfo.vendorInfo" )
	  ENCODING_TAGGED( BER_SEQUENCE, 1 ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_CERTINFO_CMS_SPCOPUSINFO_URL,
	  MKDESC( "spcOpusInfo.vendorInfo.url" )
	  ENCODING_TAGGED( BER_STRING_IA5, 0 ),
	  FL_OPTIONAL | FL_SEQEND, CHECK_HTTP },

	{ NULL, CRYPT_ERROR }, { NULL, CRYPT_ERROR }
	};

/* Subtable for encoding the contentType */

STATIC_DATA const ATTRIBUTE_INFO FAR_BSS contentTypeInfo[] = {
	{ OID_CMS_DATA, CRYPT_CONTENT_DATA,
	  MKDESC( "contentType.data (1 2 840 113549 1 7 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ OID_CMS_SIGNEDDATA, CRYPT_CONTENT_SIGNEDDATA,
	  MKDESC( "contentType.signedData (1 2 840 113549 1 7 2)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ OID_CMS_ENVELOPEDDATA, CRYPT_CONTENT_ENVELOPEDDATA,
	  MKDESC( "contentType.envelopedData (1 2 840 113549 1 7 3)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x04" ), CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA,
	  MKDESC( "contentType.signedAndEnvelopedData (1 2 840 113549 1 7 4)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ OID_CMS_DIGESTEDDATA, CRYPT_CONTENT_DIGESTEDDATA,
	  MKDESC( "contentType.digestedData (1 2 840 113549 1 7 5)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ OID_CMS_ENCRYPTEDDATA, CRYPT_CONTENT_ENCRYPTEDDATA,
	  MKDESC( "contentType.encryptedData (1 2 840 113549 1 7 6)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ OID_CMS_COMPRESSEDDATA, CRYPT_CONTENT_COMPRESSEDDATA,
	  MKDESC( "contentType.compressedData (1 2 840 113549 1 9 16 1 9)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ OID_CMS_TSTOKEN, CRYPT_CONTENT_TSTINFO,
	  MKDESC( "contentType.tstInfo (1 2 840 113549 1 9 16 1 4)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ OID_MS_SPCINDIRECTDATACONTEXT, CRYPT_CONTENT_SPCINDIRECTDATACONTEXT,
	  MKDESC( "contentType.spcIndirectDataContext (1 3 6 1 4 1 311 2 1 4)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ OID_CRYPTLIB_RTCSREQ, CRYPT_CONTENT_RTCSREQUEST,
	  MKDESC( "contentType.rtcsRequest (1 3 6 1 4 1 3029 4 1 4)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ OID_CRYPTLIB_RTCSRESP, CRYPT_CONTENT_RTCSRESPONSE,
	  MKDESC( "contentType.rtcsResponse (1 3 6 1 4 1 3029 4 1 5)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ OID_CRYPTLIB_RTCSRESP_EXT, CRYPT_CONTENT_RTCSRESPONSE_EXT,
	  MKDESC( "contentType.rtcsResponseExt (1 3 6 1 4 1 3029 4 1 6)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_MORE | FL_OPTIONAL, RANGE_NONE },
	{ MKOID( "\x06\x06\x67\x81\x08\x01\x01\x01" ), CRYPT_CONTENT_MRTD,
	  MKDESC( "contentType.mRTD (2 23 136 1 1 1)" )
	  ENCODING( FIELDTYPE_IDENTIFIER ),
	  FL_OPTIONAL, RANGE_NONE },
	{ NULL, CRYPT_ERROR }, { NULL, CRYPT_ERROR }
	};

/* Select the appropriate attribute info table for encoding/type checking, 
   and get its size */

CHECK_RETVAL_PTR \
const ATTRIBUTE_INFO *selectAttributeInfo( IN_ENUM( ATTRIBUTE ) \
											const ATTRIBUTE_TYPE attributeType )
	{
	REQUIRES_N( attributeType == ATTRIBUTE_CERTIFICATE || \
				attributeType == ATTRIBUTE_CMS );

	return( ( attributeType == ATTRIBUTE_CMS ) ? \
			cmsAttributeInfo : extensionInfo );
	}

CHECK_RETVAL_RANGE( 0, MAX_INTLENGTH_SHORT ) \
int sizeofAttributeInfo( IN_ENUM( ATTRIBUTE ) const ATTRIBUTE_TYPE attributeType )
	{
	REQUIRES_EXT( ( attributeType == ATTRIBUTE_CERTIFICATE || \
					attributeType == ATTRIBUTE_CMS ), 0 );

	return( ( attributeType == ATTRIBUTE_CMS ) ? \
			FAILSAFE_ARRAYSIZE( cmsAttributeInfo, ATTRIBUTE_INFO ) : \
			FAILSAFE_ARRAYSIZE( extensionInfo, ATTRIBUTE_INFO ) );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

#if 0	/* Currently unused, see the comment about SEQEND problems in 
		   certattr.h */

/* Check the validity of the encoding information for an extension */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkExtension( IN_ARRAY( noAttributeInfoEntries ) \
								const ATTRIBUTE_INFO *attributeInfoPtr,
							   IN_LENGTH_SHORT const int noAttributeInfoEntries )
	{
	int nestingLevel = 0, iterationCount;

	assert( isReadPtr( attributeInfoPtr, \
					   noAttributeInfoEntries * sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES_B( noAttributeInfoEntries > 0 && \
				noAttributeInfoEntries < MAX_INTLENGTH_SHORT );

	for( iterationCount = 0;
		 attributeInfoPtr->fieldID != CRYPT_ERROR && \
			iterationCount < noAttributeInfoEntries;
		 attributeInfoPtr++, iterationCount++ )
		{
		/* If it's a sequence/set, increment the nesting level; if it's an 
		   end-of-constructed-item marker, decrement it by the appropriate 
		   amount */
		if( attributeInfoPtr->fieldType == BER_SEQUENCE || \
			attributeInfoPtr->fieldType == BER_SET )
			nestingLevel++;
		nestingLevel -= decodeNestingLevel( attributeInfoPtr->flags );

		/* Make sure that the encoding information is valid */
		if( !( attributeInfoPtr->fieldEncodedType == CRYPT_UNUSED || \
			   ( attributeInfoPtr->flags & FL_ALIAS ) || \
			   ( attributeInfoPtr->fieldEncodedType >= 0 && \
				 attributeInfoPtr->fieldEncodedType < MAX_TAG_VALUE ) ) )
			return( FALSE );

		/* If it's explicitly tagged make sure that it's a constructed tag 
		   in the correct range */
		if( attributeInfoPtr->flags & FL_EXPLICIT )
			{
			if( attributeInfoPtr->fieldEncodedType < 0 || \
				attributeInfoPtr->fieldEncodedType >= MAX_TAG )
				return( FALSE );
			}

		/* If we've reached the end of the extension, we're done */
		if( !( attributeInfoPtr->flags & FL_MORE ) )
			break;
		}
	REQUIRES_B( iterationCount < noAttributeInfoEntries );

	/* Make sure that the nesting is correct and that the encoding info 
	   isn't suspiciously long.  We can exit with a nesting level of either
	   zero or one, the latter can occur when we encode a SEQUENCE OF 
	   SEQUENCE because */
	if( nestingLevel != 0 && nestingLevel != 1 )
		return( FALSE );
	if( iterationCount > FAILSAFE_ITERATIONS_MED )
		return( FALSE );

	return( TRUE );
	}

/* Check the validity of each extension in an encoding table */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkExtensionTable( IN_ARRAY( noAttributeInfoEntries ) \
										const ATTRIBUTE_INFO *attributeInfoPtr,
									IN_LENGTH_SHORT const int noAttributeInfoEntries )
	{
	int index;

	assert( isReadPtr( attributeInfoPtr, \
					   noAttributeInfoEntries * sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES_B( noAttributeInfoEntries > 0 && \
				noAttributeInfoEntries < MAX_INTLENGTH_SHORT );

	for( index = 0;
		 attributeInfoPtr->fieldID != CRYPT_ERROR && \
			index < noAttributeInfoEntries;
		 attributeInfoPtr++, index++ )
		{
		int iterationCount;

		if( !checkExtension( attributeInfoPtr, \
								noAttributeInfoEntries - index ) )
			return( FALSE );

		/* Skip the remainder of this attribute */
		for( iterationCount = 0;
			 attributeInfoPtr->fieldID != CRYPT_ERROR && \
				( attributeInfoPtr->flags & FL_MORE ) && \
				iterationCount < noAttributeInfoEntries;
			 attributeInfoPtr++, iterationCount++ );
		ENSURES_B( iterationCount < noAttributeInfoEntries );
		}
	ENSURES_B( index < noAttributeInfoEntries );

	return( TRUE );
	}
#endif /* 0 */

/* Check the validity of the encoding tables */

CHECK_RETVAL_BOOL \
BOOLEAN checkExtensionTables( void )
	{
	/* Sanity checks on various encoded attribute info flags */
	REQUIRES( decodeNestingLevel( FL_SEQEND ) == 1 );
	REQUIRES( decodeNestingLevel( FL_SEQEND_1 ) == 1 );
	REQUIRES( decodeNestingLevel( FL_SEQEND_2 ) == 2 );
	REQUIRES( decodeNestingLevel( FL_SEQEND_3 ) == 3 );
	REQUIRES( decodeComplianceLevel( FL_LEVEL_OBLIVIOUS ) == CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
	REQUIRES( decodeComplianceLevel( FL_LEVEL_REDUCED ) == CRYPT_COMPLIANCELEVEL_REDUCED );
	REQUIRES( decodeComplianceLevel( FL_LEVEL_STANDARD ) == CRYPT_COMPLIANCELEVEL_STANDARD );
	REQUIRES( decodeComplianceLevel( FL_LEVEL_PKIX_PARTIAL ) == CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL );
	REQUIRES( decodeComplianceLevel( FL_LEVEL_PKIX_FULL ) == CRYPT_COMPLIANCELEVEL_PKIX_FULL );

#if 0	/* Currently unused, see the comment about SEQEND problems in 
		   certattr.h */
	/* Check each encoding table */
	if( !checkExtensionTable( extensionInfo, 
							  FAILSAFE_ARRAYSIZE( extensionInfo, \
												  ATTRIBUTE_INFO ) ) || \
		!checkExtensionTable( cmsAttributeInfo,
							  FAILSAFE_ARRAYSIZE( cmsAttributeInfo, \
												  ATTRIBUTE_INFO ) ) || \
		!checkExtensionTable( generalNameInfo,
							  FAILSAFE_ARRAYSIZE( generalNameInfo, \
												  ATTRIBUTE_INFO ) ) || \
		!checkExtensionTable( holdInstructionInfo,
							  FAILSAFE_ARRAYSIZE( holdInstructionInfo, \
												  ATTRIBUTE_INFO ) ) || \
		!checkExtensionTable( contentTypeInfo,
							  FAILSAFE_ARRAYSIZE( contentTypeInfo, \
												  ATTRIBUTE_INFO ) ) )
		retIntError_Boolean();
#endif /* 0 */

	return( TRUE );
	}

/****************************************************************************
*																			*
*						Extended Validity Checking Functions				*
*																			*
****************************************************************************/

/* Determine whether a variety of URIs are valid and return a 
   CRYPT_ERRTYPE_TYPE describing the type of error if there's a problem.  
   The PKIX RFC refers to a pile of complex parsing rules for various URI 
   forms, since cryptlib is neither a resolver nor an MTA nor a web browser 
   it leaves it up to the calling application to decide whether a particular 
   form is acceptable to it or not.  We do however perform a few basic 
   checks to weed out obviously-incorrect forms here.
   
   In theory we could use sNetParseUrl() for this but the code won't be
   included if cryptlib is built without networking support, and in any case 
   we still need to perform some processing for URLs that aren't network
   URLs */

typedef enum {
	URL_NONE,				/* No URL */
	URL_RFC822,				/* Email address */
	URL_DNS,				/* FQDN */
	URL_HTTP,				/* HTTP URL */
	URL_ANY,				/* Generic URL */
	URL_LAST				/* Last possible URL type */
	} URL_CHECK_TYPE;

CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkURLString( IN_BUFFER( urlLength ) const char *url, 
						   IN_LENGTH_DNS const int urlLength,
						   IN_ENUM( URL ) const URL_CHECK_TYPE urlType )
	{
	const char *schema = NULL;
	int schemaLength = 0, length = urlLength, offset, i;

	assert( isReadPtr( url, urlLength ) );

	REQUIRES( urlLength >= MIN_URL_SIZE && urlLength < MAX_URL_SIZE );
	REQUIRES( urlType > URL_NONE && urlType < URL_LAST );

	/* Make a first pass over the URL checking that it follows the RFC 1738 
	   rules for valid characters.  Because of the use of wildcards in 
	   certificates we can't check for '*' at this point but have to make a
	   second pass after we've performed URL-specific processing */
	for( i = 0; i < urlLength; i++ )
		{
		const int ch = url[ i ];

		if( ch <= 0 || ch > 0x7F || !isPrint( ch ) || \
			ch == ' ' || ch == '<' || ch == '>' || ch == '"' || \
			ch == '{' || ch == '}' || ch == '|' || ch == '\\' || \
			ch == '^' || ch == '[' || ch == ']' || ch == '`' )
			return( CRYPT_ERRTYPE_ATTR_VALUE );
		}

	/* Check for a schema separator.  This get a bit complicated because
	   some use "://" (HTTP, FTP, LDAP) and others just use ":" (SMTP, SIP), 
	   so we have to check for both.  We can't check for a possibly-
	   malformed ":/" because this could be something like 
	   "file:/dir/filename", which is valid */
	if( ( offset = strFindStr( url, urlLength, "://", 3 ) ) >= 0 )
		{
		/* Extract the URI schema */
		if( offset < 2 || offset > 8 || offset >= urlLength - 1 )
			return( CRYPT_ERRTYPE_ATTR_SIZE );
		offset += 3;	/* Adjust for "://" */
		}
	else
		{
		if( ( offset = strFindCh( url, urlLength, ':' ) ) >= 0 )
			{
			/* Extract the URI schema */
			if( offset < 2 || offset > 8 || offset >= urlLength - 1 )
				return( CRYPT_ERRTYPE_ATTR_SIZE );
			offset++;	/* Adjust for ":" */
			}
		}
	if( offset > 0 )
		{
		schema = url;
		schemaLength = offset;
		url += offset;
		length = urlLength - offset;
		}

	/* Make sure that the start of the URL looks valid.  The lengths have 
	   already been checked by the kernel but we check them again here to be
	   sure */
	switch( urlType )
		{
		case URL_DNS:
			if( urlLength < MIN_DNS_SIZE || urlLength > MAX_DNS_SIZE )
				return( CRYPT_ERRTYPE_ATTR_SIZE );
			if( schema != NULL || \
				( isDigit( url[ 0 ] && isDigit( url[ 1 ] ) ) ) )
				{
				/* Catch erroneous use of URL or IP address */
				return( CRYPT_ERRTYPE_ATTR_VALUE );
				}
			if( !strCompare( url, "*.", 2 ) )
				{
				url += 2;	/* Skip wildcard */
				length -= 2;
				}
			break;

		case URL_RFC822:
			if( urlLength < MIN_RFC822_SIZE || urlLength > MAX_RFC822_SIZE )
				return( CRYPT_ERRTYPE_ATTR_SIZE );
			if( schema != NULL )
				{
				/* Catch erroneous use of URL */
				return( CRYPT_ERRTYPE_ATTR_VALUE );
				}
			if( !strCompare( url, "*@", 2 ) )
				{
				url += 2;	/* Skip wildcard */
				length -= 2;
				}
			break;

		case URL_HTTP:
			if( urlLength < MIN_URL_SIZE || urlLength > MAX_URL_SIZE )
				return( CRYPT_ERRTYPE_ATTR_SIZE );
			if( schema == NULL || \
				( strCompare( schema, "http://", 7 ) && \
				  strCompare( schema, "https://", 8 ) ) )
				return( CRYPT_ERRTYPE_ATTR_VALUE );
			if( !strCompare( url, "*.", 2 ) )
				{
				url += 2;	/* Skip wildcard */
				length -= 2;
				}
			break;

		case URL_ANY:
			if( schema == NULL || length < 3 || length > MAX_URL_SIZE )
				return( CRYPT_ERRTYPE_ATTR_VALUE );
			break;

		default:
			retIntError();
		}

	/* Make a second pass over the URL checking for any remaining invalid 
	   characters */
	for( i = 0; i < length; i++ )
		{
		const int ch = url[ i ];

		if( ch == '*' )
			return( CRYPT_ERRTYPE_ATTR_VALUE );
		}

	return( CRYPT_OK );
	}

CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkRFC822( const ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	return( checkURLString( attributeListPtr->value,
							attributeListPtr->valueLength, URL_RFC822 ) );
	}

CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkDNS( const ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	return( checkURLString( attributeListPtr->value,
							attributeListPtr->valueLength, URL_DNS ) );
	}

CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkURL( const ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	return( checkURLString( attributeListPtr->value,
							attributeListPtr->valueLength, URL_ANY ) );
	}

CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkHTTP( const ATTRIBUTE_LIST *attributeListPtr )
	{
	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	return( checkURLString( attributeListPtr->value,
							attributeListPtr->valueLength, URL_HTTP ) );
	}

/* Determine whether a DN (either a complete DN or a DN subtree) is valid.
   Most attribute fields require a full DN but some fields (which act as
   filters) are allowed a partial DN */

CHECK_RETVAL_ENUM( CRYPT_ERRTYPE ) STDC_NONNULL_ARG( ( 1 ) ) \
static int checkDirectoryName( const ATTRIBUTE_LIST *attributeListPtr )
	{
	CRYPT_ATTRIBUTE_TYPE dummy;
	const BOOLEAN checkFullDN = \
			( attributeListPtr->fieldID == CRYPT_CERTINFO_EXCLUDEDSUBTREES || \
			  attributeListPtr->fieldID == CRYPT_CERTINFO_PERMITTEDSUBTREES ) ? \
			FALSE : TRUE;
	CRYPT_ERRTYPE_TYPE errorType;

	assert( isReadPtr( attributeListPtr, sizeof( ATTRIBUTE_LIST ) ) );

	if( cryptStatusError( checkDN( attributeListPtr->value, checkFullDN, TRUE,
								   &dummy, &errorType ) ) )
		return( errorType );

	return( CRYPT_ERRTYPE_NONE );
	}

/* Get the encoded tag value for a field */

CHECK_RETVAL_RANGE( MAX_ERROR, MAX_TAG ) STDC_NONNULL_ARG( ( 1 ) ) \
int getFieldEncodedTag( const ATTRIBUTE_INFO *attributeInfoPtr )
	{
	int tag;

	assert( isReadPtr( attributeInfoPtr, sizeof( ATTRIBUTE_INFO ) ) );

	REQUIRES( attributeInfoPtr->fieldEncodedType == CRYPT_UNUSED || \
			  ( attributeInfoPtr->flags & FL_ALIAS ) || \
			  ( attributeInfoPtr->fieldEncodedType >= 0 && \
				attributeInfoPtr->fieldEncodedType < MAX_TAG_VALUE ) );

	/* If it's an aliased field (type A encoded as type B) return the type
	   used for encoding */
	if( attributeInfoPtr->flags & FL_ALIAS )
		{
		ENSURES( attributeInfoPtr->fieldEncodedType >= 0 && \
				 attributeInfoPtr->fieldEncodedType < MAX_TAG_VALUE );

		return( attributeInfoPtr->fieldEncodedType );
		}

	/* If it's a non-tagged field, we're done */
	if( attributeInfoPtr->fieldEncodedType == CRYPT_UNUSED )
		return( OK_SPECIAL );

	/* It's a tagged field then the actual tag is stored as the encoded-type 
	   value.  If it's explicitly tagged or an implictly tagged SET/SEQUENCE 
	   then it's constructed, otherwise it's primitive */
	if( ( attributeInfoPtr->fieldType == BER_SEQUENCE ||
		  attributeInfoPtr->fieldType == BER_SET ||
		  attributeInfoPtr->fieldType == FIELDTYPE_DN ||
		  ( attributeInfoPtr->flags & FL_EXPLICIT ) ) )
		tag = MAKE_CTAG( attributeInfoPtr->fieldEncodedType );
	else
		tag = MAKE_CTAG_PRIMITIVE( attributeInfoPtr->fieldEncodedType );

	ENSURES( tag >= MAKE_CTAG_PRIMITIVE( 0 ) && \
			 tag <= MAX_TAG );

	return( tag );
	}
