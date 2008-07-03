/****************************************************************************
*																			*
*						Certificate Routines Header File 					*
*						Copyright Peter Gutmann 1996-2007					*
*																			*
****************************************************************************/

#ifndef _CERT_DEFINED

#define _CERT_DEFINED

#include <time.h>
#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #else
	#include "io/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* The minimum size of an attribute, SEQUENCE (2), OID (5),
   OCTET STRING (2+3 for payload).  This is the amount of slop to allow when
   reading attributes.  Some software gets the length encoding wrong by a few
   bytes, if what's left at the end of an encoded object is >= this value
   then we look for attributes */

#define MIN_ATTRIBUTE_SIZE		12

/* The maximum size of a PKCS #7 certificate chain */

#define MAX_CHAINLENGTH			16

/* The default size of the serial number, size of the built-in serial number
   buffer (anything larger than this uses a dynamically-allocated buffer)
   and the maximum size in bytes of a serial number (for example in a
   certificate or CRL).  Technically values of any size are allowed, but
   anything larger than this is probably an error */

#define DEFAULT_SERIALNO_SIZE	8
#define SERIALNO_BUFSIZE		32
#define MAX_SERIALNO_SIZE		256

/* The size of the PKI user binary authenticator information before
   checksumming and encoding, and the size of the encrypted user info:
   sizeofObject( 2 * sizeofObject( PKIUSER_AUTHENTICATOR_SIZE ) ) + PKCS #5
   padding = 2 + ( 2 + 12 + 2 + 12 ) = 30 + 2 = 32.  This works for both 64-
   and 128-bit block ciphers */

#define PKIUSER_AUTHENTICATOR_SIZE		12
#define PKIUSER_ENCR_AUTHENTICATOR_SIZE	32

/* The size of the FIFO used to encode nested SEQUENCEs */

#define ENCODING_FIFO_SIZE				10

/* Normally we check for a valid time by making sure that it's more recent 
   than MIN_TIME_VALUE, however when reading a certificate the time can be 
   much earlier than this if it's an old certificate.  To handle this we 
   define a certificate-specific time value that we use as the oldest valid 
   time value */

#define MIN_CERT_TIME_VALUE		( ( 1996 - 1970 ) * 365 * 86400L )

/* Attribute information flags.  These are:

	FLAG_BLOB: Disables all type-checking on the field, needed to handle
			some certificates that have invalid field encodings.

	FLAG_BLOB_PAYLOAD: Disables type checking on the field payload, for
			example checking that the chars in the string are valid for the
			given ASN.1 string type.

	FLAG_CRITICAL: The extension containing the field is marked criticial.

	FLAG_DEFAULTVALUE: The field has a value which is equal to the default
			for this field, so it doesn't get encoded.  This flag is set
			during the encoding pre-processing pass.

	FLAG_IGNORED: The field is recognised but was ignored at this compliance
			level.  This prevents the certificate from being rejected if the 
			field is marked critical.

	FLAG_INVALID: Used to catch accidental use of a boolean value for the
			flag (an early version of the code used a simple boolean
			isCritical in place of the current multi-purpose flags).

	FLAG_LOCKED: The attribute can't be deleted once set, needed to handle
			fields that are added internally by cryptlib that shouldn't be
			deleted by users once set.

	FLAG_MULTIVALUED: Multiple instantiations of this field are allowed */

#define ATTR_FLAG_NONE			0x00	/* No flag */
#define ATTR_FLAG_INVALID		0x01	/* To catch use of TRUE */
#define ATTR_FLAG_CRITICAL		0x02	/* Critical cert extension */
#define ATTR_FLAG_LOCKED		0x04	/* Field can't be modified */
#define ATTR_FLAG_BLOB			0x08	/* Non-type-checked blob data */
#define ATTR_FLAG_BLOB_PAYLOAD	0x10	/* Payload is non-type-checked blob data */
#define ATTR_FLAG_MULTIVALUED	0x20	/* Multiple instances allowed */
#define ATTR_FLAG_DEFAULTVALUE	0x40	/* Field has default value */
#define ATTR_FLAG_IGNORED		0x80	/* Attribute ignored at this compl.level */
#define ATTR_FLAG_MAX			0xFF	/* Maximum possible flag value */

/* Certificate information flags.  These are:

	FLAG_CERTCOLLECTION: Indicates that a certificate chain object contains 
			only an unordered collection of (non-duplicate) certificates 
			rather than a true certificate chain.  Note that this is a pure 
			container object for which only the certificate chain member 
			contains certificates, the base certificate object doesn't 
			correspond to an actual certificate.

	FLAG_CRLENTRY: The CRL object contains the data from a single CRL entry
			rather than being a complete CRL.

	FLAG_DATAONLY: Indicates a pure data object with no attached context.

	FLAG_PATHKLUDGE: Indicates that although the certificate appears to be a 
			self-signed (CA root) certificate it's actually a PKIX path 
			kludge certificate that's used to tie a re-issued CA certificate 
			(with a new CA key) to existing issued certificates signed with 
			the old CA key.  This kludge requires that issuer DN == subject 
			DN, which denotes a CA root certificate under normal 
			circumstances.

	FLAG_SELFSIGNED: Indicates that the certificate is self-signed.

	FLAG_SIGCHECKED: Caches the check of the certificate signature.  This is 
			done because it's only necessary to perform this once when the 
			certificate is checked for the first time.  Checking of 
			certificate fields that aren't affected by the issuer 
			certificate is also cached, but this is handled by the 
			compliance-level check value rather than a simple boolean flag 
			since a certificate can be checked at various levels of 
			standards-compliance */

#define CERT_FLAG_NONE			0x00	/* No flag */
#define CERT_FLAG_SELFSIGNED	0x01	/* Certificate is self-signed */
#define CERT_FLAG_SIGCHECKED	0x02	/* Signature has been checked */
#define CERT_FLAG_DATAONLY		0x04	/* Cert is data-only (no context) */
#define CERT_FLAG_CRLENTRY		0x08	/* CRL is a standalone single entry */
#define CERT_FLAG_CERTCOLLECTION 0x10	/* Cert chain is unordered collection */
#define CERT_FLAG_PATHKLUDGE	0x20	/* Cert is a PKIX path kludge */
#define CERT_FLAG_MAX			0x3F	/* Maximum possible flag value */

/* When creating RTCS responses from a request there are several subtypes
   that we can use based on a format specifier in the request.  When we turn
   the request into a response we check the format specifiers and record the
   response format as being one of the following */

typedef enum {
	RTCSRESPONSE_TYPE_NONE,				/* No response type */
	RTCSRESPONSE_TYPE_BASIC,			/* Basic response */
	RTCSRESPONSE_TYPE_EXTENDED,			/* Extended response */
	RTCSRESPONSE_TYPE_LAST				/* Last valid response type */
	} RTCSRESPONSE_TYPE;

/* Set the error locus and type.  This is used for certificate checking 
   functions that need to return extended error information but can't modify 
   the certificate info, so that setErrorInfo() can't be used */

#define setErrorValues( locus, type ) \
		*errorLocus = ( locus ); *errorType = ( type )

/* The are several types of attributes that can be used depending on the
   object that they're associated with.  The following values are used to
   select the type of attribute that we want to work with */

typedef enum {
	ATTRIBUTE_CERTIFICATE,				/* Certificate attribute */
	ATTRIBUTE_CMS,						/* CMS / S/MIME attribute */
	ATTRIBUTE_LAST						/* Last valid attribute type */
	} ATTRIBUTE_TYPE;

/* When checking policy constraints there are several different types of
   checking that we can apply depending on the presence of other constraints 
   in the issuing certificate(s) and the level of checking that we're 
   performing.  Policies can be optional, required, or a specific-policy 
   check that disallows the wildcard anyPolicy as a matching policy */

typedef enum {							/* Issuer		Subject		*/
	POLICY_NONE,						/*	 -			 -			*/
	POLICY_NONE_SPECIFIC,				/*	 -,  !any	 -,  !any	*/
	POLICY_SUBJECT,						/*	 -			yes			*/
	POLICY_SUBJECT_SPECIFIC,			/*	 -			yes, !any	*/
	POLICY_BOTH,						/*	yes			yes			*/
	POLICY_BOTH_SPECIFIC,				/*	yes, !any	yes, !any	*/
	POLICY_LAST							/* Last valid policy type */
	} POLICY_TYPE;

/****************************************************************************
*																			*
*							Certificate Element Tags						*
*																			*
****************************************************************************/

/* Context-specific tags for certificates */

enum { CTAG_CE_VERSION, CTAG_CE_ISSUERUNIQUEID, CTAG_CE_SUBJECTUNIQUEID,
	   CTAG_CE_EXTENSIONS };

/* Context-specific tags for attribute certificates */

enum { CTAG_AC_BASECERTIFICATEID, CTAG_AC_ENTITYNAME,
	   CTAG_AC_OBJECTDIGESTINFO };

/* Context-specific tags for certification requests */

enum { CTAG_CR_ATTRIBUTES };

/* Context-specific tags for CRLs */

enum { CTAG_CL_EXTENSIONS };

/* Context-specific tags for CRMF certification requests.  The second set of 
   tags is for POP of the private key */

enum { CTAG_CF_VERSION, CTAG_CF_SERIALNUMBER, CTAG_CF_SIGNINGALG,
	   CTAG_CF_ISSUER, CTAG_CF_VALIDITY, CTAG_CF_SUBJECT, CTAG_CF_PUBLICKEY,
	   CTAG_CF_ISSUERUID, CTAG_CF_SUBJECTUID, CTAG_CF_EXTENSIONS };
enum { CTAG_CF_POP_NONE, CTAG_CF_POP_SIGNATURE, CTAG_CF_POP_ENCRKEY };

/* Context-specific tags for RTCS responses */

enum { CTAG_RP_EXTENSIONS };

/* Context-specific tags for OCSP requests.  The second set of tags
   is for each request entry in an overall request */

enum { CTAG_OR_VERSION, CTAG_OR_DUMMY, CTAG_OR_EXTENSIONS };
enum { CTAG_OR_SR_EXTENSIONS };

/* Context-specific tags for OCSP responses */

enum { CTAG_OP_VERSION, CTAG_OP_EXTENSIONS };

/* Context-specific tags for CMS attributes */

enum { CTAG_SI_AUTHENTICATEDATTRIBUTES };

/****************************************************************************
*																			*
*							Certificate Data Structures						*
*																			*
****************************************************************************/

/* The structure to hold a field of a certificate attribute */

typedef struct AL {
	/* Identification and encoding information for this attribute field or
	   attribute.  This consists of the field ID for the attribute as a
	   whole, for the attribute field (that is, a field of an attribute, not
	   an attribute field) and for the subfield of the attribute field in the
	   case of composite fields like GeneralNames, a pointer to the sync
	   point used when encoding the attribute, and the encoded size of this
	   field.  If it's a special-case attribute field the attributeID and
	   fieldID are set to special values decoded by the isXXX() macros
	   further down.  The subFieldID is only set if the fieldID is for a
	   GeneralName field.

	   Although the field type information is contained in the
	   attributeInfoPtr it's sometimes needed before this has been set up
	   to handle special formatting requirements, for example to enable
	   special-case handling for a DN attribute field or to specify that an
	   OID needs to be decoded into its string representation before being
	   returned to the caller.  Because of this we store the field type here
	   to allow for this special processing */
	CRYPT_ATTRIBUTE_TYPE attributeID;/* Attribute ID */
	CRYPT_ATTRIBUTE_TYPE fieldID;	/* Attribute field ID */
	CRYPT_ATTRIBUTE_TYPE subFieldID;	/* Attribute subfield ID */
	void *attributeInfoPtr;			/* Pointer to encoding sync point */
	int encodedSize;				/* Encoded size of this field */
	int fieldType;					/* Attribute field type */
	int flags;						/* Flags for this field */

	/* Sometimes a field is part of a constructed object or even a nested
	   series of constructed objects (these are always SEQUENCEs).  Since
	   this is purely an encoding issue there are no attribute list entries
	   for the SEQUENCE fields so when we perform the first pass over the
	   attribute list prior to encoding we remember the lengths of the
	   SEQUENCEs for later use.  Since we can have nested SEQUENCEs
	   containing a given field we store the lengths and pointers to the 
	   table entries used to encode them in a fifo with the innermost one
	   first and successive outer ones following it */
	ARRAY( ENCODING_FIFO_SIZE, fifoPos ) \
	int sizeFifo[ ENCODING_FIFO_SIZE + 2 ];	/* Encoded size of SEQUENCE containing
									   this field, if present */
	ARRAY( ENCODING_FIFO_SIZE, fifoPos ) \
	void *encodingFifo[ ENCODING_FIFO_SIZE + 2 ];/* Encoding table entry used to 
									   encode this SEQUENCE */
	int fifoEnd;					/* End of list of SEQUENCE sizes */
	int fifoPos;					/* Current position in list */

	/* The data payload for this attribute field or attribute.  If it's
	   numeric data such as a simple boolean, bitstring, or small integer,
	   we store it in the intValue member.  If it's an OID or some form of
	   string we store it in the variable-length buffer */
	long intValue;					/* Integer value for simple types */
	BUFFER_OPT_FIXED( valueLength ) \
	void *value;					/* Attribute value */
	int valueLength;				/* Attribute value length */

	/* The OID, for blob-type attributes */
	BYTE *oid;						/* Attribute OID */

	/* The previous and next list element in the linked list of elements */
	struct AL *prev, *next;

	/* Variable-length storage for the attribute data */
	DECLARE_VARSTRUCT_VARS;
	} ATTRIBUTE_LIST;

/* The structure to hold information on the current selection of attribute/
   GeneralName/DN data used when adding/reading/deleting certificate 
   components.  The usage of this information is too complex to explain 
   here, see the comments at the start of comp_get.c for more information */

typedef struct {
	void **dnPtr;						/* Pointer to current DN */
	CRYPT_ATTRIBUTE_TYPE generalName;	/* Selected GN */
	BOOLEAN dnInExtension;				/* Whether DN is in extension */
	BOOLEAN updateCursor;				/* Whether to upate attr.cursor */
	} SELECTION_INFO;

#define initSelectionInfo( certInfoPtr ) \
	memset( &( certInfoPtr )->currentSelection, 0, sizeof( SELECTION_INFO ) ); \
	( certInfoPtr )->currentSelection.dnPtr = &( ( certInfoPtr )->subjectName ); \
	( certInfoPtr )->currentSelection.generalName = CRYPT_CERTINFO_SUBJECTALTNAME;

/* Sometimes we need to manipulate an internal component which is addressed
   indirectly as a side-effect of some other processing operation.  We can't
   change the selection information for the certificate object since this will 
   affect any future operations that the user performs so we provide the 
   following macros to save and restore the selection state around these 
   operations */

typedef struct {
	int savedChainPos;					/* Current cert.chain position */
	SELECTION_INFO savedSelectionInfo;	/* Current DN/GN selection info */
	ATTRIBUTE_LIST *savedAttributeCursor;	/* Atribute cursor pos.*/
	} SELECTION_STATE;

#define saveSelectionState( savedState, certInfoPtr ) \
	{ \
	memset( &( savedState ), 0, sizeof( SELECTION_STATE ) ); \
	if( ( certInfoPtr )->type == CRYPT_CERTTYPE_CERTCHAIN ) \
		( savedState ).savedChainPos = ( certInfoPtr )->cCertCert->chainPos; \
	( savedState ).savedSelectionInfo = ( certInfoPtr )->currentSelection; \
	( savedState ).savedAttributeCursor = ( certInfoPtr )->attributeCursor; \
	}

#define restoreSelectionState( savedState, certInfoPtr ) \
	{ \
	if( ( certInfoPtr )->type == CRYPT_CERTTYPE_CERTCHAIN ) \
		( certInfoPtr )->cCertCert->chainPos = ( savedState ).savedChainPos; \
	( certInfoPtr )->currentSelection = ( savedState ).savedSelectionInfo; \
	( certInfoPtr )->attributeCursor = ( savedState ).savedAttributeCursor; \
	}

/* The structure to hold a validity information entry */

typedef struct VI {
	/* Certificate ID information */
	BUFFER_FIXED( KEYID_SIZE ) \
	BYTE data[ KEYID_SIZE + 8 ];
	int dCheck;						/* Data checksum for quick match */

	/* Validity information */
	BOOLEAN status;					/* Valid/not valid */
	int extStatus;					/* Extended validity status */
	time_t invalidityTime;			/* Cert invalidity time */

	/* Per-entry attributes.  These are a rather ugly special case for the
	   user because, unlike the attributes for all other certificate objects 
	   where cryptlib can provide the illusion of a flat type<->value 
	   mapping, there can be multiple sets of identical per-entry attributes 
	   present if there are multiple RTCS entries present */
	ATTRIBUTE_LIST *attributes;		/* RTCS entry attributes */
	int attributeSize;				/* Encoded size of attributes */

	/* The next element in the linked list of elements */
	struct VI *next;
	} VALIDITY_INFO;

/* The structure to hold a revocation information entry, either a CRL entry
   or OCSP request/response information */

typedef struct RI {
	/* Certificate ID information, either a serial number (for CRLs) or a
	   certificate hash or issuerID (for OCSP requests/responses).  In 
	   addition this could also be a pre-encoded OCSP certID, which is 
	   treated as an opaque blob of type CRYPT_ATTRIBUTE_NONE since it can't 
	   be used in any useful way.  If we're using OCSP and an alternative ID 
	   is supplied as an ESSCertID we point to this value (inside the 
	   ESSCertID) in the altIdPtr field.  
	   
	   Usually the certificate ID information fits in the id field, if it's 
	   longer than that (which can only occur with enormous serial numbers) 
	   it's held in the dynamically-allocated idPtr value */
	CRYPT_KEYID_TYPE idType;		/* ID type */
	BUFFER( 128, idLength ) \
	BYTE id[ 128 + 8 ], *idPtr;
	int idLength;					/* ID information */
	int idCheck;					/* Data checksum for quick match */
	CRYPT_KEYID_TYPE altIdType;		/* Alt.ID type for OCSP */
	BUFFER_FIXED( KEYID_SIZE ) \
	BYTE altID[ KEYID_SIZE + 8 ];	/* Alt.ID for OCSP */

	/* Revocation information */
	int status;						/* OCSP revocation status */
	time_t revocationTime;			/* Cert revocation time */

	/* Per-entry attributes.  These are a rather ugly special case for the
	   user because, unlike the attributes for all other certificate objects 
	   where cryptlib can provide the illusion of a flat type<->value 
	   mapping, there can be multiple sets of identical per-entry attributes 
	   present if there are multiple CRL/OCSP entries present */
	ATTRIBUTE_LIST *attributes;		/* CRL/OCSP entry attributes */
	int attributeSize;				/* Encoded size of attributes */

	/* The next element in the linked list of elements */
	struct RI *next;
	} REVOCATION_INFO;

/* The internal fields in a certificate that hold subtype-specific data for 
   the various certificate object types */

typedef struct {
	/* The certificate serial number.  This is stored in the buffer if it 
	   fits (it almost always does), otherwise in a dynamically-allocated 
	   buffer */
	BUFFER( SERIALNO_BUFSIZE, serialNumberLength ) \
	BYTE serialNumberBuffer[ SERIALNO_BUFSIZE + 8 ];
	BUFFER_OPT_FIXED( serialNumberLength ) \
	void *serialNumber;
	int serialNumberLength;			/* Certificate serial number */

	/* The highest compliance level at which a certificate has been checked.
	   We have to record this high water-mark level because increasing the
	   compliance level may invalidate an earlier check performed at a lower
	   level */
	int maxCheckLevel;

	/* The allowed usage for a certificate can be further controlled by the
	   user.  The trustedUsage value is a mask which is applied to the key
	   usage extension to further constrain usage, alongside this there is
	   an additional implicit trustImplicit value that acts a boolean flag
	   that indicates whether the user implicitly trusts this certificate
	   (without requiring further checking upstream).  This value isn't
	   stored with the certificate since it's a property of any 
	   instantiation of the certificate rather than just the current one so 
	   when the user queries it it's obtained dynamically from the trust 
	   manager */
	int trustedUsage;

	/* Certificate chains are a special variant of standard certificates, 
	   being complex container objects that contain further certificates 
	   leading up to a CA root certificate.  The reason why they're combined 
	   with standard certificates is because when we're building a chain 
	   from a certificate collection or assembling it from a certificate 
	   source we can't tell at the time of certificate creation which 
	   certificate will be the leaf certificate so that any certificate 
	   potentially has to be able to act as the chain container (another way 
	   of looking at this is that all standard certificates are a special 
	   case of a chain with a length of one).

	   A possible alternative to this way of handling chains is to make the
	   chain object a pure container object used only to hold pointers to
	   the actual certificates, but this requires an extra level of 
	   indirection every time a certificate chain object is used since in 
	   virtually all cases what'll be used is the leaf certificate with 
	   which the chain-as-standard-certificate model is the default 
	   certificate but with the chain-as-container model requires an extra 
	   object dereference to obtain.

	   In theory we should use a linked list to store chains but since the
	   longest chain ever seen in the wild has a length of 4 using a fixed
	   maximum length seveal times this size shouldn't be a problem.  The
	   certificates in the chain are ordered from the parent of the leaf 
	   certificate up to the root certificate with the leaf certificate 
	   corresponding to the [-1]th entry in the list.  We also maintain a 
	   current position in the certificate chain that denotes the 
	   certificate in the chain that will be accessed by the 
	   component-manipulation functions.  This is set to CRYPT_ERROR if the 
	   current certificate is the leaf certificate */
	ARRAY( MAX_CHAINLENGTH, chainEnd ) \
	CRYPT_CERTIFICATE chain[ MAX_CHAINLENGTH + 8 ];
	int chainEnd;					/* Length of cert chain */
	int chainPos;					/* Currently selected cert in chain */

	/* The hash algorithm used to sign the certificate.  Although a part of
	   the signature, a second copy of the algorithm ID is embedded inside
	   the signed certificate data because of a theoretical attack that
	   doesn't actually work with any standard signature padding
	   technique */
	CRYPT_ALGO_TYPE hashAlgo;

	/* The (deprecated) X.509v2 unique ID */
	BUFFER_OPT_FIXED( issuerUniqueIDlength ) \
	void *issuerUniqueID;
	BUFFER_OPT_FIXED( subjectUniqueIDlength ) \
	void *subjectUniqueID;
	int issuerUniqueIDlength, subjectUniqueIDlength;
	} CERT_CERT_INFO;

typedef struct {
	/* The certificate serial number, used when requesting a revocation by 
	   issuerAndSerialNumber.  This is stored in the buffer if it fits (it
	   almost always does), otherwise in a dynamically-allocated buffer */
	BUFFER( SERIALNO_BUFSIZE, serialNumberLength ) \
	BYTE serialNumberBuffer[ SERIALNO_BUFSIZE + 8 ];
	BUFFER_OPT_FIXED( serialNumberLength ) \
	void *serialNumber;
	int serialNumberLength;			/* Certificate serial number */

	/* The certificate ID of the PKI user or certificate that authorised 
	   this request.  This is from an external source, supplied when the 
	   request is used as part of the CMP protocol */
	BUFFER_FIXED( KEYID_SIZE ) \
	BYTE authCertID[ KEYID_SIZE + 8 ];
	} CERT_REQ_INFO;

typedef struct {
	/* The list of revocations for a CRL or a list of OCSP request or response
	   entries, and a pointer to the revocation/request/response which is
	   currently being accessed */
	REVOCATION_INFO *revocations;	/* List of revocations */
	REVOCATION_INFO *currentRevocation;	/* Currently selected revocation */

	/* The default revocation time for a CRL, used for if no explicit time
	   is set for a revocation */
	time_t revocationTime;			/* Default certificate revocation time */

	/* The URL for the OCSP responder */
	BUFFER_OPT_FIXED( responderUrlSize ) \
	char *responderUrl;
	int responderUrlSize;			/* OCSP responder URL */

	/* The hash algorithm used to sign the certificate.  Although a part of
	   the signature, a second copy of the algorithm ID is embedded inside
	   the signed certificate data because of a theoretical attack that
	   doesn't actually work with any standard signature padding
	   technique */
	CRYPT_ALGO_TYPE hashAlgo;

	/* Signed OCSP requests can include varying levels of detail in the
	   signature.  The following value determines how much information is
	   included in the signature */
	CRYPT_SIGNATURELEVEL_TYPE signatureLevel;
	} CERT_REV_INFO;

typedef struct {
	/* A list of RTCS request or response entries and a pointer to the
	   request/response which is currently being accessed */
	VALIDITY_INFO *validityInfo;	/* List of validity info */
	VALIDITY_INFO *currentValidity;	/* Currently selected validity info */

	/* The URL for the RTCS responder */
	BUFFER_OPT_FIXED( responderUrlSize ) \
	char *responderUrl;				/* RTCS responder URL */
	int responderUrlSize;

	/* Since RTCS allows for a variety of response types, we include an
	   indication of the request/response format */
	RTCSRESPONSE_TYPE responseType;	/* Request/response format */
	} CERT_VAL_INFO;

typedef struct {
	/* The authenticator used for authenticating certificate issue and
	   revocation requests */
	BUFFER_FIXED( 16 ) \
	BYTE pkiIssuePW[ 16 + 8 ];
	BUFFER_FIXED( 16 ) \
	BYTE pkiRevPW[ 16 + 8 ];
	} CERT_PKIUSER_INFO;

/* Defines to make access to the union fields less messy */

#define cCertCert		certInfo.certInfo
#define cCertReq		certInfo.reqInfo
#define cCertRev		certInfo.revInfo
#define cCertVal		certInfo.valInfo
#define cCertUser		certInfo.pkiUserInfo

/* The structure that stores information on a certificate object */

typedef struct {
	/* General certificate information */
	CRYPT_CERTTYPE_TYPE type;		/* Certificate type */
	int flags;						/* Certificate flags */
	int version;					/* Cert object version */

	/* Certificate type-specific information */
	union {
		CERT_CERT_INFO *certInfo;
		CERT_REQ_INFO *reqInfo;
		CERT_REV_INFO *revInfo;
		CERT_VAL_INFO *valInfo;
		CERT_PKIUSER_INFO *pkiUserInfo;
		} certInfo;

	/* The encoded certificate object.  We save this when we import it
	   because there are many different interpretations of how a certificate 
	   should be encoded and if we parse and re-encode the cert object the
	   signature check would fail */
	BUFFER_OPT_FIXED( certificateSize ) \
	void *certificate;
	int certificateSize;

	/* The public key associated with this certificate.  When the 
	   certificate is in the low (unsigned state) this consists of the 
	   encoded public-key data and associated attributes.  When the 
	   certificate is in the high (signed) state, either by being imported 
	   from an external source or by being signed by cryptlib, this consists 
	   of a public-key context.  In addition some certificates are imported 
	   as data-only certificates, denoted by CERT_FLAG_DATAONLY being set.  
	   These constitute a container object that contain no public-key context 
	   and are used for certificate chains (when read from a trusted source) 
	   and to store certificate information associated with a private-key 
	   context.  Since it's not known during the import stage whether a 
	   certificate in a chain will be a data-only or standard certificate 
	   (it's not known which certificate is the leaf certificate until the 
	   entire chain has been processed), certificate chains from a trusted 
	   source are imported as data-only certificates and then the leaf has 
	   its context instantiated */
	CRYPT_CONTEXT iPubkeyContext;	/* Public-key context */
	CRYPT_ALGO_TYPE publicKeyAlgo;	/* Key algorithm */
	int publicKeyFeatures;			/* Key features */
	BUFFER_OPT_FIXED( publicKeyInfoSize ) \
	void *publicKeyInfo;			/* Encoded key information */
	int publicKeyInfoSize;
	BUFFER_FIXED( KEYID_SIZE ) \
	BYTE publicKeyID[ KEYID_SIZE + 8 ];	/* Key ID */

	/* General certificate object information */
	void *issuerName;				/* Issuer name */
	void *subjectName;				/* Subject name */
	time_t startTime;				/* Validity start or update time */
	time_t endTime;					/* Validity end or next update time */

	/* In theory we can just copy the subject DN of a CA certificate into 
	   the issuer DN of a subject certificate, however due to broken 
	   implementations this will break chaining if we correct any problems 
	   in the DN.  Because of this we need to preserve a copy of the 
	   certificate's subject DN so that we can write it as a blob to the 
	   issuer DN field of any certificates it signs.  We also need to 
	   remember the encoded issuer DN so that we can chain upwards.  The 
	   following fields identify the size and location of the encoded DNs 
	   inside the encoded certificate object */
	BUFFER_OPT_FIXED( subjectDNsize ) \
	void *subjectDNptr;
	BUFFER_OPT_FIXED( subjectDNsize ) \
	void *issuerDNptr;					/* Pointer to encoded DN blobs */
	int subjectDNsize, issuerDNsize;	/* Size of encoded DN blobs */

	/* For some objects the public key and/or subject DN and/or issuer DN are
	   copied in from an external source before the object is signed so we
	   can't just point the issuerDNptr at the encoded object, we have to
	   allocate a separate data area to copy the DN into.  This is used in
	   cases where we don't copy in a full subject/issuerName but only use
	   an encoded DN blob for the reasons described above */
	void *publicKeyData, *subjectDNdata, *issuerDNdata;

	/* The certificate hash/fingerprint/oobCertID/thumbprint/whatever.  This
	   is used so frequently that it's cached here for future re-use */
	BUFFER_FIXED( KEYID_SIZE ) \
	BYTE certHash[ KEYID_SIZE + 8 ];/* Cached certificate hash */
	BOOLEAN certHashSet;			/* Whether hash has been set */

	/* Certificate object attributes and a cursor into the attribute list.
	   This can be moved by the user on a per-attribute, per-field, and per-
	   component basis */
	ATTRIBUTE_LIST *attributes, *attributeCursor;

	/* The currently selected GeneralName and DN.  A certificate can contain 
	   multiple GeneralNames and DNs that can be selected by their field 
	   types, after which adding DN components will affected the selected 
	   DN.  This value contains the currently selected GeneralName and DN 
	   info */
	SELECTION_INFO currentSelection;

	/* Save area for the currently selected GeneralName and DN, and position
	   in the certificate chain.  The current values are saved to this area 
	   when the object receives a lock object message and restored when the 
	   object receives the corresponding unlock message.  This guarantees 
	   that any changes made during processing while the certificate is 
	   locked don't get reflected back to external users */
	SELECTION_STATE selectionState;

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* The object's handle and the handle of the user who owns this object.
	   The former is used when sending messages to the object when only the
	   xxx_INFO is available, the latter is used to avoid having to fetch the
	   same information from the system object table */
	CRYPT_HANDLE objectHandle;
	CRYPT_USER ownerHandle;

	/* Variable-length storage for the type-specific data */
	DECLARE_VARSTRUCT_VARS;
	} CERT_INFO;

/* Certificate read/write methods for the different format types.  
   Specifying input ranges gets a bit complicated because the functions are 
   polymorphic so we have to provide the lowest common denominator of all 
   functions */

typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
		int ( *READCERT_FUNCTION )( INOUT STREAM *stream, 
									INOUT CERT_INFO *certInfoPtr );
typedef CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
		int ( *WRITECERT_FUNCTION )( INOUT STREAM *stream, 
									 INOUT CERT_INFO *subjectCertInfoPtr,
									 IN_OPT const CERT_INFO *issuerCertInfoPtr,
									 IN_HANDLE_OPT \
										const CRYPT_CONTEXT iIssuerCryptContext );

CHECK_RETVAL_PTR \
READCERT_FUNCTION getCertReadFunction( IN_ENUM( CRYPT_CERTTYPE ) \
										const CRYPT_CERTTYPE_TYPE certType );
CHECK_RETVAL_PTR \
WRITECERT_FUNCTION getCertWriteFunction( IN_ENUM( CRYPT_CERTTYPE ) \
											const CRYPT_CERTTYPE_TYPE certType );

/****************************************************************************
*																			*
*							Attribute Selection Macros						*
*																			*
****************************************************************************/

/* Determine whether an attribute list item is a dummy entry that denotes
   that this field isn't present in the list but has a default value, that
   this field isn't present in the list but represents an entire
   (constructed) attribute, or that it contains a single blob-type
   attribute */

#define DEFAULTFIELD_VALUE		{ 0, CRYPT_ERROR, 0 }
#define COMPLETEATTRIBUTE_VALUE	{ CRYPT_ERROR, 0, 0 }

#define isDefaultFieldValue( attributeListPtr ) \
		( ( attributeListPtr )->fieldID == CRYPT_ERROR && \
		  ( attributeListPtr )->attributeID == 0 )
#define isCompleteAttribute( attributeListPtr ) \
		( ( attributeListPtr )->fieldID == 0 && \
		  ( attributeListPtr )->attributeID == CRYPT_ERROR )
#define isBlobAttribute( attributeListPtr ) \
		( ( attributeListPtr )->fieldID == 0 && \
		  ( attributeListPtr )->attributeID == 0 )

/* Determine whether a component which is being added to a certificate is a 
   special-case DN selection component that selects the current DN without 
   changing the certificate itself, a GeneralName selection component, an 
   attribute cursor movement component, or a general control information 
   component */

#define isDNSelectionComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_ISSUERNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_SUBJECTNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_DIRECTORYNAME )

#define isGeneralNameSelectionComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_AUTHORITYINFO_RTCS || \
	  ( certInfoType ) == CRYPT_CERTINFO_AUTHORITYINFO_OCSP || \
	  ( certInfoType ) == CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS || \
	  ( certInfoType ) == CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY || \
	  ( certInfoType ) == CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING || \
	  ( certInfoType ) == CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR || \
	  ( certInfoType ) == CRYPT_CERTINFO_SUBJECTALTNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_ISSUERALTNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_ISSUINGDIST_FULLNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_CERTIFICATEISSUER || \
	  ( certInfoType ) == CRYPT_CERTINFO_PERMITTEDSUBTREES || \
	  ( certInfoType ) == CRYPT_CERTINFO_EXCLUDEDSUBTREES || \
	  ( certInfoType ) == CRYPT_CERTINFO_CRLDIST_FULLNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_CRLDIST_CRLISSUER || \
	  ( certInfoType ) == CRYPT_CERTINFO_AUTHORITY_CERTISSUER || \
	  ( certInfoType ) == CRYPT_CERTINFO_FRESHESTCRL_FULLNAME || \
	  ( certInfoType ) == CRYPT_CERTINFO_FRESHESTCRL_CRLISSUER || \
	  ( certInfoType ) == CRYPT_CERTINFO_CMS_RECEIPT_TO || \
	  ( certInfoType ) == CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF || \
	  ( certInfoType ) == CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO )

#define isCursorComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_CURRENT_CERTIFICATE || \
	  ( certInfoType ) == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
	  ( certInfoType ) == CRYPT_ATTRIBUTE_CURRENT || \
	  ( certInfoType ) == CRYPT_ATTRIBUTE_CURRENT_INSTANCE )

#define isControlComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_TRUSTED_USAGE || \
	  ( certInfoType ) == CRYPT_CERTINFO_TRUSTED_IMPLICIT )

/* Determine whether a component which is being added is a DN or GeneralName
   component */

#define isDNComponent( certInfoType ) \
	( ( certInfoType ) >= CRYPT_CERTINFO_FIRST_DN && \
	  ( certInfoType ) <= CRYPT_CERTINFO_LAST_DN )

#define isGeneralNameComponent( certInfoType ) \
	( ( certInfoType ) >= CRYPT_CERTINFO_FIRST_GENERALNAME && \
	  ( certInfoType ) <= CRYPT_CERTINFO_LAST_GENERALNAME )

/* Determine whether a component which is being added is pseudo-information
   that corresponds to certificate control information rather than a normal
   certificate attribute */

#define isPseudoInformation( certInfoType ) \
	( ( certInfoType ) >= CRYPT_CERTINFO_FIRST_PSEUDOINFO && \
	  ( certInfoType ) <= CRYPT_CERTINFO_LAST_PSEUDOINFO )

/* Determine whether a component which is being added to a validity/
   revocation check request/response is a standard attribute or a per-entry
   attribute */

#define isRevocationEntryComponent( certInfoType ) \
	( ( certInfoType ) == CRYPT_CERTINFO_CRLREASON || \
	  ( certInfoType ) == CRYPT_CERTINFO_HOLDINSTRUCTIONCODE || \
	  ( certInfoType ) == CRYPT_CERTINFO_INVALIDITYDATE )

/* Check whether an entry in an attribute list is valid.  This checks 
   whether the entry has a non-zero attribute ID, denoting a non blob-type 
   attribute */

#define isValidAttributeField( attributePtr ) \
		( ( attributePtr )->attributeID > 0 )

/****************************************************************************
*																			*
*							String-Handling Functions						*
*																			*
****************************************************************************/

/* Copy a string to/from an ASN.1 string type */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4, 5 ) ) \
int getAsn1StringInfo( IN_BUFFER( stringLen ) const void *string, 
					   IN_LENGTH_SHORT const int stringLen,
					   OUT_RANGE( 0, 20 ) int *stringType, 
					   int *asn1StringType,
					   OUT_LENGTH_SHORT_Z int *asn1StringLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int copyToAsn1String( OUT_BUFFER( destMaxLen, destLen ) void *dest, 
					  IN_LENGTH_SHORT const int destMaxLen, 
					  OUT_LENGTH_SHORT_Z int *destLen, 
					  IN_BUFFER( sourceLen ) const void *source, 
					  IN_LENGTH_SHORT const int sourceLen,
					  IN_RANGE( 0, 20 ) const int stringType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int copyFromAsn1String( OUT_BUFFER( destMaxLen, destLen ) void *dest, 
						IN_LENGTH_SHORT const int destMaxLen, 
						OUT_LENGTH_SHORT_Z int *destLen, 
						IN_BUFFER( sourceLen ) const void *source, 
						IN_LENGTH_SHORT const int sourceLen,
						IN_TAG_ENCODED const int stringTag );

/* Check that a text string contains valid characters for its string type.
   This is used in non-DN strings where we can't avoid the problem by varying
   the string type based on the characters being used */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkTextStringData( IN_BUFFER( stringLen ) const char *string, 
							 IN_LENGTH_SHORT const int stringLen,
							 const BOOLEAN isPrintableString );

/****************************************************************************
*																			*
*							DN Manipulation Functions						*
*																			*
****************************************************************************/

/* Selection options when working with DNs/GeneralNames in extensions.  These
   are used internally when handling user get/set/delete DN/GeneralName
   requests */

typedef enum {
	SELECTION_OPTION_NONE,	/* No selection option type */
	MAY_BE_ABSENT,			/* Component may be absent */
	MUST_BE_PRESENT,		/* Component must be present */
	CREATE_IF_ABSENT,		/* Create component if absent */
	SELECTION_OPTION_LAST	/* Last valid selection option type */
	} SELECTION_OPTION;

/* DN manipulation routines */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int insertDNComponent( INOUT_PTR void **dnComponentListPtrPtr,
					   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE componentType,
					   IN_BUFFER( valueLength ) const void *value, 
					   IN_LENGTH_SHORT const int valueLength,
					   OUT_ENUM_OPT( CRYPT_ERRTYPE_TYPE ) \
							CRYPT_ERRTYPE_TYPE *errorType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int deleteDNComponent( INOUT_PTR void **dnComponentListPtrPtr, 
					   const CRYPT_ATTRIBUTE_TYPE type,
					   IN_BUFFER_OPT( valueLength ) \
					   const void *value, const int valueLength );
STDC_NONNULL_ARG( ( 1 ) ) \
void deleteDN( INOUT_PTR void **dnComponentListPtrPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
int getDNComponentValue( INOUT_PTR const void *dnComponentList,
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type,
						 OUT_BUFFER_OPT( valueMaxLength, \
										 valueLengthlength ) void *value, 
						 IN_LENGTH_SHORT_Z const int valueMaxLength, 
						 OUT_LENGTH_SHORT_Z int *valueLength );

/* Copy and compare a DN */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int copyDN( OUT_PTR void **dnDest, IN_OPT const void *dnSrc );
CHECK_RETVAL_BOOL \
BOOLEAN compareDN( IN_OPT const void *dnComponentList1,
				   IN_OPT const void *dnComponentList2,
				   const BOOLEAN dn1substring );

/* Read/write a DN */

CHECK_RETVAL STDC_NONNULL_ARG( ( 4, 5 ) ) \
int checkDN( IN_OPT const void *dnComponentList,
			 const BOOLEAN checkCN, const BOOLEAN checkC,
			 OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
				CRYPT_ATTRIBUTE_TYPE *errorLocus,
			 OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
				CRYPT_ERRTYPE_TYPE *errorType );
CHECK_RETVAL \
int sizeofDN( INOUT_OPT void *dnComponentList );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readDN( INOUT STREAM *stream, 
			INOUT_PTR void **dnComponentListPtrPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeDN( INOUT STREAM *stream, 
			 IN_OPT const void *dnComponentList,
			 IN_TAG const int tag );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readDNstring( INOUT_PTR void **dnComponentListPtrPtr,
				  IN_BUFFER( stringLength ) const char *string, 
				  IN_LENGTH_ATTRIBUTE const int stringLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeDNstring( INOUT STREAM *stream, 
				   IN_OPT const void *dnComponentList );

/****************************************************************************
*																			*
*						Attribute Manipulation Functions					*
*																			*
****************************************************************************/

/* Find information on an attribute */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 2 ) ) \
ATTRIBUTE_LIST *findAttributeByOID( const ATTRIBUTE_LIST *attributeListPtr,
									IN_BUFFER( oidLength ) const BYTE *oid, 
									IN_RANGE( 1, MAX_OID_SIZE ) \
										const int oidLength );
CHECK_RETVAL_PTR \
ATTRIBUTE_LIST *findAttribute( IN_OPT const ATTRIBUTE_LIST *attributeListPtr,
							   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attributeID,
							   const BOOLEAN isFieldID );
CHECK_RETVAL_PTR \
ATTRIBUTE_LIST *findAttributeField( IN_OPT const ATTRIBUTE_LIST *attributeListPtr,
									IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID,
									IN_ATTRIBUTE_OPT \
										const CRYPT_ATTRIBUTE_TYPE subFieldID );
CHECK_RETVAL_PTR \
ATTRIBUTE_LIST *findAttributeFieldEx( IN_OPT const ATTRIBUTE_LIST *attributeListPtr,
									  IN_ATTRIBUTE \
										const CRYPT_ATTRIBUTE_TYPE fieldID );
CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
ATTRIBUTE_LIST *findNextFieldInstance( const ATTRIBUTE_LIST *attributeListPtr );
CHECK_RETVAL \
int getDefaultFieldValue( IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID );
CHECK_RETVAL_BOOL \
BOOLEAN checkAttributePresent( IN_OPT const ATTRIBUTE_LIST *attributeListPtr,
							   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID );

/* Move the current attribute cursor */

CHECK_RETVAL_PTR \
ATTRIBUTE_LIST *certMoveAttributeCursor( IN_OPT const ATTRIBUTE_LIST *currentCursor,
										 IN_ATTRIBUTE \
											const CRYPT_ATTRIBUTE_TYPE certInfoType,
										 IN_RANGE( CRYPT_CURSOR_FIRST, \
												   CRYPT_CURSOR_LAST ) \
											const int position );

/* Add/delete attributes/attribute fields */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 6 ) ) \
int addAttribute( IN_ENUM( ATTRIBUTE ) const ATTRIBUTE_TYPE attributeType,
				  /*?*/ ATTRIBUTE_LIST **listHeadPtr, 
				  IN_BUFFER( oidLength ) const BYTE *oid, 
				  IN_RANGE( 5, MAX_OID_SIZE ) const int oidLength,
				  const BOOLEAN critical, 
				  IN_BUFFER( dataLength ) const void *data, 
				  IN_LENGTH_SHORT const int dataLength, 
				  IN_FLAGS_Z( ATTR ) const int flags );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 7, 8 ) ) \
int addAttributeField( ATTRIBUTE_LIST **attributeListPtr,
					   const CRYPT_ATTRIBUTE_TYPE fieldID,
					   const CRYPT_ATTRIBUTE_TYPE subFieldID,
					   IN_BUFFER( dataLength ) const void *data, 
					   const int dataLength,
					   const int flags, 
					   OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
							CRYPT_ATTRIBUTE_TYPE *errorLocus,
					   OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
							CRYPT_ERRTYPE_TYPE *errorType );
RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int deleteAttributeField( INOUT ATTRIBUTE_LIST **attributeListPtr,
						  INOUT_OPT ATTRIBUTE_LIST **listCursorPtr,
						  INOUT ATTRIBUTE_LIST *listItem,
						  IN_OPT const void *dnCursor );
RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int deleteAttribute( INOUT ATTRIBUTE_LIST **attributeListPtr,
					 INOUT_OPT ATTRIBUTE_LIST **listCursorPtr,
					 INOUT ATTRIBUTE_LIST *listItem,
					 IN_OPT const void *dnCursor );
STDC_NONNULL_ARG( ( 1 ) ) \
void deleteAttributes( INOUT ATTRIBUTE_LIST **attributeListPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int copyAttributes( INOUT ATTRIBUTE_LIST **destListHeadPtr,
					const ATTRIBUTE_LIST *srcListPtr,
					OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						CRYPT_ATTRIBUTE_TYPE *errorLocus,
					OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
						CRYPT_ERRTYPE_TYPE *errorType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
int copyIssuerAttributes( INOUT ATTRIBUTE_LIST **destListHeadPtr,
						  const ATTRIBUTE_LIST *srcListPtr,
						  const CRYPT_CERTTYPE_TYPE type,
						  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
							CRYPT_ATTRIBUTE_TYPE *errorLocus,
						  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
							CRYPT_ERRTYPE_TYPE *errorType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int copyCRMFRequestAttributes( INOUT ATTRIBUTE_LIST **destListHeadPtr,
							   const ATTRIBUTE_LIST *srcListPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int copyOCSPRequestAttributes( INOUT ATTRIBUTE_LIST **destListHeadPtr,
							   const ATTRIBUTE_LIST *srcListPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int copyRevocationAttributes( INOUT ATTRIBUTE_LIST **destListHeadPtr,
							  const ATTRIBUTE_LIST *srcListPtr );

/* Read/write a collection of attributes */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 4 ) ) \
int checkAttributes( IN_ENUM( ATTRIBUTE ) const ATTRIBUTE_TYPE attributeType,
					 const ATTRIBUTE_LIST *listHeadPtr,
					 OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						CRYPT_ATTRIBUTE_TYPE *errorLocus,
					 OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
						CRYPT_ERRTYPE_TYPE *errorType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofAttributes( const ATTRIBUTE_LIST *attributeListPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeAttributes( INOUT STREAM *stream, 
					 INOUT ATTRIBUTE_LIST *attributeListPtr,
					 IN_ENUM_OPT( CRYPT_CERTTYPE ) const CRYPT_CERTTYPE_TYPE type,
					 IN_LENGTH const int attributeSize );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5, 6 ) ) \
int readAttributes( INOUT STREAM *stream, 
					/*?*/ ATTRIBUTE_LIST **attributeListPtrPtr,
					IN_ENUM_OPT( CRYPT_CERTTYPE ) const CRYPT_CERTTYPE_TYPE type, 
					IN_LENGTH_Z const int attributeLength,
					OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						CRYPT_ATTRIBUTE_TYPE *errorLocus,
					OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
						CRYPT_ERRTYPE_TYPE *errorType );

/****************************************************************************
*																			*
*			Validity/Revocation Information Manipulation Functions			*
*																			*
****************************************************************************/

/* Read/write validity/revocation information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofCRLentry( INOUT REVOCATION_INFO *crlEntry );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readCRLentry( INOUT STREAM *stream, 
				  INOUT_PTR REVOCATION_INFO **listHeadPtrPtr,
				  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
					CRYPT_ATTRIBUTE_TYPE *errorLocus,
				  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
					CRYPT_ERRTYPE_TYPE *errorType );
STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCRLentry( INOUT STREAM *stream, 
				   const REVOCATION_INFO *crlEntry );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofOcspRequestEntry( INOUT REVOCATION_INFO *ocspEntry );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readOcspRequestEntry( INOUT STREAM *stream, 
						  INOUT_PTR REVOCATION_INFO **listHeadPtrPtr,
						  INOUT CERT_INFO *certInfoPtr );
STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeOcspRequestEntry( INOUT STREAM *stream, 
						   const REVOCATION_INFO *ocspEntry );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofOcspResponseEntry( INOUT REVOCATION_INFO *ocspEntry );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readOcspResponseEntry( INOUT STREAM *stream, 
						   INOUT_PTR REVOCATION_INFO **listHeadPtrPtr,
						   INOUT CERT_INFO *certInfoPtr );
STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeOcspResponseEntry( INOUT STREAM *stream, 
							const REVOCATION_INFO *ocspEntry,
							const time_t entryTime );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofRtcsRequestEntry( INOUT VALIDITY_INFO *rtcsEntry );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readRtcsRequestEntry( INOUT STREAM *stream, 
						  INOUT_PTR VALIDITY_INFO **listHeadPtrPtr,
						  INOUT CERT_INFO *certInfoPtr );
STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeRtcsRequestEntry( INOUT STREAM *stream, 
						   const VALIDITY_INFO *rtcsEntry );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofRtcsResponseEntry( INOUT VALIDITY_INFO *rtcsEntry,
							 const BOOLEAN isFullResponse );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int readRtcsResponseEntry( INOUT STREAM *stream, 
						   INOUT_PTR VALIDITY_INFO **listHeadPtrPtr,
						   INOUT CERT_INFO *certInfoPtr,
						   const BOOLEAN isFullResponse );
STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeRtcsResponseEntry( INOUT STREAM *stream, 
						    const VALIDITY_INFO *rtcsEntry,
							const BOOLEAN isFullResponse );

/* Add/delete a validity/revocation entry */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int addValidityEntry( INOUT_PTR VALIDITY_INFO **listHeadPtrPtr,
					  OUT_OPT_PTR VALIDITY_INFO **newEntryPosition,
					  IN_BUFFER( valueLength ) const void *value, 
					  IN_LENGTH_SHORT const int valueLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int addRevocationEntry( INOUT_PTR REVOCATION_INFO **listHeadPtrPtr,
						OUT_PTR REVOCATION_INFO **newEntryPosition,
						IN_KEYID const CRYPT_KEYID_TYPE valueType,
						IN_BUFFER( valueLength ) const void *value, 
						IN_LENGTH_SHORT const int valueLength,
						const BOOLEAN noCheck );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3, 4 ) ) \
int prepareValidityEntries( INOUT_OPT VALIDITY_INFO *listPtr, 
							OUT_PTR VALIDITY_INFO **errorEntry,
							OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
								CRYPT_ATTRIBUTE_TYPE *errorLocus,
							OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 6 ) ) \
int prepareRevocationEntries( INOUT_OPT REVOCATION_INFO *listPtr, 
							  const time_t defaultTime,
							  OUT_PTR REVOCATION_INFO **errorEntry,
							  const BOOLEAN isSingleEntry,
							  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
								CRYPT_ATTRIBUTE_TYPE *errorLocus,
							  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType );
STDC_NONNULL_ARG( ( 1 ) ) \
void deleteValidityEntries( INOUT_PTR VALIDITY_INFO **listHeadPtrPtr );
STDC_NONNULL_ARG( ( 1 ) ) \
void deleteRevocationEntries( INOUT_PTR REVOCATION_INFO **listHeadPtrPtr );

/* Copy a set of validity/revocation entries */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int copyValidityEntries( INOUT_PTR VALIDITY_INFO **destListHeadPtrPtr,
						 const VALIDITY_INFO *srcListPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int copyRevocationEntries( INOUT_PTR REVOCATION_INFO **destListHeadPtrPtr,
						   const REVOCATION_INFO *srcListPtr );

/* Determine whether a certificate has been revoked by this CRL/OCSP 
   response */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkRevocation( const CERT_INFO *certInfoPtr, 
					 INOUT CERT_INFO *revocationInfoPtr );

/****************************************************************************
*																			*
*							Certificate Checking Functions					*
*																			*
****************************************************************************/

/* Check a certificate object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4, 5 ) ) \
int checkCert( INOUT CERT_INFO *subjectCertInfoPtr,
			   IN_OPT const CERT_INFO *issuerCertInfoPtr,
			   const BOOLEAN shortCircuitCheck,
			   OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
					CRYPT_ATTRIBUTE_TYPE *errorLocus,
			   OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
					CRYPT_ERRTYPE_TYPE *errorType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkCertChain( INOUT CERT_INFO *certInfoPtr );

/* Certificate key check flags.  These are:

	FLAG_NONE: No specific check.

	FLAG_CA: Certificate must contain a CA key.

	FLAG_PRIVATEKEY: Check for constraints on the corresponding private
			key's usage, not just the public key usage.

	FLAG_GENCHECK: Perform a general check that the key usage details are
			in order without checking for a particular usage */

#define CHECKKEY_FLAG_NONE			0x00	/* No specific checks */
#define CHECKKEY_FLAG_CA			0x01	/* Must be CA key */
#define CHECKKEY_FLAG_PRIVATEKEY	0x02	/* Check priv.key constraints */
#define CHECKKEY_FLAG_GENCHECK		0x04	/* General details check */
#define CHECKKEY_FLAG_MAX			0x07	/* Maximum possible flag value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int getKeyUsageFromExtKeyUsage( const CERT_INFO *certInfoPtr,
								OUT_FLAGS_Z( CRYPT_KEYUSAGE ) int *keyUsage,
								OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
									CRYPT_ATTRIBUTE_TYPE *errorLocus, 
								OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
									CRYPT_ERRTYPE_TYPE *errorType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5, 6 ) ) \
int checkKeyUsage( const CERT_INFO *certInfoPtr,
				   IN_FLAGS_Z( CHECKKEY ) const int flags, 
				   IN_FLAGS_Z( CRYPT_KEYUSAGE ) const int specificUsage,
				   IN_RANGE( CRYPT_COMPLIANCELEVEL_OBLIVIOUS, \
							 CRYPT_COMPLIANCELEVEL_LAST - 1 ) \
						const int complianceLevel,
				   OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						CRYPT_ATTRIBUTE_TYPE *errorLocus,
				   OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
						CRYPT_ERRTYPE_TYPE *errorType );

/* Check certificate constraints */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
int checkNameConstraints( const CERT_INFO *subjectCertInfoPtr,
						  const ATTRIBUTE_LIST *issuerAttributes,
						  const BOOLEAN isExcluded,
						  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
							CRYPT_ATTRIBUTE_TYPE *errorLocus,
						  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
							CRYPT_ERRTYPE_TYPE *errorType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 5 ) ) \
int checkPolicyConstraints( const CERT_INFO *subjectCertInfoPtr,
							const ATTRIBUTE_LIST *issuerAttributes,
							IN_ENUM_OPT( POLICY ) const POLICY_TYPE policyType,
							OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
								CRYPT_ATTRIBUTE_TYPE *errorLocus,
							OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int checkPathConstraints( const CERT_INFO *subjectCertInfoPtr,
						  const ATTRIBUTE_LIST *issuerAttributes,
						  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
							CRYPT_ATTRIBUTE_TYPE *errorLocus,
						  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
							CRYPT_ERRTYPE_TYPE *errorType );

/* Sign/sig check a certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int signCert( INOUT CERT_INFO *certInfoPtr, 
			  IN_HANDLE_OPT const CRYPT_CONTEXT iSignContext );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int checkCertValidity( INOUT CERT_INFO *certInfoPtr, 
					   IN_HANDLE_OPT const CRYPT_HANDLE iSigCheckObject );

/****************************************************************************
*																			*
*							Certificate Chain Functions						*
*																			*
****************************************************************************/

/* Read/write/copy a certificate chain */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readCertChain( INOUT STREAM *stream, OUT CRYPT_CERTIFICATE *iCryptCert,
				   IN_HANDLE const CRYPT_USER iCryptOwner,
				   IN_ENUM( CRYPT_CERTTYPE ) const CRYPT_CERTTYPE_TYPE type,
				   IN_KEYID_OPT const CRYPT_KEYID_TYPE keyIDtype,
				   IN_BUFFER_OPT( keyIDlength ) const void *keyID, 
				   IN_LENGTH_KEYID_Z const int keyIDlength,
				   const BOOLEAN dataOnlyCert );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCertChain( INOUT STREAM *stream, 
					const CERT_INFO *certInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int copyCertChain( INOUT CERT_INFO *certInfoPtr, 
				   IN_HANDLE const CRYPT_HANDLE certChain,
				   const BOOLEAN isCertCollection );

/* Read/write certificate collections in assorted formats */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int sizeofCertCollection( const CERT_INFO *certInfoPtr,
						  IN_ENUM( CRYPT_CERTFORMAT ) \
							const CRYPT_CERTFORMAT_TYPE certFormatType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeCertCollection( INOUT STREAM *stream, 
						 const CERT_INFO *certInfoPtr,
						 IN_ENUM( CRYPT_CERTFORMAT ) \
							const CRYPT_CERTFORMAT_TYPE certFormatType );

/* Assemble a certificate chain from certificates read from an object */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 4 ) ) \
int assembleCertChain( OUT CRYPT_CERTIFICATE *iCertificate,
					   IN_HANDLE const CRYPT_HANDLE iCertSource,
					   IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
					   IN_BUFFER( keyIDlength ) const void *keyID, 
					   IN_LENGTH_KEYID const int keyIDlength,
					   IN_FLAGS( KEYMGMT ) const int options );

/****************************************************************************
*																			*
*								Certificate Functions						*
*																			*
****************************************************************************/

/* Create a certificate object ready for further initialisation */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int createCertificateInfo( OUT_PTR CERT_INFO **certInfoPtrPtr, 
						   IN_HANDLE const CRYPT_USER iCryptOwner,
						   IN_ENUM( CRYPT_CERTTYPE ) \
							const CRYPT_CERTTYPE_TYPE certType );

/* Add/get/delete a certificate component */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int addCertComponent( INOUT CERT_INFO *certInfoPtr,
					  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  /*?*/ const void *certInfo, 
					  /*?*/ const int certInfoLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
int getCertComponent( INOUT CERT_INFO *certInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  OUT_BUFFER_OPT( certInfoMaxLength, \
									  *certInfoLength ) void *certInfo, 
					  const int certInfoMaxLength, 
					  int *certInfoLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int deleteCertComponent( INOUT CERT_INFO *certInfoPtr,
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE certInfoType );

/* Import/export a certificate */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int importCert( IN_BUFFER( certObjectLength ) const void *certObject, 
				IN_LENGTH const int certObjectLength,
				OUT_HANDLE_OPT CRYPT_CERTIFICATE *certificate,
				IN_HANDLE const CRYPT_USER iCryptOwner,
				IN_KEYID const CRYPT_KEYID_TYPE keyIDtype,
				IN_BUFFER_OPT( keyIDlength ) const void *keyID, 
				IN_LENGTH_KEYID_Z const int keyIDlength,
				IN_ENUM_OPT( CRYPT_CERTTYPE ) \
					const CRYPT_CERTTYPE_TYPE formatHint );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5 ) ) \
int exportCert( OUT_BUFFER_OPT( certObjectMaxLength, *certObjectLength ) \
					void *certObject, 
				IN_LENGTH const int certObjectMaxLength, 
				OUT_LENGTH_Z int *certObjectLength,
				IN_ENUM( CRYPT_CERTFORMAT ) \
					const CRYPT_CERTFORMAT_TYPE certFormatType,
				const CERT_INFO *certInfoPtr );

/* Oddball routines: work with a certificate's serial number */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setSerialNumber( INOUT CERT_INFO *certInfoPtr, 
					 IN_BUFFER_OPT( serialNumberLength ) const void *serialNumber, 
					 IN_LENGTH_SHORT_Z const int serialNumberLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
BOOLEAN compareSerialNumber( IN_BUFFER( canonSerialNumberLength ) \
								const void *canonSerialNumber,
							 IN_LENGTH_SHORT const int canonSerialNumberLength,
							 IN_BUFFER( serialNumberLength ) \
								const void *serialNumber,
							 IN_LENGTH_SHORT const int serialNumberLength );

/****************************************************************************
*																			*
*							Miscellaneous Functions							*
*																			*
****************************************************************************/

/* Convert a text-form OID to its binary form */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int textToOID( IN_BUFFER( oidLength ) const char *textOID, 
			   IN_RANGE( MIN_ASCII_OIDSIZE, CRYPT_MAX_TEXTSIZE ) \
					const int textOIDlength, 
			   OUT_BUFFER( binaryOidMaxLen, binaryOidLen ) BYTE *binaryOID, 
			   IN_LENGTH_SHORT const int binaryOidMaxLen, 
			   OUT_LENGTH_SHORT_Z int *binaryOidLen );

/* Prototypes for functions in certext.c */

CHECK_RETVAL_BOOL \
BOOLEAN isValidField( IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE fieldID,
					  IN_ENUM( CRYPT_CERTTYPE ) \
						const CRYPT_CERTTYPE_TYPE certType );

/* Prototypes for functions in comp_get.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int moveCursorToField( INOUT CERT_INFO *certInfoPtr,
					   const CRYPT_ATTRIBUTE_TYPE certInfoType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int selectGeneralName( INOUT CERT_INFO *certInfoPtr,
					   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE certInfoType,
					   IN_ENUM( SELECTION_OPTION ) const SELECTION_OPTION option );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int selectDN( INOUT CERT_INFO *certInfoPtr, 
			  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE certInfoType,
			  IN_ENUM( SELECTION_OPTION ) const SELECTION_OPTION option );
void syncSelection( INOUT CERT_INFO *certInfoPtr ) \
					STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
time_t *getRevocationTimePtr( const CERT_INFO *certInfoPtr );

/* Prototypes for functions in certschk.c */

int checkCertDetails( CERT_INFO *subjectCertInfoPtr,
					  CERT_INFO *issuerCertInfoPtr,
					  const CRYPT_CONTEXT iIssuerPubKey,
					  const X509SIG_FORMATINFO *formatInfo,
					  const BOOLEAN trustAnchorCheck,
					  const BOOLEAN shortCircuitCheck,
					  OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
						CRYPT_ATTRIBUTE_TYPE *errorLocus,
					  OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
						CRYPT_ERRTYPE_TYPE *errorType );

/* Prototypes for functions in dn.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int convertEmail( INOUT CERT_INFO *certInfoPtr, 
				  /*?*/ void **dnComponentListPtrPtr,
				  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE altNameType );

/* Prototypes for functions in ext.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int fixAttributes( INOUT CERT_INFO *certInfoPtr );

/* Prototypes for functions in ext_def.c */

CHECK_RETVAL_BOOL \
BOOLEAN checkExtensionTables( void );

#endif /* _CERT_DEFINED */
