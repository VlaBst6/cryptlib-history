/****************************************************************************
*																			*
*							SCEP Definitions Header File					*
*						Copyright Peter Gutmann 1999-2007					*
*																			*
****************************************************************************/

#ifndef _SCEP_DEFINED

#define _SCEP_DEFINED

/* Various SCEP constants */

#define SCEP_NONCE_SIZE			16

/* SCEP protocol-specific flags that augment the general session flags */

#define SCEP_PFLAG_NONE			0x00	/* No protocol-specific flags */
#define SCEP_PFLAG_PNPPKI		0x01	/* Session is PnP PKI-capable */

/* The SCEP message type, status, and failure info.  For some bizarre
   reason these integer values are communicated as text strings */

#define MESSAGETYPE_CERTREP				"3"
#define MESSAGETYPE_PKCSREQ				"19"

#define MESSAGESTATUS_SUCCESS			"0"
#define MESSAGESTATUS_FAILURE			"2"
#define MESSAGESTATUS_PENDING			"3"

#define MESSAGEFAILINFO_BADALG			"0"
#define MESSAGEFAILINFO_BADMESSAGECHECK	"1"
#define MESSAGEFAILINFO_BADREQUEST		"2"
#define MESSAGEFAILINFO_BADTIME			"3"
#define MESSAGEFAILINFO_BADCERTID		"4"

/* Numeric equivalents of the above, to make them easier to work with */

#define MESSAGETYPE_CERTREP_VALUE		3
#define MESSAGETYPE_PKCSREQ_VALUE		19

#define MESSAGESTATUS_SUCCESS_VALUE		0
#define MESSAGESTATUS_FAILURE_VALUE		2
#define MESSAGESTATUS_PENDING_VALUE		3

/* SCEP HTTP content type */

#define SCEP_CONTENT_TYPE				"application/x-pki-message"
#define SCEP_CONTENT_TYPE_LEN			25
#define SCEP_CONTENT_TYPE_GETCACERT		"application/x-x509-ca-cert"
#define SCEP_CONTENT_TYPE_GETCACERT_LEN	26
#define SCEP_CONTENT_TYPE_GETCACERTCHAIN "application/x-x509-ca-ra-cert-chain"
#define SCEP_CONTENT_TYPE_GETCACERTCHAIN_LEN 35

/* SCEP protocol state information.  This is passed around various
   subfunctions that handle individual parts of the protocol */

typedef struct {
	/* Identification/state variable information.  SCEP uses a single
	   nonce, but when present in the initiator's message it's identified
	   as a sender nonce and when present in the responder's message
	   it's identified as a recipient nonce.
	
	   In order to accommodate nonstandard implementations, we allow for 
	   nonces that are slightly larger than the required size */
	BYTE transID[ CRYPT_MAX_HASHSIZE + 8 ];	/* Transaction nonce */
	BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];	/* Nonce */
	int transIDsize, nonceSize;

	/* When sending/receiving SCEP messages, the user has to sign the
	   request data and decrypt the response data.  Since they don't
	   have a cert at this point, they need to create an ephemeral
	   self-signed cert to handle this task */
	CRYPT_CERTIFICATE iScepCert;
	} SCEP_PROTOCOL_INFO;

/* Prototypes for functions in scep.c */

CHECK_RETVAL \
BOOLEAN checkCACert( const CRYPT_CERTIFICATE iCaCert );
CHECK_RETVAL \
int processKeyFingerprint( INOUT SESSION_INFO *sessionInfoPtr ) \
						   STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL \
int createScepAttributes( INOUT SESSION_INFO *sessionInfoPtr,
						  INOUT SCEP_PROTOCOL_INFO *protocolInfo,
						  OUT CRYPT_CERTIFICATE *iScepAttributes,
						  const BOOLEAN isInitiator, const int scepStatus ) \
						  STDC_NONNULL_ARG( ( 1, 2, 3 ) );
CHECK_RETVAL \
int getScepStatusValue( const CRYPT_CERTIFICATE iCmsAttributes,
						const CRYPT_ATTRIBUTE_TYPE attributeType, 
						OUT int *value ) \
						STDC_NONNULL_ARG( ( 3 ) );

/* Prototypes for functions in scep_cli.c */

CHECK_RETVAL \
int createScepRequest( INOUT SESSION_INFO *sessionInfoPtr,
					   INOUT SCEP_PROTOCOL_INFO *protocolInfo ) \
					   STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int checkScepResponse( INOUT SESSION_INFO *sessionInfoPtr,
					   INOUT SCEP_PROTOCOL_INFO *protocolInfo ) \
					   STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int createAdditionalScepRequest( INOUT SESSION_INFO *sessionInfoPtr ) \
								 STDC_NONNULL_ARG( ( 1 ) );

/* Prototypes for functions in scep_svr.c */

CHECK_RETVAL \
int checkScepRequest( INOUT SESSION_INFO *sessionInfoPtr,
					  INOUT SCEP_PROTOCOL_INFO *protocolInfo ) \
					  STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int createScepResponse( INOUT SESSION_INFO *sessionInfoPtr,
						INOUT SCEP_PROTOCOL_INFO *protocolInfo ) \
						STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int processAdditionalScepRequest( INOUT SESSION_INFO *sessionInfoPtr,
								  const HTTP_URI_INFO *httpReqInfo ) \
								  STDC_NONNULL_ARG( ( 1, 2 ) );

#endif /* _SCEP_DEFINED */
