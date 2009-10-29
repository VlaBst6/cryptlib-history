/****************************************************************************
*																			*
*						SSL v3/TLS Definitions Header File					*
*						Copyright Peter Gutmann 1998-2008					*
*																			*
****************************************************************************/

#ifndef _SSL_DEFINED

#define _SSL_DEFINED

/****************************************************************************
*																			*
*								SSL Constants								*
*																			*
****************************************************************************/

/* Default SSL port */

#define SSL_PORT					443

/* SSL constants */

#define ID_SIZE						1	/* ID byte */
#define LENGTH_SIZE					3	/* 24 bits */
#define SEQNO_SIZE					8	/* 64 bits */
#define VERSIONINFO_SIZE			2	/* 0x03, 0x0n */
#define ALERTINFO_SIZE				2	/* level + description */
#define SSL_HEADER_SIZE				5	/* Type, version, length */
#define SSL_NONCE_SIZE				32	/* Size of client/svr nonce */
#define SSL_SECRET_SIZE				48	/* Size of premaster/master secret */
#define MD5MAC_SIZE					16	/* Size of MD5 proto-HMAC/dual hash */
#define SHA1MAC_SIZE				20	/* Size of SHA-1 proto-HMAC/dual hash */
#define TLS_HASHEDMAC_SIZE			12	/* Size of TLS PRF( MD5 + SHA1 ) */
#define SESSIONID_SIZE				16	/* Size of session ID */
#define MAX_SESSIONID_SIZE			32	/* Max.allowed session ID size */
#define MAX_KEYBLOCK_SIZE			( ( 20 + 32 + 16 ) * 2 )/* HMAC-SHA1 + AES */
#define MIN_PACKET_SIZE				4	/* Minimum SSL packet size */
#define MAX_PACKET_SIZE				16384	/* Maximum SSL packet size */
#define MAX_CIPHERSUITES			200	/* Max.allowed cipher suites */

/* SSL packet/buffer size information.  The extra packet size is somewhat 
   large because it can contains the packet header (5 bytes), IV (0/8/16 
   bytes), MAC (16/20 bytes), and cipher block padding (up to 256 bytes) */

#define EXTRA_PACKET_SIZE			512	

/* By default, cryptlib uses RSA key transport, which is supported by all 
   servers.  It's also possible to use DH key agreement, however this isn't
   supported by all servers (particularly Microsoft ones) and has a 
   considerably higher cryptographic overhead than RSA, requiring a DH 
   (pseudo-)private key operation on both client and server as well as a 
   standard RSA private-key operation on the server.  To use DH cipher 
   suites in preference to RSA ones, uncomment the following */

/* #define PREFER_DH_SUITES */

/* SSL protocol-specific flags that augment the general session flags.  The 
   alert-sent flag is required because we're required to send a close alert 
   when shutting down to prevent a truncation attack, however lower-level 
   code may have already sent an alert so we have to remember not to send it 
   twice */

#define SSL_PFLAG_NONE				0x0	/* No protocol-specific flags */
#define SSL_PFLAG_ALERTSENT			0x1	/* Close alert sent */

/* SSL message types */

#define SSL_MSG_CHANGE_CIPHER_SPEC	20
#define SSL_MSG_ALERT				21
#define SSL_MSG_HANDSHAKE			22
#define SSL_MSG_APPLICATION_DATA	23

#define SSL_MSG_FIRST				SSL_MSG_CHANGE_CIPHER_SPEC
#define SSL_MSG_LAST				SSL_MSG_APPLICATION_DATA

/* Special-case expected packet-type values that are passed to 
   readHSPacketSSL() to handle situations where more than one packet type is 
   valid.  The first handshake packet from the client or server is treated 
   specially in that both the version number information is taken from this 
   packet, and the packet itself may have to be treated specially because 
   although the client handshake is supposed to be a v3 handshake, the first 
   handshake packet is often a hacked v2 one with forwards-compatibility 
   kludges */

#define SSL_MSG_FIRST_HANDSHAKE		0xFF
#define SSL_MSG_LAST_SPECIAL		SSL_MSG_FIRST_HANDSHAKE
#define SSL_MSG_V2HANDSHAKE			0x80

/* SSL handshake message subtypes */

#define SSL_HAND_CLIENT_HELLO		0x01
#define SSL_HAND_SERVER_HELLO		0x02
#define SSL_HAND_CERTIFICATE		0x0B
#define SSL_HAND_SERVER_KEYEXCHANGE	0x0C
#define SSL_HAND_SERVER_CERTREQUEST	0x0D
#define SSL_HAND_SERVER_HELLODONE	0x0E
#define SSL_HAND_CLIENT_CERTVERIFY	0x0F
#define SSL_HAND_CLIENT_KEYEXCHANGE	0x10
#define SSL_HAND_FINISHED			0x14
#define SSL_HAND_SUPPLEMENTAL_DATA	0x17

#define SSL_HAND_FIRST				SSL_HAND_CLIENT_HELLO
#define SSL_HAND_LAST				SSL_HAND_SUPPLEMENTAL_DATA

/* SSL alert levels and types */

#define SSL_ALERTLEVEL_WARNING				1
#define SSL_ALERTLEVEL_FATAL				2

#define SSL_ALERT_CLOSE_NOTIFY				0
#define SSL_ALERT_UNEXPECTED_MESSAGE		10
#define SSL_ALERT_BAD_RECORD_MAC			20
#define TLS_ALERT_DECRYPTION_FAILED			21
#define TLS_ALERT_RECORD_OVERFLOW			22
#define SSL_ALERT_DECOMPRESSION_FAILURE		30
#define SSL_ALERT_HANDSHAKE_FAILURE			40
#define SSL_ALERT_NO_CERTIFICATE			41
#define SSL_ALERT_BAD_CERTIFICATE			42
#define SSL_ALERT_UNSUPPORTED_CERTIFICATE	43
#define SSL_ALERT_CERTIFICATE_REVOKED		44
#define SSL_ALERT_CERTIFICATE_EXPIRED		45
#define SSL_ALERT_CERTIFICATE_UNKNOWN		46
#define SSL_ALERT_ILLEGAL_PARAMETER			47
#define TLS_ALERT_UNKNOWN_CA				48
#define TLS_ALERT_ACCESS_DENIED				49
#define TLS_ALERT_DECODE_ERROR				50
#define TLS_ALERT_DECRYPT_ERROR				51
#define TLS_ALERT_EXPORT_RESTRICTION		60
#define TLS_ALERT_PROTOCOL_VERSION			70
#define TLS_ALERT_INSUFFICIENT_SECURITY		71
#define TLS_ALERT_INTERNAL_ERROR			80
#define TLS_ALERT_USER_CANCELLED			90
#define TLS_ALERT_NO_RENEGOTIATION			100
#define TLS_ALERT_UNSUPPORTED_EXTENSION		110
#define TLS_ALERT_CERTIFICATE_UNOBTAINABLE	111
#define TLS_ALERT_UNRECOGNIZED_NAME			112
#define TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE 113
#define TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE 114
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY		115

#define SSL_ALERT_FIRST						SSL_ALERT_CLOSE_NOTIFY
#define SSL_ALERT_LAST						TLS_ALERT_UNKNOWN_PSK_IDENTITY

/* SSL supplemental data subtypes */

#define TLS_SUPPDATA_USERMAPPING			0

/* SSL cipher suites */

typedef enum {
	/* SSLv3 cipher suites (0-10) */
	SSL_NULL_WITH_NULL, SSL_RSA_WITH_NULL_MD5, SSL_RSA_WITH_NULL_SHA,
	SSL_RSA_EXPORT_WITH_RC4_40_MD5, SSL_RSA_WITH_RC4_128_MD5,
	SSL_RSA_WITH_RC4_128_SHA, SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	SSL_RSA_WITH_IDEA_CBC_SHA, SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSL_RSA_WITH_DES_CBC_SHA, SSL_RSA_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) DH cipher suites (11-22) */
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_DSS_WITH_DES_CBC_SHA,
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DH_RSA_WITH_DES_CBC_SHA, TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, TLS_DHE_DSS_WITH_DES_CBC_SHA,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_DHE_RSA_WITH_DES_CBC_SHA, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) anon-DH cipher suites (23-27) */
	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, TLS_DH_anon_WITH_RC4_128_MD5,
	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, TLS_DH_anon_WITH_DES_CBC_SHA,
	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,

	/* TLS (RFC 2246) reserved cipher suites (28-29, used for Fortezza in
	   SSLv3) */
	TLS_reserved_1, TLS_reserved_2,

	/* TLS with Kerberos (RFC 2712) suites (30-43) */
	TLS_KRB5_WITH_DES_CBC_SHA, TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
	TLS_KRB5_WITH_RC4_128_SHA, TLS_KRB5_WITH_IDEA_CBC_SHA,
	TLS_KRB5_WITH_DES_CBC_MD5, TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
	TLS_KRB5_WITH_RC4_128_MD5, TLS_KRB5_WITH_IDEA_CBC_MD5,
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
	TLS_KRB5_EXPORT_WITH_RC4_40_SHA, TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, TLS_KRB5_EXPORT_WITH_RC4_40_MD5,

	/* Unknown suites (44-46) */

	/* TLS (post-2246) cipher suites (47-58) */
	TLS_RSA_WITH_AES_128_CBC_SHA = 0x2F, TLS_DH_DSS_WITH_AES_128_CBC_SHA,
	TLS_DH_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DH_anon_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA, TLS_DH_DSS_WITH_AES_256_CBC_SHA,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_DH_anon_WITH_AES_256_CBC_SHA,

	/* Unknown suites (59-64) */

	/* Camellia (RFC 4132) suites (65-70) */
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 65, 
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA, TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA, TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,

	/* Unknown suites (71-131) */

	/* Camellia (RFC 4132) suites (132-137) */
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 132,
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA, TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA, TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,

	/* TLS-PSK cipher suites (138-149) */
	TLS_PSK_WITH_RC4_128_SHA, TLS_PSK_WITH_3DES_EDE_CBC_SHA, 
	TLS_PSK_WITH_AES_128_CBC_SHA, TLS_PSK_WITH_AES_256_CBC_SHA, 
	TLS_DHE_PSK_WITH_RC4_128_SHA, TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA, TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
	TLS_RSA_PSK_WITH_RC4_128_SHA, TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA, TLS_RSA_PSK_WITH_AES_256_CBC_SHA,

	/* TLS-ECC cipher suites.  For some unknown reason these start above 
	   49152/0xC000, so the range is 49153...49177 */
	TLS_ECDH_ECDSA_WITH_NULL_SHA = 49153, TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_NULL_SHA,
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_RSA_WITH_NULL_SHA, TLS_ECDH_RSA_WITH_RC4_128_SHA,
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_NULL_SHA,
	TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_anon_WITH_NULL_SHA, TLS_ECDH_anon_WITH_RC4_128_SHA,
	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA,

	SSL_LAST 
	} SSL_CIPHERSUITE_TYPE;

/* TLS extension types */

typedef enum {
	TLS_EXT_SERVER_NAME,		/* Name of virtual server to contact */
	TLS_EXT_MAX_FRAGMENT_LENTH,	/* Max.fragment length if smaller than 2^14 bytes */
	TLS_EXT_CLIENT_CERTIFICATE_URL,	/* Location for server to find client certificate */
	TLS_EXT_TRUSTED_CA_KEYS,	/* Indication of which CAs clients trust */
	TLS_EXT_TRUNCATED_HMAC,		/* Use 80-bit truncated HMAC */
	TLS_EXT_STATUS_REQUEST,		/* OCSP status request from server */
	TLS_EXT_USER_MAPPING,		/* RFC 4681 mapping of user name to account */
	TLS_EXT_RESERVED1,			/* For future use */
	TLS_EXT_RESERVED2,			/* For future use */
	TLS_EXT_CERTTYPE,			/* RFC 5081 OpenPGP key support */
	TLS_EXT_ELLIPTIC_CURVES,	/* RFC 4492 ECDH/ECDSA support */
	TLS_EXT_EC_POINT_FORMATS,	/* RFC 4492 ECDH/ECDSA support */
	TLS_EXT_SRP,				/* RFC 5054 SRP support */
	TLS_EXT_SIGNATURE_ALGORITHMS,	/* RFC 5246 TLSv1.2 */
		/* 14...34 unused */
	TLS_EXT_SESSIONTICKET = 35,	/* RFC 4507 session ticket support */
	TLS_EXT_LAST
	} TLS_EXT_TYPE;

/* SSL and TLS major and minor version numbers */

#define SSL_MAJOR_VERSION		3
#define SSL_MINOR_VERSION_SSL	0
#define SSL_MINOR_VERSION_TLS	1
#define SSL_MINOR_VERSION_TLS11	2
#define SSL_MINOR_VERSION_TLS12	3

/* SSL sender label values for the finished message MAC */

#define SSL_SENDER_CLIENTLABEL	"CLNT"
#define SSL_SENDER_SERVERLABEL	"SRVR"
#define SSL_SENDERLABEL_SIZE	4

/* SSL cipher suite information, used to map the SSL/TLS suite ID to 
   cryptlib algorithms and key/block sizes */

#define CIPHERSUITE_FLAG_NONE	0x00
#define CIPHERSUITE_FLAG_PSK	0x01	/* TLS-PSK suite */
#define CIPHERSUITE_FLAG_DH		0x02	/* DH suite */
#define CIPHERSUITE_FLAG_ECC	0x06	/* ECC suite (also a DH suite) */
#define CIPHERSUITE_FLAG_MAX	0x07	/* Maximum possible flag value */

typedef struct {
	/* The SSL/TLS cipher suite */
	const int cipherSuite;

	/* cryptlib algorithms for the cipher suite */
	const CRYPT_ALGO_TYPE keyexAlgo, authAlgo, cryptAlgo, macAlgo;

	/* Auxiliary information for the suite */
	const int cryptKeySize, macBlockSize;
	const int flags;
	} CIPHERSUITE_INFO;

/****************************************************************************
*																			*
*								SSL Structures								*
*																			*
****************************************************************************/

/* SSL handshake state information.  This is passed around various
   subfunctions that handle individual parts of the handshake */

typedef struct SL {
	/* Client and server proto-HMAC/dual-hash contexts */
	CRYPT_CONTEXT clientMD5context, clientSHA1context;
	CRYPT_CONTEXT serverMD5context, serverSHA1context;

	/* Client and server nonces and session ID */
	BUFFER_FIXED( SSL_NONCE_SIZE ) \
	BYTE clientNonce[ SSL_NONCE_SIZE + 8 ];
	BUFFER_FIXED( SSL_NONCE_SIZE ) \
	BYTE serverNonce[ SSL_NONCE_SIZE + 8 ];
	BUFFER( MAX_SESSIONID_SIZE, sessionIDlength ) \
	BYTE sessionID[ MAX_SESSIONID_SIZE + 8 ];
	int sessionIDlength;

	/* Premaster/master secret */
	BUFFER( CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE, premasterSecretSize ) \
	BYTE premasterSecret[ CRYPT_MAX_PKCSIZE + CRYPT_MAX_TEXTSIZE + 8 ];
	int premasterSecretSize;

	/* Encryption/security information */
	CRYPT_CONTEXT dhContext;	/* DH ctx.if DHE is being used */
	int cipherSuite;			/* Selected cipher suite */
	CRYPT_ALGO_TYPE keyexAlgo, authAlgo;/* Selected cipher suite algos */
	int cryptKeysize;			/* Size of session key */

	/* Other information */
	int clientOfferedVersion;	/* Prot.vers.originally offered by client */
#if 0	/* 28/01/08 Disabled since it's now finally removed in MSIE and 
		   Firefox */
	BOOLEAN isSSLv2;			/* Client hello is SSLv2 */
#endif /* 0 */
	BOOLEAN hasExtensions;		/* Hello has TLS extensions */

	/* ECC-related information.  Since ECC algorithms have a huge pile of
	   parameters we need to parse any extensions that the client sends in 
	   order to locate any additional information required to handle them.  
	   In the worst case these can retroactively modify the already-
	   negotiated cipher suites, disabling the use of ECC algorithms after 
	   they were agreed on via cipher suites.  To handle this we remember
	   both the preferred mainstream suite and a pointer to the preferred
	   ECC suite in 'eccSuiteInfoPtr', if it later turns out that the use
	   of ECC is OK we reset the crypto parameters using the save ECC suite
	   pointer.
	   
	   If the use of ECC isn't retroactively disabled then the eccCurveID 
	   and sendECCPointExtn values indicate which curve to use and whether 
	   the server needs to respond with a point-extension indicator */
	BOOLEAN disableECC;			/* Extn.disabled use of ECC suites */
	int eccCurveID;				/* cryptlib ID of ECC curve to use */
	BOOLEAN sendECCPointExtn;	/* Whether svr.has to respond with ECC point ext.*/
	const void *eccSuiteInfoPtr;	/* ECC suite information */

	/* The packet data stream.  Since SSL can encapsulate multiple handshake
	   packets within a single SSL packet, the stream has to be persistent
	   across the different handshake functions to allow the continuation of
	   packets */
	STREAM stream;				/* Packet data stream */

	/* Function pointers to handshaking functions.  These are set up as 
	   required depending on whether the session is client or server */
	CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
	int ( *beginHandshake )( INOUT SESSION_INFO *sessionInfoPtr,
							 struct SL *handshakeInfo );
	CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
	int ( *exchangeKeys )( INOUT SESSION_INFO *sessionInfoPtr,
						   struct SL *handshakeInfo );
	} SSL_HANDSHAKE_INFO;

/****************************************************************************
*																			*
*								SSL Functions								*
*																			*
****************************************************************************/

/* Prototypes for functions in ssl.c */

CHECK_RETVAL_LENGTH STDC_NONNULL_ARG( ( 1 ) ) \
int readUint24( INOUT STREAM *stream );
STDC_NONNULL_ARG( ( 1 ) ) \
int writeUint24( INOUT STREAM *stream, IN_LENGTH const int length );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int readSSLCertChain( INOUT SESSION_INFO *sessionInfoPtr, 
					  INOUT SSL_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT STREAM *stream,
					  OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertChain, 
					  const BOOLEAN isServer );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeSSLCertChain( INOUT SESSION_INFO *sessionInfoPtr, 
					   INOUT STREAM *stream );

/* Prototypes for functions in ssl_hs.c/ssl_hsc.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int processHelloSSL( INOUT SESSION_INFO *sessionInfoPtr, 
					 INOUT SSL_HANDSHAKE_INFO *handshakeInfo, 
					 INOUT STREAM *stream, const BOOLEAN isServer );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int completeHandshakeSSL( INOUT SESSION_INFO *sessionInfoPtr,
						  INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						  const BOOLEAN isClient,
						  const BOOLEAN isResumedSession );

/* Prototypes for functions in ssl_rd.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processVersionInfo( INOUT SESSION_INFO *sessionInfoPtr, 
						INOUT STREAM *stream, 
						OUT_OPT_INT_Z int *clientVersion );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkPacketHeaderSSL( INOUT SESSION_INFO *sessionInfoPtr, 
						  INOUT STREAM *stream, 
						  OUT_LENGTH_Z int *packetLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkHSPacketHeader( INOUT SESSION_INFO *sessionInfoPtr, 
						 INOUT STREAM *stream, 
						 OUT_LENGTH_Z int *packetLength, 
						 IN_RANGE( SSL_HAND_FIRST, \
								   SSL_HAND_LAST ) const int packetType, 
						 IN_LENGTH_SHORT_Z const int minSize );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int unwrapPacketSSL( INOUT SESSION_INFO *sessionInfoPtr, 
					 INOUT_BUFFER( dataMaxLength, \
								   *dataLength ) void *data, 
					 IN_LENGTH const int dataMaxLength, 
					 OUT_LENGTH_Z int *dataLength,
					 IN_RANGE( SSL_HAND_FIRST, \
							   SSL_HAND_LAST ) const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int readHSPacketSSL( INOUT SESSION_INFO *sessionInfoPtr,
					 INOUT_OPT SSL_HANDSHAKE_INFO *handshakeInfo, 
					 OUT_LENGTH_Z int *packetLength, 
					 IN_RANGE( SSL_HAND_FIRST, \
							   SSL_MSG_LAST_SPECIAL ) const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int refreshHSStream( INOUT SESSION_INFO *sessionInfoPtr, 
					 INOUT SSL_HANDSHAKE_INFO *handshakeInfo );

/* Prototypes for functions in ssl_wr.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int wrapPacketSSL( INOUT SESSION_INFO *sessionInfoPtr, 
				   INOUT STREAM *stream, 
				   IN_LENGTH_Z const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int sendPacketSSL( INOUT SESSION_INFO *sessionInfoPtr, 
				   INOUT STREAM *stream, const BOOLEAN sendOnly );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int openPacketStreamSSL( INOUT STREAM *stream, 
						 const SESSION_INFO *sessionInfoPtr, 
						 IN_LENGTH_OPT const int bufferSize, 
						 IN_RANGE( SSL_HAND_FIRST, \
								   SSL_HAND_LAST ) const int packetType );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int continuePacketStreamSSL( INOUT STREAM *stream, 
							 const SESSION_INFO *sessionInfoPtr, 
							 IN_RANGE( SSL_HAND_FIRST, \
									   SSL_HAND_LAST ) const int packetType,
							 OUT_LENGTH_SHORT_Z int *packetOffset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int completePacketStreamSSL( INOUT STREAM *stream, 
							 IN_LENGTH_Z const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int continueHSPacketStream( INOUT STREAM *stream, 
							IN_RANGE( SSL_HAND_FIRST, \
									  SSL_HAND_LAST ) const int packetType,
							OUT_LENGTH_SHORT_Z int *packetOffset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int completeHSPacketStream( INOUT STREAM *stream, 
							IN_LENGTH const int offset );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int processAlert( INOUT SESSION_INFO *sessionInfoPtr, 
				  IN_BUFFER( headerLength ) const void *header, 
				  IN_LENGTH const int headerLength );
STDC_NONNULL_ARG( ( 1 ) ) \
void sendCloseAlert( INOUT SESSION_INFO *sessionInfoPtr, 
					 const BOOLEAN alertReceived );
STDC_NONNULL_ARG( ( 1 ) ) \
void sendHandshakeFailAlert( INOUT SESSION_INFO *sessionInfoPtr );

/* Prototypes for functions in ssl_keymgmt.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initSecurityContextsSSL( INOUT SESSION_INFO *sessionInfoPtr );
STDC_NONNULL_ARG( ( 1 ) ) \
void destroySecurityContextsSSL( INOUT SESSION_INFO *sessionInfoPtr );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initHandshakeCryptInfo( INOUT SSL_HANDSHAKE_INFO *handshakeInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void destroyHandshakeCryptInfo( INOUT SSL_HANDSHAKE_INFO *handshakeInfo );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initDHcontextSSL( OUT_HANDLE_OPT CRYPT_CONTEXT *iCryptContext, 
					  IN_BUFFER_OPT( keyDataLength ) const void *keyData, 
					  IN_LENGTH_SHORT_Z const int keyDataLength,
					  IN_HANDLE_OPT const CRYPT_CONTEXT iServerKeyTemplate,
					  IN_ENUM_OPT( CRYPT_ECCCURVE ) \
							const CRYPT_ECCCURVE_TYPE eccParams );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int createSharedPremasterSecret( OUT_BUFFER( premasterSecretMaxLength, \
											 *premasterSecretLength ) \
									void *premasterSecret, 
								 IN_LENGTH_SHORT \
									const int premasterSecretMaxLength, 
								 OUT_LENGTH_SHORT_Z int *premasterSecretLength,
								 IN_BUFFER( sharedSecretLength ) \
									const void *sharedSecret, 
								 IN_LENGTH_SHORT const int sharedSecretLength,
								 const BOOLEAN isEncodedValue );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int wrapPremasterSecret( INOUT SESSION_INFO *sessionInfoPtr,
						 INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						 OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
						 IN_LENGTH_SHORT const int dataMaxLength, 
						 OUT_LENGTH_SHORT_Z int *dataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int unwrapPremasterSecret( INOUT SESSION_INFO *sessionInfoPtr, 
						   INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						   IN_BUFFER( dataLength ) const void *data, 
						   IN_LENGTH_SHORT const int dataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int premasterToMaster( const SESSION_INFO *sessionInfoPtr, 
					   const SSL_HANDSHAKE_INFO *handshakeInfo, 
					   OUT_BUFFER_FIXED( masterSecretLength ) void *masterSecret, 
					   IN_LENGTH_SHORT const int masterSecretLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) ) \
int masterToKeys( const SESSION_INFO *sessionInfoPtr, 
				  const SSL_HANDSHAKE_INFO *handshakeInfo, 
				  IN_BUFFER( masterSecretLength ) const void *masterSecret, 
				  IN_LENGTH_SHORT const int masterSecretLength,
				  OUT_BUFFER_FIXED( keyBlockLength ) void *keyBlock, 
				  IN_LENGTH_SHORT const int keyBlockLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int loadKeys( INOUT SESSION_INFO *sessionInfoPtr,
			  const SSL_HANDSHAKE_INFO *handshakeInfo,
			  IN_BUFFER( keyBlockLength ) const void *keyBlock, 
			  IN_LENGTH_SHORT_MIN( 16 ) const int keyBlockLength,
			  const BOOLEAN isClient );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int loadExplicitIV( INOUT SESSION_INFO *sessionInfoPtr, 
					INOUT STREAM *stream, 
					OUT_INT_SHORT_Z int *ivLength );

/* Prototypes for functions in ssl_cry.c */

CHECK_RETVAL \
int getCipherSuiteInfo( OUT const CIPHERSUITE_INFO **cipherSuiteInfo,
						OUT_INT_Z int *noSuiteEntries );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int encryptData( const SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER( dataMaxLength, *dataLength ) \
					BYTE *data, 
				 IN_LENGTH const int dataMaxLength,
				 OUT_LENGTH_Z int *dataLength,
				 IN_LENGTH const int payloadLength );
				 /* This one's a bit tricky, the input is 
				    { data, payloadLength } which is padded (if necessary) 
					and the padded length returned in '*dataLength' */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int decryptData( SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER_FIXED( dataLength ) \
					BYTE *data, 
				 IN_LENGTH const int dataLength, 
				 OUT_LENGTH_Z int *processedDataLength );
				/* This one's also tricky, the entire data block will be 
				   processed but only 'processedDataLength' bytes of result 
				   are valid output */
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacSSL( INOUT SESSION_INFO *sessionInfoPtr, 
				  INOUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
				  IN_LENGTH const int dataMaxLength, 
				  OUT_LENGTH_Z int *dataLength,
				  IN_LENGTH const int payloadLength, 
				  IN_RANGE( 0, 255 ) const int type );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int createMacTLS( INOUT SESSION_INFO *sessionInfoPtr, 
				  OUT_BUFFER( dataMaxLength, *dataLength ) void *data, 
				  IN_LENGTH const int dataMaxLength, 
				  OUT_LENGTH_Z int *dataLength,
				  IN_LENGTH const int payloadLength, 
				  IN_RANGE( 0, 255 ) const int type );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacSSL( INOUT SESSION_INFO *sessionInfoPtr, 
				 IN_BUFFER( dataLength ) const void *data, 
				 IN_LENGTH const int dataLength, 
				 IN_LENGTH_Z const int payloadLength, 
				 IN_RANGE( 0, 255 ) const int type, 
				 const BOOLEAN noReportError );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkMacTLS( INOUT SESSION_INFO *sessionInfoPtr, 
				 IN_BUFFER( dataLength ) const void *data, 
				 IN_LENGTH const int dataLength, 
				 IN_LENGTH_Z const int payloadLength, 
				 IN_RANGE( 0, 255 ) const int type, 
				 const BOOLEAN noReportError );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int dualMacDataRead( const SSL_HANDSHAKE_INFO *handshakeInfo, 
					 INOUT STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int dualMacDataWrite( const SSL_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 6, 8 ) ) \
int completeSSLDualMAC( IN_HANDLE const CRYPT_CONTEXT md5context,
						IN_HANDLE const CRYPT_CONTEXT sha1context, 
						OUT_BUFFER( hashValuesMaxLen, *hashValuesLen )
							BYTE *hashValues, 
						IN_LENGTH_SHORT_MIN( MD5MAC_SIZE + SHA1MAC_SIZE ) \
							const int hashValuesMaxLen,
						OUT_LENGTH_SHORT_Z int *hashValuesLen,
						IN_BUFFER( labelLength ) const char *label, 
						IN_RANGE( 1, 64 ) const int labelLength, 
						IN_BUFFER( masterSecretLen ) const BYTE *masterSecret, 
						IN_LENGTH_SHORT const int masterSecretLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 3, 5, 6, 8 ) ) \
int completeTLSHashedMAC( IN_HANDLE const CRYPT_CONTEXT md5context,
						  IN_HANDLE const CRYPT_CONTEXT sha1context, 
						  OUT_BUFFER( hashValuesMaxLen, *hashValuesLen )
								BYTE *hashValues, 
						  IN_LENGTH_SHORT_MIN( TLS_HASHEDMAC_SIZE ) \
								const int hashValuesMaxLen,
						  OUT_LENGTH_SHORT_Z int *hashValuesLen,
						  IN_BUFFER( labelLength ) const char *label, 
						  IN_RANGE( 1, 64 ) const int labelLength, 
						  IN_BUFFER( masterSecretLen ) const BYTE *masterSecret, 
						  IN_LENGTH_SHORT const int masterSecretLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int createCertVerify( const SESSION_INFO *sessionInfoPtr,
					  const SSL_HANDSHAKE_INFO *handshakeInfo,
					  INOUT STREAM *stream );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int checkCertVerify( const SESSION_INFO *sessionInfoPtr,
					 const SSL_HANDSHAKE_INFO *handshakeInfo,
					 INOUT STREAM *stream, 
					 IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
						const int sigLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int createKeyexSignature( INOUT SESSION_INFO *sessionInfoPtr, 
						  INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						  INOUT STREAM *stream, 
						  IN_BUFFER( keyDataLength ) const void *keyData, 
						  IN_LENGTH_SHORT const int keyDataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
int checkKeyexSignature( INOUT SESSION_INFO *sessionInfoPtr, 
						 INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						 INOUT STREAM *stream, 
						 IN_BUFFER( keyDataLength ) const void *keyData, 
						 IN_LENGTH_SHORT const int keyDataLength,
						 const BOOLEAN isECC );

/* Prototypes for session mapping functions */

STDC_NONNULL_ARG( ( 1 ) ) \
void initSSLclientProcessing( INOUT SSL_HANDSHAKE_INFO *handshakeInfo );
STDC_NONNULL_ARG( ( 1 ) ) \
void initSSLserverProcessing( SSL_HANDSHAKE_INFO *handshakeInfo );

#endif /* _SSL_DEFINED */
