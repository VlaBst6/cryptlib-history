/****************************************************************************
*																			*
*						SSL v3/TLS Definitions Header File					*
*						Copyright Peter Gutmann 1998-2008					*
*																			*
****************************************************************************/

#ifndef _SSL_DEFINED

#define _SSL_DEFINED

/* Default SSL port */

#define SSL_PORT					443

/* SSL constants */

#define ID_SIZE						1	/* ID byte */
#define UINT16_SIZE					2	/* 16 bits */
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
   specially in that both the version number info is taken from this packet,
   and the packet itself may have to be treated specially because although
   the client handshake is supposed to be a v3 handshake, the first 
   handshake packet is often a hacked v2 one with forwards-compatibility 
   kludges */

#define SSL_MSG_FIRST_HANDSHAKE		0xFF
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

	SSL_LAST 
	} SSL_CIPHERSUITE_TYPE;

/* TLS extension types */

typedef enum {
	TLS_EXT_SERVER_NAME,		/* Name of virtual server to contact */
	TLS_EXT_MAX_FRAGMENT_LENTH,	/* Max.fragment length if smaller than 2^14 bytes */
	TLS_EXT_CLIENT_CERTIFICATE_URL,	/* Location for server to find client cert */
	TLS_EXT_TRUSTED_CA_KEYS,	/* Indication of which CAs clients trust */
	TLS_EXT_TRUNCATED_HMAC,		/* Use 80-bit truncated HMAC */
	TLS_EXT_STATUS_REQUEST,		/* OCSP status request from server */
	TLS_EXT_USER_MAPPING,		/* RFC 4681 mapping of user name to account */
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

	/* Encryption/security info */
	CRYPT_CONTEXT dhContext;	/* DH ctx.if DHE is being used */
	int cipherSuite;			/* Selected cipher suite */
	CRYPT_ALGO_TYPE keyexAlgo, authAlgo;/* Selected cipher suite algos */
	int cryptKeysize;			/* Size of session key */
	BOOLEAN serverSigKey;		/* Server sig.key can auth.DH exchange */

	/* Other info */
	int clientOfferedVersion;	/* Prot.vers.originally offered by client */
#if 0	/* 28/01/08 Disabled since it's now finally removed in MSIE and 
		   Firefox */
	BOOLEAN isSSLv2;			/* Client hello is SSLv2 */
#endif /* 0 */
	BOOLEAN hasExtensions;		/* Hello has TLS extensions */

	/* The packet data stream.  Since SSL can encapsulate multiple handshake
	   packets within a single SSL packet, the stream has to be persistent
	   across the different handshake functions to allow the continuation of
	   packets */
	STREAM stream;				/* Packet data stream */

	/* Function pointers to handshaking functions.  These are set up as 
	   required depending on whether the session is client or server */
	CHECK_RETVAL \
	int ( *beginHandshake )( INOUT SESSION_INFO *sessionInfoPtr,
							 struct SL *handshakeInfo ) \
							 STDC_NONNULL_ARG( ( 1, 2 ) );
	CHECK_RETVAL \
	int ( *exchangeKeys )( INOUT SESSION_INFO *sessionInfoPtr,
						   struct SL *handshakeInfo ) \
						   STDC_NONNULL_ARG( ( 1, 2 ) );
	} SSL_HANDSHAKE_INFO;

/* Prototypes for functions in ssl.c */

CHECK_RETVAL \
int readUint24( INOUT STREAM *stream ) \
				STDC_NONNULL_ARG( ( 1 ) );
int writeUint24( INOUT STREAM *stream, const int length ) \
				 STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL \
int processHelloSSL( INOUT SESSION_INFO *sessionInfoPtr, 
					 INOUT SSL_HANDSHAKE_INFO *handshakeInfo, 
					 INOUT STREAM *stream, const BOOLEAN isServer ) \
					 STDC_NONNULL_ARG( ( 1, 2, 3 ) );
CHECK_RETVAL \
int readSSLCertChain( INOUT SESSION_INFO *sessionInfoPtr, 
					  INOUT SSL_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT STREAM *stream,
					  OUT CRYPT_CERTIFICATE *iCertChain, 
					  const BOOLEAN isServer ) \
					  STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) );
CHECK_RETVAL \
int writeSSLCertChain( INOUT SESSION_INFO *sessionInfoPtr, 
					   INOUT STREAM *stream ) \
					   STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int checkPacketHeaderSSL( INOUT SESSION_INFO *sessionInfoPtr, 
						  INOUT STREAM *stream, OUT int *packetLength ) \
						  STDC_NONNULL_ARG( ( 1, 2, 3 ) );
CHECK_RETVAL \
int checkHSPacketHeader( INOUT SESSION_INFO *sessionInfoPtr, 
						 INOUT STREAM *stream, OUT int *packetLength, 
						 const int packetType, const int minSize ) \
						 STDC_NONNULL_ARG( ( 1, 2, 3 ) );
CHECK_RETVAL \
int processVersionInfo( INOUT SESSION_INFO *sessionInfoPtr, 
						INOUT STREAM *stream, OUT_OPT int *clientVersion ) \
						STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int processCipherSuite( INOUT SESSION_INFO *sessionInfoPtr, 
						INOUT SSL_HANDSHAKE_INFO *handshakeInfo, 
						INOUT STREAM *stream, const int noSuites ) \
						STDC_NONNULL_ARG( ( 1, 2, 3 ) );

/* Prototypes for functions in ssl_rw.c */

CHECK_RETVAL \
int unwrapPacketSSL( INOUT SESSION_INFO *sessionInfoPtr, 
					 INOUT_BUFFER( dataMaxLength, *dataLength ) \
					 void *data, const int dataMaxLength, int *dataLength,
					 const int packetType ) \
					 STDC_NONNULL_ARG( ( 1, 2, 4 ) );
CHECK_RETVAL \
int readHSPacketSSL( INOUT SESSION_INFO *sessionInfoPtr,
					 INOUT_OPT SSL_HANDSHAKE_INFO *handshakeInfo, 
					 OUT int *packetLength, const int packetType ) \
					 STDC_NONNULL_ARG( ( 1, 3 ) );
CHECK_RETVAL \
int refreshHSStream( INOUT SESSION_INFO *sessionInfoPtr, 
					 INOUT SSL_HANDSHAKE_INFO *handshakeInfo ) \
					 STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int wrapPacketSSL( INOUT SESSION_INFO *sessionInfoPtr, INOUT STREAM *stream, 
				   const int offset ) \
				   STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int sendPacketSSL( INOUT SESSION_INFO *sessionInfoPtr, INOUT STREAM *stream, 
				   const BOOLEAN sendOnly ) \
				   STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int openPacketStreamSSL( INOUT STREAM *stream, 
						 const SESSION_INFO *sessionInfoPtr, 
						 const int bufferSize, const int packetType ) \
						 STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int continuePacketStreamSSL( INOUT STREAM *stream, 
							 const SESSION_INFO *sessionInfoPtr, 
							 const int packetType ) \
							 STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int completePacketStreamSSL( INOUT STREAM *stream, const int offset ) \
							 STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL \
int continueHSPacketStream( INOUT STREAM *stream, const int packetType ) \
							STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL \
int completeHSPacketStream( INOUT STREAM *stream, const int offset ) \
							STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL \
int processAlert( INOUT SESSION_INFO *sessionInfoPtr, 
				  IN_BUFFER( headerLength ) \
				  const void *header, const int headerLength ) \
				  STDC_NONNULL_ARG( ( 1, 2 ) );
void sendCloseAlert( INOUT SESSION_INFO *sessionInfoPtr, 
					 const BOOLEAN alertReceived ) \
					 STDC_NONNULL_ARG( ( 1 ) );
void sendHandshakeFailAlert( INOUT SESSION_INFO *sessionInfoPtr ) \
							 STDC_NONNULL_ARG( ( 1 ) );

/* Prototypes for functions in ssl_keymgmt.c */

CHECK_RETVAL \
int initSecurityContextsSSL( INOUT SESSION_INFO *sessionInfoPtr ) \
							 STDC_NONNULL_ARG( ( 1 ) );
void destroySecurityContextsSSL( INOUT SESSION_INFO *sessionInfoPtr ) \
								 STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL \
int initHandshakeCryptInfo( INOUT SSL_HANDSHAKE_INFO *handshakeInfo ) \
							STDC_NONNULL_ARG( ( 1 ) );
void destroyHandshakeCryptInfo( INOUT SSL_HANDSHAKE_INFO *handshakeInfo ) \
							    STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL \
int initDHcontextSSL( OUT CRYPT_CONTEXT *iCryptContext, 
					  IN_BUFFER_OPT( keyDataLength ) \
					  const void *keyData, const int keyDataLength,
					  const CRYPT_CONTEXT iServerKeyTemplate ) \
					  STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL \
int createSharedPremasterSecret( OUT_BUFFER( premasterSecretMaxLength, *premasterSecretLength ) \
								 void *premasterSecret, 
								 const int premasterSecretMaxLength, 
								 int *premasterSecretLength,
								 const ATTRIBUTE_LIST *attributeListPtr ) \
								 STDC_NONNULL_ARG( ( 1, 3, 4 ) );
CHECK_RETVAL \
int wrapPremasterSecret( INOUT SESSION_INFO *sessionInfoPtr,
						 INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						 OUT_BUFFER( dataMaxLength, *dataLength ) \
						 void *data, const int dataMaxLength, 
						 int *dataLength ) \
						 STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) );
CHECK_RETVAL \
int unwrapPremasterSecret( INOUT SESSION_INFO *sessionInfoPtr, 
						   INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						   IN_BUFFER( dataLength ) \
						   const void *data, const int dataLength ) \
						   STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int premasterToMaster( const SESSION_INFO *sessionInfoPtr, 
					   const SSL_HANDSHAKE_INFO *handshakeInfo, 
					   OUT_BUFFER_FIXED( masterSecretLength ) \
					   void *masterSecret, const int masterSecretLength ) \
					   STDC_NONNULL_ARG( ( 1, 2, 3 ) );
CHECK_RETVAL \
int masterToKeys( const SESSION_INFO *sessionInfoPtr, 
				  const SSL_HANDSHAKE_INFO *handshakeInfo, 
				  IN_BUFFER( masterSecretLength ) \
				  const void *masterSecret, const int masterSecretLength,
				  OUT_BUFFER_FIXED( keyBlockLength ) \
				  void *keyBlock, const int keyBlockLength ) \
				  STDC_NONNULL_ARG( ( 1, 2, 3, 5 ) );
CHECK_RETVAL \
int loadKeys( INOUT SESSION_INFO *sessionInfoPtr,
			  const SSL_HANDSHAKE_INFO *handshakeInfo,
			  IN_BUFFER( keyBlockLength ) \
			  const void *keyBlock, const int keyBlockLength,
			  const BOOLEAN isClient ) \
			  STDC_NONNULL_ARG( ( 1, 2, 3 ) );
CHECK_RETVAL \
int loadExplicitIV( INOUT SESSION_INFO *sessionInfoPtr, 
					INOUT STREAM *stream, OUT int *ivLength ) \
					STDC_NONNULL_ARG( ( 1, 2, 3 ) );

/* Prototypes for functions in ssl_cry.c */

CHECK_RETVAL \
int encryptData( const SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER( dataMaxLength, *dataLength ) \
				 BYTE *data, const int dataMaxLength,
				 int *dataLength,
				 const int payloadLength ) \
				 STDC_NONNULL_ARG( ( 1, 2, 4 ) );
				 /* This one's a bit tricky, the input is 
				    { data, payloadLength } which is padded (if necessary) 
					and the padded length returned in 'dataLength' */
CHECK_RETVAL \
int decryptData( SESSION_INFO *sessionInfoPtr, 
				 INOUT_BUFFER_FIXED( dataLength ) \
				 BYTE *data, const int dataLength, 
				 OUT int *processedDataLength ) \
				 STDC_NONNULL_ARG( ( 1, 2, 4 ) );
				/* This one's also tricky, the entire data block will be 
				   processed but only 'processedDataLength' bytes of result 
				   are valid output */
CHECK_RETVAL \
int dualMacDataRead( const SSL_HANDSHAKE_INFO *handshakeInfo, 
					 INOUT STREAM *stream ) \
					 STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int dualMacDataWrite( const SSL_HANDSHAKE_INFO *handshakeInfo, 
					  INOUT STREAM *stream ) \
					  STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int completeSSLDualMAC( const CRYPT_CONTEXT md5context,
						const CRYPT_CONTEXT sha1context, 
						OUT_BUFFER( hashValuesMaxLen, *hashValuesLen )
						BYTE *hashValues, const int hashValuesMaxLen,
						int *hashValuesLen,
						IN_BUFFER( labelLength ) \
						const char *label, const int labelLength, 
						IN_BUFFER( masterSecretLen ) \
						const BYTE *masterSecret, const int masterSecretLen ) \
						STDC_NONNULL_ARG( ( 3, 5, 6, 8 ) );
CHECK_RETVAL \
int completeTLSHashedMAC( const CRYPT_CONTEXT md5context,
						  const CRYPT_CONTEXT sha1context, 
						  OUT_BUFFER( hashValuesMaxLen, *hashValuesLen )
						  BYTE *hashValues, const int hashValuesMaxLen,
						  int *hashValuesLen,
						  IN_BUFFER( labelLength ) \
						  const char *label, const int labelLength, 
						  IN_BUFFER( masterSecretLen ) \
						  const BYTE *masterSecret, const int masterSecretLen ) \
						  STDC_NONNULL_ARG( ( 3, 5, 6, 8 ) );
CHECK_RETVAL \
int createMacSSL( INOUT SESSION_INFO *sessionInfoPtr, 
				  OUT_BUFFER( dataMaxLength, *dataLength ) \
				  void *data, const int dataMaxLength, int *dataLength,
				  const int payloadLength, const int type ) \
				  STDC_NONNULL_ARG( ( 1, 2, 4 ) );
CHECK_RETVAL \
int createMacTLS( INOUT SESSION_INFO *sessionInfoPtr, 
				  OUT_BUFFER( dataMaxLength, *dataLength ) \
				  void *data, const int dataMaxLength, int *dataLength,
				  const int payloadLength, const int type ) \
				  STDC_NONNULL_ARG( ( 1, 2, 4 ) );
CHECK_RETVAL \
int checkMacSSL( INOUT SESSION_INFO *sessionInfoPtr, 
				 IN_BUFFER( dataLength ) \
				 const void *data, const int dataLength, 
				 const int payloadLength, const int type, 
				 const BOOLEAN noReportError ) \
				 STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int checkMacTLS( INOUT SESSION_INFO *sessionInfoPtr, 
				 IN_BUFFER( dataLength ) \
				 const void *data, const int dataLength, 
				 const int payloadLength, const int type, 
				 const BOOLEAN noReportError ) \
				 STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL \
int createCertVerify( const SESSION_INFO *sessionInfoPtr,
					  const SSL_HANDSHAKE_INFO *handshakeInfo,
					  INOUT STREAM *stream ) \
					  STDC_NONNULL_ARG( ( 1, 2, 3 ) );
CHECK_RETVAL \
int checkCertVerify( const SESSION_INFO *sessionInfoPtr,
					 const SSL_HANDSHAKE_INFO *handshakeInfo,
					 INOUT STREAM *stream, const int sigLength ) \
					 STDC_NONNULL_ARG( ( 1, 2, 3 ) );
CHECK_RETVAL \
int createKeyexSignature( INOUT SESSION_INFO *sessionInfoPtr, 
						  INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						  INOUT STREAM *stream, 
						  IN_BUFFER( keyDataLength ) \
						  const void *keyData, const int keyDataLength ) \
						  STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) );
CHECK_RETVAL \
int checkKeyexSignature( INOUT SESSION_INFO *sessionInfoPtr, 
						 INOUT SSL_HANDSHAKE_INFO *handshakeInfo,
						 INOUT STREAM *stream, 
						 IN_BUFFER( keyDataLength ) \
						 const void *keyData, const int keyDataLength ) \
						 STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) );

/* Prototypes for session mapping functions */

void initSSLclientProcessing( SSL_HANDSHAKE_INFO *handshakeInfo ) \
							  STDC_NONNULL_ARG( ( 1 ) );
void initSSLserverProcessing( SSL_HANDSHAKE_INFO *handshakeInfo ) \
							  STDC_NONNULL_ARG( ( 1 ) );

#endif /* _SSL_DEFINED */
