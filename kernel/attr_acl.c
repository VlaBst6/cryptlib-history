/****************************************************************************
*																			*
*							Object Attribute ACLs							*
*						Copyright Peter Gutmann 1997-2005					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "acl.h"
  #include "kernel.h"
#else
  #include "crypt.h"
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */

/* Common object ACLs for various object types */

static const OBJECT_ACL FAR_BSS objectCtxConv = {
		ST_CTX_CONV, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL FAR_BSS objectCtxPKC = {
		ST_CTX_PKC, ST_NONE, ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CTX };
static const OBJECT_ACL FAR_BSS objectCtxHash = {
		ST_CTX_HASH, ST_NONE, ACL_FLAG_HIGH_STATE };

static const OBJECT_ACL FAR_BSS objectCertificate = {
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACL_FLAG_HIGH_STATE | ACL_FLAG_ROUTE_TO_CERT };
static const OBJECT_ACL FAR_BSS objectCertificateTemplate = {
		ST_CERT_CERT, ST_NONE, ACL_FLAG_ANY_STATE };		/* Template for cert.attrs */
static const OBJECT_ACL FAR_BSS objectCertRequest = {
		ST_CERT_CERTREQ | ST_CERT_REQ_CERT, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL FAR_BSS objectCertRevRequest = {
		ST_CERT_REQ_REV, ST_NONE, ACL_FLAG_ANY_STATE };		/* Unsigned obj.*/
static const OBJECT_ACL FAR_BSS objectCertSessionRTCSRequest = {
		ST_CERT_RTCS_REQ, ST_NONE, ACL_FLAG_ANY_STATE };	/* Unsigned obj.*/
static const OBJECT_ACL FAR_BSS objectCertSessionOCSPRequest = {
		ST_CERT_OCSP_REQ, ST_NONE, ACL_FLAG_ANY_STATE };	/* Unsigned obj.*/
static const OBJECT_ACL FAR_BSS objectCertSessionCMPRequest = {
		ST_CERT_CERTREQ | ST_CERT_REQ_CERT | ST_CERT_REQ_REV, ST_NONE, ACL_FLAG_ANY_STATE };
static const OBJECT_ACL FAR_BSS objectCertSessionUnsignedPKCS10Request = {
		ST_CERT_CERTREQ, ST_NONE, ACL_FLAG_LOW_STATE };
static const OBJECT_ACL FAR_BSS objectCertRTCSRequest = {
		ST_CERT_RTCS_REQ, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL FAR_BSS objectCertRTCSResponse = {
		ST_CERT_RTCS_RESP, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL FAR_BSS objectCertOCSPRequest = {
		ST_CERT_OCSP_REQ, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL FAR_BSS objectCertOCSPResponse = {
		ST_CERT_OCSP_RESP, ST_NONE, ACL_FLAG_HIGH_STATE };
static const OBJECT_ACL FAR_BSS objectCertPKIUser = {
		ST_CERT_PKIUSER, ST_NONE, ACL_FLAG_HIGH_STATE };

static const OBJECT_ACL FAR_BSS objectCMSAttr = {
		ST_CERT_CMSATTR, ST_NONE, ACL_FLAG_ANY_STATE };

static const OBJECT_ACL FAR_BSS objectKeyset = {
		ST_KEYSET_ANY | ST_DEV_ANY_STD, ST_NONE, ACL_FLAG_NONE };
static const OBJECT_ACL FAR_BSS objectKeysetCerts = {
		ST_KEYSET_DBMS, ST_NONE, ACL_FLAG_NONE };
static const OBJECT_ACL FAR_BSS objectKeysetCertstore = {
		SUBTYPE_KEYSET_DBMS_STORE, ST_NONE, ACL_FLAG_NONE };
static const OBJECT_ACL FAR_BSS objectKeysetPrivate = {
		ST_KEYSET_FILE | ST_DEV_FORT | ST_DEV_P11, ST_NONE, ACL_FLAG_NONE };
static const OBJECT_ACL FAR_BSS objectKeysetConfigdata = {
		SUBTYPE_KEYSET_FILE, ST_NONE, ACL_FLAG_NONE };

static const OBJECT_ACL FAR_BSS objectDeenvelope = {
		ST_NONE, ST_ENV_DEENV, ACL_FLAG_HIGH_STATE };

static const OBJECT_ACL FAR_BSS objectSessionDataClient = {
		ST_NONE, ST_SESS_SSH | ST_SESS_SSL, ACL_FLAG_NONE };
static const OBJECT_ACL FAR_BSS objectSessionDataServer = {
		ST_NONE, ST_SESS_SSH_SVR | ST_SESS_SSL_SVR, ACL_FLAG_NONE };
static const OBJECT_ACL FAR_BSS objectSessionTSP = {
		ST_NONE, ST_SESS_TSP, ACL_FLAG_LOW_STATE };

/****************************************************************************
*																			*
*								Object/Property ACLs						*
*																			*
****************************************************************************/

static const RANGE_SUBRANGE_TYPE FAR_BSS allowedCertCursorSubranges[] = {
	{ CRYPT_CURSOR_FIRST, CRYPT_CURSOR_LAST },
	{ CRYPT_CERTINFO_FIRST_EXTENSION, CRYPT_CERTINFO_LAST_EXTENSION },
	{ CRYPT_ERROR, CRYPT_ERROR } };
static const RANGE_SUBRANGE_TYPE FAR_BSS allowedEnvCursorSubranges[] = {
	{ CRYPT_CURSOR_FIRST, CRYPT_CURSOR_LAST },
	{ CRYPT_ENVINFO_FIRST, CRYPT_ENVINFO_LAST },
	{ CRYPT_ERROR, CRYPT_ERROR } };
static const RANGE_SUBRANGE_TYPE FAR_BSS allowedSessionCursorSubranges[] = {
	{ CRYPT_CURSOR_FIRST, CRYPT_CURSOR_LAST },
	{ CRYPT_SESSINFO_FIRST, CRYPT_SESSINFO_LAST },
	{ CRYPT_ERROR, CRYPT_ERROR } };

static const ATTRIBUTE_ACL FAR_BSS subACL_AttributeCurrentGroup[] = {
	MKACL_EX(	/* Certs */
		CRYPT_ATTRIBUTE_CURRENT_GROUP, ATTRIBUTE_VALUE_NUMERIC,
		ST_CERT_ANY, ST_NONE, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_SUBRANGES, allowedCertCursorSubranges ),
	MKACL_EX(	/* Envelopes */
		CRYPT_ATTRIBUTE_CURRENT_GROUP, ATTRIBUTE_VALUE_NUMERIC,
		ST_NONE, ST_ENV_DEENV, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE_SUBRANGES, allowedEnvCursorSubranges ),
	MKACL_EX(	/* Sessions */
		CRYPT_ATTRIBUTE_CURRENT_GROUP, ATTRIBUTE_VALUE_NUMERIC,
		ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE_SUBRANGES, allowedSessionCursorSubranges ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_AttributeCurrent[] = {
	MKACL_EX(	/* Certs */
		CRYPT_ATTRIBUTE_CURRENT, ATTRIBUTE_VALUE_NUMERIC,
		ST_CERT_ANY, ST_NONE, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_SUBRANGES, allowedCertCursorSubranges ),
	MKACL_EX(	/* Envelopes */
		CRYPT_ATTRIBUTE_CURRENT, ATTRIBUTE_VALUE_NUMERIC,
		ST_NONE, ST_ENV_DEENV, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE_SUBRANGES, allowedEnvCursorSubranges ),
	MKACL_EX(	/* Sessions */
		CRYPT_ATTRIBUTE_CURRENT, ATTRIBUTE_VALUE_NUMERIC,
		ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE_SUBRANGES, allowedSessionCursorSubranges ),
	MKACL_END_SUBACL()
	};

/* Object properties */

static const ATTRIBUTE_ACL FAR_BSS propertyACL[] = {
	MKACL(		/* Owned+non-forwardable+locked */
		CRYPT_PROPERTY_HIGHSECURITY, ATTRIBUTE_VALUE_BOOLEAN,
		ST_ANY_A, ST_ANY_B, ACCESS_xWx_xWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( TRUE, TRUE ) ),
	MKACL_N_EX(	/* Object owner */
		CRYPT_PROPERTY_OWNER,
		ST_ANY_A, ST_ANY_B, ACCESS_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE_ANY ),
	MKACL_N_EX(	/* No.of times object can be forwarded */
		CRYPT_PROPERTY_FORWARDCOUNT,
		ST_ANY_A, ST_ANY_B, ACCESS_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( 1, 1000 ) ),
	MKACL(		/* Whether properties can be chged/read */
		CRYPT_PROPERTY_LOCKED, ATTRIBUTE_VALUE_BOOLEAN,
		ST_ANY_A, ST_ANY_B, ACCESS_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( TRUE, TRUE ) ),
	MKACL_N_EX(	/* Usage count before object expires */
		CRYPT_PROPERTY_USAGECOUNT,
		ST_ANY_A, ST_ANY_B, ACCESS_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( 1, 1000 ) ),
	MKACL(		/* Whether key is nonexp.from context */
		CRYPT_PROPERTY_NONEXPORTABLE, ATTRIBUTE_VALUE_BOOLEAN,
		ST_CTX_ANY, ST_NONE, ACCESS_xxx_xxx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( TRUE, TRUE ) ),

	MKACL_END()
	};

/* Generic attributes */

static const ATTRIBUTE_ACL FAR_BSS genericACL[] = {
	MKACL_N(	/* Type of last error */
		CRYPT_ATTRIBUTE_ERRORTYPE,
		ST_ANY_A, ST_ANY_B, ACCESS_Rxx_Rxx,
		ROUTE_NONE, RANGE( CRYPT_ERRTYPE_NONE, CRYPT_ERRTYPE_LAST - 1 ) ),
	MKACL_N(	/* Locus of last error */
		CRYPT_ATTRIBUTE_ERRORLOCUS,
		ST_ANY_A, ST_ANY_B, ACCESS_Rxx_Rxx,
		ROUTE_NONE, RANGE( CRYPT_ATTRIBUTE_NONE, CRYPT_ATTRIBUTE_LAST ) ),
	MKACL_N(	/* Low-level, software-specific */
		CRYPT_ATTRIBUTE_INT_ERRORCODE,
		ST_KEYSET_ANY | ST_DEV_ANY_STD, ST_SESS_ANY, ACCESS_Rxx_Rxx,
		ROUTE_ALT2( OBJECT_TYPE_DEVICE, OBJECT_TYPE_KEYSET, OBJECT_TYPE_SESSION ), RANGE_ANY ),
	MKACL_S(	/*   error code and message */
		CRYPT_ATTRIBUTE_INT_ERRORMESSAGE,
		ST_KEYSET_ANY | ST_DEV_ANY_STD, ST_SESS_ANY, ACCESS_Rxx_Rxx,
		ROUTE_ALT2( OBJECT_TYPE_DEVICE, OBJECT_TYPE_KEYSET, OBJECT_TYPE_SESSION ), RANGE( 0, 512 ) ),
	MKACL_X(	/* Cursor mgt: Group in attribute list */
/* In = cursor components, out = component type */
		CRYPT_ATTRIBUTE_CURRENT_GROUP,
		ST_CERT_ANY, ST_ENV_DEENV | ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_RWx_RWx,
		ROUTE_ALT2( OBJECT_TYPE_CERTIFICATE, OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ),
		subACL_AttributeCurrentGroup ),
	MKACL_X(	/* Cursor mgt: Entry in attribute list */
/* In = cursor components, out = component type */
		CRYPT_ATTRIBUTE_CURRENT,
		ST_CERT_ANY, ST_ENV_DEENV | ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_RWx_RWx,
		ROUTE_ALT2( OBJECT_TYPE_CERTIFICATE, OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ),
		subACL_AttributeCurrent ),
	MKACL_N(	/* Cursor mgt: Instance in attribute list */
/* In = cursor components, out = component type */
		/* This value is readable but always returns the basic field value
		   since it represents multiple instantiations of the same field */
		CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
		ST_CERT_ANY, ST_ENV_DEENV | ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_RWx_RWx,
		ROUTE_ALT2( OBJECT_TYPE_CERTIFICATE, OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ),
		RANGE( CRYPT_CURSOR_FIRST, CRYPT_CURSOR_LAST ) ),
	MKACL_N(	/* Internal data buffer size */
		CRYPT_ATTRIBUTE_BUFFERSIZE,
		ST_NONE, ST_ENV_ANY | ST_SESS_ANY, ACCESS_Rxx_RWx,
		ROUTE_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ), RANGE( MIN_BUFFER_SIZE, RANGE_MAX ) ),

	MKACL_END()
	};

/****************************************************************************
*																			*
*								Config Option ACLs							*
*																			*
****************************************************************************/

static const RANGE_SUBRANGE_TYPE FAR_BSS allowedEncrAlgoSubranges[] = {
	{ CRYPT_ALGO_3DES, CRYPT_ALGO_CAST },		/* No DES */
	{ CRYPT_ALGO_RC5, CRYPT_ALGO_BLOWFISH },	/* No RC2, RC4 */
	{ CRYPT_ALGO_SKIPJACK + 1, CRYPT_ALGO_LAST_CONVENTIONAL },/* No Skipjack */
	{ CRYPT_ERROR, CRYPT_ERROR } };
static const RANGE_SUBRANGE_TYPE FAR_BSS allowedSelftestSubranges[] = {
	{ CRYPT_ALGO_NONE + 1, CRYPT_ALGO_LAST - 1 },
	{ CRYPT_USE_DEFAULT, CRYPT_USE_DEFAULT },
	{ CRYPT_ERROR, CRYPT_ERROR } };
static const int FAR_BSS allowedLDAPObjectTypes[] = {
	CRYPT_CERTTYPE_NONE, CRYPT_CERTTYPE_CERTIFICATE, CRYPT_CERTTYPE_CRL,
	CRYPT_ERROR };

/* Config attributes */

static const ATTRIBUTE_ACL FAR_BSS optionACL[] = {
	MKACL_S(	/* Text description */
		CRYPT_OPTION_INFO_DESCRIPTION,
		ST_NONE, ST_USER_ANY, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 16, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Copyright notice */
		CRYPT_OPTION_INFO_COPYRIGHT,
		ST_NONE, ST_USER_ANY, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 16, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_N(	/* Major release version */
		CRYPT_OPTION_INFO_MAJORVERSION,
		ST_NONE, ST_USER_ANY, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 3, 3 ) ),
	MKACL_N(	/* Minor release version */
		CRYPT_OPTION_INFO_MINORVERSION,
		ST_NONE, ST_USER_ANY, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 0, 5 ) ),
	MKACL_N(	/* Stepping version */
		CRYPT_OPTION_INFO_STEPPING,
		ST_NONE, ST_USER_ANY, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 1, 50 ) ),

	MKACL_EX(	/* Encryption algorithm */
		/* We restrict the subrange to disallow the selection of the
		   insecure or deprecated DES, RC2, RC4, and Skipjack algorithms
		   as the default encryption algorithms */
		CRYPT_OPTION_ENCR_ALGO, ATTRIBUTE_VALUE_NUMERIC,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP | ST_USER_ANY, ACCESS_RWx_RWx, 0,
		ROUTE_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_USER ),
		RANGE_SUBRANGES, allowedEncrAlgoSubranges ),
	MKACL_N(	/* Hash algorithm */
		/* We restrict the subrange to disallow the selection of the
		   insecure or deprecated MD2, MD4, and MD5 algorithms as the
		   default hash algorithm */
		CRYPT_OPTION_ENCR_HASH,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP | ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_USER ),
		RANGE( CRYPT_ALGO_SHA, CRYPT_ALGO_LAST_HASH ) ),
	MKACL_N(	/* MAC algorithm */
		CRYPT_OPTION_ENCR_MAC,
		ST_NONE, ST_ENV_ENV | ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_USER ),
		RANGE( CRYPT_ALGO_FIRST_MAC, CRYPT_ALGO_LAST_MAC ) ),
	MKACL_N(	/* Public-key encryption algorithm */
		CRYPT_OPTION_PKC_ALGO,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( CRYPT_ALGO_FIRST_PKC, CRYPT_ALGO_LAST_PKC ) ),
	MKACL_N(	/* Public-key encryption key size */
		CRYPT_OPTION_PKC_KEYSIZE,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( bitsToBytes( 512 ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Signature algorithm */
		CRYPT_OPTION_SIG_ALGO,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( CRYPT_ALGO_FIRST_PKC, CRYPT_ALGO_LAST_PKC ) ),
	MKACL_N(	/* Signature keysize */
		CRYPT_OPTION_SIG_KEYSIZE,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( bitsToBytes( 512 ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Key processing algorithm */
		CRYPT_OPTION_KEYING_ALGO,
		ST_CTX_CONV, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_CONTEXT, OBJECT_TYPE_USER ),
		RANGE( CRYPT_ALGO_HMAC_SHA, CRYPT_ALGO_HMAC_SHA ) ),
	MKACL_N(	/* Key processing iterations */
		CRYPT_OPTION_KEYING_ITERATIONS,
		ST_CTX_CONV, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_CONTEXT, OBJECT_TYPE_USER ),
		RANGE( 1, 20000 ) ),

	MKACL_B(	/* Whether to sign unrecog.attrs */
		CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ) ),
	MKACL_N(	/* Certificate validity period */
		CRYPT_OPTION_CERT_VALIDITY,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 1, 20 * 365 ) ),
	MKACL_N(	/* CRL update interval */
		CRYPT_OPTION_CERT_UPDATEINTERVAL,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 1, 365 ) ),
	MKACL_N(	/* PKIX compliance level for cert chks.*/
		CRYPT_OPTION_CERT_COMPLIANCELEVEL,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( CRYPT_COMPLIANCELEVEL_OBLIVIOUS, CRYPT_COMPLIANCELEVEL_PKIX_FULL ) ),
	MKACL_B(	/* Whether explicit policy req'd for certs */
		CRYPT_OPTION_CERT_REQUIREPOLICY,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ) ),

	MKACL_B(	/* Add default CMS attributes */
		CRYPT_OPTION_CMS_DEFAULTATTRIBUTES,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ) ),

	MKACL_S(	/* Object class */
		CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS,
		ST_KEYSET_LDAP, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_EX(	/* Object type to fetch */
		CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, ATTRIBUTE_VALUE_NUMERIC,
		ST_KEYSET_LDAP, ST_USER_ANY, ACCESS_RWx_RWx, 0,
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE_ALLOWEDVALUES, allowedLDAPObjectTypes ),
	MKACL_S(	/* Query filter */
		CRYPT_OPTION_KEYS_LDAP_FILTER,
		ST_KEYSET_LDAP, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CA certificate attribute name */
		CRYPT_OPTION_KEYS_LDAP_CACERTNAME,
		ST_KEYSET_LDAP, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Certificate attribute name */
		CRYPT_OPTION_KEYS_LDAP_CERTNAME,
		ST_KEYSET_LDAP, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CRL attribute name */
		CRYPT_OPTION_KEYS_LDAP_CRLNAME,
		ST_KEYSET_LDAP, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Email attribute name */
		CRYPT_OPTION_KEYS_LDAP_EMAILNAME,
		ST_KEYSET_LDAP, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_S(	/* Name of first PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR01,
		ST_NONE, ST_USER_ANY, ACCESS_RWD_RWD,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of second PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR02,
		ST_NONE, ST_USER_ANY, ACCESS_RWD_RWD,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of third PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR03,
		ST_NONE, ST_USER_ANY, ACCESS_RWD_RWD,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of fourth PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR04,
		ST_NONE, ST_USER_ANY, ACCESS_RWD_RWD,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of fifth PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR05,
		ST_NONE, ST_USER_ANY, ACCESS_RWD_RWD,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_B(	/* Use only hardware mechanisms */
		CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ) ),

	MKACL_S(	/* Socks server name */
		CRYPT_OPTION_NET_SOCKS_SERVER,
		ST_NONE, ST_SESS_ANY | ST_USER_ANY, ACCESS_RWD_RWD,
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( MIN_DNS_SIZE, MAX_DNS_SIZE ) ),
	MKACL_S(	/* Socks user name */
		CRYPT_OPTION_NET_SOCKS_USERNAME,
		ST_NONE, ST_SESS_ANY | ST_USER_ANY, ACCESS_RWD_RWD,
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Web proxy server */
		CRYPT_OPTION_NET_HTTP_PROXY,
		ST_NONE, ST_SESS_ANY | ST_USER_ANY, ACCESS_RWD_RWD,
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( MIN_DNS_SIZE, MAX_DNS_SIZE ) ),
	MKACL_N(	/* Timeout for network connection setup */
		CRYPT_OPTION_NET_CONNECTTIMEOUT,
		ST_NONE, ST_SESS_ANY | ST_USER_ANY, ACCESS_Rxx_RWx,
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( 5, 300 ) ),
	MKACL_N(	/* Timeout for network reads */
		CRYPT_OPTION_NET_READTIMEOUT,
		ST_NONE, ST_SESS_ANY | ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( 0, 300 ) ),
	MKACL_N(	/* Timeout for network writes */
		CRYPT_OPTION_NET_WRITETIMEOUT,
		ST_NONE, ST_SESS_ANY | ST_USER_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_SESSION, OBJECT_TYPE_USER ),
		RANGE( 0, 300 ) ),

	MKACL_B(	/* Whether to init cryptlib async'ly */
		CRYPT_OPTION_MISC_ASYNCINIT,
		ST_NONE, ST_USER_SO, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_USER ) ),
	MKACL_B(	/* Protect against side-channel attacks */
		CRYPT_OPTION_MISC_SIDECHANNELPROTECTION,
		ST_CTX_PKC, ST_USER_SO, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_CONTEXT, OBJECT_TYPE_USER ) ),

	MKACL(		/* Whether in-mem.opts match on-disk ones */
		/* This is a special-case boolean attribute value that can only be
		   set to FALSE to indicate that the config options should be
		   flushed to disk */
		CRYPT_OPTION_CONFIGCHANGED, ATTRIBUTE_VALUE_BOOLEAN,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( FALSE, FALSE ) ),

	MKACL_EX(	/* Algorithm self-test status */
		CRYPT_OPTION_SELFTESTOK, ATTRIBUTE_VALUE_NUMERIC,
		ST_NONE, ST_USER_ANY, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE_SUBRANGES, allowedSelftestSubranges ),

	MKACL_END()
	};

/****************************************************************************
*																			*
*									Context ACLs							*
*																			*
****************************************************************************/

static const int FAR_BSS allowedPKCKeysizes[] = {
	sizeof( CRYPT_PKCINFO_DLP ), sizeof( CRYPT_PKCINFO_RSA ), CRYPT_ERROR };
static const int FAR_BSS allowedKeyingAlgos[] = {
	CRYPT_ALGO_MD5, CRYPT_ALGO_SHA, CRYPT_ALGO_RIPEMD160,
	CRYPT_ALGO_HMAC_SHA, CRYPT_ERROR };

/* Context attributes */

static const ATTRIBUTE_ACL FAR_BSS contextACL[] = {
	MKACL_N(	/* Algorithm */
		CRYPT_CTXINFO_ALGO,
		ST_CTX_ANY, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( CRYPT_ALGO_NONE + 1, CRYPT_ALGO_LAST - 1 ) ),
	MKACL_N(	/* Mode */
		CRYPT_CTXINFO_MODE,
		ST_CTX_CONV, ST_NONE, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( CRYPT_MODE_NONE + 1, CRYPT_MODE_LAST - 1 ) ),
	MKACL_S(	/* Algorithm name */
		CRYPT_CTXINFO_NAME_ALGO,
		ST_CTX_ANY, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 3, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Mode name */
		CRYPT_CTXINFO_NAME_MODE,
		ST_CTX_CONV, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 3, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_N(	/* Key size in bytes */
		CRYPT_CTXINFO_KEYSIZE,
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC, ST_NONE, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Block size in bytes */
		CRYPT_CTXINFO_BLOCKSIZE,
		ST_CTX_ANY, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 1, CRYPT_MAX_HASHSIZE ) ),
	MKACL_N(	/* IV size in bytes */
		CRYPT_CTXINFO_IVSIZE,
		ST_CTX_CONV, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 8, CRYPT_MAX_IVSIZE ) ),
	MKACL_EX(	/* Key processing algorithm */
		/* The allowed algorithm range is a bit peculiar, usually we only
		   allow HMAC-SHA1 for normal key derivation, however PGP uses
		   plain hash algorithms for the derivation and although these
		   are never applied, they are stored in the context when PGP keys
		   are loaded */
		CRYPT_CTXINFO_KEYING_ALGO, ATTRIBUTE_VALUE_NUMERIC,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ACCESS_Rxx_RWD, 0,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE_ALLOWEDVALUES, allowedKeyingAlgos ),
	MKACL_N(	/* Key processing iterations */
		CRYPT_CTXINFO_KEYING_ITERATIONS,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 1, 20000 ) ),
	MKACL_S(	/* Key processing salt */
		CRYPT_CTXINFO_KEYING_SALT,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 8, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S_EX(	/* Value used to derive key */
		CRYPT_CTXINFO_KEYING_VALUE,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ACCESS_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 1, MAX_ATTRIBUTE_SIZE ) ),
#ifdef USE_FIPS140
	MKACL_S_EX(	/* Key */
		CRYPT_CTXINFO_KEY,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ACCESS_INT_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_KEYSIZE ) ),
	MKACL_EX(	/* Public-key components */
		CRYPT_CTXINFO_KEY_COMPONENTS, ATTRIBUTE_VALUE_STRING,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE_ALLOWEDVALUES, allowedPKCKeysizes ),
#else
	MKACL_S_EX(	/* Key */
		CRYPT_CTXINFO_KEY,
		ST_CTX_CONV | ST_CTX_MAC, ST_NONE, ACCESS_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_KEYSIZE ) ),
	MKACL_EX(	/* Public-key components */
		CRYPT_CTXINFO_KEY_COMPONENTS, ATTRIBUTE_VALUE_STRING,
		ST_CTX_PKC, ST_NONE, ACCESS_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE_ALLOWEDVALUES, allowedPKCKeysizes ),
#endif /* FIPS 140 keying rules */
	MKACL_S(	/* IV */
		CRYPT_CTXINFO_IV,
		ST_CTX_CONV, ST_NONE, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 8, CRYPT_MAX_IVSIZE ) ),
	MKACL_S(	/* Hash value */
		CRYPT_CTXINFO_HASHVALUE,
		ST_CTX_HASH | ST_CTX_MAC, ST_NONE, ACCESS_RxD_RxD,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 16, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* Label for private/secret key */
		CRYPT_CTXINFO_LABEL,
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CONTEXT ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_END()
	};

/****************************************************************************
*																			*
*								Certificate ACLs							*
*																			*
****************************************************************************/

static const int FAR_BSS allowedIPAddressSizes[] = \
	{ 4, 16, CRYPT_ERROR };

static const ATTRIBUTE_ACL FAR_BSS subACL_CertinfoFingerprintSHA[] = {
	MKACL_S(	/* Certs: General access */
		CRYPT_CERTINFO_FINGERPRINT_SHA,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 20, 20 ) ),
	MKACL_S(	/* Selected other objs (requests, PKI users): Int.access only */
		CRYPT_CERTINFO_FINGERPRINT_SHA,
		ST_CERT_ANY_CERT | ST_CERT_REQ_REV | ST_CERT_PKIUSER, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 20, 20 ) ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_CertinfoSerialNumber[] = {
	MKACL_S(	/* Certificates: General access */
		/* In theory we shouldn't allow this access since the serial number
		   should be chosen by the CA, however it's required for SCEP, which
		   requires that the cert serial number contain a transaction ID (!!)
		   so we make it writeable for internal access */
		CRYPT_CERTINFO_SERIALNUMBER,
		ST_CERT_CERT, ST_NONE, ACCESS_SPECIAL_Rxx_RWx_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 32 ) ),
	MKACL_S(	/* Everything else: Read-only */
		CRYPT_CERTINFO_SERIALNUMBER,
		ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_CRL | \
							ST_CERT_REQ_CERT, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 32 ) ),
	MKACL_END_SUBACL()
	};

/* Certificate: General info */

static const ATTRIBUTE_ACL FAR_BSS certificateACL[] = {
	MKACL_B(	/* Cert is self-signed */
		CRYPT_CERTINFO_SELFSIGNED,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* Cert is signed and immutable */
		CRYPT_CERTINFO_IMMUTABLE,
		ST_CERT_ANY, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* Cert is a magic just-works cert */
		CRYPT_CERTINFO_XYZZY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* Certificate object type */
		CRYPT_CERTINFO_CERTTYPE,
		ST_CERT_ANY, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CERTTYPE_NONE + 1, CRYPT_CERTTYPE_LAST - 1 ) ),
	MKACL_S(	/* Certificate fingerprint: MD5 */
		CRYPT_CERTINFO_FINGERPRINT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 16, 16 ) ),
	MKACL_X(	/* Certificate fingerprint: SHA-1 */
		CRYPT_CERTINFO_FINGERPRINT_SHA,
		ST_CERT_ANY_CERT | ST_CERT_REQ_REV | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		subACL_CertinfoFingerprintSHA ),
	MKACL_N(	/* Cursor mgt: Rel.pos in chain/CRL/OCSP */
		/* The subtype flag is somewhat unusual since it includes as an
		   allowed subtype a cert, which doesn't have further cert components.
		   The reason for this is that when the chain is created it's just a
		   collection of certs, it isn't until all of them are available that
		   one can be marked the leaf cert and its type changed to cert chain.
		   Since an object's subtype can't be changed after it's created, we
		   have to allow cursor movement commands to certs in case one of
		   them is really the leaf in a cert chain - it's because of the way
		   the leaf can act as both a cert and a cert chain.  A pure cert
		   looks just like a one-cert chain, so there's no harm in sending a
		   movement command to a cert that isn't a chain leaf */
		CRYPT_CERTINFO_CURRENT_CERTIFICATE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL | ST_CERT_RTCS_REQ | \
					   ST_CERT_RTCS_RESP | ST_CERT_OCSP_REQ | \
					   ST_CERT_OCSP_RESP, ST_NONE, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CURSOR_FIRST, CRYPT_CURSOR_LAST ) ),
	MKACL_N(	/* Usage that cert is trusted for */
		CRYPT_CERTINFO_TRUSTED_USAGE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_RWD_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_KEYUSAGE_NONE, CRYPT_KEYUSAGE_LAST - 1 ) ),
	MKACL_B(	/* Whether cert is implicitly trusted */
		CRYPT_CERTINFO_TRUSTED_IMPLICIT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_RWD_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* Amount of detail to include in sigs.*/
		CRYPT_CERTINFO_SIGNATURELEVEL,
		ST_CERT_OCSP_REQ, ST_NONE, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_SIGNATURELEVEL_NONE, CRYPT_SIGNATURELEVEL_ALL ) ),

	MKACL_N(	/* Cert.format version */
		CRYPT_CERTINFO_VERSION,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_CRL | \
					   ST_CERT_RTCS_REQ | ST_CERT_RTCS_RESP | \
					   ST_CERT_OCSP_REQ | ST_CERT_OCSP_RESP, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 3 ) ),
	MKACL_X(	/* Serial number */
		CRYPT_CERTINFO_SERIALNUMBER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_CRL | \
					   ST_CERT_REQ_CERT, ST_NONE, ACCESS_SPECIAL_Rxx_RWx_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		subACL_CertinfoSerialNumber ),
	MKACL_O(	/* Public key */
		CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCtxPKC ),
	MKACL_O(	/* User certificate */
		CRYPT_CERTINFO_CERTIFICATE,
		ST_CERT_CERTCHAIN | ST_CERT_CRL | ST_CERT_REQ_CERT | ST_CERT_REQ_REV | \
							ST_CERT_RTCS_REQ | ST_CERT_OCSP_REQ, ST_NONE, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertificate ),
	MKACL_O(	/* CA certificate */
		CRYPT_CERTINFO_CACERTIFICATE,
		ST_CERT_OCSP_REQ, ST_NONE, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertificate ),
	MKACL_N(	/* Issuer DN */
		CRYPT_CERTINFO_ISSUERNAME,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
					   ST_CERT_CRL | ST_CERT_OCSP_RESP, ST_NONE, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_SELECTVALUE ),
	MKACL_T(	/* Cert valid-from time */
		CRYPT_CERTINFO_VALIDFROM,
		ST_CERT_CERT | ST_CERT_REQ_CERT | ST_CERT_CERTCHAIN | \
					   ST_CERT_ATTRCERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* Cert valid-to time */
		CRYPT_CERTINFO_VALIDTO,
		ST_CERT_CERT | ST_CERT_REQ_CERT | ST_CERT_CERTCHAIN | \
					   ST_CERT_ATTRCERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* Subject DN */
		CRYPT_CERTINFO_SUBJECTNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_SELECTVALUE ),
	MKACL_S(	/* Issuer unique ID */
		CRYPT_CERTINFO_ISSUERUNIQUEID,
		ST_CERT_CERT, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Subject unique ID */
		CRYPT_CERTINFO_SUBJECTUNIQUEID,
		ST_CERT_CERT, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* Cert.request (DN + public key) */
		CRYPT_CERTINFO_CERTREQUEST,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ST_NONE, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertRequest ),
	MKACL_T(	/* CRL/OCSP current-update time */
		CRYPT_CERTINFO_THISUPDATE,
		ST_CERT_CRL | ST_CERT_OCSP_RESP, ST_NONE, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* CRL/OCSP next-update time */
		CRYPT_CERTINFO_NEXTUPDATE,
		ST_CERT_CRL | ST_CERT_OCSP_RESP, ST_NONE, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* CRL/RTCS/OCSP cert-revocation time */
		CRYPT_CERTINFO_REVOCATIONDATE,
		ST_CERT_CRL | ST_CERT_RTCS_RESP | ST_CERT_OCSP_RESP, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* OCSP revocation status */
		CRYPT_CERTINFO_REVOCATIONSTATUS,
		ST_CERT_OCSP_RESP, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_OCSPSTATUS_NOTREVOKED, CRYPT_OCSPSTATUS_UNKNOWN ) ),
	MKACL_N(	/* RTCS certificate status */
		CRYPT_CERTINFO_CERTSTATUS,
		ST_CERT_RTCS_RESP, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CERTSTATUS_VALID, CRYPT_CERTSTATUS_UNKNOWN ) ),
	MKACL_S(	/* Currently selected DN in string form */
		CRYPT_CERTINFO_DN,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, MAX_ATTRIBUTE_SIZE ) ),
	MKACL_S(	/* PKI user ID */
		CRYPT_CERTINFO_PKIUSER_ID,
		ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 17, 17 ) ),
	MKACL_S(	/* PKI user issue password */
		CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
		ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 23, 23 ) ),
	MKACL_S(	/* PKI user revocation password */
		CRYPT_CERTINFO_PKIUSER_REVPASSWORD,
		ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 23, 23 ) ),

	MKACL_END()
	};

/* Certificate: Name components */

static const ATTRIBUTE_ACL FAR_BSS certNameACL[] = {
	MKACL_S(	/* countryName */
		CRYPT_CERTINFO_COUNTRYNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, 2 ) ),
	MKACL_WCS(	/* stateOrProvinceName */
		CRYPT_CERTINFO_STATEORPROVINCENAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),
	MKACL_WCS(	/* localityName */
		CRYPT_CERTINFO_LOCALITYNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),
	MKACL_WCS(	/* organizationName */
		CRYPT_CERTINFO_ORGANIZATIONNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_WCS(	/* organizationalUnitName */
		CRYPT_CERTINFO_ORGANIZATIONALUNITNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_WCS(	/* commonName */
		CRYPT_CERTINFO_COMMONNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_OCSP_RESP | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_S(	/* otherName.typeID */
		CRYPT_CERTINFO_OTHERNAME_TYPEID,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* otherName.value */
		CRYPT_CERTINFO_OTHERNAME_VALUE,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* rfc822Name */
		CRYPT_CERTINFO_RFC822NAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_RFC822_SIZE, MAX_RFC822_SIZE ) ),
	MKACL_S(	/* dNSName */
		CRYPT_CERTINFO_DNSNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_DNS_SIZE, MAX_DNS_SIZE ) ),
	MKACL_N(	/* directoryName */
		CRYPT_CERTINFO_DIRECTORYNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_S(	/* ediPartyName.nameAssigner */
		CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* ediPartyName.partyName */
		CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* uniformResourceIdentifier */
		CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_EX(	/* iPAddress */
		CRYPT_CERTINFO_IPADDRESS, ATTRIBUTE_VALUE_STRING,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD, 0,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_ALLOWEDVALUES, allowedIPAddressSizes ),
	MKACL_S(	/* registeredID */
		CRYPT_CERTINFO_REGISTEREDID,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_CRL | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_END()
	};

/* Certificate: Extensions */

static const ATTRIBUTE_ACL FAR_BSS certExtensionACL[] = {
	/* 1 2 840 113549 1 9 7 challengePassword.  This is here even though it's
	   a CMS attribute because SCEP stuffs it into PKCS #10 requests */
	MKACL_S(	/* nonce */
		CRYPT_CERTINFO_CHALLENGEPASSWORD,
		ST_CERT_CERTREQ, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),

	/* 1 3 6 1 4 1 3029 3 1 4 cRLExtReason */
	MKACL_N(	/* cRLExtReason */
		CRYPT_CERTINFO_CRLEXTREASON,
		ST_CERT_CRL | ST_CERT_REQ_REV, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASON_UNSPECIFIED, CRYPT_CRLEXTREASON_LAST - 1 ) ),

	/* 1 3 6 1 4 1 3029 3 1 5 keyFeatures */
	MKACL_N(	/* keyFeatures */
		CRYPT_CERTINFO_KEYFEATURES,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 7 ) ),

	/* 1 3 6 1 5 5 7 1 1 authorityInfoAccess.  The values are GeneralName
	   selectors so the ACL doesn't allow writes, since they can only be
	   used to select the GeneralName that's written to */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_AUTHORITYINFOACCESS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_RTCS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_OCSP,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_CERTSTORE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_CRLS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 3 6 1 5 5 7 1 2 biometricInfo */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_BIOMETRICINFO,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* biometricData.typeOfData */
		CRYPT_CERTINFO_BIOMETRICINFO_TYPE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 1 ) ),
	MKACL_S(	/* biometricData.hashAlgorithm */
		CRYPT_CERTINFO_BIOMETRICINFO_HASHALGO,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_S(	/* biometricData.dataHash */
		CRYPT_CERTINFO_BIOMETRICINFO_HASH,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 16, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* biometricData.sourceDataUri */
		CRYPT_CERTINFO_BIOMETRICINFO_URL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),

	/* 1 3 6 1 5 5 7 1 3 qcStatements */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_QCSTATEMENT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* qcStatement.statementInfo.semanticsIdentifier */
		CRYPT_CERTINFO_QCSTATEMENT_SEMANTICS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_N(	/* qcStatement.statementInfo.nameRegistrationAuthorities */
		/* This is a GeneralName selector so it can't be written to directly */
		CRYPT_CERTINFO_QCSTATEMENT_REGISTRATIONAUTHORITY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 3 6 1 5 5 7 48 1 2 ocspNonce */
	MKACL_S(	/* nonce */
		CRYPT_CERTINFO_OCSP_NONCE,
		ST_CERT_OCSP_REQ | ST_CERT_OCSP_RESP, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),

	/* 1 3 6 1 5 5 7 48 1 4 ocspAcceptableResponses */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_OCSP_RESPONSE,
		ST_CERT_OCSP_REQ, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* OCSP standard response */
		CRYPT_CERTINFO_OCSP_RESPONSE_OCSP,
		ST_CERT_OCSP_REQ, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 1 3 6 1 5 5 7 48 1 5 ocspNoCheck */
	MKACL_N(	/* noCheck */
		CRYPT_CERTINFO_OCSP_NOCHECK,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),

	/* 1 3 6 1 5 5 7 48 1 6 ocspArchiveCutoff */
	MKACL_T(	/* archiveCutoff */
		CRYPT_CERTINFO_OCSP_ARCHIVECUTOFF,
		ST_CERT_OCSP_RESP, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 1 3 6 1 5 5 7 48 1 11 subjectInfoAccess.  The values are GeneralName
	   selectors so the ACL doesn't allow writes, since they can only be
	   used to select the GeneralName that's written to */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SUBJECTINFOACCESS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 3 36 8 3 1 dateOfCertGen */
	MKACL_T(	/* dateOfCertGen */
		CRYPT_CERTINFO_SIGG_DATEOFCERTGEN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 1 3 36 8 3 2 procuration */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SIGG_PROCURATION,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* country */
		CRYPT_CERTINFO_SIGG_PROCURE_COUNTRY,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, 2 ) ),
	MKACL_S(	/* typeOfSubstitution */
		CRYPT_CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),
	MKACL_N(	/* signingFor.thirdPerson */
		CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 3 36 8 3 4 monetaryLimit */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SIGG_MONETARYLIMIT,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* currency */
		CRYPT_CERTINFO_SIGG_MONETARY_CURRENCY,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 3 ) ),
	MKACL_N(	/* amount */
		CRYPT_CERTINFO_SIGG_MONETARY_AMOUNT,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 255 ) ),
	MKACL_N(	/* exponent */
		CRYPT_CERTINFO_SIGG_MONETARY_EXPONENT,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 255 ) ),

	/* 1 3 36 8 3 8 restriction */
	MKACL_S(	/* restriction */
		CRYPT_CERTINFO_SIGG_RESTRICTION,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),

	/* 1 3 101 1 4 1 strongExtranet */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_STRONGEXTRANET,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* sxNetIDList.sxNetID.zone */
		CRYPT_CERTINFO_STRONGEXTRANET_ZONE,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, RANGE_MAX ) ),
	MKACL_S(	/* sxNetIDList.sxNetID.id */
		CRYPT_CERTINFO_STRONGEXTRANET_ID,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),

	/* 2 5 29 9 subjectDirectoryAttributes */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* attribute.type */
		CRYPT_CERTINFO_SUBJECTDIR_TYPE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_S(	/* attribute.values */
		CRYPT_CERTINFO_SUBJECTDIR_VALUES,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, MAX_ATTRIBUTE_SIZE ) ),

	/* 2 5 29 14 subjectKeyIdentifier */
	MKACL_S(	/* subjectKeyIdentifier */
		CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),

	/* 2 5 29 15 keyUsage */
	MKACL_N(	/* keyUsage */
		CRYPT_CERTINFO_KEYUSAGE,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_KEYUSAGE_NONE + 1, CRYPT_KEYUSAGE_LAST + 1 ) ),

	/* 2 5 29 16 privateKeyUsagePeriod */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* notBefore */
		CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* notBefore */
		CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 17 subjectAltName */
	MKACL_N(	/* subjectAltName */
		CRYPT_CERTINFO_SUBJECTALTNAME,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 18 issuerAltName */
	MKACL_N(	/* issuerAltName */
		CRYPT_CERTINFO_ISSUERALTNAME,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 19 basicConstraints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_BASICCONSTRAINTS,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* cA */
		CRYPT_CERTINFO_CA,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* pathLenConstraint */
		CRYPT_CERTINFO_PATHLENCONSTRAINT,
		ST_CERT_ANY_CERT | ST_CERT_ATTRCERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),

	/* 2 5 29 20 cRLNumber */
	MKACL_N(	/* cRLNumber */
		CRYPT_CERTINFO_CRLNUMBER,
		ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, RANGE_MAX ) ),

	/* 2 5 29 21 cRLReason */
	MKACL_N(	/* cRLReason */
		/* We allow a range up to the last extended reason because the cert-
		   handling code transparently maps one to the other to provide the
		   illusion of a unified crlReason attribute */
		CRYPT_CERTINFO_CRLREASON,
		ST_CERT_CRL | ST_CERT_REQ_REV, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASON_UNSPECIFIED, CRYPT_CRLEXTREASON_LAST - 1 ) ),

	/* 2 5 29 23 holdInstructionCode */
	MKACL_N(	/* holdInstructionCode */
		CRYPT_CERTINFO_HOLDINSTRUCTIONCODE,
		ST_CERT_CRL | ST_CERT_REQ_REV, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_HOLDINSTRUCTION_NONE + 1, CRYPT_HOLDINSTRUCTION_LAST - 1 ) ),

	/* 2 5 29 24 invalidityDate */
	MKACL_T(	/* invalidityDate */
		CRYPT_CERTINFO_INVALIDITYDATE,
		ST_CERT_CRL | ST_CERT_REQ_REV, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 27 deltaCRLIndicator */
	MKACL_N(	/* deltaCRLIndicator */
		CRYPT_CERTINFO_DELTACRLINDICATOR,
		ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, RANGE_MAX ) ),

	/* 2 5 29 28 issuingDistributionPoint */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT,
		ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* distributionPointName.fullName */
		CRYPT_CERTINFO_ISSUINGDIST_FULLNAME,
		ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_B(	/* onlyContainsUserCerts */
		CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY,
		ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* onlyContainsCACerts */
		CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY,
		ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* onlySomeReasons */
		CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY,
		ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASONFLAG_UNUSED, CRYPT_CRLREASONFLAG_LAST - 1 ) ),
	MKACL_B(	/* indirectCRL */
		CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL,
		ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 29 certificateIssuer */
	MKACL_N(	/* certificateIssuer */
		CRYPT_CERTINFO_CERTIFICATEISSUER,
		ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 30 nameConstraints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_NAMECONSTRAINTS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* permittedSubtrees */
		CRYPT_CERTINFO_PERMITTEDSUBTREES,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* excludedSubtrees */
		CRYPT_CERTINFO_EXCLUDEDSUBTREES,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 31 cRLDistributionPoint */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* distributionPointName.fullName */
		CRYPT_CERTINFO_CRLDIST_FULLNAME,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* reasons */
		CRYPT_CERTINFO_CRLDIST_REASONS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASONFLAG_UNUSED, CRYPT_CRLREASONFLAG_LAST - 1 ) ),
	MKACL_N(	/* cRLIssuer */
		CRYPT_CERTINFO_CRLDIST_CRLISSUER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | \
			ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 32 certificatePolicies */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CERTIFICATEPOLICIES,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* policyInformation.policyIdentifier */
		CRYPT_CERTINFO_CERTPOLICYID,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_S(	/* policyInformation.policyQualifiers.qualifier.cPSuri */
		CRYPT_CERTINFO_CERTPOLICY_CPSURI,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.organization */
		CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 200 ) ),
	MKACL_N(	/* policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.noticeNumbers */
		CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 1024 ) ),
	MKACL_S(	/* policyInformation.policyQualifiers.qualifier.userNotice.explicitText */
		CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 200 ) ),

	/* 2 5 29 33 policyMappings */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_POLICYMAPPINGS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* policyMappings.issuerDomainPolicy */
		CRYPT_CERTINFO_ISSUERDOMAINPOLICY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_S(	/* policyMappings.subjectDomainPolicy */
		CRYPT_CERTINFO_SUBJECTDOMAINPOLICY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),

	/* 2 5 29 35 authorityKeyIdentifier */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* keyIdentifier */
		CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_N(	/* authorityCertIssuer */
		CRYPT_CERTINFO_AUTHORITY_CERTISSUER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_S(	/* authorityCertSerialNumber */
		CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 32 ) ),

	/* 2 5 29 36 policyConstraints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_POLICYCONSTRAINTS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* policyConstraints.requireExplicitPolicy */
		CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),
	MKACL_N(	/* policyConstraints.inhibitPolicyMapping */
		CRYPT_CERTINFO_INHIBITPOLICYMAPPING,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),

	/* 2 5 29 37 extKeyUsage */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_EXTKEYUSAGE,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* individualCodeSigning */
		CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* commercialCodeSigning */
		CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* certTrustListSigning */
		CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* timeStampSigning */
		CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* serverGatedCrypto */
		CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* encrypedFileSystem */
		CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* serverAuth */
		CRYPT_CERTINFO_EXTKEY_SERVERAUTH,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* clientAuth */
		CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* codeSigning */
		CRYPT_CERTINFO_EXTKEY_CODESIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* emailProtection */
		CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* ipsecEndSystem */
		CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* ipsecTunnel */
		CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* ipsecUser */
		CRYPT_CERTINFO_EXTKEY_IPSECUSER,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* timeStamping */
		CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* ocspSigning */
		CRYPT_CERTINFO_EXTKEY_OCSPSIGNING,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* directoryService */
		CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* anyExtendedKeyUsage */
		/* This extension exists solely as a bugfix for a circular
		   definition in the PKIX RFC and introduces a number of further
		   problems, to avoid falling into this rathole we don't allow
		   the creation of certs with this usage type */
		CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* serverGatedCrypto */
		CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* serverGatedCrypto CA */
		CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 46 freshestCRL */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_FRESHESTCRL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* distributionPointName.fullName */
		CRYPT_CERTINFO_FRESHESTCRL_FULLNAME,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* reasons */
		CRYPT_CERTINFO_FRESHESTCRL_REASONS,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CRLREASONFLAG_UNUSED, CRYPT_CRLREASONFLAG_LAST - 1 ) ),
	MKACL_N(	/* cRLIssuer */
		CRYPT_CERTINFO_FRESHESTCRL_CRLISSUER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 2 5 29 54 inhibitAnyPolicy */
	MKACL_N(	/* inhibitAnyPolicy */
		CRYPT_CERTINFO_INHIBITANYPOLICY,
		ST_CERT_ANY_CERT | ST_CERT_PKIUSER, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),

	/* 2 16 840 1 113730 1 x Netscape extensions (obsolete) */
	MKACL_N(	/* netscape-cert-type */
		/* This attribute can't normally be set, however when creating a
		   template of disallowed attributes to apply to an about-to-be-
		   issued cert we need to be able to set it to mask out any
		   attributes of this type that may have come in via a cert
		   request */
		CRYPT_CERTINFO_NS_CERTTYPE,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_SPECIAL_Rxx_RWx_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_NS_CERTTYPE_SSLCLIENT, CRYPT_NS_CERTTYPE_LAST - 1 ) ),
	MKACL_S(	/* netscape-base-url */
		CRYPT_CERTINFO_NS_BASEURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-revocation-url */
		CRYPT_CERTINFO_NS_REVOCATIONURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-ca-revocation-url */
		CRYPT_CERTINFO_NS_CAREVOCATIONURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-cert-renewal-url */
		CRYPT_CERTINFO_NS_CERTRENEWALURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-ca-policy-url */
		CRYPT_CERTINFO_NS_CAPOLICYURL,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-ssl-server-name */
		CRYPT_CERTINFO_NS_SSLSERVERNAME,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-comment */
		CRYPT_CERTINFO_NS_COMMENT,
		ST_CERT_ANY_CERT, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, MAX_ATTRIBUTE_SIZE ) ),

	/* 2 23 42 7 0 SET hashedRootKey */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SET_HASHEDROOTKEY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* rootKeyThumbPrint */
		CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 20, 20 ) ),

	/* 2 23 42 7 1 SET certificateType */
	MKACL_N(	/* certificateType */
		CRYPT_CERTINFO_SET_CERTIFICATETYPE,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_SET_CERTTYPE_CARD, CRYPT_SET_CERTTYPE_LAST - 1 ) ),

	/* 2 23 42 7 2 SET merchantData */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SET_MERCHANTDATA,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* merID */
		CRYPT_CERTINFO_SET_MERID,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 30 ) ),
	MKACL_S(	/* merAcquirerBIN */
		CRYPT_CERTINFO_SET_MERACQUIRERBIN,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 6, 6 ) ),
	MKACL_S(	/* merNames.language */
		CRYPT_CERTINFO_SET_MERCHANTLANGUAGE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 35 ) ),
	MKACL_S(	/* merNames.name */
		CRYPT_CERTINFO_SET_MERCHANTNAME,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.city */
		CRYPT_CERTINFO_SET_MERCHANTCITY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.stateProvince */
		CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.postalCode */
		CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.countryName */
		CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_N(	/* merCountry */
		CRYPT_CERTINFO_SET_MERCOUNTRY,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 999 ) ),
	MKACL_B(	/* merAuthFlag */
		CRYPT_CERTINFO_SET_MERAUTHFLAG,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 23 42 7 3 SET certCardRequired */
	MKACL_B(	/* certCardRequired */
		CRYPT_CERTINFO_SET_CERTCARDREQUIRED,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 23 42 7 4 SET tunneling */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SET_TUNNELING,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* tunneling */
		CRYPT_CERTINFO_SET_TUNNELINGFLAG,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* tunnelingAlgID */
		CRYPT_CERTINFO_SET_TUNNELINGALGID,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),

	MKACL_END()
	};

/* Certificate: S/MIME attributes */

static const ATTRIBUTE_ACL FAR_BSS certSmimeACL[] = {
	/* 1 2 840 113549 1 9 3 contentType */
	MKACL_N(	/* contentType */
		CRYPT_CERTINFO_CMS_CONTENTTYPE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CONTENT_NONE + 1, CRYPT_CONTENT_LAST - 1 ) ),

	/* 1 2 840 113549 1 9 4 messageDigest */
	MKACL_S(	/* messageDigest */
		CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 16, CRYPT_MAX_HASHSIZE ) ),

	/* 1 2 840 113549 1 9 5 signingTime */
	MKACL_T(	/* signingTime */
		CRYPT_CERTINFO_CMS_SIGNINGTIME,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_SPECIAL_Rxx_RWD_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 1 2 840 113549 1 9 6 counterSignature */
	MKACL_S(	/* counterSignature */
		CRYPT_CERTINFO_CMS_COUNTERSIGNATURE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 64, MAX_ATTRIBUTE_SIZE ) ),

	/* 1 2 840 113549 1 9 13 signingDescription */
	MKACL_S(	/* counterSignature */
		CRYPT_CERTINFO_CMS_SIGNINGDESCRIPTION,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, MAX_ATTRIBUTE_SIZE ) ),

	/* 1 2 840 113549 1 9 15 sMIMECapabilities */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SMIMECAPABILITIES,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* 3DES encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_3DES,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* AES encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_AES,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* CAST-128 encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_CAST128,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* IDEA encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_IDEA,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* RC2 encryption (w.128 key) */
		CRYPT_CERTINFO_CMS_SMIMECAP_RC2,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* RC5 encryption (w.128 key) */
		CRYPT_CERTINFO_CMS_SMIMECAP_RC5,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* Skipjack encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* DES encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_DES,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* preferSignedData */
		CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* canNotDecryptAny */
		CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),

	/* 1 2 840 113549 1 9 16 2 1 receiptRequest */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_RECEIPTREQUEST,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* contentIdentifier */
		CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 16, 64 ) ),
	MKACL_N(	/* receiptsFrom */
		CRYPT_CERTINFO_CMS_RECEIPT_FROM,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 1 ) ),
	MKACL_N(	/* receiptsTo */
		CRYPT_CERTINFO_CMS_RECEIPT_TO,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 2 840 113549 1 9 16 2 2 essSecurityLabel */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SECURITYLABEL,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* securityPolicyIdentifier */
		CRYPT_CERTINFO_CMS_SECLABEL_POLICY,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_N(	/* securityClassification */
		CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST ) ),
	MKACL_S(	/* privacyMark */
		CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_S(	/* securityCategories.securityCategory.type */
		CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_S(	/* securityCategories.securityCategory.value */
		CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 512 ) ),

	/* 1 2 840 113549 1 9 16 2 3 mlExpansionHistory */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* mlData.mailListIdentifier.issuerAndSerialNumber */
		CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 512 ) ),
	MKACL_T(	/* mlData.expansionTime */
		CRYPT_CERTINFO_CMS_MLEXP_TIME,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* mlData.mlReceiptPolicy.none */
		CRYPT_CERTINFO_CMS_MLEXP_NONE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* mlData.mlReceiptPolicy.insteadOf.generalNames.generalName */
		CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),
	MKACL_N(	/* mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName */
		CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( FALSE, TRUE ) ),

	/* 1 2 840 113549 1 9 16 2 4 contentHints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_CONTENTHINTS,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* contentDescription */
		CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_N(	/* contentType */
		CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CONTENT_DATA, CRYPT_CONTENT_LAST - 1 ) ),

	/* 1 2 840 113549 1 9 16 2 9 equivalentLabels */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_EQUIVALENTLABEL,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* securityPolicyIdentifier */
		CRYPT_CERTINFO_CMS_EQVLABEL_POLICY,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_N(	/* securityClassification */
		CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST ) ),
	MKACL_S(	/* privacyMark */
		CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_S(	/* securityCategories.securityCategory.type */
		CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_S(	/* securityCategories.securityCategory.value */
		CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 512 ) ),

	/* 1 2 840 113549 1 9 16 2 12 signingCertificate */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* certs.essCertID */
		CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 32, MAX_ATTRIBUTE_SIZE ) ),
	MKACL_S(	/* policies.policyInformation.policyIdentifier */
		CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),

	/* 1 2 840 113549 1 9 16 2 15 signaturePolicyID */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SIGNATUREPOLICYID,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* signaturePolicyID.sigPolicyID */
		CRYPT_CERTINFO_CMS_SIGPOLICYID,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_S(	/* signaturePolicyID.sigPolicyHash */
		CRYPT_CERTINFO_CMS_SIGPOLICYHASH,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 32, MAX_ATTRIBUTE_SIZE ) ),
	MKACL_S(	/* signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.cPSuri */
		CRYPT_CERTINFO_CMS_SIGPOLICY_CPSURI,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.organization */
		CRYPT_CERTINFO_CMS_SIGPOLICY_ORGANIZATION,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 200 ) ),
	MKACL_N(	/* signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.noticeNumbers */
		CRYPT_CERTINFO_CMS_SIGPOLICY_NOTICENUMBERS,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 1024 ) ),
	MKACL_S(	/* signaturePolicyID.sigPolicyQualifiers.sigPolicyQualifier.userNotice.explicitText */
		CRYPT_CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 200 ) ),

	/* 1 2 840 113549 1 9 16 9 signatureTypeIdentifier */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SIGTYPEIDENTIFIER,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* originatorSig */
		CRYPT_CERTINFO_CMS_SIGTYPEID_ORIGINATORSIG,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* domainSig */
		CRYPT_CERTINFO_CMS_SIGTYPEID_DOMAINSIG,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* additionalAttributesSig */
		CRYPT_CERTINFO_CMS_SIGTYPEID_ADDITIONALATTRIBUTES,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* reviewSig */
		CRYPT_CERTINFO_CMS_SIGTYPEID_REVIEWSIG,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),

	/* 1 2 840 113549 1 9 25 3 randomNonce */
	MKACL_S(	/* randomNonce */
		/* This is valid in RTCS requests, which are occasionally
		   communicated using a CMS content-type that can't provide
		   attributes so they need to be bundled with the request instead */
		CRYPT_CERTINFO_CMS_NONCE,
		ST_CERT_CMSATTR | ST_CERT_RTCS_REQ, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 4, CRYPT_MAX_HASHSIZE ) ),

	/* SCEP attributes:
	   2 16 840 1 113733 1 9 2 messageType
	   2 16 840 1 113733 1 9 3 pkiStatus
	   2 16 840 1 113733 1 9 4 failInfo
	   2 16 840 1 113733 1 9 5 senderNonce
	   2 16 840 1 113733 1 9 6 recipientNonce
	   2 16 840 1 113733 1 9 7 transID */
	MKACL_S(	/* messageType */
		CRYPT_CERTINFO_SCEP_MESSAGETYPE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 2 ) ),
	MKACL_S(	/* pkiStatus */
		CRYPT_CERTINFO_SCEP_PKISTATUS,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 1 ) ),
	MKACL_S(	/* failInfo */
		CRYPT_CERTINFO_SCEP_FAILINFO,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 1 ) ),
	MKACL_S(	/* senderNonce */
		CRYPT_CERTINFO_SCEP_SENDERNONCE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 8, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* recipientNonce */
		CRYPT_CERTINFO_SCEP_RECIPIENTNONCE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 8, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* transID */
		CRYPT_CERTINFO_SCEP_TRANSACTIONID,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),

	/* 1 3 6 1 4 1 311 2 1 10 spcAgencyInfo */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SPCAGENCYINFO,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* spcAgencyInfo.url */
		CRYPT_CERTINFO_CMS_SPCAGENCYURL,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),

	/* 1 3 6 1 4 1 311 2 1 11 spcStatementType */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* individualCodeSigning */
		CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* commercialCodeSigning */
		CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),

	/* 1 3 6 1 4 1 311 2 1 12 spcOpusInfo */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SPCOPUSINFO,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* spcOpusInfo.name */
		CRYPT_CERTINFO_CMS_SPCOPUSINFO_NAME,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, 128 ) ),
	MKACL_S(	/* spcOpusInfo.url */
		CRYPT_CERTINFO_CMS_SPCOPUSINFO_URL,
		ST_CERT_CMSATTR, ST_NONE, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),

	MKACL_END()
	};

/****************************************************************************
*																			*
*									Keyset ACLs								*
*																			*
****************************************************************************/

/* Keyset attributes */

static const ATTRIBUTE_ACL FAR_BSS keysetACL[] = {
	MKACL_S(	/* Keyset query */
		CRYPT_KEYINFO_QUERY,
		ST_KEYSET_DBMS, ST_NONE, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_KEYSET ),
		RANGE( 6, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Query of requests in cert store */
		CRYPT_KEYINFO_QUERY_REQUESTS,
		ST_KEYSET_DBMS_STORE, ST_NONE, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_KEYSET ),
		RANGE( 6, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_END()
	};

/****************************************************************************
*																			*
*									Device ACLs								*
*																			*
****************************************************************************/

/* Device attributes */

static const ATTRIBUTE_ACL FAR_BSS deviceACL[] = {
	MKACL_S_EX(	/* Initialise device for use */
		CRYPT_DEVINFO_INITIALISE,
		ST_DEV_ANY_STD, ST_NONE, ACCESS_xWx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S_EX(	/* Authenticate user to device */
		/* This is allowed in both the low and high states since the device
		   may be in the SSO initialised state and all we're doing is
		   switching it to the user initialised state */
		CRYPT_DEVINFO_AUTHENT_USER,
		ST_DEV_ANY_STD, ST_NONE, ACCESS_xWx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S_EX(	/* Authenticate supervisor to dev.*/
		CRYPT_DEVINFO_AUTHENT_SUPERVISOR,
		ST_DEV_ANY_STD, ST_NONE, ACCESS_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Set user authent.value */
		CRYPT_DEVINFO_SET_AUTHENT_USER,
		ST_DEV_ANY_STD, ST_NONE, ACCESS_xWx_xxx,
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Set supervisor auth.val.*/
		CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR,
		ST_DEV_ANY_STD, ST_NONE, ACCESS_xWx_xxx,
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Zeroise device */
		CRYPT_DEVINFO_ZEROISE,
		ST_DEV_ANY_STD, ST_NONE, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_B(	/* Whether user is logged in */
		CRYPT_DEVINFO_LOGGEDIN,
		ST_DEV_ANY_STD, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_DEVICE ) ),
	MKACL_S(	/* Device/token label */
		CRYPT_DEVINFO_LABEL,
		ST_DEV_ANY_STD, ST_NONE, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_DEVICE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_END()
	};

/****************************************************************************
*																			*
*									Envelope ACLs							*
*																			*
****************************************************************************/

static const RANGE_SUBRANGE_TYPE FAR_BSS allowedSigResultSubranges[] = {
	/* We make the error subrange start at CRYPT_ERROR_MEMORY rather than
	   the generic CRYPT_ERROR_PARAM1, which is the same as CRYPT_ERROR,
	   the end-of-range marker */
	{ CRYPT_OK, CRYPT_OK },
	{ CRYPT_ERROR_MEMORY, CRYPT_ENVELOPE_RESOURCE },
	{ CRYPT_ERROR, CRYPT_ERROR } };

static const ATTRIBUTE_ACL FAR_BSS subACL_EnvinfoContentType[] = {
	MKACL_N(	/* Envelope: Read/write */
		CRYPT_ENVINFO_CONTENTTYPE,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( CRYPT_CONTENT_NONE + 1, CRYPT_CONTENT_LAST - 1 ) ),
	MKACL_N(	/* Deenvelope: Read-only */
		CRYPT_ENVINFO_CONTENTTYPE,
		ST_NONE, ST_ENV_DEENV, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( CRYPT_CONTENT_NONE + 1, CRYPT_CONTENT_LAST - 1 ) ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_EnvinfoSignature[] = {
	MKACL_O(	/* Envelope: Write-only */
		CRYPT_ENVINFO_SIGNATURE,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxPKC ),
	MKACL_O(	/* De-envelope: Read/write */
		/* This is readable and writeable since it can be used to add a sig-
		   check key to an envelope that doesn't include certs */
		CRYPT_ENVINFO_SIGNATURE,
		ST_NONE, ST_ENV_DEENV, ACCESS_RWx_xxx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxPKC ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_EnvinfoSignatureExtraData[] = {
	MKACL_O(	/* Envelope: Write-only */
		CRYPT_ENVINFO_SIGNATURE_EXTRADATA,
		ST_NONE, ST_ENV_ENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCMSAttr ),
	MKACL_O(	/* De-envelope: Read-only */
		CRYPT_ENVINFO_SIGNATURE_EXTRADATA,
		ST_NONE, ST_ENV_DEENV, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCMSAttr ),
	MKACL_END_SUBACL()
	};

static const ATTRIBUTE_ACL FAR_BSS subACL_EnvinfoTimestamp[] = {
	MKACL_O(	/* Envelope: Write-only TSP session */
		CRYPT_ENVINFO_TIMESTAMP,
		ST_NONE, ST_ENV_ENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectSessionTSP ),
	MKACL_O(	/* De-envelope: Read-only sub-envelope */
		CRYPT_ENVINFO_TIMESTAMP,
		ST_NONE, ST_ENV_DEENV, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectDeenvelope ),
	MKACL_END_SUBACL()
	};

/* Envelope attributes */

static const ATTRIBUTE_ACL FAR_BSS envelopeACL[] = {
	MKACL_N(	/* Data size information */
		/* The maximum length is adjusted by MAX_INTLENGTH_DELTA bytes
		   because what this attribute specifies is only the payload size
		   and not the overall message size, which could be up to
		   MAX_INTLENGTH_DELTA bytes larger */
		CRYPT_ENVINFO_DATASIZE,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( 0, MAX_INTLENGTH - MAX_INTLENGTH_DELTA ) ),
	MKACL_N(	/* Compression information */
		CRYPT_ENVINFO_COMPRESSION,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_X(	/* Inner CMS content type */
		CRYPT_ENVINFO_CONTENTTYPE,
		ST_NONE, ST_ENV_ANY, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		subACL_EnvinfoContentType ),
	MKACL_B(	/* Generate CMS detached signature */
		CRYPT_ENVINFO_DETACHEDSIGNATURE,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_EX(	/* Signature check result */
		/* This is a special case because an OK status is positive but an
		   error status is negative, which spans two range types.  To handle
		   this we treat it as two distinct subranges, the positive CRYPT_OK
		   and the negative error values */
		CRYPT_ENVINFO_SIGNATURE_RESULT, ATTRIBUTE_VALUE_NUMERIC,
		ST_NONE, ST_ENV_DEENV, ACCESS_Rxx_xxx, 0,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE_SUBRANGES, allowedSigResultSubranges ),
	MKACL_B(	/* Use MAC instead of encrypting */
		CRYPT_ENVINFO_MAC,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_S(	/* User password */
		CRYPT_ENVINFO_PASSWORD,
		ST_NONE, ST_ENV_ANY, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* Conventional encryption key */
		CRYPT_ENVINFO_KEY,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxConv ),
	MKACL_X(	/* Signature/signature check key */
		CRYPT_ENVINFO_SIGNATURE,
		ST_NONE, ST_ENV_ANY, ACCESS_RWx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		subACL_EnvinfoSignature ),
	MKACL_X(	/* Extra information added to CMS sigs */
		CRYPT_ENVINFO_SIGNATURE_EXTRADATA,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ACCESS_Rxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		subACL_EnvinfoSignatureExtraData ),
	MKACL_S(	/* Recipient email address */
		CRYPT_ENVINFO_RECIPIENT,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* PKC encryption key */
		CRYPT_ENVINFO_PUBLICKEY,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxPKC ),
	MKACL_O(	/* PKC decryption key */
		CRYPT_ENVINFO_PRIVATEKEY,
		ST_NONE, ST_ENV_DEENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),  &objectCtxPKC ),
	MKACL_S(	/* Label of PKC decryption key */
		CRYPT_ENVINFO_PRIVATEKEY_LABEL,
		ST_NONE, ST_ENV_DEENV, ACCESS_xxx_Rxx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* Originator info/key */
		CRYPT_ENVINFO_ORIGINATOR,
		ST_NONE, ST_ENV_ENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxPKC ),
	MKACL_O(	/* Session key */
		CRYPT_ENVINFO_SESSIONKEY,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxConv ),
	MKACL_O(	/* Hash value */
		CRYPT_ENVINFO_HASH,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP | ST_ENV_DEENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectCtxHash ),
	MKACL_X(	/* Timestamp */
		CRYPT_ENVINFO_TIMESTAMP,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ACCESS_Rxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		subACL_EnvinfoTimestamp ),
	MKACL_O(	/* Signature check keyset */
		CRYPT_ENVINFO_KEYSET_SIGCHECK,
		ST_NONE, ST_ENV_DEENV, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectKeyset ),
	MKACL_O(	/* PKC encryption keyset */
		CRYPT_ENVINFO_KEYSET_ENCRYPT,
		ST_NONE, ST_ENV_ENV | ST_ENV_ENV_PGP, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectKeyset ),
	MKACL_O(	/* PKC decryption keyset */
		CRYPT_ENVINFO_KEYSET_DECRYPT,
		ST_NONE, ST_ENV_DEENV, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), &objectKeyset ),

	MKACL_END()
	};

/****************************************************************************
*																			*
*									Session ACLs							*
*																			*
****************************************************************************/

static const RANGE_SUBRANGE_TYPE FAR_BSS allowedSSHChannelSubranges[] = {
	{ CRYPT_UNUSED, CRYPT_UNUSED },
	{ 1, RANGE_MAX },
	{ CRYPT_ERROR, CRYPT_ERROR } };
static const int FAR_BSS allowedAuthResponses[] = \
	{ CRYPT_UNUSED, FALSE, TRUE, CRYPT_ERROR };

static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoActive[] = {
	MKACL_B_EX(	/* SSH/SSL: Can only be activated once */
		CRYPT_SESSINFO_ACTIVE,
		ST_NONE, ST_SESS_ANY_DATA, ACCESS_Rxx_RWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_SESSION ) ),
	MKACL_B_EX(	/* Ongoing protocol: Persistent connections */
		CRYPT_SESSINFO_ACTIVE,
		ST_NONE, ST_SESS_ANY_REQRESP, ACCESS_RWx_RWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_SESSION ) ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoUsername[] = {
	MKACL_S(	/* SSH/SSL/SCEP client: RWD for client auth */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_SESS_SSH | ST_SESS_SSL | ST_SESS_SCEP, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* SSH server: Read-only for client auth */
		/* We can read this attribute in the low state because we might be
		   going back to the caller for confirmation before we transition
		   into the high state */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_SESS_SSH_SVR, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CMP server: Read-only for client auth */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_SESS_CMP_SVR, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* SSL server: RW for client auth */
		/* For SSL the username doesn't work like a standard user name but
		   instead acts as a magic value to identify a shared secret in the
		   session cache which is used to peform an SSL resume when the
		   client connects.  Multiple username/password combinations can be
		   added, what's read back is either the last one added if the
		   session hasn't been activated, or the one that was used to provide
		   the encryption keys for the currently-active session */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_SESS_SSL_SVR, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CMP client: RWD in both states for persistent conns */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_SESS_CMP, ACCESS_RWD_RWD,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoPassword[] = {
	MKACL_S(	/* SSH/SSL/SCEP client: Write-only for client auth */
		CRYPT_SESSINFO_PASSWORD,
		ST_NONE, ST_SESS_SSH | ST_SESS_SSL | ST_SESS_SCEP, ACCESS_xxx_xWD,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* SSH server: Read-only from client auth */
		/* We can read this attribute in the low state because we might be
		   going back to the caller for confirmation before we transition
		   into the high state */
		CRYPT_SESSINFO_PASSWORD,
		ST_NONE, ST_SESS_SSH_SVR, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* SSL server: Write-only in both states for client auth */
		CRYPT_SESSINFO_PASSWORD,
		ST_NONE, ST_SESS_SSL_SVR, ACCESS_xWD_xWD,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CMP client: Write-only in both states for persistent conns */
		CRYPT_SESSINFO_PASSWORD,
		ST_NONE, ST_SESS_CMP, ACCESS_xWD_xWD,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoPrivatekey[] = {
	MKACL_O(	/* Server or SSH/SSL/SCEP client: Write-only */
		CRYPT_SESSINFO_PRIVATEKEY,
		ST_NONE, ( ST_SESS_ANY_SVR & ~ST_SESS_CERT_SVR ) | ST_SESS_SSH | \
				 ST_SESS_SSL | ST_SESS_SCEP, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCtxPKC ),
	MKACL_O(	/* CMP client: Write-only in both states for persistent conns */
		CRYPT_SESSINFO_PRIVATEKEY,
		ST_NONE, ST_SESS_CMP, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCtxPKC ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoKeyset[] = {
	MKACL_O(	/* SSL and cert status/access protocols: Certificate source */
		CRYPT_SESSINFO_KEYSET,
		ST_NONE, ST_SESS_SSL_SVR | ST_SESS_RTCS_SVR | ST_SESS_OCSP_SVR | \
				 ST_SESS_CERT_SVR, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectKeysetCerts ),
	MKACL_O(	/* Cert management protocols: Certificate store */
		CRYPT_SESSINFO_KEYSET,
		ST_NONE, ST_SESS_CMP_SVR | ST_SESS_SCEP_SVR, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectKeysetCertstore ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoFingerprint[] = {
	MKACL_S(	/* Client: Write-only low, read-only high */
		CRYPT_SESSINFO_SERVER_FINGERPRINT,
		ST_NONE, ST_SESS_SSL | ST_SESS_SSH, ACCESS_Rxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 16, 20 ) ),
	MKACL_S(	/* Server: Read-only */
		CRYPT_SESSINFO_SERVER_FINGERPRINT,
		ST_NONE, ST_SESS_SSH_SVR, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 16, 20 ) ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoSession[] = {
	MKACL_O(	/* Client: Client session */
		CRYPT_SESSINFO_SESSION,
		ST_NONE, ST_SESS_RTCS | ST_SESS_OCSP | ST_SESS_TSP | \
				 ST_SESS_CMP | ST_SESS_SCEP, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectSessionDataClient ),
	MKACL_O(	/* Server: Server session */
		CRYPT_SESSINFO_SESSION,
		ST_NONE, ST_SESS_RTCS_SVR | ST_SESS_OCSP_SVR | ST_SESS_TSP_SVR | \
				 ST_SESS_CMP_SVR | ST_SESS_SCEP_SVR, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectSessionDataServer ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoRequest[] = {
	MKACL_O(	/* RTCS session: RTCS request */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_SESS_RTCS, ACCESS_xWD_xWD,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertSessionRTCSRequest ),
	MKACL_O(	/* OCSP session: OCSP request */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_SESS_OCSP, ACCESS_xWD_xWD,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertSessionOCSPRequest ),
	MKACL_O(	/* CMP session: Cert/rev.request */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_SESS_CMP, ACCESS_xWD_xWD,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertSessionCMPRequest ),
	MKACL_O(	/* SCEP session: Unsigned PKCS #10 request */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_SESS_SCEP, ACCESS_xWD_xWD,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertSessionUnsignedPKCS10Request ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoResponse[] = {
	MKACL_O(	/* RTCS session: RTCS response */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_SESS_RTCS, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertRTCSResponse ),
	MKACL_O(	/* OCSP session: OCSP response */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_SESS_OCSP, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertOCSPResponse ),
	MKACL_O(	/* SSL, PKI mgt.session: Cert, cert.response */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_SESS_SSL | ST_SESS_SSL_SVR | ST_SESS_CMP | \
				 ST_SESS_SCEP, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertificate ),
	MKACL_O(	/* TSP session: CMS enveloped timestamp */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_SESS_TSP, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectDeenvelope ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoRequesttype[] = {
	MKACL_N(	/* CMP client: Read/write */
		CRYPT_SESSINFO_CMP_REQUESTTYPE,
		ST_NONE, ST_SESS_CMP, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( CRYPT_REQUESTTYPE_NONE + 1, CRYPT_REQUESTTYPE_LAST - 1 ) ),
	MKACL_N(	/* CMP server: Read-only info from client */
		CRYPT_SESSINFO_CMP_REQUESTTYPE,
		ST_NONE, ST_SESS_CMP_SVR, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( CRYPT_REQUESTTYPE_NONE + 1, CRYPT_REQUESTTYPE_LAST - 1 ) ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoSSHChannel[] = {
	MKACL_EX(	/* SSH client: Read/write */
		/* Write = CRYPT_UNUSED to create channel, read = channel number */
		CRYPT_SESSINFO_SSH_CHANNEL, ATTRIBUTE_VALUE_NUMERIC,
		ST_NONE, ST_SESS_SSH, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE_SUBRANGES, allowedSSHChannelSubranges ),
	MKACL_EX(	/* SSH server: Read-only info from client */
		/* Write = CRYPT_UNUSED to create channel, read = channel number */
		CRYPT_SESSINFO_SSH_CHANNEL, ATTRIBUTE_VALUE_NUMERIC,
		ST_NONE, ST_SESS_SSH_SVR, ACCESS_RWx_xxx, 0,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE_SUBRANGES, allowedSSHChannelSubranges ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoSSHChannelType[] = {
	MKACL_S(	/* SSH client: Read/write */
		/* Shortest valid name = "exec" */
		CRYPT_SESSINFO_SSH_CHANNEL_TYPE,
		ST_NONE, ST_SESS_SSH, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 4, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* SSH server: Read-only info from client */
		CRYPT_SESSINFO_SSH_CHANNEL_TYPE,
		ST_NONE, ST_SESS_SSH_SVR, ACCESS_RWx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 7, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END_SUBACL()
	};
static const ATTRIBUTE_ACL FAR_BSS subACL_SessinfoSSHChannelArg1[] = {
	MKACL_S(	/* SSH client: Read/write */
		/* Shortest valid name = "sftp" */
		CRYPT_SESSINFO_SSH_CHANNEL_ARG1,
		ST_NONE, ST_SESS_SSH, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 4, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* SSH server: Read-only info from client */
		CRYPT_SESSINFO_SSH_CHANNEL_ARG1,
		ST_NONE, ST_SESS_SSH_SVR, ACCESS_RWx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 4, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_END_SUBACL()
	};

/* Session attributes */

static const ATTRIBUTE_ACL FAR_BSS sessionACL[] = {
	MKACL_X_EX(	/* Whether session is active */
		CRYPT_SESSINFO_ACTIVE,
		ST_NONE, ST_SESS_ANY, ACCESS_RWx_RWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoActive ),
	MKACL_B(	/* Whether network connection is active */
		CRYPT_SESSINFO_CONNECTIONACTIVE,
		ST_NONE, ST_SESS_ANY, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_SESSION ) ),
	MKACL_X(	/* User name */
		CRYPT_SESSINFO_USERNAME,
		ST_NONE, ST_SESS_ANY_DATA | ST_SESS_CMP | ST_SESS_CMP_SVR | \
				 ST_SESS_SCEP, ACCESS_RWD_RWD,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoUsername ),
	MKACL_X(	/* Password */
		CRYPT_SESSINFO_PASSWORD,
		ST_NONE, ST_SESS_ANY_DATA | ST_SESS_CMP | ST_SESS_SCEP, ACCESS_RWD_RWD,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoPassword ),
	MKACL_X(	/* Server/client private key */
		CRYPT_SESSINFO_PRIVATEKEY,
		ST_NONE, ( ST_SESS_ANY_SVR & ~ST_SESS_CERT_SVR ) | ST_SESS_SSH | \
				 ST_SESS_SSL | ST_SESS_CMP | ST_SESS_SCEP, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoPrivatekey ),
	MKACL_X(	/* Certificate store */
		CRYPT_SESSINFO_KEYSET,
		ST_NONE, ST_SESS_SSL_SVR | ST_SESS_RTCS_SVR | ST_SESS_OCSP_SVR | \
				 ST_SESS_CMP_SVR | ST_SESS_SCEP_SVR | ST_SESS_CERT_SVR, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoKeyset ),
	MKACL_EX(	/* Session authorisation OK */
		CRYPT_SESSINFO_AUTHRESPONSE, ATTRIBUTE_VALUE_NUMERIC,
		ST_NONE, ST_SESS_SSH_SVR, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE_ALLOWEDVALUES, allowedAuthResponses ),
	MKACL_S(	/* Server name */
		CRYPT_SESSINFO_SERVER_NAME,
		ST_NONE, ST_SESS_ANY, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 2, MAX_URL_SIZE ) ),
	MKACL_N(	/* Server port number */
		CRYPT_SESSINFO_SERVER_PORT,
		ST_NONE, ST_SESS_ANY, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 22, 65534L ) ),
	MKACL_X(	/* Server key fingerprint */
		CRYPT_SESSINFO_SERVER_FINGERPRINT,
		ST_NONE, ST_SESS_SSL | ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoFingerprint ),
	MKACL_S(	/* Client name */
		CRYPT_SESSINFO_CLIENT_NAME,
		ST_NONE, ST_SESS_ANY_SVR, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 2, MAX_URL_SIZE ) ),
	MKACL_N(	/* Client port number */
		CRYPT_SESSINFO_CLIENT_PORT,
		ST_NONE, ST_SESS_ANY_SVR, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 22, 65534L ) ),
	MKACL_X(	/* Transport mechanism */
		CRYPT_SESSINFO_SESSION,
		ST_NONE, ST_SESS_RTCS | ST_SESS_RTCS_SVR | \
				 ST_SESS_OCSP | ST_SESS_OCSP_SVR | \
				 ST_SESS_TSP | ST_SESS_TSP_SVR | \
				 ST_SESS_CMP | ST_SESS_CMP_SVR | \
				 ST_SESS_SCEP | ST_SESS_SCEP_SVR, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoSession ),
	MKACL_N(	/* User-supplied network socket */
		CRYPT_SESSINFO_NETWORKSOCKET,
		ST_NONE, ST_SESS_ANY, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE_ANY ),

	MKACL_N(	/* Session protocol version */
		CRYPT_SESSINFO_VERSION,
		ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR | ST_SESS_SSL | \
				 ST_SESS_SSL_SVR | ST_SESS_OCSP | ST_SESS_OCSP_SVR, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		RANGE( 0, 2 ) ),
	MKACL_X(	/* Cert.request object */
		/* The object can be updated in both states for persistent
		   connections */
		CRYPT_SESSINFO_REQUEST,
		ST_NONE, ST_SESS_RTCS | ST_SESS_OCSP | ST_SESS_CMP | ST_SESS_SCEP, ACCESS_xWD_xWD,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoRequest ),
	MKACL_X(	/* Cert.response object */
		CRYPT_SESSINFO_RESPONSE,
		ST_NONE, ST_SESS_SSL | ST_SESS_SSL_SVR | ST_SESS_RTCS | \
				 ST_SESS_OCSP | ST_SESS_TSP | ST_SESS_CMP | ST_SESS_SCEP, ACCESS_Rxx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoResponse ),
	MKACL_O(	/* Issuing CA certificate */
		CRYPT_SESSINFO_CACERTIFICATE,
		ST_NONE, ST_SESS_CMP | ST_SESS_SCEP, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCertificate ),

	MKACL_O(	/* TSP message imprint */
		/* The object can be updated in both states for persistent
		   connections */
		CRYPT_SESSINFO_TSP_MSGIMPRINT,
		ST_NONE, ST_SESS_TSP, ACCESS_xWD_xWD,
		ROUTE( OBJECT_TYPE_SESSION ), &objectCtxHash ),

	MKACL_X(	/* CMP request type */
		CRYPT_SESSINFO_CMP_REQUESTTYPE,
		ST_NONE, ST_SESS_CMP | ST_SESS_CMP_SVR, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoRequesttype ),
	MKACL_B(	/* CMP enable PKIBoot facility */
		CRYPT_SESSINFO_CMP_PKIBOOT,
		ST_NONE, ST_SESS_CMP | ST_SESS_CMP_SVR, ACCESS_xxx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ) ),
	MKACL_O(	/* Private-key keyset */
		CRYPT_SESSINFO_CMP_PRIVKEYSET,
		ST_NONE, ST_SESS_CMP, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_SESSION ), &objectKeysetPrivate ),

	MKACL_X(	/* SSH current channel */
		/* Write = CRYPT_UNUSED to create channel, read = channel number */
		CRYPT_SESSINFO_SSH_CHANNEL,
		ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoSSHChannel ),
	MKACL_X(	/* SSH channel type */
		CRYPT_SESSINFO_SSH_CHANNEL_TYPE,
		ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoSSHChannelType ),
	MKACL_X(	/* SSH channel argument 1 */
		CRYPT_SESSINFO_SSH_CHANNEL_ARG1,
		ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_SESSION ),
		subACL_SessinfoSSHChannelArg1 ),
	MKACL_S(	/* SSH channel argument 2 */
		CRYPT_SESSINFO_SSH_CHANNEL_ARG2,
		ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_RWx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ), RANGE( 5, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_B(	/* SSH channel active */
		CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE,
		ST_NONE, ST_SESS_SSH | ST_SESS_SSH_SVR, ACCESS_RWx_xxx,
		ROUTE( OBJECT_TYPE_SESSION ) ),

	MKACL_END()
	};

/****************************************************************************
*																			*
*									User ACLs								*
*																			*
****************************************************************************/

/* User attributes */

static const ATTRIBUTE_ACL FAR_BSS userACL[] = {
	MKACL_S_EX(	/* Password */
		CRYPT_USERINFO_PASSWORD,
		ST_NONE, ST_USER_ANY, ACCESS_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_USER ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_O(	/* CA cert signing key */
		CRYPT_USERINFO_CAKEY_CERTSIGN,
		ST_NONE, ST_USER_CA, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_O(	/* CA CRL signing key */
		CRYPT_USERINFO_CAKEY_CRLSIGN,
		ST_NONE, ST_USER_CA, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_O(	/* CA RTCS signing key */
		CRYPT_USERINFO_CAKEY_RTCSSIGN,
		ST_NONE, ST_USER_CA, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_O(	/* CA OCSP signing key */
		CRYPT_USERINFO_CAKEY_OCSPSIGN,
		ST_NONE, ST_USER_CA, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),

	MKACL_END()
	};

/****************************************************************************
*																			*
*									Internal ACLs							*
*																			*
****************************************************************************/

static const int FAR_BSS allowedObjectStatusValues[] = {
	CRYPT_OK, CRYPT_ERROR_TIMEOUT, CRYPT_ERROR };

static const ATTRIBUTE_ACL FAR_BSS subACL_IAttributeSubject[] = {
	MKACL_S(	/* CRMF objects: Readable in any state (unsigned in CMP msgs) */
		CRYPT_IATTRIBUTE_SUBJECT,
		ST_CERT_REQ_CERT | ST_CERT_REQ_REV, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Other objects: Object must be in high state */
		CRYPT_IATTRIBUTE_SUBJECT,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CERTREQ | ST_CERT_PKIUSER, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_END_SUBACL()
	};

/* Internal attributes */

static const ATTRIBUTE_ACL FAR_BSS internalACL[] = {
	MKACL_N_EX(	/* Object type */
		CRYPT_IATTRIBUTE_TYPE,
		ST_ANY_A, ST_ANY_B, ACCESS_INT_Rxx_Rxx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( OBJECT_TYPE_NONE + 1, OBJECT_TYPE_LAST - 1 ) ),
	MKACL_N_EX(	/* Object subtype */
		CRYPT_IATTRIBUTE_SUBTYPE,
		ST_ANY_A, ST_ANY_B, ACCESS_INT_Rxx_Rxx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( OBJECT_TYPE_NONE + 1, OBJECT_TYPE_LAST - 1 ) ),
	MKACL_EX(	/* Object status */
		/* Write = status value, read = OBJECT_FLAG_xxx (since an object may
		   be, for example, busy and signalled at the same time) */
		CRYPT_IATTRIBUTE_STATUS, ATTRIBUTE_VALUE_NUMERIC,
		ST_ANY_A, ST_ANY_B, ACCESS_INT_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE_ALLOWEDVALUES, allowedObjectStatusValues ),
	MKACL_B_EX(	/* Object internal flag */
		CRYPT_IATTRIBUTE_INTERNAL,
		ST_ANY_A, ST_ANY_B, ACCESS_INT_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE ),
	MKACL_N_EX(	/* Object action permissions */
		CRYPT_IATTRIBUTE_ACTIONPERMS,
		ST_CTX_ANY, ST_NONE, ACCESS_INT_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( ACTION_PERM_NOTAVAIL, ACTION_PERM_LAST ) ),
	MKACL_B_EX(	/* Object locked for exclusive use */
		CRYPT_IATTRIBUTE_LOCKED,
		ST_CTX_PKC | ST_CTX_CONV | ST_CERT_ANY_CERT | ST_CERT_CRL , ST_NONE, ACCESS_INT_xWx_xWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE ),
	MKACL_N_EX(	/* Object inited (e.g. key loaded, cert signed) */
		CRYPT_IATTRIBUTE_INITIALISED,
		ST_ANY_A, ST_ANY_B, ACCESS_INT_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE_NONE, RANGE( CRYPT_UNUSED, CRYPT_UNUSED ) ),
	MKACL_N(	/* Ctx: Key size (for non-native ctxts) */
		CRYPT_IATTRIBUTE_KEYSIZE,
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC, ST_NONE, ACCESS_INT_xxx_xWx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Ctx: Key feature info */
		CRYPT_IATTRIBUTE_KEYFEATURES,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 0, 16 ) ),
	MKACL_S(	/* Ctx: Key ID */
		CRYPT_IATTRIBUTE_KEYID,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 20, 20 ) ),
	MKACL_S(	/* Ctx: PGP key ID */
		CRYPT_IATTRIBUTE_KEYID_PGP,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8, 8 ) ),
	MKACL_S(	/* Ctx: OpenPGP key ID */
		/* This attribute is writeable in the high state since it may be
		   retroactively set for objects for which the value couldn't be
		   calculated at object instantiation time, for example a
		   certificate that has the OpenPGP information stored alongside
		   it */
		CRYPT_IATTRIBUTE_KEYID_OPENPGP,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_RWx_RWx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8, 8 ) ),
	MKACL_S(	/* Ctx: Key agreement domain parameters */
		CRYPT_IATTRIBUTE_KEY_KEADOMAINPARAMS,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 10, 10 ) ),
	MKACL_S(	/* Ctx: Key agreement public value */
		CRYPT_IATTRIBUTE_KEY_KEAPUBLICVALUE,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( bitsToBytes( MIN_PKCSIZE_BITS ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_S_EX(	/* Ctx: SubjectPublicKeyInfo */
		/* The attribute length values are only approximate because there's
		   wrapper data involved, and (for the maximum length) several of
		   the DLP PKC values are only a fraction of CRYPT_MAX_PKCSIZE, the
		   rest of the space requirement being allocated to the wrapper */
		CRYPT_IATTRIBUTE_KEY_SPKI,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_Rxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8 + bitsToBytes( MIN_PKCSIZE_BITS ), CRYPT_MAX_PKCSIZE * 4 ) ),
	MKACL_S_EX(	/* Ctx: PGP-format public key */
		CRYPT_IATTRIBUTE_KEY_PGP,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_Rxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 10 + bitsToBytes( MIN_PKCSIZE_BITS ), CRYPT_MAX_PKCSIZE * 4 ) ),
	MKACL_S_EX(	/* Ctx: SSH-format public key */
		CRYPT_IATTRIBUTE_KEY_SSH,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_Rxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 16 + bitsToBytes( MIN_PKCSIZE_BITS ), ( CRYPT_MAX_PKCSIZE * 4 ) + 20 ) ),
	MKACL_S_EX(	/* Ctx: SSHv1-format public key */
		CRYPT_IATTRIBUTE_KEY_SSH1,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_Rxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8 + bitsToBytes( MIN_PKCSIZE_BITS ), CRYPT_MAX_PKCSIZE + 10 ) ),
	MKACL_S_EX(	/* Ctx: SSL-format public key */
		CRYPT_IATTRIBUTE_KEY_SSL,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_Rxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 16 + bitsToBytes( MIN_PKCSIZE_BITS ), ( CRYPT_MAX_PKCSIZE * 4 ) + 20 ) ),
	MKACL_S(	/* Ctx: SubjectPublicKeyInfo w/o trigger */
		CRYPT_IATTRIBUTE_KEY_SPKI_PARTIAL,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_xxx_xWx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 8 + bitsToBytes( MIN_PKCSIZE_BITS ), CRYPT_MAX_PKCSIZE * 4 ) ),
	MKACL_S(	/* Ctx: PGP public key w/o trigger */
		CRYPT_IATTRIBUTE_KEY_PGP_PARTIAL,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_xxx_xWx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 10 + bitsToBytes( MIN_PKCSIZE_BITS ), CRYPT_MAX_PKCSIZE * 3 ) ),
	MKACL_T(	/* Ctx: PGP key validity */
		/* This attribute is writeable in the high state since it may be
		   retroactively set for objects for which the value couldn't be
		   calculated at object instantiation time, for example a
		   certificate that has the OpenPGP information stored alongside
		   it */
		CRYPT_IATTRIBUTE_PGPVALIDITY,
		ST_CTX_PKC, ST_NONE, ACCESS_INT_RWx_RWx,
		ROUTE( OBJECT_TYPE_CONTEXT ) ),
	MKACL_N(	/* Ctx: Device object handle */
		CRYPT_IATTRIBUTE_DEVICEOBJECT,
		ST_CTX_ANY, ST_NONE, ACCESS_INT_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE_ANY ),
	MKACL_S(	/* Cert: Individual entry from CRL */
		CRYPT_IATTRIBUTE_CRLENTRY,
		ST_CERT_CRL, ST_NONE, ACCESS_INT_Rxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 8, MAX_ATTRIBUTE_SIZE ) ),
	MKACL_X(	/* Cert: SubjectName */
		/* Although in theory this attribute should only be present for
		   signed cert objects, it also exists in CRMF objects that are
		   being used as CMP revocation requests and that aren't signed and
		   are therefore never in the high state.  Because of this we have to
		   allow reads in the low state for this one object type */
		CRYPT_IATTRIBUTE_SUBJECT,
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_REQ_CERT | ST_CERT_REQ_REV | \
					   ST_CERT_CERTCHAIN | ST_CERT_PKIUSER, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), subACL_IAttributeSubject ),
	MKACL_S(	/* Cert: IssuerName */
		CRYPT_IATTRIBUTE_ISSUER,
		ST_CERT_CERT | ST_CERT_REQ_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Cert: IssuerAndSerial */
		CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_REQ_REV | ST_CERT_CRL, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Cert: Encoded SubjectPublicKeyInfo */
		/* Although we never need to extract the SPKI from a CRMF request, we
		   have to be able to read it so we can do a presence check since we
		   can't issue a cert without having a public key present (although
		   this would be detcted later on, it allows us to report the error
		   at an earlier stage by explicitly checking).  Since the same
		   checks are also applied to PKCS #10 cert requests, we also have to
		   make it readable for those */
		CRYPT_IATTRIBUTE_SPKI,
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CERTREQ | ST_CERT_REQ_CERT, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, CRYPT_MAX_PKCSIZE * 3 ) ),
	MKACL_N(	/* Cert: Hash algo.used for cert */
		/* Although this attribute is technically valid for most cert types,
		   it's only used with standard certificates, where it's used as
		   an implicit indicator of the preferred hash algorithm to use when
		   signing data */
		CRYPT_IATTRIBUTE_CERTHASHALGO,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( CRYPT_ALGO_FIRST_HASH, CRYPT_ALGO_LAST_HASH ) ),
	MKACL_O_EX(	/* Cert: Certs added to cert chain */
		/* This attribute is marked as a trigger attribute since the cert
		   chain object it affects doesn't contain a true chain of certs but
		   only a collection of non-duplicate certs that are never
		   explicitly signed.  To allow it to function as a normal cert
		   chain, we move it into the high state as soon as at least on cert
		   is added.  In addition, this is a retriggerable attribute in that
		   further data can be added after the initial trigger action */
		CRYPT_IATTRIBUTE_CERTCOLLECTION,
		ST_CERT_CERTCHAIN, ST_NONE, ACCESS_INT_xWx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertificate ),
	MKACL_S(	/* Cert: RTCS/OCSP responder name */
		CRYPT_IATTRIBUTE_RESPONDERURL,
		ST_CERT_RTCS_REQ | ST_CERT_OCSP_REQ, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_O(	/* Cert: RTCS req.info added to RTCS resp.*/
		CRYPT_IATTRIBUTE_RTCSREQUEST,
		ST_CERT_RTCS_RESP, ST_NONE, ACCESS_INT_xxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertRTCSRequest ),
	MKACL_O(	/* Cert: OCSP req.info added to OCSP resp.*/
		CRYPT_IATTRIBUTE_OCSPREQUEST,
		ST_CERT_OCSP_RESP, ST_NONE, ACCESS_INT_xxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertOCSPRequest ),
	MKACL_O_EX(	/* Cert: CRMF rev.request added to CRL */
		/* This is marked as a trigger attribute since it's used to create a
		   CRL template from a CRMF request (i.e. to turn a CRMF revocation
		   request into something that the rest of cryptlib can work with),
		   so adding it has to create a pseudosigned CRL from which we can
		   read things like the encoded CRL entry and the
		   issuerAndSerialNumber */
		CRYPT_IATTRIBUTE_REVREQUEST,
		ST_CERT_CRL, ST_NONE, ACCESS_INT_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertRevRequest ),
	MKACL_O(	/* Cert: Additional user info added to cert.request */
		CRYPT_IATTRIBUTE_PKIUSERINFO,
		ST_CERT_CERTREQ | ST_CERT_REQ_CERT, ST_NONE, ACCESS_INT_xWx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertPKIUser ),
	MKACL_O(	/* Cert: Template of disallowed attrs.in cert */
		CRYPT_IATTRIBUTE_BLOCKEDATTRS,
		ST_CERT_CERT, ST_NONE, ACCESS_INT_xxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), &objectCertificateTemplate ),
	MKACL_S(	/* Cert: Authorising cert ID for a cert/rev.request */
		CRYPT_IATTRIBUTE_AUTHCERTID,
		ST_CERT_REQ_CERT | ST_CERT_REQ_REV, ST_NONE, ACCESS_INT_RWx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 20, 20 ) ),
	MKACL_S(	/* Cert: ESSCertID */
		CRYPT_IATTRIBUTE_ESSCERTID,
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 32, 8192 ) ),
	MKACL_S(	/* Dev: Polled entropy data */
		CRYPT_IATTRIBUTE_ENTROPY,
		ST_DEV_ANY, ST_NONE, ACCESS_INT_xWx_xWx,
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( 1, MAX_INTLENGTH ) ),
	MKACL_N(	/* Dev: Quality of entropy */
		CRYPT_IATTRIBUTE_ENTROPY_QUALITY,
		ST_DEV_ANY, ST_NONE, ACCESS_INT_xWx_xWx,
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( 1, 100 ) ),
	MKACL_N(	/* Dev: Low picket for random data attrs.*/
		/* This and the high picket are used to protect the critical
		   randomness attributes from accidental access due to fencepost
		   errors or similar problems. They're marked as non-accessible numeric
		   attributes (randomness is a string attribute) to ensure they'll both
		   be trapped as an error in the debug kernel and rejected in normal
		   use */
		CRYPT_IATTRIBUTE_RANDOM_LOPICKET,
		ST_DEV_ANY, ST_NONE, ACCESS_INT_xxx_xxx,
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( 0, 0 ) ),
	MKACL_S(	/* Dev: Random data */
		CRYPT_IATTRIBUTE_RANDOM,
		ST_DEV_ANY, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_S(	/* Dev: Nonzero random data */
		CRYPT_IATTRIBUTE_RANDOM_NZ,
		ST_DEV_ANY, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Dev: High picket for random data attrs.*/
		CRYPT_IATTRIBUTE_RANDOM_HIPICKET,
		ST_DEV_ANY, ST_NONE, ACCESS_INT_xxx_xxx,
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( 0, 0 ) ),
	MKACL_S(	/* Dev: Basic nonce */
		CRYPT_IATTRIBUTE_RANDOM_NONCE,
		ST_DEV_SYSTEM, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ), RANGE( 1, 16384 ) ),
	MKACL_EX(	/* Dev: Perform self-test */
		CRYPT_IATTRIBUTE_SELFTEST, ATTRIBUTE_VALUE_NUMERIC,
		ST_DEV_SYSTEM, ST_NONE, ACCESS_INT_xWx_xWx, 0,
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ),
		RANGE_SUBRANGES, allowedSelftestSubranges ),
	MKACL_T(	/* Dev: Reliable (hardware-based) time value */
		CRYPT_IATTRIBUTE_TIME,
		ST_DEV_ANY, ST_NONE, ACCESS_INT_Rxx_xxx,
		ROUTE_FIXED( OBJECT_TYPE_DEVICE ) ),
	MKACL_B(	/* Env: Whether to include signing cert(s) */
		CRYPT_IATTRIBUTE_INCLUDESIGCERT,
		ST_NONE, ST_ENV_ENV, ACCESS_INT_xxx_xWx,
		ROUTE_FIXED( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_B(	/* Env: Signed data contains only CMS attrs.*/
		CRYPT_IATTRIBUTE_ATTRONLY,
		ST_NONE, ST_ENV_ENV | ST_ENV_DEENV, ACCESS_INT_xWx_xWx,
		ROUTE_FIXED( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_S(	/* Keyset: Config information */
		CRYPT_IATTRIBUTE_CONFIGDATA,
		ST_KEYSET_FILE, ST_NONE, ACCESS_INT_RWx_RWx,
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( 8, 16384 ) ),
	MKACL_S(	/* Keyset: Index of users */
		/* The odd low length range is used to delete user info by setting
		   a zero-length SEQUENCE (this should really be done as yet another
		   keyset item type in order to allow it to be explicitly deleted,
		   rather than using a zero-length write to indicate a delete) */
		CRYPT_IATTRIBUTE_USERINDEX,
		ST_KEYSET_FILE, ST_NONE, ACCESS_INT_RWx_RWx,
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( 2, 16384 ) ),
	MKACL_S(	/* Keyset: User ID */
		CRYPT_IATTRIBUTE_USERID,
		ST_KEYSET_FILE, ST_NONE, ACCESS_INT_RWx_RWx,
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( KEYID_SIZE, KEYID_SIZE ) ),
	MKACL_S(	/* Keyset: User information */
		CRYPT_IATTRIBUTE_USERINFO,
		ST_KEYSET_FILE, ST_NONE, ACCESS_INT_RWx_RWx,
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( 64, 16384 ) ),
	MKACL_S(	/* Keyset: First trusted cert */
		CRYPT_IATTRIBUTE_TRUSTEDCERT,
		ST_KEYSET_FILE, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( 64, 2048 ) ),
	MKACL_S(	/* Keyset: Successive trusted certs */
		CRYPT_IATTRIBUTE_TRUSTEDCERT_NEXT,
		ST_KEYSET_FILE, ST_NONE, ACCESS_INT_Rxx_Rxx,
		ROUTE_FIXED( OBJECT_TYPE_KEYSET ), RANGE( 64, 2048 ) ),
	MKACL_S(	/* Session: Encoded TSA timestamp */
		CRYPT_IATTRIBUTE_ENC_TIMESTAMP,
		ST_NONE, ST_SESS_TSP, ACCESS_INT_Rxx_xxx,
		ROUTE_FIXED( OBJECT_TYPE_SESSION ), RANGE( 128, 8192 ) ),
	MKACL_O(	/* User: Keyset to send trusted certs to */
		CRYPT_IATTRUBUTE_CERTKEYSET,
		ST_NONE, ST_USER_ANY, ACCESS_INT_xWx_xxx,
		ROUTE( OBJECT_TYPE_USER ), &objectKeysetConfigdata ),
	MKACL_O(	/* User: Cert.trust list */
		CRYPT_IATTRIBUTE_CTL,
		ST_NONE, ST_USER_ANY, ACCESS_INT_RWx_xxx,
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_O(	/* User: Set trusted cert */
		CRYPT_IATTRIBUTE_CERT_TRUSTED,
		ST_NONE, ST_USER_ANY, ACCESS_INT_xWx_xxx,
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_O(	/* User: Unset trusted cert */
		CRYPT_IATTRIBUTE_CERT_UNTRUSTED,
		ST_NONE, ST_USER_ANY, ACCESS_INT_xWx_xxx,
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_O(	/* User: Check trust status of cert */
		CRYPT_IATTRIBUTE_CERT_CHECKTRUST,
		ST_NONE, ST_USER_ANY, ACCESS_INT_xWx_xxx,
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),
	MKACL_O(	/* User: Get trusted issuer of cert */
		CRYPT_IATTRIBUTE_CERT_TRUSTEDISSUER,
		ST_NONE, ST_USER_ANY, ACCESS_INT_xWx_xxx,
		ROUTE( OBJECT_TYPE_USER ), &objectCertificate ),

	MKACL_END()
	};

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* Check that a special range entry is consistent */

static BOOLEAN specialRangeConsistent( const ATTRIBUTE_ACL *attributeACL )
	{
	switch( getSpecialRangeType( attributeACL ) )
		{
		case RANGEVAL_ANY:
		case RANGEVAL_SELECTVALUE:
			if( getSpecialRangeInfo( attributeACL ) != NULL )
				return( FALSE );
			break;

		case RANGEVAL_ALLOWEDVALUES:
			{
			const int *rangeVal = getSpecialRangeInfo( attributeACL );
			int i;

			if( rangeVal == NULL )
				return( FALSE );
			for( i = 0; i < 5; i++ )
				if( *rangeVal++ == CRYPT_ERROR )
					break;
			if( i >= 5 )
				return( FALSE );
			break;
			}

		case RANGEVAL_SUBRANGES:
			{
			const RANGE_SUBRANGE_TYPE *rangeVal = \
									getSpecialRangeInfo( attributeACL );
			int i;

			if( rangeVal == NULL )
				return( FALSE );
			for( i = 0; i < 5; i++ )
				{
				if( rangeVal->highRange == CRYPT_ERROR )
					break;
				if( rangeVal->lowRange < 0 )
					{
					if( !( rangeVal->lowRange < 0 && \
						   rangeVal->highRange < 0 ) || \
						rangeVal->lowRange < rangeVal->highRange )
						return( FALSE );
					}
				else
					if( !( rangeVal->lowRange >= 0 && \
						   rangeVal->highRange >= 0 ) || \
						rangeVal->lowRange > rangeVal->highRange )
						return( FALSE );
				rangeVal++;
				}
			if( i >= 5 )
				return( FALSE );
			break;
			}

		default:
			return( FALSE );
		}

	return( TRUE );
	}

/* Check that an ACL is consistent */

#define ACCESS_RWx_xxx		0x6060	/* Special-case used for consistency check */

static BOOLEAN aclConsistent( const ATTRIBUTE_ACL *attributeACL,
							  const CRYPT_ATTRIBUTE_TYPE attribute,
							  const OBJECT_SUBTYPE subTypeA, 
							  const OBJECT_SUBTYPE subTypeB )
	{
	/* General consistency checks.  We can only check the attribute type in
	   the debug build because it's not present in the release to save
	   space */
#ifndef NDEBUG
	if( attributeACL->attribute != attribute )
		return( FALSE );
#endif /* !NDEBUG */
	if( attributeACL->flags >= ATTRIBUTE_FLAG_LAST )
		return( FALSE );
	if( ( attributeACL->subTypeA & SUBTYPE_CLASS_B ) || \
		( attributeACL->subTypeB & SUBTYPE_CLASS_A ) )
		return( FALSE );
	if( ( attributeACL->subTypeA & ~( SUBTYPE_CLASS_A | subTypeA ) ) != 0 || \
		( attributeACL->subTypeB & ~( SUBTYPE_CLASS_B | subTypeB ) ) != 0 )
		return( FALSE );

	/* ACL-specific checks */
	switch( attributeACL->valueType )
		{
		case ATTRIBUTE_VALUE_BOOLEAN:
			/* Some boolean values can only be set to TRUE or FALSE, so it's
			   possible to have a range of { FALSE, FALSE } or
			   { TRUE, TRUE } */
			if( ( attributeACL->lowRange != FALSE && \
				  attributeACL->lowRange != TRUE ) || \
				( attributeACL->highRange != FALSE && \
				  attributeACL->highRange != TRUE ) || \
				attributeACL->extendedInfo != NULL )
				return( FALSE );
			break;

		case ATTRIBUTE_VALUE_NUMERIC:
			if( isSpecialRange( attributeACL ) )
				{
				if( !specialRangeConsistent( attributeACL ) )
					return( FALSE );
				}
			else
				{
				if( attributeACL->lowRange < 0 )
					{
					if( !( attributeACL->lowRange < 0 && \
						   attributeACL->highRange < 0 ) || \
						attributeACL->lowRange < attributeACL->highRange )
						return( FALSE );
					}
				else
					if( !( attributeACL->lowRange >= 0 && \
						   attributeACL->highRange >= 0 ) || \
						attributeACL->lowRange > attributeACL->highRange )
						return( FALSE );
				if( attributeACL->extendedInfo != NULL )
					return( FALSE );
				}
			break;

		case ATTRIBUTE_VALUE_STRING:
			if( isSpecialRange( attributeACL ) )
				{
				if( getSpecialRangeType( attributeACL ) != RANGEVAL_ALLOWEDVALUES || \
					getSpecialRangeInfo( attributeACL ) == NULL )
					return( FALSE );
				if( !specialRangeConsistent( attributeACL ) )
					return( FALSE );
				}
			else
				{
				/* The special-case check for MAX_INTLENGTH is needed for
				   polled entropy data, which can be of arbitrary length */
				if( attributeACL->extendedInfo != NULL )
					return( FALSE );
				if( attributeACL->lowRange < 0 || \
					( attributeACL->highRange > 16384 && \
					  attributeACL->highRange != MAX_INTLENGTH ) || \
					attributeACL->lowRange > attributeACL->highRange )
					return( FALSE );
				}
			break;

		case ATTRIBUTE_VALUE_WCSTRING:
			if( attributeACL->extendedInfo != NULL )
				return( FALSE );
			if( attributeACL->lowRange < 0 || \
				attributeACL->highRange > 16384 || \
				attributeACL->lowRange > attributeACL->highRange )
				return( FALSE );
			break;

		case ATTRIBUTE_VALUE_OBJECT:
			if( attributeACL->lowRange != 0 || \
				attributeACL->highRange != 0 || \
				attributeACL->extendedInfo == NULL )
				return( FALSE );
			break;

		case ATTRIBUTE_VALUE_TIME:
			if( attributeACL->lowRange != 0 || \
				attributeACL->highRange != 0 || \
				attributeACL->extendedInfo != NULL )
				return( FALSE );
			break;

		case ATTRIBUTE_VALUE_SPECIAL:
			{
			const ATTRIBUTE_ACL *attributeACLPtr;
			int access = attributeACL->access;
			int subTypes = attributeACL->subTypeA | \
						   attributeACL->subTypeB;
			int iterationCount;

			if( !isSpecialRange( attributeACL ) || \
				getSpecialRangeType( attributeACL ) != RANGEVAL_SUBTYPED || \
				getSpecialRangeInfo( attributeACL ) == NULL )
				return( FALSE );

			/* Recursively check the sub-ACLs */
			for( attributeACLPtr = getSpecialRangeInfo( attributeACL ), \
					iterationCount = 0;
				 attributeACLPtr->valueType != ATTRIBUTE_VALUE_NONE && \
					iterationCount++ < FAILSAFE_ITERATIONS_MED;
				 attributeACLPtr++ )
				{
#ifndef NDEBUG
				if( !aclConsistent( attributeACLPtr, attributeACL->attribute,
									attributeACL->subTypeA,
									attributeACL->subTypeB ) )
#else
				if( !aclConsistent( attributeACLPtr, CRYPT_ATTRIBUTE_NONE,
									attributeACL->subTypeA,
									attributeACL->subTypeB ) )
#endif /* !NDEBUG */
					return( FALSE );
				}
			if( iterationCount >= FAILSAFE_ITERATIONS_MED )
				retIntError_Boolean();

			/* Make sure that all subtypes and acess settings in the main
			   attribute are handled in the sub-attributes */
			for( attributeACLPtr = getSpecialRangeInfo( attributeACL ), \
					iterationCount = 0;
				 attributeACLPtr->valueType != ATTRIBUTE_VALUE_NONE && \
					iterationCount++ < FAILSAFE_ITERATIONS_MED;
				 attributeACLPtr++ )
				{
				subTypes &= ~( attributeACLPtr->subTypeA | \
							   attributeACLPtr->subTypeB );
				access &= ~attributeACLPtr->access;
				}
			if( iterationCount >= FAILSAFE_ITERATIONS_MED )
				retIntError_Boolean();
			if( subTypes != 0 || access != 0 )
				return( FALSE );
			break;
			}

		default:
			return( FALSE );
		}

	return( TRUE );
	}

int initAttributeACL( KERNEL_DATA *krnlDataPtr )
	{
	int i;

	UNUSED( krnlDataPtr );

	/* Perform a consistency check on values used to handle ACL subranges.
	   These are somewhat tricky to check automatically since they represent
	   variable start and end ranges, we hardcode in absolute values to
	   ensure that adding new attributes in the header file will trigger an
	   exception here to provide a reminder to change the range-end
	   definitions as well */
	assert( CRYPT_CERTINFO_FIRST_CERTINFO == 2001 );
	assert( CRYPT_CERTINFO_LAST_CERTINFO == 2031 );
	assert( CRYPT_CERTINFO_FIRST_PSEUDOINFO == 2001 );
	assert( CRYPT_CERTINFO_LAST_PSEUDOINFO == 2010 );
	assert( CRYPT_CERTINFO_FIRST_NAME == 2100 );
	assert( CRYPT_CERTINFO_LAST_NAME == 2115 );
	assert( CRYPT_CERTINFO_FIRST_DN == 2100 );
	assert( CRYPT_CERTINFO_LAST_DN == 2105 );
	assert( CRYPT_CERTINFO_FIRST_GENERALNAME == 2106 );
	assert( CRYPT_CERTINFO_LAST_GENERALNAME == 2115 );
	assert( CRYPT_CERTINFO_FIRST_EXTENSION == 2200 );
	assert( CRYPT_CERTINFO_FIRST_CMS == 2500 );
	assert( CRYPT_SESSINFO_FIRST_SPECIFIC == 6016 );
	assert( CRYPT_SESSINFO_LAST_SPECIFIC == 6027 );
	assert( CRYPT_CERTFORMAT_LAST == 11 );

	/* Perform a consistency check on the attribute ACLs.  The ACLs are
	   complex enough that we assert on each one to quickly catch problems
	   when one is changed */
	for( i = 0; i < CRYPT_PROPERTY_LAST - CRYPT_PROPERTY_FIRST - 1 && \
				i < FAILSAFE_ARRAYSIZE( propertyACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &propertyACL[ i ], i + CRYPT_PROPERTY_FIRST + 1,
							ST_ANY_A, ST_ANY_B ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( propertyACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( propertyACL[ CRYPT_PROPERTY_LAST - \
					 CRYPT_PROPERTY_FIRST - 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_GENERIC_LAST - CRYPT_GENERIC_FIRST - 1 && \
				i < FAILSAFE_ARRAYSIZE( genericACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &genericACL[ i ], i + CRYPT_GENERIC_FIRST + 1,
							ST_ANY_A, ST_ANY_B ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( genericACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( genericACL[ CRYPT_GENERIC_LAST - \
					CRYPT_GENERIC_FIRST - 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST - 1 && \
				i < FAILSAFE_ARRAYSIZE( optionACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &optionACL[ i ], i + CRYPT_OPTION_FIRST + 1,
							ST_CTX_CONV | ST_CTX_PKC | ST_KEYSET_LDAP,
							ST_ENV_ENV | ST_ENV_ENV_PGP | ST_SESS_ANY | \
								ST_USER_ANY ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
#ifndef NDEBUG
		if( optionACL[ i ].attribute >= CRYPT_OPTION_KEYING_ALGO && \
			optionACL[ i ].attribute <= CRYPT_OPTION_KEYING_ITERATIONS )
			{
			if( optionACL[ i ].subTypeA != ST_CTX_CONV )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			}
		else
		if( optionACL[ i ].attribute >= CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS && \
			optionACL[ i ].attribute <= CRYPT_OPTION_KEYS_LDAP_EMAILNAME )
			{
			if( optionACL[ i ].subTypeA != ST_KEYSET_LDAP )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			}
		else
		if( optionACL[ i ].attribute == CRYPT_OPTION_MISC_SIDECHANNELPROTECTION )
			{
			if( optionACL[ i ].subTypeA != ST_CTX_PKC )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			}
		else
		if( optionACL[ i ].subTypeA != ST_NONE )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		if( optionACL[ i ].attribute >= CRYPT_OPTION_ENCR_ALGO && \
			optionACL[ i ].attribute <= CRYPT_OPTION_ENCR_MAC )
			{
			if( optionACL[ i ].subTypeB & ~( SUBTYPE_CLASS_B | ST_ENV_ENV | \
											 ST_ENV_ENV_PGP | ST_USER_ANY ) )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			}
		else
		if( optionACL[ i ].attribute >= CRYPT_OPTION_NET_SOCKS_SERVER && \
			optionACL[ i ].attribute <= CRYPT_OPTION_NET_WRITETIMEOUT )
			{
			if( optionACL[ i ].subTypeB != ( ST_SESS_ANY | ST_USER_ANY ) )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			}
		else
		if( optionACL[ i ].subTypeB & ~( SUBTYPE_CLASS_B | ST_USER_ANY ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
#endif /* !NDEBUG */
		}
	if( i >= FAILSAFE_ARRAYSIZE( optionACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( optionACL[ CRYPT_OPTION_LAST - \
				   CRYPT_OPTION_FIRST - 1 ].attribute != CRYPT_ERROR )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_CTXINFO_LAST - CRYPT_CTXINFO_FIRST - 1 && \
				i < FAILSAFE_ARRAYSIZE( contextACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &contextACL[ i ], i + CRYPT_CTXINFO_FIRST + 1,
							ST_CTX_ANY, ST_NONE ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( contextACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( contextACL[ CRYPT_CTXINFO_LAST - \
					CRYPT_CTXINFO_FIRST - 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_CERTINFO_LAST_CERTINFO - CRYPT_CERTINFO_FIRST_CERTINFO && \
				i < FAILSAFE_ARRAYSIZE( certificateACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &certificateACL[ i ],
							i + CRYPT_CERTINFO_FIRST_CERTINFO,
							ST_CERT_ANY, ST_NONE ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( certificateACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( certificateACL[ CRYPT_CERTINFO_LAST_CERTINFO - \
						CRYPT_CERTINFO_FIRST_CERTINFO + 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_CERTINFO_LAST_NAME - CRYPT_CERTINFO_FIRST_NAME && \
				i < FAILSAFE_ARRAYSIZE( certNameACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &certNameACL[ i ], i + CRYPT_CERTINFO_FIRST_NAME,
							ST_CERT_ANY, ST_NONE ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
#ifndef NDEBUG
		if( certNameACL[ i ].attribute != CRYPT_CERTINFO_DIRECTORYNAME && \
			certNameACL[ i ].access != ACCESS_Rxx_RWD )
			return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
		}
	if( i >= FAILSAFE_ARRAYSIZE( certNameACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( certNameACL[ CRYPT_CERTINFO_LAST_NAME - \
					 CRYPT_CERTINFO_FIRST_NAME + 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_CERTINFO_LAST_EXTENSION - CRYPT_CERTINFO_FIRST_EXTENSION && \
				i < FAILSAFE_ARRAYSIZE( certExtensionACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &certExtensionACL[ i ],
							i + CRYPT_CERTINFO_FIRST_EXTENSION,
							ST_CERT_ANY, ST_NONE ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}

		if( ( certExtensionACL[ i ].access & ACCESS_RWD_xxx ) != \
			( ( certExtensionACL[ i ].lowRange == RANGE_EXT_MARKER && \
				certExtensionACL[ i ].highRange == RANGEVAL_SELECTVALUE ) ?
			  ACCESS_RWx_xxx : ACCESS_Rxx_xxx ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( certExtensionACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( certExtensionACL[ CRYPT_CERTINFO_LAST_EXTENSION - \
						  CRYPT_CERTINFO_FIRST_EXTENSION + 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_CERTINFO_LAST_CMS - CRYPT_CERTINFO_FIRST_CMS && \
				i < FAILSAFE_ARRAYSIZE( certSmimeACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &certSmimeACL[ i ], i + CRYPT_CERTINFO_FIRST_CMS,
							ST_CERT_CMSATTR | ST_CERT_RTCS_REQ, ST_NONE ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
#ifndef NDEBUG
		if( certSmimeACL[ i ].attribute == CRYPT_CERTINFO_CMS_NONCE )
			{
			if( certSmimeACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_CERT_CMSATTR | \
												ST_CERT_RTCS_REQ ) )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
			}
		else
			if( certSmimeACL[ i ].subTypeA & ~( SUBTYPE_CLASS_A | ST_CERT_CMSATTR ) )
				{
				assert( NOTREACHED );
				return( CRYPT_ERROR_FAILED );
				}
#endif /* !NDEBUG */
		if( ( certSmimeACL[ i ].access & ACCESS_RWD_xxx ) != \
			( ( certSmimeACL[ i ].lowRange == RANGE_EXT_MARKER && \
				certSmimeACL[ i ].highRange == RANGEVAL_SELECTVALUE ) ?
			  ACCESS_RWx_xxx : ACCESS_Rxx_xxx ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( certSmimeACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( certSmimeACL[ CRYPT_CERTINFO_LAST_CMS - \
					  CRYPT_CERTINFO_FIRST_CMS + 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_KEYINFO_LAST - CRYPT_KEYINFO_FIRST - 1 && \
				i < FAILSAFE_ARRAYSIZE( keysetACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &keysetACL[ i ], i + CRYPT_KEYINFO_FIRST + 1,
							ST_KEYSET_ANY, ST_NONE ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( keysetACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( keysetACL[ CRYPT_KEYINFO_LAST - \
				   CRYPT_KEYINFO_FIRST - 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_DEVINFO_LAST - CRYPT_DEVINFO_FIRST - 1 && \
				i < FAILSAFE_ARRAYSIZE( deviceACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &deviceACL[ i ], i + CRYPT_DEVINFO_FIRST + 1,
							ST_DEV_ANY_STD, ST_NONE ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( deviceACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( deviceACL[ CRYPT_DEVINFO_LAST - \
				   CRYPT_DEVINFO_FIRST - 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_ENVINFO_LAST - CRYPT_ENVINFO_FIRST - 1 && \
				i < FAILSAFE_ARRAYSIZE( envelopeACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &envelopeACL[ i ], i + CRYPT_ENVINFO_FIRST + 1,
							ST_NONE, ST_ENV_ANY ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( envelopeACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( envelopeACL[ CRYPT_ENVINFO_LAST - \
					 CRYPT_ENVINFO_FIRST - 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_SESSINFO_LAST - CRYPT_SESSINFO_FIRST - 1 && \
				i < FAILSAFE_ARRAYSIZE( sessionACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &sessionACL[ i ], i + CRYPT_SESSINFO_FIRST + 1,
							ST_NONE, ST_SESS_ANY ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( sessionACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( sessionACL[ CRYPT_SESSINFO_LAST - \
					CRYPT_SESSINFO_FIRST - 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_USERINFO_LAST - CRYPT_USERINFO_FIRST - 1 && \
				i < FAILSAFE_ARRAYSIZE( userACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &userACL[ i ], i + CRYPT_USERINFO_FIRST + 1,
							ST_NONE, ST_USER_ANY ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( userACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( userACL[ CRYPT_USERINFO_LAST - \
				 CRYPT_USERINFO_FIRST - 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */
	for( i = 0; i < CRYPT_IATTRIBUTE_LAST - CRYPT_IATTRIBUTE_FIRST - 1 && \
				i < FAILSAFE_ARRAYSIZE( internalACL, ATTRIBUTE_ACL ); i++ )
		{
		if( !aclConsistent( &internalACL[ i ],
							i + CRYPT_IATTRIBUTE_FIRST + 1,
							ST_ANY_A, ST_ANY_B ) )
			{
			assert( NOTREACHED );
			return( CRYPT_ERROR_FAILED );
			}
		if( ( internalACL[ i ].access & ACCESS_MASK_EXTERNAL ) != 0 )
			return( CRYPT_ERROR_FAILED );
		}
	if( i >= FAILSAFE_ARRAYSIZE( internalACL, ATTRIBUTE_ACL ) )
		retIntError();
#ifndef NDEBUG
	if( internalACL[ CRYPT_IATTRIBUTE_LAST - \
					 CRYPT_IATTRIBUTE_FIRST - 1 ].attribute != CRYPT_ERROR )
		return( CRYPT_ERROR_FAILED );
#endif /* !NDEBUG */

	return( CRYPT_OK );
	}

void endAttributeACL( void )
	{
	}

/****************************************************************************
*																			*
*								ACL Lookup Functions						*
*																			*
****************************************************************************/

/* Find the ACL for an object attribute */

const void *findAttributeACL( const CRYPT_ATTRIBUTE_TYPE attribute,
							  const BOOLEAN isInternalMessage )
	{
	/* Precondition: If it's an internal message (i.e. not raw data from the
	   user) then the attribute is valid */
	PRE( !isInternalMessage || \
		 isAttribute( attribute ) || isInternalAttribute( attribute ) );

	/* Perform a hardcoded binary search for the attribute ACL, this minimises
	   the number of comparisons necessary to find a match */
	if( attribute < CRYPT_CTXINFO_LAST )
		{
		if( attribute < CRYPT_GENERIC_LAST )
			{
			if( attribute > CRYPT_PROPERTY_FIRST && \
				attribute < CRYPT_PROPERTY_LAST )
				{
				POST( propertyACL[ attribute - CRYPT_PROPERTY_FIRST - 1 ].attribute == attribute );
				return( &propertyACL[ attribute - CRYPT_PROPERTY_FIRST - 1 ] );
				}
			if( attribute > CRYPT_GENERIC_FIRST && \
				attribute < CRYPT_GENERIC_LAST )
				{
				POST( genericACL[ attribute - CRYPT_GENERIC_FIRST - 1 ].attribute == attribute );
				return( &genericACL[ attribute - CRYPT_GENERIC_FIRST - 1 ] );
				}
			}
		else
			{
			if( attribute > CRYPT_OPTION_FIRST && \
				attribute < CRYPT_OPTION_LAST )
				{
				POST( optionACL[ attribute - CRYPT_OPTION_FIRST - 1 ].attribute == attribute );
				return( &optionACL[ attribute - CRYPT_OPTION_FIRST - 1 ] );
				}
			if( attribute > CRYPT_CTXINFO_FIRST && \
				attribute < CRYPT_CTXINFO_LAST )
				{
				POST( contextACL[ attribute - CRYPT_CTXINFO_FIRST - 1 ].attribute == attribute );
				return( &contextACL[ attribute - CRYPT_CTXINFO_FIRST - 1 ] );
				}
			}
		}
	else
		{
		if( attribute < CRYPT_KEYINFO_LAST )
			{
			if( attribute > CRYPT_CERTINFO_FIRST && \
				attribute < CRYPT_CERTINFO_LAST )
				{
				/* Certificate attributes are split into subranges so we have
				   to adjust the offsets to get the right ACL.  The subrange
				   specifiers are inclusive ranges rather than bounding
				   values, so we use >= rather than > comparisons */
				if( attribute < CRYPT_CERTINFO_FIRST_EXTENSION )
					{
					if( attribute >= CRYPT_CERTINFO_FIRST_CERTINFO && \
						attribute <= CRYPT_CERTINFO_LAST_CERTINFO )
						{
						POST( certificateACL[ attribute - CRYPT_CERTINFO_FIRST_CERTINFO ].attribute == attribute );
						return( &certificateACL[ attribute - CRYPT_CERTINFO_FIRST_CERTINFO ] );
						}
					if( attribute >= CRYPT_CERTINFO_FIRST_NAME && \
						attribute <= CRYPT_CERTINFO_LAST_NAME )
						{
						POST( certNameACL[ attribute - CRYPT_CERTINFO_FIRST_NAME ].attribute == attribute );
						return( &certNameACL[ attribute - CRYPT_CERTINFO_FIRST_NAME ] );
						}
					}
				else
					{
					if( attribute >= CRYPT_CERTINFO_FIRST_EXTENSION && \
						attribute <= CRYPT_CERTINFO_LAST_EXTENSION )
						{
						POST( certExtensionACL[ attribute - CRYPT_CERTINFO_FIRST_EXTENSION ].attribute == attribute );
						return( &certExtensionACL[ attribute - CRYPT_CERTINFO_FIRST_EXTENSION ] );
						}
					if( attribute >= CRYPT_CERTINFO_FIRST_CMS && \
						attribute <= CRYPT_CERTINFO_LAST_CMS )
						{
						POST( certSmimeACL[ attribute - CRYPT_CERTINFO_FIRST_CMS ].attribute == attribute );
						return( &certSmimeACL[ attribute - CRYPT_CERTINFO_FIRST_CMS ] );
						}
					}
				}
			if( attribute > CRYPT_KEYINFO_FIRST && \
				attribute < CRYPT_KEYINFO_LAST )
				{
				POST( keysetACL[ attribute - CRYPT_KEYINFO_FIRST - 1 ].attribute == attribute );
				return( &keysetACL[ attribute - CRYPT_KEYINFO_FIRST - 1 ] );
				}
			}
		else
			{
			if( attribute > CRYPT_DEVINFO_FIRST && \
				attribute < CRYPT_DEVINFO_LAST )
				{
				POST( deviceACL[ attribute - CRYPT_DEVINFO_FIRST - 1 ].attribute == attribute );
				return( &deviceACL[ attribute - CRYPT_DEVINFO_FIRST - 1 ] );
				}
			if( attribute > CRYPT_ENVINFO_FIRST && \
				attribute < CRYPT_ENVINFO_LAST )
				{
				POST( envelopeACL[ attribute - CRYPT_ENVINFO_FIRST - 1 ].attribute == attribute );
				return( &envelopeACL[ attribute - CRYPT_ENVINFO_FIRST - 1 ] );
				}
			if( attribute > CRYPT_SESSINFO_FIRST && \
				attribute < CRYPT_SESSINFO_LAST )
				{
				POST( sessionACL[ attribute - CRYPT_SESSINFO_FIRST - 1 ].attribute == attribute );
				return( &sessionACL[ attribute - CRYPT_SESSINFO_FIRST - 1 ] );
				}
			if( attribute > CRYPT_USERINFO_FIRST && \
				attribute < CRYPT_USERINFO_LAST )
				{
				POST( userACL[ attribute - CRYPT_USERINFO_FIRST - 1 ].attribute == attribute );
				return( &userACL[ attribute - CRYPT_USERINFO_FIRST - 1 ] );
				}

			/* If it's an external message then the internal attributes don't exist */
			if( isInternalMessage && \
				attribute > CRYPT_IATTRIBUTE_FIRST && \
				attribute < CRYPT_IATTRIBUTE_LAST )
				{
				POST( isInternalMessage );
				POST( internalACL[ attribute - CRYPT_IATTRIBUTE_FIRST - 1 ].attribute == attribute );
				return( &internalACL[ attribute - CRYPT_IATTRIBUTE_FIRST - 1 ] );
				}
			}
		}

	return( NULL );
	}
