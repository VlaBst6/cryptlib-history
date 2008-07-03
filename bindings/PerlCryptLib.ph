
# *****************************************************************************
# *                                                                           *
# *                        cryptlib External API Interface                    *
# *                       Copyright Peter Gutmann 1997-2008                   *
# *                                                                           *
# *                 adapted for Perl Version 5.x  by Alvaro Livraghi          *
# *****************************************************************************
#
#
# ----------------------------------------------------------------------------
#
# This file has been created automatically by a perl script from the file:
#
# "cryptlib.h" dated Fri Nov 23 02:07:02 2007, filesize = 85740.
#
# Please check twice that the file matches the version of cryptlib.h
# in your cryptlib source! If this is not the right version, try to download an
# update from CPAN web site. If the filesize or file creation date do not match,
# then please do not complain about problems.
#
# Published by Alvaro Livraghi, 
# mailto: perlcryptlib@gmail.com if you find errors in this file.
#
# -----------------------------------------------------------------------------
#

	sub CRYPTLIB_VERSION { 3320 }


#****************************************************************************
#*                                                                           *
#*                           Algorithm and Object Types                      *
#*                                                                           *
#****************************************************************************

# Algorithm and mode types 

##### BEGIN ENUM CRYPT_ALGO_TYPE 	# Algorithms
	# No encryption
	sub CRYPT_ALGO_NONE { 0 }	# No encryption

	# Conventional encryption
	sub CRYPT_ALGO_DES { 1 }	# DES
	sub CRYPT_ALGO_3DES { 2 }	# Triple DES
	sub CRYPT_ALGO_IDEA { 3 }	# IDEA
	sub CRYPT_ALGO_CAST { 4 }	# CAST-128
	sub CRYPT_ALGO_RC2 { 5 }	# RC2
	sub CRYPT_ALGO_RC4 { 6 }	# RC4
	sub CRYPT_ALGO_RC5 { 7 }	# RC5
	sub CRYPT_ALGO_AES { 8 }	# AES
	sub CRYPT_ALGO_BLOWFISH { 9 }	# Blowfish
	sub CRYPT_ALGO_SKIPJACK { 10 }	# Skipjack

	# Public-key encryption
	sub CRYPT_ALGO_DH { 100 }	# Diffie-Hellman
	sub CRYPT_ALGO_RSA { 101 }	# RSA
	sub CRYPT_ALGO_DSA { 102 }	# DSA
	sub CRYPT_ALGO_ELGAMAL { 103 }	# ElGamal
	sub CRYPT_ALGO_KEA { 104 }	# KEA
	sub CRYPT_ALGO_ECDSA { 105 }	# ECDSA

	# Hash algorithms
	sub CRYPT_ALGO_MD2 { 200 }	# MD2
	sub CRYPT_ALGO_MD4 { 201 }	# MD4
	sub CRYPT_ALGO_MD5 { 202 }	# MD5
	sub CRYPT_ALGO_SHA { 203 }	# SHA/SHA1
	sub CRYPT_ALGO_RIPEMD160 { 204 }	# RIPE-MD 160
	sub CRYPT_ALGO_SHA2 { 205 }	# SHA2 (SHA-256/384/512)

	# MAC's
	sub CRYPT_ALGO_HMAC_MD5 { 300 }	# HMAC-MD5
	sub CRYPT_ALGO_HMAC_SHA1 { 301 }	# HMAC-SHA
	sub CRYPT_ALGO_HMAC_SHA { CRYPT_ALGO_HMAC_SHA1 }	# Older form
	sub CRYPT_ALGO_HMAC_RIPEMD160 { 302 }	# HMAC-RIPEMD-160

	# Vendors may want to use their own algorithms that aren't part of the
	# general cryptlib suite.  The following values are for vendor-defined
	# algorithms, and can be used just like the named algorithm types (it's
	# up to the vendor to keep track of what _VENDOR1 actually corresponds
	# to)

	sub CRYPT_ALGO_LAST { 303 }	# Last possible crypt algo value

	# In order that we can scan through a range of algorithms with
	# cryptQueryCapability(), we define the following boundary points for
	# each algorithm class
	sub CRYPT_ALGO_FIRST_CONVENTIONAL { CRYPT_ALGO_DES }
	sub CRYPT_ALGO_LAST_CONVENTIONAL { CRYPT_ALGO_DH - 1 }
	sub CRYPT_ALGO_FIRST_PKC { CRYPT_ALGO_DH }
	sub CRYPT_ALGO_LAST_PKC { CRYPT_ALGO_MD2 - 1 }
	sub CRYPT_ALGO_FIRST_HASH { CRYPT_ALGO_MD2 }
	sub CRYPT_ALGO_LAST_HASH { CRYPT_ALGO_HMAC_MD5 - 1 }
	sub CRYPT_ALGO_FIRST_MAC { CRYPT_ALGO_HMAC_MD5 }
	sub CRYPT_ALGO_LAST_MAC { CRYPT_ALGO_HMAC_MD5 + 99 }	# End of mac algo.range


##### END ENUM CRYPT_ALGO_TYPE

##### BEGIN ENUM CRYPT_MODE_TYPE
	# Block cipher modes
	sub CRYPT_MODE_NONE { 0 }	# No encryption mode
	sub CRYPT_MODE_ECB { 1 }	# ECB
	sub CRYPT_MODE_CBC { 2 }	# CBC
	sub CRYPT_MODE_CFB { 3 }	# CFB
	sub CRYPT_MODE_OFB { 4 }	# OFB
	sub CRYPT_MODE_LAST { 5 }	# Last possible crypt mode value


##### END ENUM CRYPT_MODE_TYPE


# Keyset subtypes 

##### BEGIN ENUM CRYPT_KEYSET_TYPE
	# Keyset types
	sub CRYPT_KEYSET_NONE { 0 }	# No keyset type
	sub CRYPT_KEYSET_FILE { 1 }	# Generic flat file keyset
	sub CRYPT_KEYSET_HTTP { 2 }	# Web page containing cert/CRL
	sub CRYPT_KEYSET_LDAP { 3 }	# LDAP directory service
	sub CRYPT_KEYSET_ODBC { 4 }	# Generic ODBC interface
	sub CRYPT_KEYSET_DATABASE { 5 }	# Generic RDBMS interface
	sub CRYPT_KEYSET_PLUGIN { 6 }	# Generic database plugin
	sub CRYPT_KEYSET_ODBC_STORE { 7 }	# ODBC certificate store
	sub CRYPT_KEYSET_DATABASE_STORE { 8 }	# Database certificate store
	sub CRYPT_KEYSET_PLUGIN_STORE { 9 }	# Database plugin certificate store
	sub CRYPT_KEYSET_LAST { 10 }	# Last possible keyset type



##### END ENUM CRYPT_KEYSET_TYPE

# Device subtypes 

##### BEGIN ENUM CRYPT_DEVICE_TYPE
	# Crypto device types
	sub CRYPT_DEVICE_NONE { 0 }	# No crypto device
	sub CRYPT_DEVICE_FORTEZZA { 1 }	# Fortezza card
	sub CRYPT_DEVICE_PKCS11 { 2 }	# PKCS #11 crypto token
	sub CRYPT_DEVICE_CRYPTOAPI { 3 }	# Microsoft CryptoAPI
	sub CRYPT_DEVICE_LAST { 4 }	# Last possible crypto device type


##### END ENUM CRYPT_DEVICE_TYPE

# Certificate subtypes 

##### BEGIN ENUM CRYPT_CERTTYPE_TYPE
	# Certificate object types
	sub CRYPT_CERTTYPE_NONE { 0 }	# No certificate type
	sub CRYPT_CERTTYPE_CERTIFICATE { 1 }	# Certificate
	sub CRYPT_CERTTYPE_ATTRIBUTE_CERT { 2 }	# Attribute certificate
	sub CRYPT_CERTTYPE_CERTCHAIN { 3 }	# PKCS #7 certificate chain
	sub CRYPT_CERTTYPE_CERTREQUEST { 4 }	# PKCS #10 certification request
	sub CRYPT_CERTTYPE_REQUEST_CERT { 5 }	# CRMF certification request
	sub CRYPT_CERTTYPE_REQUEST_REVOCATION { 6 }	# CRMF revocation request
	sub CRYPT_CERTTYPE_CRL { 7 }	# CRL
	sub CRYPT_CERTTYPE_CMS_ATTRIBUTES { 8 }	# CMS attributes
	sub CRYPT_CERTTYPE_RTCS_REQUEST { 9 }	# RTCS request
	sub CRYPT_CERTTYPE_RTCS_RESPONSE { 10 }	# RTCS response
	sub CRYPT_CERTTYPE_OCSP_REQUEST { 11 }	# OCSP request
	sub CRYPT_CERTTYPE_OCSP_RESPONSE { 12 }	# OCSP response
	sub CRYPT_CERTTYPE_PKIUSER { 13 }	# PKI user information
	sub CRYPT_CERTTYPE_LAST { 14 }	# Last possible cert.type


##### END ENUM CRYPT_CERTTYPE_TYPE

# Envelope/data format subtypes 

##### BEGIN ENUM CRYPT_FORMAT_TYPE

	sub CRYPT_FORMAT_NONE { 0 }	# No format type
	sub CRYPT_FORMAT_AUTO { 1 }	# Deenv, auto-determine type
	sub CRYPT_FORMAT_CRYPTLIB { 2 }	# cryptlib native format
	sub CRYPT_FORMAT_CMS { 3 }	# PKCS #7 / CMS / S/MIME fmt.
	sub CRYPT_FORMAT_PKCS7 { CRYPT_FORMAT_CMS }
	sub CRYPT_FORMAT_SMIME { 4 }	# As CMS with MSG-style behaviour
	sub CRYPT_FORMAT_PGP { 5 }	# PGP format
	sub CRYPT_FORMAT_LAST { 6 }	# Last possible format type


##### END ENUM CRYPT_FORMAT_TYPE

# Session subtypes 

##### BEGIN ENUM CRYPT_SESSION_TYPE

	sub CRYPT_SESSION_NONE { 0 }	# No session type
	sub CRYPT_SESSION_SSH { 1 }	# SSH
	sub CRYPT_SESSION_SSH_SERVER { 2 }	# SSH server
	sub CRYPT_SESSION_SSL { 3 }	# SSL/TLS
	sub CRYPT_SESSION_SSL_SERVER { 4 }	# SSL/TLS server
	sub CRYPT_SESSION_RTCS { 5 }	# RTCS
	sub CRYPT_SESSION_RTCS_SERVER { 6 }	# RTCS server
	sub CRYPT_SESSION_OCSP { 7 }	# OCSP
	sub CRYPT_SESSION_OCSP_SERVER { 8 }	# OCSP server
	sub CRYPT_SESSION_TSP { 9 }	# TSP
	sub CRYPT_SESSION_TSP_SERVER { 10 }	# TSP server
	sub CRYPT_SESSION_CMP { 11 }	# CMP
	sub CRYPT_SESSION_CMP_SERVER { 12 }	# CMP server
	sub CRYPT_SESSION_SCEP { 13 }	# SCEP
	sub CRYPT_SESSION_SCEP_SERVER { 14 }	# SCEP server
	sub CRYPT_SESSION_CERTSTORE_SERVER { 15 }	# HTTP cert store interface
	sub CRYPT_SESSION_LAST { 16 }	# Last possible session type


##### END ENUM CRYPT_SESSION_TYPE

# User subtypes 

##### BEGIN ENUM CRYPT_USER_TYPE

	sub CRYPT_USER_NONE { 0 }	# No user type
	sub CRYPT_USER_NORMAL { 1 }	# Normal user
	sub CRYPT_USER_SO { 2 }	# Security officer
	sub CRYPT_USER_CA { 3 }	# CA user
	sub CRYPT_USER_LAST { 4 }	# Last possible user type


##### END ENUM CRYPT_USER_TYPE

#****************************************************************************
#*                                                                           *
#*                               Attribute Types                             *
#*                                                                           *
#****************************************************************************

#  Attribute types.  These are arranged in the following order:
#
#   PROPERTY    - Object property
#   ATTRIBUTE   - Generic attributes
#   OPTION      - Global or object-specific config.option
#   CTXINFO     - Context-specific attribute
#   CERTINFO    - Certificate-specific attribute
#   KEYINFO     - Keyset-specific attribute
#   DEVINFO     - Device-specific attribute
#   ENVINFO     - Envelope-specific attribute
#   SESSINFO    - Session-specific attribute
#   USERINFO    - User-specific attribute 

##### BEGIN ENUM CRYPT_ATTRIBUTE_TYPE 
	sub CRYPT_ATTRIBUTE_NONE { 0 }	# Non-value

	# Used internally
	sub CRYPT_PROPERTY_FIRST { 1 }

	# *******************
	# Object attributes
	# *******************

	# Object properties
	sub CRYPT_PROPERTY_HIGHSECURITY { 2 }	# Owned+non-forwardcount+locked
	sub CRYPT_PROPERTY_OWNER { 3 }	# Object owner
	sub CRYPT_PROPERTY_FORWARDCOUNT { 4 }	# No.of times object can be forwarded
	sub CRYPT_PROPERTY_LOCKED { 5 }	# Whether properties can be chged/read
	sub CRYPT_PROPERTY_USAGECOUNT { 6 }	# Usage count before object expires
	sub CRYPT_PROPERTY_NONEXPORTABLE { 7 }	# Whether key is nonexp.from context

	# Used internally
	sub CRYPT_PROPERTY_LAST { 8 }
	sub CRYPT_GENERIC_FIRST { 8 }

	# Extended error information
	sub CRYPT_ATTRIBUTE_ERRORTYPE { 9 }	# Type of last error
	sub CRYPT_ATTRIBUTE_ERRORLOCUS { 10 }	# Locus of last error
	sub CRYPT_ATTRIBUTE_INT_ERRORCODE { 11 }	# Low-level software-specific
	sub CRYPT_ATTRIBUTE_INT_ERRORMESSAGE { 12 }	# error code and message

	# Generic information
	sub CRYPT_ATTRIBUTE_CURRENT_GROUP { 13 }	# Cursor mgt: Group in attribute list
	sub CRYPT_ATTRIBUTE_CURRENT { 14 }	# Cursor mgt: Entry in attribute list
	sub CRYPT_ATTRIBUTE_CURRENT_INSTANCE { 15 }	# Cursor mgt: Instance in attribute list
	sub CRYPT_ATTRIBUTE_BUFFERSIZE { 16 }	# Internal data buffer size

	# User internally
	sub CRYPT_GENERIC_LAST { 100 }
	sub CRYPT_OPTION_FIRST { 100 }

	# **************************
	# Configuration attributes
	# **************************

	# cryptlib information (read-only)
	sub CRYPT_OPTION_INFO_DESCRIPTION { 101 }	# Text description
	sub CRYPT_OPTION_INFO_COPYRIGHT { 102 }	# Copyright notice
	sub CRYPT_OPTION_INFO_MAJORVERSION { 103 }	# Major release version
	sub CRYPT_OPTION_INFO_MINORVERSION { 104 }	# Minor release version
	sub CRYPT_OPTION_INFO_STEPPING { 105 }	# Release stepping

	# Encryption options
	sub CRYPT_OPTION_ENCR_ALGO { 106 }	# Encryption algorithm
	sub CRYPT_OPTION_ENCR_HASH { 107 }	# Hash algorithm
	sub CRYPT_OPTION_ENCR_MAC { 108 }	# MAC algorithm

	# PKC options
	sub CRYPT_OPTION_PKC_ALGO { 109 }	# Public-key encryption algorithm
	sub CRYPT_OPTION_PKC_KEYSIZE { 110 }	# Public-key encryption key size

	# Signature options
	sub CRYPT_OPTION_SIG_ALGO { 111 }	# Signature algorithm
	sub CRYPT_OPTION_SIG_KEYSIZE { 112 }	# Signature keysize

	# Keying options
	sub CRYPT_OPTION_KEYING_ALGO { 113 }	# Key processing algorithm
	sub CRYPT_OPTION_KEYING_ITERATIONS { 114 }	# Key processing iterations

	# Certificate options
	sub CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES { 115 }	# Whether to sign unrecog.attrs
	sub CRYPT_OPTION_CERT_VALIDITY { 116 }	# Certificate validity period
	sub CRYPT_OPTION_CERT_UPDATEINTERVAL { 117 }	# CRL update interval
	sub CRYPT_OPTION_CERT_COMPLIANCELEVEL { 118 }	# PKIX compliance level for cert chks.
	sub CRYPT_OPTION_CERT_REQUIREPOLICY { 119 }	# Whether explicit policy req'd for certs

	# CMS/SMIME options
	sub CRYPT_OPTION_CMS_DEFAULTATTRIBUTES { 120 }	# Add default CMS attributes
	sub CRYPT_OPTION_SMIME_DEFAULTATTRIBUTES { CRYPT_OPTION_CMS_DEFAULTATTRIBUTES }

	# LDAP keyset options
	sub CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS { 121 }	# Object class
	sub CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE { 122 }	# Object type to fetch
	sub CRYPT_OPTION_KEYS_LDAP_FILTER { 123 }	# Query filter
	sub CRYPT_OPTION_KEYS_LDAP_CACERTNAME { 124 }	# CA certificate attribute name
	sub CRYPT_OPTION_KEYS_LDAP_CERTNAME { 125 }	# Certificate attribute name
	sub CRYPT_OPTION_KEYS_LDAP_CRLNAME { 126 }	# CRL attribute name
	sub CRYPT_OPTION_KEYS_LDAP_EMAILNAME { 127 }	# Email attribute name

	# Crypto device options
	sub CRYPT_OPTION_DEVICE_PKCS11_DVR01 { 128 }	# Name of first PKCS #11 driver
	sub CRYPT_OPTION_DEVICE_PKCS11_DVR02 { 129 }	# Name of second PKCS #11 driver
	sub CRYPT_OPTION_DEVICE_PKCS11_DVR03 { 130 }	# Name of third PKCS #11 driver
	sub CRYPT_OPTION_DEVICE_PKCS11_DVR04 { 131 }	# Name of fourth PKCS #11 driver
	sub CRYPT_OPTION_DEVICE_PKCS11_DVR05 { 132 }	# Name of fifth PKCS #11 driver
	sub CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY { 133 }	# Use only hardware mechanisms

	# Network access options
	sub CRYPT_OPTION_NET_SOCKS_SERVER { 134 }	# Socks server name
	sub CRYPT_OPTION_NET_SOCKS_USERNAME { 135 }	# Socks user name
	sub CRYPT_OPTION_NET_HTTP_PROXY { 136 }	# Web proxy server
	sub CRYPT_OPTION_NET_CONNECTTIMEOUT { 137 }	# Timeout for network connection setup
	sub CRYPT_OPTION_NET_READTIMEOUT { 138 }	# Timeout for network reads
	sub CRYPT_OPTION_NET_WRITETIMEOUT { 139 }	# Timeout for network writes

	# Miscellaneous options
	sub CRYPT_OPTION_MISC_ASYNCINIT { 140 }	# Whether to init cryptlib async'ly
	sub CRYPT_OPTION_MISC_SIDECHANNELPROTECTION { 141 }	# Protect against side-channel attacks

	# cryptlib state information
	sub CRYPT_OPTION_CONFIGCHANGED { 142 }	# Whether in-mem.opts match on-disk ones
	sub CRYPT_OPTION_SELFTESTOK { 143 }	# Whether self-test was completed and OK

	# Used internally
	sub CRYPT_OPTION_LAST { 1000 }
	sub CRYPT_CTXINFO_FIRST { 1000 }

	# ********************
	# Context attributes
	# ********************

	# Algorithm and mode information
	sub CRYPT_CTXINFO_ALGO { 1001 }	# Algorithm
	sub CRYPT_CTXINFO_MODE { 1002 }	# Mode
	sub CRYPT_CTXINFO_NAME_ALGO { 1003 }	# Algorithm name
	sub CRYPT_CTXINFO_NAME_MODE { 1004 }	# Mode name
	sub CRYPT_CTXINFO_KEYSIZE { 1005 }	# Key size in bytes
	sub CRYPT_CTXINFO_BLOCKSIZE { 1006 }	# Block size
	sub CRYPT_CTXINFO_IVSIZE { 1007 }	# IV size
	sub CRYPT_CTXINFO_KEYING_ALGO { 1008 }	# Key processing algorithm
	sub CRYPT_CTXINFO_KEYING_ITERATIONS { 1009 }	# Key processing iterations
	sub CRYPT_CTXINFO_KEYING_SALT { 1010 }	# Key processing salt
	sub CRYPT_CTXINFO_KEYING_VALUE { 1011 }	# Value used to derive key

	# State information
	sub CRYPT_CTXINFO_KEY { 1012 }	# Key
	sub CRYPT_CTXINFO_KEY_COMPONENTS { 1013 }	# Public-key components
	sub CRYPT_CTXINFO_IV { 1014 }	# IV
	sub CRYPT_CTXINFO_HASHVALUE { 1015 }	# Hash value

	# Misc.information
	sub CRYPT_CTXINFO_LABEL { 1016 }	# Label for private/secret key
	sub CRYPT_CTXINFO_PERSISTENT { 1017 }	# Obj.is backed by device or keyset

	# Used internally
	sub CRYPT_CTXINFO_LAST { 2000 }
	sub CRYPT_CERTINFO_FIRST { 2000 }

	# ************************
	# Certificate attributes
	# ************************

	# Because there are so many cert attributes, we break them down into
	# blocks to minimise the number of values that change if a new one is
	# added halfway through

	# Pseudo-information on a cert object or meta-information which is used
	# to control the way that a cert object is processed
	sub CRYPT_CERTINFO_SELFSIGNED { 2001 }	# Cert is self-signed
	sub CRYPT_CERTINFO_IMMUTABLE { 2002 }	# Cert is signed and immutable
	sub CRYPT_CERTINFO_XYZZY { 2003 }	# Cert is a magic just-works cert
	sub CRYPT_CERTINFO_CERTTYPE { 2004 }	# Certificate object type
	sub CRYPT_CERTINFO_FINGERPRINT { 2005 }	# Certificate fingerprints
	sub CRYPT_CERTINFO_FINGERPRINT_MD5 { CRYPT_CERTINFO_FINGERPRINT }
	sub CRYPT_CERTINFO_FINGERPRINT_SHA { 2006 }
	sub CRYPT_CERTINFO_CURRENT_CERTIFICATE { 2007 }	# Cursor mgt: Rel.pos in chain/CRL/OCSP
	sub CRYPT_CERTINFO_TRUSTED_USAGE { 2008 }	# Usage that cert is trusted for
	sub CRYPT_CERTINFO_TRUSTED_IMPLICIT { 2009 }	# Whether cert is implicitly trusted
	sub CRYPT_CERTINFO_SIGNATURELEVEL { 2010 }	# Amount of detail to include in sigs.

	# General certificate object information
	sub CRYPT_CERTINFO_VERSION { 2011 }	# Cert.format version
	sub CRYPT_CERTINFO_SERIALNUMBER { 2012 }	# Serial number
	sub CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO { 2013 }	# Public key
	sub CRYPT_CERTINFO_CERTIFICATE { 2014 }	# User certificate
	sub CRYPT_CERTINFO_USERCERTIFICATE { CRYPT_CERTINFO_CERTIFICATE }
	sub CRYPT_CERTINFO_CACERTIFICATE { 2015 }	# CA certificate
	sub CRYPT_CERTINFO_ISSUERNAME { 2016 }	# Issuer DN
	sub CRYPT_CERTINFO_VALIDFROM { 2017 }	# Cert valid-from time
	sub CRYPT_CERTINFO_VALIDTO { 2018 }	# Cert valid-to time
	sub CRYPT_CERTINFO_SUBJECTNAME { 2019 }	# Subject DN
	sub CRYPT_CERTINFO_ISSUERUNIQUEID { 2020 }	# Issuer unique ID
	sub CRYPT_CERTINFO_SUBJECTUNIQUEID { 2021 }	# Subject unique ID
	sub CRYPT_CERTINFO_CERTREQUEST { 2022 }	# Cert.request (DN + public key)
	sub CRYPT_CERTINFO_THISUPDATE { 2023 }	# CRL/OCSP current-update time
	sub CRYPT_CERTINFO_NEXTUPDATE { 2024 }	# CRL/OCSP next-update time
	sub CRYPT_CERTINFO_REVOCATIONDATE { 2025 }	# CRL/OCSP cert-revocation time
	sub CRYPT_CERTINFO_REVOCATIONSTATUS { 2026 }	# OCSP revocation status
	sub CRYPT_CERTINFO_CERTSTATUS { 2027 }	# RTCS certificate status
	sub CRYPT_CERTINFO_DN { 2028 }	# Currently selected DN in string form
	sub CRYPT_CERTINFO_PKIUSER_ID { 2029 }	# PKI user ID
	sub CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD { 2030 }	# PKI user issue password
	sub CRYPT_CERTINFO_PKIUSER_REVPASSWORD { 2031 }	# PKI user revocation password

	# X.520 Distinguished Name components.  This is a composite field, the
	# DN to be manipulated is selected through the addition of a
	# pseudocomponent, and then one of the following is used to access the
	# DN components directly
	sub CRYPT_CERTINFO_COUNTRYNAME { CRYPT_CERTINFO_FIRST + 100 }	# countryName
	sub CRYPT_CERTINFO_STATEORPROVINCENAME { 2032 }	# stateOrProvinceName
	sub CRYPT_CERTINFO_LOCALITYNAME { 2033 }	# localityName
	sub CRYPT_CERTINFO_ORGANIZATIONNAME { 2034 }	# organizationName
	sub CRYPT_CERTINFO_ORGANISATIONNAME { CRYPT_CERTINFO_ORGANIZATIONNAME }
	sub CRYPT_CERTINFO_ORGANIZATIONALUNITNAME { 2035 }	# organizationalUnitName
	sub CRYPT_CERTINFO_ORGANISATIONALUNITNAME { CRYPT_CERTINFO_ORGANIZATIONALUNITNAME }
	sub CRYPT_CERTINFO_COMMONNAME { 2036 }	# commonName

	# X.509 General Name components.  These are handled in the same way as
	# the DN composite field, with the current GeneralName being selected by
	# a pseudo-component after which the individual components can be
	# modified through one of the following
	sub CRYPT_CERTINFO_OTHERNAME_TYPEID { 2037 }	# otherName.typeID
	sub CRYPT_CERTINFO_OTHERNAME_VALUE { 2038 }	# otherName.value
	sub CRYPT_CERTINFO_RFC822NAME { 2039 }	# rfc822Name
	sub CRYPT_CERTINFO_EMAIL { CRYPT_CERTINFO_RFC822NAME }
	sub CRYPT_CERTINFO_DNSNAME { 2040 }	# dNSName
	sub CRYPT_CERTINFO_DIRECTORYNAME { 2041 }	# directoryName
	sub CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER { 2042 }	# ediPartyName.nameAssigner
	sub CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME { 2043 }	# ediPartyName.partyName
	sub CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER { 2044 }	# uniformResourceIdentifier
	sub CRYPT_CERTINFO_IPADDRESS { 2045 }	# iPAddress
	sub CRYPT_CERTINFO_REGISTEREDID { 2046 }	# registeredID

	# X.509 certificate extensions.  Although it would be nicer to use names
	# that match the extensions more closely (e.g.
	# CRYPT_CERTINFO_BASICCONSTRAINTS_PATHLENCONSTRAINT), these exceed the
	# 32-character ANSI minimum length for unique names, and get really
	# hairy once you get into the weird policy constraints extensions whose
	# names wrap around the screen about three times.

	# The following values are defined in OID order, this isn't absolutely
	# necessary but saves an extra layer of processing when encoding them

	# 1 2 840 113549 1 9 7 challengePassword.  This is here even though it's
	# a CMS attribute because SCEP stuffs it into PKCS #10 requests
	sub CRYPT_CERTINFO_CHALLENGEPASSWORD { CRYPT_CERTINFO_FIRST + 200 }

	# 1 3 6 1 4 1 3029 3 1 4 cRLExtReason
	sub CRYPT_CERTINFO_CRLEXTREASON { 2047 }

	# 1 3 6 1 4 1 3029 3 1 5 keyFeatures
	sub CRYPT_CERTINFO_KEYFEATURES { 2048 }

	# 1 3 6 1 5 5 7 1 1 authorityInfoAccess
	sub CRYPT_CERTINFO_AUTHORITYINFOACCESS { 2049 }
	sub CRYPT_CERTINFO_AUTHORITYINFO_RTCS { 2050 }	# accessDescription.accessLocation
	sub CRYPT_CERTINFO_AUTHORITYINFO_OCSP { 2051 }	# accessDescription.accessLocation
	sub CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS { 2052 }	# accessDescription.accessLocation
	sub CRYPT_CERTINFO_AUTHORITYINFO_CERTSTORE { 2053 }	# accessDescription.accessLocation
	sub CRYPT_CERTINFO_AUTHORITYINFO_CRLS { 2054 }	# accessDescription.accessLocation

	# 1 3 6 1 5 5 7 1 2 biometricInfo
	sub CRYPT_CERTINFO_BIOMETRICINFO { 2055 }
	sub CRYPT_CERTINFO_BIOMETRICINFO_TYPE { 2056 }	# biometricData.typeOfData
	sub CRYPT_CERTINFO_BIOMETRICINFO_HASHALGO { 2057 }	# biometricData.hashAlgorithm
	sub CRYPT_CERTINFO_BIOMETRICINFO_HASH { 2058 }	# biometricData.dataHash
	sub CRYPT_CERTINFO_BIOMETRICINFO_URL { 2059 }	# biometricData.sourceDataUri

	# 1 3 6 1 5 5 7 1 3 qcStatements
	sub CRYPT_CERTINFO_QCSTATEMENT { 2060 }
	sub CRYPT_CERTINFO_QCSTATEMENT_SEMANTICS { 2061 }
	# qcStatement.statementInfo.semanticsIdentifier
	sub CRYPT_CERTINFO_QCSTATEMENT_REGISTRATIONAUTHORITY { 2062 }
	# qcStatement.statementInfo.nameRegistrationAuthorities

	# 1 3 6 1 5 5 7 48 1 2 ocspNonce
	sub CRYPT_CERTINFO_OCSP_NONCE { 2063 }	# nonce

	# 1 3 6 1 5 5 7 48 1 4 ocspAcceptableResponses
	sub CRYPT_CERTINFO_OCSP_RESPONSE { 2064 }
	sub CRYPT_CERTINFO_OCSP_RESPONSE_OCSP { 2065 }	# OCSP standard response

	# 1 3 6 1 5 5 7 48 1 5 ocspNoCheck
	sub CRYPT_CERTINFO_OCSP_NOCHECK { 2066 }

	# 1 3 6 1 5 5 7 48 1 6 ocspArchiveCutoff
	sub CRYPT_CERTINFO_OCSP_ARCHIVECUTOFF { 2067 }

	# 1 3 6 1 5 5 7 48 1 11 subjectInfoAccess
	sub CRYPT_CERTINFO_SUBJECTINFOACCESS { 2068 }
	sub CRYPT_CERTINFO_SUBJECTINFO_CAREPOSITORY { 2069 }	# accessDescription.accessLocation
	sub CRYPT_CERTINFO_SUBJECTINFO_TIMESTAMPING { 2070 }	# accessDescription.accessLocation

	# 1 3 36 8 3 1 siggDateOfCertGen
	sub CRYPT_CERTINFO_SIGG_DATEOFCERTGEN { 2071 }

	# 1 3 36 8 3 2 siggProcuration
	sub CRYPT_CERTINFO_SIGG_PROCURATION { 2072 }
	sub CRYPT_CERTINFO_SIGG_PROCURE_COUNTRY { 2073 }	# country
	sub CRYPT_CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION { 2074 }	# typeOfSubstitution
	sub CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR { 2075 }	# signingFor.thirdPerson

	# 1 3 36 8 3 4 siggMonetaryLimit
	sub CRYPT_CERTINFO_SIGG_MONETARYLIMIT { 2076 }
	sub CRYPT_CERTINFO_SIGG_MONETARY_CURRENCY { 2077 }	# currency
	sub CRYPT_CERTINFO_SIGG_MONETARY_AMOUNT { 2078 }	# amount
	sub CRYPT_CERTINFO_SIGG_MONETARY_EXPONENT { 2079 }	# exponent

	# 1 3 36 8 3 8 siggRestriction
	sub CRYPT_CERTINFO_SIGG_RESTRICTION { 2080 }

	# 1 3 101 1 4 1 strongExtranet
	sub CRYPT_CERTINFO_STRONGEXTRANET { 2081 }
	sub CRYPT_CERTINFO_STRONGEXTRANET_ZONE { 2082 }	# sxNetIDList.sxNetID.zone
	sub CRYPT_CERTINFO_STRONGEXTRANET_ID { 2083 }	# sxNetIDList.sxNetID.id

	# 2 5 29 9 subjectDirectoryAttributes
	sub CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES { 2084 }
	sub CRYPT_CERTINFO_SUBJECTDIR_TYPE { 2085 }	# attribute.type
	sub CRYPT_CERTINFO_SUBJECTDIR_VALUES { 2086 }	# attribute.values

	# 2 5 29 14 subjectKeyIdentifier
	sub CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER { 2087 }

	# 2 5 29 15 keyUsage
	sub CRYPT_CERTINFO_KEYUSAGE { 2088 }

	# 2 5 29 16 privateKeyUsagePeriod
	sub CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD { 2089 }
	sub CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE { 2090 }	# notBefore
	sub CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER { 2091 }	# notAfter

	# 2 5 29 17 subjectAltName
	sub CRYPT_CERTINFO_SUBJECTALTNAME { 2092 }

	# 2 5 29 18 issuerAltName
	sub CRYPT_CERTINFO_ISSUERALTNAME { 2093 }

	# 2 5 29 19 basicConstraints
	sub CRYPT_CERTINFO_BASICCONSTRAINTS { 2094 }
	sub CRYPT_CERTINFO_CA { 2095 }	# cA
	sub CRYPT_CERTINFO_AUTHORITY { CRYPT_CERTINFO_CA }
	sub CRYPT_CERTINFO_PATHLENCONSTRAINT { 2096 }	# pathLenConstraint

	# 2 5 29 20 cRLNumber
	sub CRYPT_CERTINFO_CRLNUMBER { 2097 }

	# 2 5 29 21 cRLReason
	sub CRYPT_CERTINFO_CRLREASON { 2098 }

	# 2 5 29 23 holdInstructionCode
	sub CRYPT_CERTINFO_HOLDINSTRUCTIONCODE { 2099 }

	# 2 5 29 24 invalidityDate
	sub CRYPT_CERTINFO_INVALIDITYDATE { 2100 }

	# 2 5 29 27 deltaCRLIndicator
	sub CRYPT_CERTINFO_DELTACRLINDICATOR { 2101 }

	# 2 5 29 28 issuingDistributionPoint
	sub CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT { 2102 }
	sub CRYPT_CERTINFO_ISSUINGDIST_FULLNAME { 2103 }	# distributionPointName.fullName
	sub CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY { 2104 }	# onlyContainsUserCerts
	sub CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY { 2105 }	# onlyContainsCACerts
	sub CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY { 2106 }	# onlySomeReasons
	sub CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL { 2107 }	# indirectCRL

	# 2 5 29 29 certificateIssuer
	sub CRYPT_CERTINFO_CERTIFICATEISSUER { 2108 }

	# 2 5 29 30 nameConstraints
	sub CRYPT_CERTINFO_NAMECONSTRAINTS { 2109 }
	sub CRYPT_CERTINFO_PERMITTEDSUBTREES { 2110 }	# permittedSubtrees
	sub CRYPT_CERTINFO_EXCLUDEDSUBTREES { 2111 }	# excludedSubtrees

	# 2 5 29 31 cRLDistributionPoint
	sub CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT { 2112 }
	sub CRYPT_CERTINFO_CRLDIST_FULLNAME { 2113 }	# distributionPointName.fullName
	sub CRYPT_CERTINFO_CRLDIST_REASONS { 2114 }	# reasons
	sub CRYPT_CERTINFO_CRLDIST_CRLISSUER { 2115 }	# cRLIssuer

	# 2 5 29 32 certificatePolicies
	sub CRYPT_CERTINFO_CERTIFICATEPOLICIES { 2116 }
	sub CRYPT_CERTINFO_CERTPOLICYID { 2117 }	# policyInformation.policyIdentifier
	sub CRYPT_CERTINFO_CERTPOLICY_CPSURI { 2118 }
	# policyInformation.policyQualifiers.qualifier.cPSuri
	sub CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION { 2119 }
	# policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.organization
	sub CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS { 2120 }
	# policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.noticeNumbers
	sub CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT { 2121 }
	# policyInformation.policyQualifiers.qualifier.userNotice.explicitText

	# 2 5 29 33 policyMappings
	sub CRYPT_CERTINFO_POLICYMAPPINGS { 2122 }
	sub CRYPT_CERTINFO_ISSUERDOMAINPOLICY { 2123 }	# policyMappings.issuerDomainPolicy
	sub CRYPT_CERTINFO_SUBJECTDOMAINPOLICY { 2124 }	# policyMappings.subjectDomainPolicy

	# 2 5 29 35 authorityKeyIdentifier
	sub CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER { 2125 }
	sub CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER { 2126 }	# keyIdentifier
	sub CRYPT_CERTINFO_AUTHORITY_CERTISSUER { 2127 }	# authorityCertIssuer
	sub CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER { 2128 }	# authorityCertSerialNumber

	# 2 5 29 36 policyConstraints
	sub CRYPT_CERTINFO_POLICYCONSTRAINTS { 2129 }
	sub CRYPT_CERTINFO_REQUIREEXPLICITPOLICY { 2130 }	# policyConstraints.requireExplicitPolicy
	sub CRYPT_CERTINFO_INHIBITPOLICYMAPPING { 2131 }	# policyConstraints.inhibitPolicyMapping

	# 2 5 29 37 extKeyUsage
	sub CRYPT_CERTINFO_EXTKEYUSAGE { 2132 }
	sub CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING { 2133 }	# individualCodeSigning
	sub CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING { 2134 }	# commercialCodeSigning
	sub CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING { 2135 }	# certTrustListSigning
	sub CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING { 2136 }	# timeStampSigning
	sub CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO { 2137 }	# serverGatedCrypto
	sub CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM { 2138 }	# encrypedFileSystem
	sub CRYPT_CERTINFO_EXTKEY_SERVERAUTH { 2139 }	# serverAuth
	sub CRYPT_CERTINFO_EXTKEY_CLIENTAUTH { 2140 }	# clientAuth
	sub CRYPT_CERTINFO_EXTKEY_CODESIGNING { 2141 }	# codeSigning
	sub CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION { 2142 }	# emailProtection
	sub CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM { 2143 }	# ipsecEndSystem
	sub CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL { 2144 }	# ipsecTunnel
	sub CRYPT_CERTINFO_EXTKEY_IPSECUSER { 2145 }	# ipsecUser
	sub CRYPT_CERTINFO_EXTKEY_TIMESTAMPING { 2146 }	# timeStamping
	sub CRYPT_CERTINFO_EXTKEY_OCSPSIGNING { 2147 }	# ocspSigning
	sub CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE { 2148 }	# directoryService
	sub CRYPT_CERTINFO_EXTKEY_ANYKEYUSAGE { 2149 }	# anyExtendedKeyUsage
	sub CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO { 2150 }	# serverGatedCrypto
	sub CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA { 2151 }	# serverGatedCrypto CA

	# 2 5 29 46 freshestCRL
	sub CRYPT_CERTINFO_FRESHESTCRL { 2152 }
	sub CRYPT_CERTINFO_FRESHESTCRL_FULLNAME { 2153 }	# distributionPointName.fullName
	sub CRYPT_CERTINFO_FRESHESTCRL_REASONS { 2154 }	# reasons
	sub CRYPT_CERTINFO_FRESHESTCRL_CRLISSUER { 2155 }	# cRLIssuer

	# 2 5 29 54 inhibitAnyPolicy
	sub CRYPT_CERTINFO_INHIBITANYPOLICY { 2156 }

	# 2 16 840 1 113730 1 x Netscape extensions
	sub CRYPT_CERTINFO_NS_CERTTYPE { 2157 }	# netscape-cert-type
	sub CRYPT_CERTINFO_NS_BASEURL { 2158 }	# netscape-base-url
	sub CRYPT_CERTINFO_NS_REVOCATIONURL { 2159 }	# netscape-revocation-url
	sub CRYPT_CERTINFO_NS_CAREVOCATIONURL { 2160 }	# netscape-ca-revocation-url
	sub CRYPT_CERTINFO_NS_CERTRENEWALURL { 2161 }	# netscape-cert-renewal-url
	sub CRYPT_CERTINFO_NS_CAPOLICYURL { 2162 }	# netscape-ca-policy-url
	sub CRYPT_CERTINFO_NS_SSLSERVERNAME { 2163 }	# netscape-ssl-server-name
	sub CRYPT_CERTINFO_NS_COMMENT { 2164 }	# netscape-comment

	# 2 23 42 7 0 SET hashedRootKey
	sub CRYPT_CERTINFO_SET_HASHEDROOTKEY { 2165 }
	sub CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT { 2166 }	# rootKeyThumbPrint

	# 2 23 42 7 1 SET certificateType
	sub CRYPT_CERTINFO_SET_CERTIFICATETYPE { 2167 }

	# 2 23 42 7 2 SET merchantData
	sub CRYPT_CERTINFO_SET_MERCHANTDATA { 2168 }
	sub CRYPT_CERTINFO_SET_MERID { 2169 }	# merID
	sub CRYPT_CERTINFO_SET_MERACQUIRERBIN { 2170 }	# merAcquirerBIN
	sub CRYPT_CERTINFO_SET_MERCHANTLANGUAGE { 2171 }	# merNames.language
	sub CRYPT_CERTINFO_SET_MERCHANTNAME { 2172 }	# merNames.name
	sub CRYPT_CERTINFO_SET_MERCHANTCITY { 2173 }	# merNames.city
	sub CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE { 2174 }	# merNames.stateProvince
	sub CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE { 2175 }	# merNames.postalCode
	sub CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME { 2176 }	# merNames.countryName
	sub CRYPT_CERTINFO_SET_MERCOUNTRY { 2177 }	# merCountry
	sub CRYPT_CERTINFO_SET_MERAUTHFLAG { 2178 }	# merAuthFlag

	# 2 23 42 7 3 SET certCardRequired
	sub CRYPT_CERTINFO_SET_CERTCARDREQUIRED { 2179 }

	# 2 23 42 7 4 SET tunneling
	sub CRYPT_CERTINFO_SET_TUNNELING { 2180 }
	sub CRYPT_CERTINFO_SET_TUNNELLING { CRYPT_CERTINFO_SET_TUNNELING }
	sub CRYPT_CERTINFO_SET_TUNNELINGFLAG { 2181 }	# tunneling
	sub CRYPT_CERTINFO_SET_TUNNELLINGFLAG { CRYPT_CERTINFO_SET_TUNNELINGFLAG }
	sub CRYPT_CERTINFO_SET_TUNNELINGALGID { 2182 }	# tunnelingAlgID
	sub CRYPT_CERTINFO_SET_TUNNELLINGALGID { CRYPT_CERTINFO_SET_TUNNELINGALGID }

	# S/MIME attributes

	# 1 2 840 113549 1 9 3 contentType
	sub CRYPT_CERTINFO_CMS_CONTENTTYPE { CRYPT_CERTINFO_FIRST + 500 }

	# 1 2 840 113549 1 9 4 messageDigest
	sub CRYPT_CERTINFO_CMS_MESSAGEDIGEST { 2183 }

	# 1 2 840 113549 1 9 5 signingTime
	sub CRYPT_CERTINFO_CMS_SIGNINGTIME { 2184 }

	# 1 2 840 113549 1 9 6 counterSignature
	sub CRYPT_CERTINFO_CMS_COUNTERSIGNATURE { 2185 }	# counterSignature

	# 1 2 840 113549 1 9 13 signingDescription
	sub CRYPT_CERTINFO_CMS_SIGNINGDESCRIPTION { 2186 }

	# 1 2 840 113549 1 9 15 sMIMECapabilities
	sub CRYPT_CERTINFO_CMS_SMIMECAPABILITIES { 2187 }
	sub CRYPT_CERTINFO_CMS_SMIMECAP_3DES { 2188 }	# 3DES encryption
	sub CRYPT_CERTINFO_CMS_SMIMECAP_AES { 2189 }	# AES encryption
	sub CRYPT_CERTINFO_CMS_SMIMECAP_CAST128 { 2190 }	# CAST-128 encryption
	sub CRYPT_CERTINFO_CMS_SMIMECAP_IDEA { 2191 }	# IDEA encryption
	sub CRYPT_CERTINFO_CMS_SMIMECAP_RC2 { 2192 }	# RC2 encryption (w.128 key)
	sub CRYPT_CERTINFO_CMS_SMIMECAP_RC5 { 2193 }	# RC5 encryption (w.128 key)
	sub CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK { 2194 }	# Skipjack encryption
	sub CRYPT_CERTINFO_CMS_SMIMECAP_DES { 2195 }	# DES encryption
	sub CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA { 2196 }	# preferSignedData
	sub CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY { 2197 }	# canNotDecryptAny

	# 1 2 840 113549 1 9 16 2 1 receiptRequest
	sub CRYPT_CERTINFO_CMS_RECEIPTREQUEST { 2198 }
	sub CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER { 2199 }	# contentIdentifier
	sub CRYPT_CERTINFO_CMS_RECEIPT_FROM { 2200 }	# receiptsFrom
	sub CRYPT_CERTINFO_CMS_RECEIPT_TO { 2201 }	# receiptsTo

	# 1 2 840 113549 1 9 16 2 2 essSecurityLabel
	sub CRYPT_CERTINFO_CMS_SECURITYLABEL { 2202 }
	sub CRYPT_CERTINFO_CMS_SECLABEL_POLICY { 2203 }	# securityPolicyIdentifier
	sub CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION { 2204 }	# securityClassification
	sub CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK { 2205 }	# privacyMark
	sub CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE { 2206 }	# securityCategories.securityCategory.type
	sub CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE { 2207 }	# securityCategories.securityCategory.value

	# 1 2 840 113549 1 9 16 2 3 mlExpansionHistory
	sub CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY { 2208 }
	sub CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER { 2209 }	# mlData.mailListIdentifier.issuerAndSerialNumber
	sub CRYPT_CERTINFO_CMS_MLEXP_TIME { 2210 }	# mlData.expansionTime
	sub CRYPT_CERTINFO_CMS_MLEXP_NONE { 2211 }	# mlData.mlReceiptPolicy.none
	sub CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF { 2212 }	# mlData.mlReceiptPolicy.insteadOf.generalNames.generalName
	sub CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO { 2213 }	# mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName

	# 1 2 840 113549 1 9 16 2 4 contentHints
	sub CRYPT_CERTINFO_CMS_CONTENTHINTS { 2214 }
	sub CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION { 2215 }	# contentDescription
	sub CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE { 2216 }	# contentType

	# 1 2 840 113549 1 9 16 2 9 equivalentLabels
	sub CRYPT_CERTINFO_CMS_EQUIVALENTLABEL { 2217 }
	sub CRYPT_CERTINFO_CMS_EQVLABEL_POLICY { 2218 }	# securityPolicyIdentifier
	sub CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION { 2219 }	# securityClassification
	sub CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK { 2220 }	# privacyMark
	sub CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE { 2221 }	# securityCategories.securityCategory.type
	sub CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE { 2222 }	# securityCategories.securityCategory.value

	# 1 2 840 113549 1 9 16 2 12 signingCertificate
	sub CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE { 2223 }
	sub CRYPT_CERTINFO_CMS_SIGNINGCERT_ESSCERTID { 2224 }	# certs.essCertID
	sub CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES { 2225 }	# policies.policyInformation.policyIdentifier

	# 1 2 840 113549 1 9 16 2 15 signaturePolicyID
	sub CRYPT_CERTINFO_CMS_SIGNATUREPOLICYID { 2226 }
	sub CRYPT_CERTINFO_CMS_SIGPOLICYID { 2227 }	# sigPolicyID
	sub CRYPT_CERTINFO_CMS_SIGPOLICYHASH { 2228 }	# sigPolicyHash
	sub CRYPT_CERTINFO_CMS_SIGPOLICY_CPSURI { 2229 }	# sigPolicyQualifiers.sigPolicyQualifier.cPSuri
	sub CRYPT_CERTINFO_CMS_SIGPOLICY_ORGANIZATION { 2230 }
	# sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.organization
	sub CRYPT_CERTINFO_CMS_SIGPOLICY_NOTICENUMBERS { 2231 }
	# sigPolicyQualifiers.sigPolicyQualifier.userNotice.noticeRef.noticeNumbers
	sub CRYPT_CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT { 2232 }
	# sigPolicyQualifiers.sigPolicyQualifier.userNotice.explicitText

	# 1 2 840 113549 1 9 16 9 signatureTypeIdentifier
	sub CRYPT_CERTINFO_CMS_SIGTYPEIDENTIFIER { 2233 }
	sub CRYPT_CERTINFO_CMS_SIGTYPEID_ORIGINATORSIG { 2234 }	# originatorSig
	sub CRYPT_CERTINFO_CMS_SIGTYPEID_DOMAINSIG { 2235 }	# domainSig
	sub CRYPT_CERTINFO_CMS_SIGTYPEID_ADDITIONALATTRIBUTES { 2236 }	# additionalAttributesSig
	sub CRYPT_CERTINFO_CMS_SIGTYPEID_REVIEWSIG { 2237 }	# reviewSig

	# 1 2 840 113549 1 9 25 3 randomNonce
	sub CRYPT_CERTINFO_CMS_NONCE { 2238 }	# randomNonce

	# SCEP attributes:
	# 2 16 840 1 113733 1 9 2 messageType
	# 2 16 840 1 113733 1 9 3 pkiStatus
	# 2 16 840 1 113733 1 9 4 failInfo
	# 2 16 840 1 113733 1 9 5 senderNonce
	# 2 16 840 1 113733 1 9 6 recipientNonce
	# 2 16 840 1 113733 1 9 7 transID
	sub CRYPT_CERTINFO_SCEP_MESSAGETYPE { 2239 }	# messageType
	sub CRYPT_CERTINFO_SCEP_PKISTATUS { 2240 }	# pkiStatus
	sub CRYPT_CERTINFO_SCEP_FAILINFO { 2241 }	# failInfo
	sub CRYPT_CERTINFO_SCEP_SENDERNONCE { 2242 }	# senderNonce
	sub CRYPT_CERTINFO_SCEP_RECIPIENTNONCE { 2243 }	# recipientNonce
	sub CRYPT_CERTINFO_SCEP_TRANSACTIONID { 2244 }	# transID

	# 1 3 6 1 4 1 311 2 1 10 spcAgencyInfo
	sub CRYPT_CERTINFO_CMS_SPCAGENCYINFO { 2245 }
	sub CRYPT_CERTINFO_CMS_SPCAGENCYURL { 2246 }	# spcAgencyInfo.url

	# 1 3 6 1 4 1 311 2 1 11 spcStatementType
	sub CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE { 2247 }
	sub CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING { 2248 }	# individualCodeSigning
	sub CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING { 2249 }	# commercialCodeSigning

	# 1 3 6 1 4 1 311 2 1 12 spcOpusInfo
	sub CRYPT_CERTINFO_CMS_SPCOPUSINFO { 2250 }
	sub CRYPT_CERTINFO_CMS_SPCOPUSINFO_NAME { 2251 }	# spcOpusInfo.name
	sub CRYPT_CERTINFO_CMS_SPCOPUSINFO_URL { 2252 }	# spcOpusInfo.url

	# Used internally
	sub CRYPT_CERTINFO_LAST { 3000 }
	sub CRYPT_KEYINFO_FIRST { 3000 }

	# *******************
	# Keyset attributes
	# *******************

	sub CRYPT_KEYINFO_QUERY { 3001 }	# Keyset query
	sub CRYPT_KEYINFO_QUERY_REQUESTS { 3002 }	# Query of requests in cert store

	# Used internally
	sub CRYPT_KEYINFO_LAST { 4000 }
	sub CRYPT_DEVINFO_FIRST { 4000 }

	# *******************
	# Device attributes
	# *******************

	sub CRYPT_DEVINFO_INITIALISE { 4001 }	# Initialise device for use
	sub CRYPT_DEVINFO_INITIALIZE { CRYPT_DEVINFO_INITIALISE }
	sub CRYPT_DEVINFO_AUTHENT_USER { 4002 }	# Authenticate user to device
	sub CRYPT_DEVINFO_AUTHENT_SUPERVISOR { 4003 }	# Authenticate supervisor to dev.
	sub CRYPT_DEVINFO_SET_AUTHENT_USER { 4004 }	# Set user authent.value
	sub CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR { 4005 }	# Set supervisor auth.val.
	sub CRYPT_DEVINFO_ZEROISE { 4006 }	# Zeroise device
	sub CRYPT_DEVINFO_ZEROIZE { CRYPT_DEVINFO_ZEROISE }
	sub CRYPT_DEVINFO_LOGGEDIN { 4007 }	# Whether user is logged in
	sub CRYPT_DEVINFO_LABEL { 4008 }	# Device/token label

	# Used internally
	sub CRYPT_DEVINFO_LAST { 5000 }
	sub CRYPT_ENVINFO_FIRST { 5000 }

	# *********************
	# Envelope attributes
	# *********************

	# Pseudo-information on an envelope or meta-information which is used to
	# control the way that data in an envelope is processed
	sub CRYPT_ENVINFO_DATASIZE { 5001 }	# Data size information
	sub CRYPT_ENVINFO_COMPRESSION { 5002 }	# Compression information
	sub CRYPT_ENVINFO_CONTENTTYPE { 5003 }	# Inner CMS content type
	sub CRYPT_ENVINFO_DETACHEDSIGNATURE { 5004 }	# Detached signature
	sub CRYPT_ENVINFO_SIGNATURE_RESULT { 5005 }	# Signature check result
	sub CRYPT_ENVINFO_INTEGRITY { 5006 }	# Integrity-protection level

	# Resources required for enveloping/deenveloping
	sub CRYPT_ENVINFO_PASSWORD { 5007 }	# User password
	sub CRYPT_ENVINFO_KEY { 5008 }	# Conventional encryption key
	sub CRYPT_ENVINFO_SIGNATURE { 5009 }	# Signature/signature check key
	sub CRYPT_ENVINFO_SIGNATURE_EXTRADATA { 5010 }	# Extra information added to CMS sigs
	sub CRYPT_ENVINFO_RECIPIENT { 5011 }	# Recipient email address
	sub CRYPT_ENVINFO_PUBLICKEY { 5012 }	# PKC encryption key
	sub CRYPT_ENVINFO_PRIVATEKEY { 5013 }	# PKC decryption key
	sub CRYPT_ENVINFO_PRIVATEKEY_LABEL { 5014 }	# Label of PKC decryption key
	sub CRYPT_ENVINFO_ORIGINATOR { 5015 }	# Originator info/key
	sub CRYPT_ENVINFO_SESSIONKEY { 5016 }	# Session key
	sub CRYPT_ENVINFO_HASH { 5017 }	# Hash value
	sub CRYPT_ENVINFO_TIMESTAMP { 5018 }	# Timestamp information

	# Keysets used to retrieve keys needed for enveloping/deenveloping
	sub CRYPT_ENVINFO_KEYSET_SIGCHECK { 5019 }	# Signature check keyset
	sub CRYPT_ENVINFO_KEYSET_ENCRYPT { 5020 }	# PKC encryption keyset
	sub CRYPT_ENVINFO_KEYSET_DECRYPT { 5021 }	# PKC decryption keyset

	# Used internally
	sub CRYPT_ENVINFO_LAST { 6000 }
	sub CRYPT_SESSINFO_FIRST { 6000 }

	# ********************
	# Session attributes
	# ********************

	# Pseudo-information about the session
	sub CRYPT_SESSINFO_ACTIVE { 6001 }	# Whether session is active
	sub CRYPT_SESSINFO_CONNECTIONACTIVE { 6002 }	# Whether network connection is active

	# Security-related information
	sub CRYPT_SESSINFO_USERNAME { 6003 }	# User name
	sub CRYPT_SESSINFO_PASSWORD { 6004 }	# Password
	sub CRYPT_SESSINFO_PRIVATEKEY { 6005 }	# Server/client private key
	sub CRYPT_SESSINFO_KEYSET { 6006 }	# Certificate store
	sub CRYPT_SESSINFO_AUTHRESPONSE { 6007 }	# Session authorisation OK

	# Client/server information
	sub CRYPT_SESSINFO_SERVER_NAME { 6008 }	# Server name
	sub CRYPT_SESSINFO_SERVER_PORT { 6009 }	# Server port number
	sub CRYPT_SESSINFO_SERVER_FINGERPRINT { 6010 }	# Server key fingerprint
	sub CRYPT_SESSINFO_CLIENT_NAME { 6011 }	# Client name
	sub CRYPT_SESSINFO_CLIENT_PORT { 6012 }	# Client port number
	sub CRYPT_SESSINFO_SESSION { 6013 }	# Transport mechanism
	sub CRYPT_SESSINFO_NETWORKSOCKET { 6014 }	# User-supplied network socket

	# Generic protocol-related information
	sub CRYPT_SESSINFO_VERSION { 6015 }	# Protocol version
	sub CRYPT_SESSINFO_REQUEST { 6016 }	# Cert.request object
	sub CRYPT_SESSINFO_RESPONSE { 6017 }	# Cert.response object
	sub CRYPT_SESSINFO_CACERTIFICATE { 6018 }	# Issuing CA certificate

	# Protocol-specific information
	sub CRYPT_SESSINFO_TSP_MSGIMPRINT { 6019 }	# TSP message imprint
	sub CRYPT_SESSINFO_CMP_REQUESTTYPE { 6020 }	# Request type
	sub CRYPT_SESSINFO_CMP_PKIBOOT { 6021 }	# Enable PKIBoot facility
	sub CRYPT_SESSINFO_CMP_PRIVKEYSET { 6022 }	# Private-key keyset
	sub CRYPT_SESSINFO_SSH_CHANNEL { 6023 }	# SSH current channel
	sub CRYPT_SESSINFO_SSH_CHANNEL_TYPE { 6024 }	# SSH channel type
	sub CRYPT_SESSINFO_SSH_CHANNEL_ARG1 { 6025 }	# SSH channel argument 1
	sub CRYPT_SESSINFO_SSH_CHANNEL_ARG2 { 6026 }	# SSH channel argument 2
	sub CRYPT_SESSINFO_SSH_CHANNEL_ACTIVE { 6027 }	# SSH channel active

	# Used internally
	sub CRYPT_SESSINFO_LAST { 7000 }
	sub CRYPT_USERINFO_FIRST { 7000 }

	# ********************
	# User attributes
	# ********************

	# Security-related information
	sub CRYPT_USERINFO_PASSWORD { 7001 }	# Password

	# User role-related information
	sub CRYPT_USERINFO_CAKEY_CERTSIGN { 7002 }	# CA cert signing key
	sub CRYPT_USERINFO_CAKEY_CRLSIGN { 7003 }	# CA CRL signing key
	sub CRYPT_USERINFO_CAKEY_RTCSSIGN { 7004 }	# CA RTCS signing key
	sub CRYPT_USERINFO_CAKEY_OCSPSIGN { 7005 }	# CA OCSP signing key

	# Used internally for range checking
	sub CRYPT_USERINFO_LAST { CRYPT_USERINFO_LAST }
	sub CRYPT_ATTRIBUTE_LAST { CRYPT_USERINFO_LAST }



##### END ENUM CRYPT_ATTRIBUTE_TYPE

#****************************************************************************
#*                                                                           *
#*                       Attribute Subtypes and Related Values               *
#*                                                                           *
#****************************************************************************

# Flags for the X.509 keyUsage extension 

	sub CRYPT_KEYUSAGE_NONE { 0x000 }
	sub CRYPT_KEYUSAGE_DIGITALSIGNATURE { 0x001 }
	sub CRYPT_KEYUSAGE_NONREPUDIATION { 0x002 }
	sub CRYPT_KEYUSAGE_KEYENCIPHERMENT { 0x004 }
	sub CRYPT_KEYUSAGE_DATAENCIPHERMENT { 0x008 }
	sub CRYPT_KEYUSAGE_KEYAGREEMENT { 0x010 }
	sub CRYPT_KEYUSAGE_KEYCERTSIGN { 0x020 }
	sub CRYPT_KEYUSAGE_CRLSIGN { 0x040 }
	sub CRYPT_KEYUSAGE_ENCIPHERONLY { 0x080 }
	sub CRYPT_KEYUSAGE_DECIPHERONLY { 0x100 }
	sub CRYPT_KEYUSAGE_LAST { 0x200 }   # Last possible value 

# X.509 cRLReason and cryptlib cRLExtReason codes 

  sub CRYPT_CRLREASON_UNSPECIFIED { 0 }
  sub CRYPT_CRLREASON_KEYCOMPROMISE { 1 }
  sub CRYPT_CRLREASON_CACOMPROMISE { 2 }
  sub CRYPT_CRLREASON_AFFILIATIONCHANGED { 3 }
  sub CRYPT_CRLREASON_SUPERSEDED { 4 }
  sub CRYPT_CRLREASON_CESSATIONOFOPERATION { 5 }
  sub CRYPT_CRLREASON_CERTIFICATEHOLD { 6 }
  sub CRYPT_CRLREASON_REMOVEFROMCRL { 8 }
  sub CRYPT_CRLREASON_PRIVILEGEWITHDRAWN { 9 }
  sub CRYPT_CRLREASON_AACOMPROMISE { 10 }
  sub CRYPT_CRLREASON_LAST { 11 }
  sub CRYPT_CRLREASON_NEVERVALID { 20 }
  sub CRYPT_CRLEXTREASON_LAST  { 21 }


#  X.509 CRL reason flags.  These identify the same thing as the cRLReason
#  codes but allow for multiple reasons to be specified.  Note that these
#  don't follow the X.509 naming since in that scheme the enumerated types
#  and bitflags have the same names 

	sub CRYPT_CRLREASONFLAG_UNUSED { 0x001 }
	sub CRYPT_CRLREASONFLAG_KEYCOMPROMISE { 0x002 }
	sub CRYPT_CRLREASONFLAG_CACOMPROMISE { 0x004 }
	sub CRYPT_CRLREASONFLAG_AFFILIATIONCHANGED { 0x008 }
	sub CRYPT_CRLREASONFLAG_SUPERSEDED { 0x010 }
	sub CRYPT_CRLREASONFLAG_CESSATIONOFOPERATION { 0x020 }
	sub CRYPT_CRLREASONFLAG_CERTIFICATEHOLD { 0x040 }
	sub CRYPT_CRLREASONFLAG_LAST { 0x080 }   # Last poss.value 

# X.509 CRL holdInstruction codes 

  sub CRYPT_HOLDINSTRUCTION_NONE { 0 }
  sub CRYPT_HOLDINSTRUCTION_CALLISSUER { 1 }
  sub CRYPT_HOLDINSTRUCTION_REJECT { 2 }
  sub CRYPT_HOLDINSTRUCTION_PICKUPTOKEN { 3 }
  sub CRYPT_HOLDINSTRUCTION_LAST  { 4 }


# Certificate checking compliance levels 

  sub CRYPT_COMPLIANCELEVEL_OBLIVIOUS { 0 }
  sub CRYPT_COMPLIANCELEVEL_REDUCED { 1 }
  sub CRYPT_COMPLIANCELEVEL_STANDARD { 2 }
  sub CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL { 3 }
  sub CRYPT_COMPLIANCELEVEL_PKIX_FULL { 4 }
  sub CRYPT_COMPLIANCELEVEL_LAST  { 5 }


# Flags for the Netscape netscape-cert-type extension 

	sub CRYPT_NS_CERTTYPE_SSLCLIENT { 0x001 }
	sub CRYPT_NS_CERTTYPE_SSLSERVER { 0x002 }
	sub CRYPT_NS_CERTTYPE_SMIME { 0x004 }
	sub CRYPT_NS_CERTTYPE_OBJECTSIGNING { 0x008 }
	sub CRYPT_NS_CERTTYPE_RESERVED { 0x010 }
	sub CRYPT_NS_CERTTYPE_SSLCA { 0x020 }
	sub CRYPT_NS_CERTTYPE_SMIMECA { 0x040 }
	sub CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA { 0x080 }
	sub CRYPT_NS_CERTTYPE_LAST { 0x100 }   # Last possible value 

# Flags for the SET certificate-type extension 

	sub CRYPT_SET_CERTTYPE_CARD { 0x001 }
	sub CRYPT_SET_CERTTYPE_MER { 0x002 }
	sub CRYPT_SET_CERTTYPE_PGWY { 0x004 }
	sub CRYPT_SET_CERTTYPE_CCA { 0x008 }
	sub CRYPT_SET_CERTTYPE_MCA { 0x010 }
	sub CRYPT_SET_CERTTYPE_PCA { 0x020 }
	sub CRYPT_SET_CERTTYPE_GCA { 0x040 }
	sub CRYPT_SET_CERTTYPE_BCA { 0x080 }
	sub CRYPT_SET_CERTTYPE_RCA { 0x100 }
	sub CRYPT_SET_CERTTYPE_ACQ { 0x200 }
	sub CRYPT_SET_CERTTYPE_LAST { 0x400 }   # Last possible value 

# CMS contentType values 

##### BEGIN ENUM CRYPT_CONTENT_TYPE
	sub CRYPT_CONTENT_NONE { 0 }
	sub CRYPT_CONTENT_DATA { 0 }
	sub CRYPT_CONTENT_SIGNEDDATA { 1 }
	sub CRYPT_CONTENT_ENVELOPEDDATA { 1 }
	sub CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA { 2 }
	sub CRYPT_CONTENT_DIGESTEDDATA { 3 }
	sub CRYPT_CONTENT_ENCRYPTEDDATA { 3 }
	sub CRYPT_CONTENT_COMPRESSEDDATA { 4 }
	sub CRYPT_CONTENT_AUTHDATA { 4 }
	sub CRYPT_CONTENT_AUTHENVDATA { 5 }
	sub CRYPT_CONTENT_TSTINFO { 5 }
	sub CRYPT_CONTENT_SPCINDIRECTDATACONTEXT { 6 }
	sub CRYPT_CONTENT_RTCSREQUEST { 7 }
	sub CRYPT_CONTENT_RTCSRESPONSE { 7 }
	sub CRYPT_CONTENT_RTCSRESPONSE_EXT { 8 }
	sub CRYPT_CONTENT_LAST { 8 }


##### END ENUM CRYPT_CONTENT_TYPE

# ESS securityClassification codes 

  sub CRYPT_CLASSIFICATION_UNMARKED { 0 }
  sub CRYPT_CLASSIFICATION_UNCLASSIFIED { 1 }
  sub CRYPT_CLASSIFICATION_RESTRICTED { 2 }
  sub CRYPT_CLASSIFICATION_CONFIDENTIAL { 3 }
  sub CRYPT_CLASSIFICATION_SECRET { 4 }
  sub CRYPT_CLASSIFICATION_TOP_SECRET { 5 }
  sub CRYPT_CLASSIFICATION_LAST { 255 }


# RTCS certificate status 

  sub CRYPT_CERTSTATUS_VALID { 0 }
  sub CRYPT_CERTSTATUS_NOTVALID { 1 }
  sub CRYPT_CERTSTATUS_NONAUTHORITATIVE { 2 }
  sub CRYPT_CERTSTATUS_UNKNOWN  { 3 }


# OCSP revocation status 

  sub CRYPT_OCSPSTATUS_NOTREVOKED { 0 }
  sub CRYPT_OCSPSTATUS_REVOKED { 1 }
  sub CRYPT_OCSPSTATUS_UNKNOWN  { 2 }


#  The amount of detail to include in signatures when signing certificate
#  objects 

##### BEGIN ENUM CRYPT_SIGNATURELEVEL_TYPE

	sub CRYPT_SIGNATURELEVEL_NONE { 0 }	# Include only signature
	sub CRYPT_SIGNATURELEVEL_SIGNERCERT { 1 }	# Include signer cert
	sub CRYPT_SIGNATURELEVEL_ALL { 2 }	# Include all relevant info
	sub CRYPT_SIGNATURELEVEL_LAST { 3 }	# Last possible sig.level type


##### END ENUM CRYPT_SIGNATURELEVEL_TYPE

#  The level of integrity protection to apply to enveloped data.  The 
#  default envelope protection for an envelope with keying information 
#  applied is encryption, this can be modified to use MAC-only protection
#  (with no encryption) or hybrid encryption + authentication 

##### BEGIN ENUM CRYPT_INTEGRITY_TYPE

	sub CRYPT_INTEGRITY_NONE { 0 }	# No integrity protection
	sub CRYPT_INTEGRITY_MACONLY { 1 }	# MAC only, no encryption
	sub CRYPT_INTEGRITY_FULL { 2 }	# Encryption + ingerity protection


##### END ENUM CRYPT_INTEGRITY_TYPE

#  The certificate export format type, which defines the format in which a
#  certificate object is exported 

##### BEGIN ENUM CRYPT_CERTFORMAT_TYPE

	sub CRYPT_CERTFORMAT_NONE { 0 }	# No certificate format
	sub CRYPT_CERTFORMAT_CERTIFICATE { 1 }	# DER-encoded certificate
	sub CRYPT_CERTFORMAT_CERTCHAIN { 2 }	# PKCS #7 certificate chain
	sub CRYPT_CERTFORMAT_TEXT_CERTIFICATE { 3 }	# base-64 wrapped cert
	sub CRYPT_CERTFORMAT_TEXT_CERTCHAIN { 4 }	# base-64 wrapped cert chain
	sub CRYPT_CERTFORMAT_XML_CERTIFICATE { 5 }	# XML wrapped cert
	sub CRYPT_CERTFORMAT_XML_CERTCHAIN { 6 }	# XML wrapped cert chain
	sub CRYPT_CERTFORMAT_LAST { 7 }	# Last possible cert.format type


##### END ENUM CRYPT_CERTFORMAT_TYPE

# CMP request types 

##### BEGIN ENUM CRYPT_REQUESTTYPE_TYPE

	sub CRYPT_REQUESTTYPE_NONE { 0 }	# No request type
	sub CRYPT_REQUESTTYPE_INITIALISATION { 1 }	# Initialisation request
	sub CRYPT_REQUESTTYPE_INITIALIZATION { CRYPT_REQUESTTYPE_INITIALISATION }
	sub CRYPT_REQUESTTYPE_CERTIFICATE { 2 }	# Certification request
	sub CRYPT_REQUESTTYPE_KEYUPDATE { 3 }	# Key update request
	sub CRYPT_REQUESTTYPE_REVOCATION { 4 }	# Cert revocation request
	sub CRYPT_REQUESTTYPE_PKIBOOT { 5 }	# PKIBoot request
	sub CRYPT_REQUESTTYPE_LAST { 6 }	# Last possible request type


##### END ENUM CRYPT_REQUESTTYPE_TYPE

# Key ID types 

##### BEGIN ENUM CRYPT_KEYID_TYPE

	sub CRYPT_KEYID_NONE { 0 }	# No key ID type
	sub CRYPT_KEYID_NAME { 1 }	# Key owner name
	sub CRYPT_KEYID_URI { 2 }	# Key owner URI
	sub CRYPT_KEYID_EMAIL { CRYPT_KEYID_URI }	# Synonym: owner email addr.
	sub CRYPT_KEYID_LAST { 3 }	# Last possible key ID type


##### END ENUM CRYPT_KEYID_TYPE

# The encryption object types 

##### BEGIN ENUM CRYPT_OBJECT_TYPE

	sub CRYPT_OBJECT_NONE { 0 }	# No object type
	sub CRYPT_OBJECT_ENCRYPTED_KEY { 1 }	# Conventionally encrypted key
	sub CRYPT_OBJECT_PKCENCRYPTED_KEY { 2 }	# PKC-encrypted key
	sub CRYPT_OBJECT_KEYAGREEMENT { 3 }	# Key agreement information
	sub CRYPT_OBJECT_SIGNATURE { 4 }	# Signature
	sub CRYPT_OBJECT_LAST { 5 }	# Last possible object type


##### END ENUM CRYPT_OBJECT_TYPE

# Object/attribute error type information 

##### BEGIN ENUM CRYPT_ERRTYPE_TYPE

	sub CRYPT_ERRTYPE_NONE { 0 }	# No error information
	sub CRYPT_ERRTYPE_ATTR_SIZE { 1 }	# Attribute data too small or large
	sub CRYPT_ERRTYPE_ATTR_VALUE { 2 }	# Attribute value is invalid
	sub CRYPT_ERRTYPE_ATTR_ABSENT { 3 }	# Required attribute missing
	sub CRYPT_ERRTYPE_ATTR_PRESENT { 4 }	# Non-allowed attribute present
	sub CRYPT_ERRTYPE_CONSTRAINT { 5 }	# Cert: Constraint violation in object
	sub CRYPT_ERRTYPE_ISSUERCONSTRAINT { 6 }	# Cert: Constraint viol.in issuing cert
	sub CRYPT_ERRTYPE_LAST { 7 }	# Last possible error info type


##### END ENUM CRYPT_ERRTYPE_TYPE

# Cert store management action type 

##### BEGIN ENUM CRYPT_CERTACTION_TYPE

	sub CRYPT_CERTACTION_NONE { 0 }	# No cert management action
	sub CRYPT_CERTACTION_CREATE { 1 }	# Create cert store
	sub CRYPT_CERTACTION_CONNECT { 2 }	# Connect to cert store
	sub CRYPT_CERTACTION_DISCONNECT { 3 }	# Disconnect from cert store
	sub CRYPT_CERTACTION_ERROR { 4 }	# Error information
	sub CRYPT_CERTACTION_ADDUSER { 5 }	# Add PKI user
	sub CRYPT_CERTACTION_DELETEUSER { 6 }	# Delete PKI user
	sub CRYPT_CERTACTION_REQUEST_CERT { 7 }	# Cert request
	sub CRYPT_CERTACTION_REQUEST_RENEWAL { 8 }	# Cert renewal request
	sub CRYPT_CERTACTION_REQUEST_REVOCATION { 9 }	# Cert revocation request
	sub CRYPT_CERTACTION_CERT_CREATION { 10 }	# Cert creation
	sub CRYPT_CERTACTION_CERT_CREATION_COMPLETE { 11 }	# Confirmation of cert creation
	sub CRYPT_CERTACTION_CERT_CREATION_DROP { 12 }	# Cancellation of cert creation
	sub CRYPT_CERTACTION_CERT_CREATION_REVERSE { 13 }	# Cancel of creation w.revocation
	sub CRYPT_CERTACTION_RESTART_CLEANUP { 14 }	# Delete reqs after restart
	sub CRYPT_CERTACTION_RESTART_REVOKE_CERT { 15 }	# Complete revocation after restart
	sub CRYPT_CERTACTION_ISSUE_CERT { 16 }	# Cert issue
	sub CRYPT_CERTACTION_ISSUE_CRL { 17 }	# CRL issue
	sub CRYPT_CERTACTION_REVOKE_CERT { 18 }	# Cert revocation
	sub CRYPT_CERTACTION_EXPIRE_CERT { 19 }	# Cert expiry
	sub CRYPT_CERTACTION_CLEANUP { 20 }	# Clean up on restart
	sub CRYPT_CERTACTION_LAST { 21 }	# Last possible cert store log action


##### END ENUM CRYPT_CERTACTION_TYPE

#****************************************************************************
#*                                                                           *
#*                               General Constants                           *
#*                                                                           *
#****************************************************************************

# The maximum user key size - 2048 bits 

	sub CRYPT_MAX_KEYSIZE { 256 }

# The maximum IV size - 256 bits 

	sub CRYPT_MAX_IVSIZE { 32 }

#  The maximum public-key component size - 4096 bits, and maximum component
#  size for ECCs - 256 bits 

	sub CRYPT_MAX_PKCSIZE { 512 }
	sub CRYPT_MAX_PKCSIZE_ECC { 32 }

# The maximum hash size - 256 bits 

	sub CRYPT_MAX_HASHSIZE { 32 }

# The maximum size of a text string (e.g.key owner name) 

	sub CRYPT_MAX_TEXTSIZE { 64 }

#  A magic value indicating that the default setting for this parameter
#  should be used 

	sub CRYPT_USE_DEFAULT { -100 }

# A magic value for unused parameters 

	sub CRYPT_UNUSED { -101 }

# Cursor positioning codes for certificate/CRL extensions 

	sub CRYPT_CURSOR_FIRST { -200 }
	sub CRYPT_CURSOR_PREVIOUS { -201 }
	sub CRYPT_CURSOR_NEXT { -202 }
	sub CRYPT_CURSOR_LAST { -203 }

#  The type of information polling to perform to get random seed 
#  information.  These values have to be negative because they're used
#  as magic length values for cryptAddRandom() 

	sub CRYPT_RANDOM_FASTPOLL { -300 }
	sub CRYPT_RANDOM_SLOWPOLL { -301 }

# Whether the PKC key is a public or private key 

	sub CRYPT_KEYTYPE_PRIVATE { 0 }
	sub CRYPT_KEYTYPE_PUBLIC { 1 }

# Keyset open options 

##### BEGIN ENUM CRYPT_KEYOPT_TYPE

	sub CRYPT_KEYOPT_NONE { 0 }	# No options
	sub CRYPT_KEYOPT_READONLY { 1 }	# Open keyset in read-only mode
	sub CRYPT_KEYOPT_CREATE { 2 }	# Create a new keyset
	sub CRYPT_KEYOPT_LAST { 3 }	# Last possible key option type


##### END ENUM CRYPT_KEYOPT_TYPE

# The various cryptlib objects - these are just integer handles 

sub CRYPT_CERTIFICATE { 0 }
sub CRYPT_CONTEXT { 0 }
sub CRYPT_DEVICE { 0 }
sub CRYPT_ENVELOPE { 0 }
sub CRYPT_KEYSET { 0 }
sub CRYPT_SESSION { 0 }
sub CRYPT_USER { 0 }

#  Sometimes we don't know the exact type of a cryptlib object, so we use a
#  generic handle type to identify it 

sub CRYPT_HANDLE { 0 }

#****************************************************************************
#*                                                                           *
#*                           Encryption Data Structures                      *
#*                                                                           *
#****************************************************************************

# Results returned from the capability query 

sub CRYPT_QUERY_INFO
{
	{
	#  Algorithm information 
     algoName => ' ' x CRYPT_MAX_TEXTSIZE	#  Algorithm name 
    ,blockSize => 0	#  Block size of the algorithm 
    ,minKeySize => 0	#  Minimum key size in bytes 
    ,keySize => 0	#  Recommended key size in bytes 
    ,maxKeySize => 0	#  Maximum key size in bytes 
    
	}
}

#  Results returned from the encoded object query.  These provide
#  information on the objects created by cryptExportKey()/
#  cryptCreateSignature() 

sub CRYPT_OBJECT_INFO
{
	{
	#  The object type 
     objectType => 0	#  The encryption algorithm and mode 
    ,cryptAlgo => 0
    ,cryptMode => 0	#  The hash algorithm for Signature objects 
    ,hashAlgo => 0	#  The salt for derived keys 
    ,salt => ' ' x CRYPT_MAX_HASHSIZE
    ,saltSize => 0
    
	}
}

#  Key information for the public-key encryption algorithms.  These fields
#  are not accessed directly, but can be manipulated with the init/set/
#  destroyComponents() macros 

sub CRYPT_PKCINFO_RSA
{
	{
	#  Status information 
     isPublicKey => 0	#  Whether this is a public or private key 
	#  Public components 
    ,n => ' ' x CRYPT_MAX_PKCSIZE	#  Modulus 
    ,nLen => 0	#  Length of modulus in bits 
    ,e => ' ' x CRYPT_MAX_PKCSIZE	#  Public exponent 
    ,eLen => 0	#  Length of public exponent in bits 
	#  Private components 
    ,d => ' ' x CRYPT_MAX_PKCSIZE	#  Private exponent 
    ,dLen => 0	#  Length of private exponent in bits 
    ,p => ' ' x CRYPT_MAX_PKCSIZE	#  Prime factor 1 
    ,pLen => 0	#  Length of prime factor 1 in bits 
    ,q => ' ' x CRYPT_MAX_PKCSIZE	#  Prime factor 2 
    ,qLen => 0	#  Length of prime factor 2 in bits 
    ,u => ' ' x CRYPT_MAX_PKCSIZE	#  Mult.inverse of q, mod p 
    ,uLen => 0	#  Length of private exponent in bits 
    ,e1 => ' ' x CRYPT_MAX_PKCSIZE	#  Private exponent 1 (PKCS) 
    ,e1Len => 0	#  Length of private exponent in bits 
    ,e2 => ' ' x CRYPT_MAX_PKCSIZE	#  Private exponent 2 (PKCS) 
    ,e2Len => 0	#  Length of private exponent in bits 
    
	}
}

sub CRYPT_PKCINFO_DLP
{
	{
	#  Status information 
     isPublicKey => 0	#  Whether this is a public or private key 
	#  Public components 
    ,p => ' ' x CRYPT_MAX_PKCSIZE	#  Prime modulus 
    ,pLen => 0	#  Length of prime modulus in bits 
    ,q => ' ' x CRYPT_MAX_PKCSIZE	#  Prime divisor 
    ,qLen => 0	#  Length of prime divisor in bits 
    ,g => ' ' x CRYPT_MAX_PKCSIZE	#  h^( ( p - 1 ) / q ) mod p 
    ,gLen => 0	#  Length of g in bits 
    ,y => ' ' x CRYPT_MAX_PKCSIZE	#  Public random integer 
    ,yLen => 0	#  Length of public integer in bits 
	#  Private components 
    ,x => ' ' x CRYPT_MAX_PKCSIZE	#  Private random integer 
    ,xLen => 0	#  Length of private integer in bits 
    
	}
}

sub CRYPT_PKCINFO_ECC
{
	{
	#  Status information 
     isPublicKey => 0	#  Whether this is a public or private key 
	#  Curve 
    ,p => ' ' x CRYPT_MAX_PKCSIZE_ECC	#  Prime defining Fq 
    ,pLen => 0	#  Length of prime in bits 
    ,a => ' ' x CRYPT_MAX_PKCSIZE_ECC	#  Element in Fq defining curve 
    ,aLen => 0	#  Length of element a in bits 
    ,b => ' ' x CRYPT_MAX_PKCSIZE_ECC	#  Element in Fq defining curve 
    ,bLen => 0	#  Length of element b in bits 
	#  Generator 
    ,gx => ' ' x CRYPT_MAX_PKCSIZE_ECC	#  Element in Fq defining point 
    ,gxLen => 0	#  Length of element gx in bits 
    ,gy => ' ' x CRYPT_MAX_PKCSIZE_ECC	#  Element in Fq defining point 
    ,gyLen => 0	#  Length of element gy in bits 
    ,r => ' ' x CRYPT_MAX_PKCSIZE_ECC	#  Order of point 
    ,rLen => 0	#  Length of order in bits 
    ,h => ' ' x CRYPT_MAX_PKCSIZE_ECC	#  Optional cofactor 
    ,hLen => 0	#  Length of cofactor in bits 
	#  Public components 
    ,qx => ' ' x CRYPT_MAX_PKCSIZE_ECC	#  Point Q on the curve 
    ,qxLen => 0	#  Length of point xq in bits 
    ,qy => ' ' x CRYPT_MAX_PKCSIZE_ECC	#  Point Q on the curve 
    ,qyLen => 0	#  Length of point xy in bits 
	#  Private components 
    ,d => ' ' x CRYPT_MAX_PKCSIZE_ECC	#  Private random integer 
    ,dLen => 0	#  Length of integer in bits 
    
	}
}

#  Macros to initialise and destroy the structure that stores the components
#  of a public key 

# C-macro not translated to Perl code but implemented apart: 
#   #define cryptInitComponents( componentInfo, componentKeyType ) 
#    { memset( ( componentInfo ), 0, sizeof( *componentInfo ) ); 
#      ( componentInfo )->isPublicKey = ( ( componentKeyType ) ? 1 : 0 ); }
#

# C-macro not translated to Perl code but implemented apart: 
#   #define cryptDestroyComponents( componentInfo ) 
#    memset( ( componentInfo ), 0, sizeof( *componentInfo ) )
#

# Macros to set a component of a public key 

# C-macro not translated to Perl code but implemented apart: 
#   #define cryptSetComponent( destination, source, length ) 
#    { memcpy( ( destination ), ( source ), ( ( length ) + 7 ) >> 3 ); 
#      ( destination##Len ) = length; }
#

#****************************************************************************
#*                                                                           *
#*                               Status Codes                                *
#*                                                                           *
#****************************************************************************

# No error in function call 

	sub CRYPT_OK { 0 }   # No error 

# Error in parameters passed to function 

	sub CRYPT_ERROR_PARAM1 { -1 }  # Bad argument, parameter 1 
	sub CRYPT_ERROR_PARAM2 { -2 }  # Bad argument, parameter 2 
	sub CRYPT_ERROR_PARAM3 { -3 }  # Bad argument, parameter 3 
	sub CRYPT_ERROR_PARAM4 { -4 }  # Bad argument, parameter 4 
	sub CRYPT_ERROR_PARAM5 { -5 }  # Bad argument, parameter 5 
	sub CRYPT_ERROR_PARAM6 { -6 }  # Bad argument, parameter 6 
	sub CRYPT_ERROR_PARAM7 { -7 }  # Bad argument, parameter 7 

# Errors due to insufficient resources 

	sub CRYPT_ERROR_MEMORY { -10 } # Out of memory 
	sub CRYPT_ERROR_NOTINITED { -11 } # Data has not been initialised 
	sub CRYPT_ERROR_INITED { -12 } # Data has already been init'd 
	sub CRYPT_ERROR_NOSECURE { -13 } # Opn.not avail.at requested sec.level 
	sub CRYPT_ERROR_RANDOM { -14 } # No reliable random data available 
	sub CRYPT_ERROR_FAILED { -15 } # Operation failed 
	sub CRYPT_ERROR_INTERNAL { -16 } # Internal consistency check failed 

# Security violations 

	sub CRYPT_ERROR_NOTAVAIL { -20 } # This type of opn.not available 
	sub CRYPT_ERROR_PERMISSION { -21 } # No permiss.to perform this operation 
	sub CRYPT_ERROR_WRONGKEY { -22 } # Incorrect key used to decrypt data 
	sub CRYPT_ERROR_INCOMPLETE { -23 } # Operation incomplete/still in progress 
	sub CRYPT_ERROR_COMPLETE { -24 } # Operation complete/can't continue 
	sub CRYPT_ERROR_TIMEOUT { -25 } # Operation timed out before completion 
	sub CRYPT_ERROR_INVALID { -26 } # Invalid/inconsistent information 
	sub CRYPT_ERROR_SIGNALLED { -27 } # Resource destroyed by extnl.event 

# High-level function errors 

	sub CRYPT_ERROR_OVERFLOW { -30 } # Resources/space exhausted 
	sub CRYPT_ERROR_UNDERFLOW { -31 } # Not enough data available 
	sub CRYPT_ERROR_BADDATA { -32 } # Bad/unrecognised data format 
	sub CRYPT_ERROR_SIGNATURE { -33 } # Signature/integrity check failed 

# Data access function errors 

	sub CRYPT_ERROR_OPEN { -40 } # Cannot open object 
	sub CRYPT_ERROR_READ { -41 } # Cannot read item from object 
	sub CRYPT_ERROR_WRITE { -42 } # Cannot write item to object 
	sub CRYPT_ERROR_NOTFOUND { -43 } # Requested item not found in object 
	sub CRYPT_ERROR_DUPLICATE { -44 } # Item already present in object 

# Data enveloping errors 

	sub CRYPT_ENVELOPE_RESOURCE { -50 } # Need resource to proceed 

# Macros to examine return values 

# C-macro not translated to Perl code but implemented apart: 
#   #define cryptStatusError( status )  ( ( status ) < CRYPT_OK )
#
# C-macro not translated to Perl code but implemented apart: 
#   #define cryptStatusOK( status )     ( ( status ) == CRYPT_OK )
#

#****************************************************************************
#*                                                                           *
#*                                   General Functions                       *
#*                                                                           *
#****************************************************************************

# The following is necessary to stop C++ name mangling 


# Initialise and shut down cryptlib 

#C_RET cryptInit( void );
##C_RET cryptEnd( void );
#
# Query cryptlibs capabilities 

#C_RET cryptQueryCapability( C_IN CRYPT_ALGO_TYPE cryptAlgo,
#                            C_OUT CRYPT_QUERY_INFO C_PTR cryptQueryInfo );
#
# Create and destroy an encryption context 

#C_RET cryptCreateContext( C_OUT CRYPT_CONTEXT C_PTR cryptContext,
#                          C_IN CRYPT_USER cryptUser,
#                          C_IN CRYPT_ALGO_TYPE cryptAlgo );
##C_RET cryptDestroyContext( C_IN CRYPT_CONTEXT cryptContext );
#
# Generic "destroy an object" function 

#C_RET cryptDestroyObject( C_IN CRYPT_HANDLE cryptObject );
#
# Generate a key into a context 

#C_RET cryptGenerateKey( C_IN CRYPT_CONTEXT cryptContext );
##C_RET cryptGenerateKeyAsync( C_IN CRYPT_CONTEXT cryptContext );
##C_RET cryptAsyncQuery( C_IN CRYPT_HANDLE cryptObject );
##C_RET cryptAsyncCancel( C_IN CRYPT_HANDLE cryptObject );
#
# Encrypt/decrypt/hash a block of memory 

#C_RET cryptEncrypt( C_IN CRYPT_CONTEXT cryptContext, C_INOUT void C_PTR buffer,
#                    C_IN int length );
##C_RET cryptDecrypt( C_IN CRYPT_CONTEXT cryptContext, C_INOUT void C_PTR buffer,
#                    C_IN int length );
#
# Get/set/delete attribute functions 

#C_RET cryptSetAttribute( C_IN CRYPT_HANDLE cryptHandle,
#                         C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
#                         C_IN int value );
##C_RET cryptSetAttributeString( C_IN CRYPT_HANDLE cryptHandle,
#                               C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
#                               C_IN void C_PTR value, C_IN int valueLength );
##C_RET cryptGetAttribute( C_IN CRYPT_HANDLE cryptHandle,
#                         C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
#                         C_OUT int C_PTR value );
##C_RET cryptGetAttributeString( C_IN CRYPT_HANDLE cryptHandle,
#                               C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
#                               C_OUT void C_PTR value,
#                               C_OUT int C_PTR valueLength );
##C_RET cryptDeleteAttribute( C_IN CRYPT_HANDLE cryptHandle,
#                            C_IN CRYPT_ATTRIBUTE_TYPE attributeType );
#
#  Oddball functions: Add random data to the pool, query an encoded signature
#  or key data.  These are due to be replaced once a suitable alternative can
#  be found 

#C_RET cryptAddRandom( C_IN void C_PTR randomData, C_IN int randomDataLength );
##C_RET cryptQueryObject( C_IN void C_PTR objectData,
#                        C_IN int objectDataLength,
#                        C_OUT CRYPT_OBJECT_INFO C_PTR cryptObjectInfo );
#
#****************************************************************************
#*                                                                           *
#*                           Mid-level Encryption Functions                  *
#*                                                                           *
#****************************************************************************

# Export and import an encrypted session key 

#C_RET cryptExportKey( C_OUT void C_PTR encryptedKey,
#                      C_IN int encryptedKeyMaxLength,
#                      C_OUT int C_PTR encryptedKeyLength,
#                      C_IN CRYPT_HANDLE exportKey,
#                      C_IN CRYPT_CONTEXT sessionKeyContext );
##C_RET cryptExportKeyEx( C_OUT void C_PTR encryptedKey,
#                        C_IN int encryptedKeyMaxLength,
#                        C_OUT int C_PTR encryptedKeyLength,
#                        C_IN CRYPT_FORMAT_TYPE formatType,
#                        C_IN CRYPT_HANDLE exportKey,
#                        C_IN CRYPT_CONTEXT sessionKeyContext );
##C_RET cryptImportKey( C_IN void C_PTR encryptedKey,
#                      C_IN int encryptedKeyLength,
#                      C_IN CRYPT_CONTEXT importKey,
#                      C_IN CRYPT_CONTEXT sessionKeyContext );
##C_RET cryptImportKeyEx( C_IN void C_PTR encryptedKey,
#                        C_IN int encryptedKeyLength,
#                        C_IN CRYPT_CONTEXT importKey,
#                        C_IN CRYPT_CONTEXT sessionKeyContext,
#                        C_OUT CRYPT_CONTEXT C_PTR returnedContext );
#
# Create and check a digital signature 

#C_RET cryptCreateSignature( C_OUT void C_PTR signature,
#                            C_IN int signatureMaxLength,
#                            C_OUT int C_PTR signatureLength,
#                            C_IN CRYPT_CONTEXT signContext,
#                            C_IN CRYPT_CONTEXT hashContext );
##C_RET cryptCreateSignatureEx( C_OUT void C_PTR signature,
#                              C_IN int signatureMaxLength,
#                              C_OUT int C_PTR signatureLength,
#                              C_IN CRYPT_FORMAT_TYPE formatType,
#                              C_IN CRYPT_CONTEXT signContext,
#                              C_IN CRYPT_CONTEXT hashContext,
#                              C_IN CRYPT_CERTIFICATE extraData );
##C_RET cryptCheckSignature( C_IN void C_PTR signature,
#                           C_IN int signatureLength,
#                           C_IN CRYPT_HANDLE sigCheckKey,
#                           C_IN CRYPT_CONTEXT hashContext );
##C_RET cryptCheckSignatureEx( C_IN void C_PTR signature,
#                             C_IN int signatureLength,
#                             C_IN CRYPT_HANDLE sigCheckKey,
#                             C_IN CRYPT_CONTEXT hashContext,
#                             C_OUT CRYPT_HANDLE C_PTR extraData );
#
#****************************************************************************
#*                                                                           *
#*                                   Keyset Functions                        *
#*                                                                           *
#****************************************************************************

# Open and close a keyset 

#C_RET cryptKeysetOpen( C_OUT CRYPT_KEYSET C_PTR keyset,
#                       C_IN CRYPT_USER cryptUser,
#                       C_IN CRYPT_KEYSET_TYPE keysetType,
#                       C_IN C_STR name, C_IN CRYPT_KEYOPT_TYPE options );
##C_RET cryptKeysetClose( C_IN CRYPT_KEYSET keyset );
#
# Get a key from a keyset or device 

#C_RET cryptGetPublicKey( C_IN CRYPT_KEYSET keyset,
#                         C_OUT CRYPT_CONTEXT C_PTR cryptContext,
#                         C_IN CRYPT_KEYID_TYPE keyIDtype,
#                         C_IN C_STR keyID );
##C_RET cryptGetPrivateKey( C_IN CRYPT_KEYSET keyset,
#                          C_OUT CRYPT_CONTEXT C_PTR cryptContext,
#                          C_IN CRYPT_KEYID_TYPE keyIDtype,
#                          C_IN C_STR keyID, C_IN C_STR password );
##C_RET cryptGetKey( C_IN CRYPT_KEYSET keyset,
#                   C_OUT CRYPT_CONTEXT C_PTR cryptContext,
#                   C_IN CRYPT_KEYID_TYPE keyIDtype, C_IN C_STR keyID, 
#                   C_IN C_STR password );
#
# Add/delete a key to/from a keyset or device 

#C_RET cryptAddPublicKey( C_IN CRYPT_KEYSET keyset,
#                         C_IN CRYPT_CERTIFICATE certificate );
##C_RET cryptAddPrivateKey( C_IN CRYPT_KEYSET keyset,
#                          C_IN CRYPT_HANDLE cryptKey,
#                          C_IN C_STR password );
##C_RET cryptDeleteKey( C_IN CRYPT_KEYSET keyset,
#                      C_IN CRYPT_KEYID_TYPE keyIDtype,
#                      C_IN C_STR keyID );
#
#****************************************************************************
#*                                                                           *
#*                               Certificate Functions                       *
#*                                                                           *
#****************************************************************************

# Create/destroy a certificate 

#C_RET cryptCreateCert( C_OUT CRYPT_CERTIFICATE C_PTR certificate,
#                       C_IN CRYPT_USER cryptUser,
#                       C_IN CRYPT_CERTTYPE_TYPE certType );
##C_RET cryptDestroyCert( C_IN CRYPT_CERTIFICATE certificate );
#
#  Get/add/delete certificate extensions.  These are direct data insertion
#  functions whose use is discouraged, so they fix the string at char *
#  rather than C_STR 

#C_RET cryptGetCertExtension( C_IN CRYPT_CERTIFICATE certificate,
#                             C_IN char C_PTR oid,
#                             C_OUT int C_PTR criticalFlag,
#                             C_OUT void C_PTR extension,
#                             C_IN int extensionMaxLength,
#                             C_OUT int C_PTR extensionLength );
##C_RET cryptAddCertExtension( C_IN CRYPT_CERTIFICATE certificate,
#                             C_IN char C_PTR oid, C_IN int criticalFlag,
#                             C_IN void C_PTR extension,
#                             C_IN int extensionLength );
##C_RET cryptDeleteCertExtension( C_IN CRYPT_CERTIFICATE certificate,
#                                C_IN char C_PTR oid );
#
# Sign/sig.check a certificate/certification request 

#C_RET cryptSignCert( C_IN CRYPT_CERTIFICATE certificate,
#                     C_IN CRYPT_CONTEXT signContext );
##C_RET cryptCheckCert( C_IN CRYPT_CERTIFICATE certificate,
#                      C_IN CRYPT_HANDLE sigCheckKey );
#
# Import/export a certificate/certification request 

#C_RET cryptImportCert( C_IN void C_PTR certObject,
#                       C_IN int certObjectLength,
#                       C_IN CRYPT_USER cryptUser,
#                       C_OUT CRYPT_CERTIFICATE C_PTR certificate );
##C_RET cryptExportCert( C_OUT void C_PTR certObject,
#                       C_IN int certObjectMaxLength,
#                       C_OUT int C_PTR certObjectLength,
#                       C_IN CRYPT_CERTFORMAT_TYPE certFormatType,
#                       C_IN CRYPT_CERTIFICATE certificate );
#
# CA management functions 

#C_RET cryptCAAddItem( C_IN CRYPT_KEYSET keyset,
#                      C_IN CRYPT_CERTIFICATE certificate );
##C_RET cryptCAGetItem( C_IN CRYPT_KEYSET keyset,
#                      C_OUT CRYPT_CERTIFICATE C_PTR certificate,
#                      C_IN CRYPT_CERTTYPE_TYPE certType,
#                      C_IN CRYPT_KEYID_TYPE keyIDtype,
#                      C_IN C_STR keyID );
##C_RET cryptCADeleteItem( C_IN CRYPT_KEYSET keyset,
#                         C_IN CRYPT_CERTTYPE_TYPE certType,
#                         C_IN CRYPT_KEYID_TYPE keyIDtype,
#                         C_IN C_STR keyID );
##C_RET cryptCACertManagement( C_OUT CRYPT_CERTIFICATE C_PTR certificate,
#                             C_IN CRYPT_CERTACTION_TYPE action,
#                             C_IN CRYPT_KEYSET keyset,
#                             C_IN CRYPT_CONTEXT caKey,
#                             C_IN CRYPT_CERTIFICATE certRequest );
#
#****************************************************************************
#*                                                                           *
#*                           Envelope and Session Functions                  *
#*                                                                           *
#****************************************************************************

# Create/destroy an envelope 

#C_RET cryptCreateEnvelope( C_OUT CRYPT_ENVELOPE C_PTR envelope,
#                           C_IN CRYPT_USER cryptUser,
#                           C_IN CRYPT_FORMAT_TYPE formatType );
##C_RET cryptDestroyEnvelope( C_IN CRYPT_ENVELOPE envelope );
#
# Create/destroy a session 

#C_RET cryptCreateSession( C_OUT CRYPT_SESSION C_PTR session,
#                          C_IN CRYPT_USER cryptUser,
#                          C_IN CRYPT_SESSION_TYPE formatType );
##C_RET cryptDestroySession( C_IN CRYPT_SESSION session );
#
# Add/remove data to/from and envelope or session 

#C_RET cryptPushData( C_IN CRYPT_HANDLE envelope, C_IN void C_PTR buffer,
#                     C_IN int length, C_OUT int C_PTR bytesCopied );
##C_RET cryptFlushData( C_IN CRYPT_HANDLE envelope );
##C_RET cryptPopData( C_IN CRYPT_HANDLE envelope, C_OUT void C_PTR buffer,
#                    C_IN int length, C_OUT int C_PTR bytesCopied );
#
#****************************************************************************
#*                                                                           *
#*                               Device Functions                            *
#*                                                                           *
#****************************************************************************

# Open and close a device 

#C_RET cryptDeviceOpen( C_OUT CRYPT_DEVICE C_PTR device,
#                       C_IN CRYPT_USER cryptUser,
#                       C_IN CRYPT_DEVICE_TYPE deviceType,
#                       C_IN C_STR name );
##C_RET cryptDeviceClose( C_IN CRYPT_DEVICE device );
#
# Query a devices capabilities 

#C_RET cryptDeviceQueryCapability( C_IN CRYPT_DEVICE device,
#                                  C_IN CRYPT_ALGO_TYPE cryptAlgo,
#                                  C_OUT CRYPT_QUERY_INFO C_PTR cryptQueryInfo );
#
# Create an encryption context via the device 

#C_RET cryptDeviceCreateContext( C_IN CRYPT_DEVICE device,
#                                C_OUT CRYPT_CONTEXT C_PTR cryptContext,
#                                C_IN CRYPT_ALGO_TYPE cryptAlgo );
#
#****************************************************************************
#*                                                                           *
#*                           User Management Functions                       *
#*                                                                           *
#****************************************************************************

# Log on and off (create/destroy a user object) 

#C_RET cryptLogin( C_OUT CRYPT_USER C_PTR user,
#                  C_IN C_STR name, C_IN C_STR password );
##C_RET cryptLogout( C_IN CRYPT_USER user );
#


#
# *****************************************************************************
# *                                                                           *
# *                    End of Perl Functions                                  *
# *                                                                           *
# *****************************************************************************
#

1; ##### End-of perl header file!

