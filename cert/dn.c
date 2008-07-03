/****************************************************************************
*																			*
*							Certificate DN Routines							*
*						Copyright Peter Gutmann 1996-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "cert.h"
  #include "asn1.h"
#else
  #include "cert/cert.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

/* DN component info flags.  Some implementations may place more than one
   AVA into a RDN, in which case we set a flag to indicate that the RDN
   continues in the next DN component structure.  If the RDN/DN was set by
   specifying the entire DN at once using a free-format text DN string, it's
   not a good idea to allow random changes to it so we mark the components
   as locked.  If we're reading data from an external source the DN can
   contain all sorts of strange stuff so we set a flag to tell the DN
   component-handling code not to perform any validity checking on the
   components as they're added */

#define DN_FLAG_NONE		0x00	/* No DN flag */
#define DN_FLAG_CONTINUED	0x01	/* RDN continues with another AVA */
#define DN_FLAG_LOCKED		0x02	/* RDN can't be modified */
#define DN_FLAG_PREENCODED	0x04	/* RDN has had pre-encoding done */
#define DN_FLAG_NOCHECK		0x08	/* Don't check validity of components */
#define DN_FLAG_MAX			0x0F	/* Maximum possible flag value */

/* The structure to hold a DN component */

typedef struct DC {
	/* DN component type and type information */
	int type;						/* cryptlib component type, either a
									   CRYPT_ATTRIBUTE_TYPE or an integer ID */
	const void *typeInfo;			/* Type info for this component */
	int flags;

	/* DN component data */
	BUFFER_FIXED( valueLength ) \
	void *value;					/* DN component value */
	int valueLength;				/* DN component value length */
	int valueStringType;			/* DN component native string type */

	/* Encoding information: The native string type (used for conversion to
	   ASN.1 string type when encoding), the encoded string type, the 
	   overall size of the RDN data (without the tag and length) if this is 
	   the first or only component of an RDN, and the size of the AVA data */
	int encodingStringType, encodedStringType;
	int encodedRDNdataSize, encodedAVAdataSize;

	/* The next and previous list element in the linked list of DN
	   components */
	struct DC *next, *prev;

	/* Variable-length storage for the DN data */
	DECLARE_VARSTRUCT_VARS;
	} DN_COMPONENT;

/****************************************************************************
*																			*
*							DN Information Tables							*
*																			*
****************************************************************************/

/* A macro to make make declaring DN OIDs simpler */

#define MKDNOID( value )			MKOID( "\x06\x03" value )

/* Type information for DN components.  If the OID doesn't correspond to a 
   valid cryptlib component (i.e. it's one of the 1,001 other odd things that 
   can be crammed into a DN) we can't directly identify it with a type but 
   instead return a simple integer value in the info table.  This works 
   because the certificate component values don't start until x000 */

typedef struct {
	const CRYPT_ATTRIBUTE_TYPE type;/* cryptlib type */
	const BYTE *oid;				/* OID for this type */
	const char *name, *altName;		/* Name for this type */
	const int maxLength;			/* Maximum allowed length for this type */
	const BOOLEAN ia5OK;			/* Whether IA5 is allowed for this comp.*/
	const BOOLEAN wcsOK;			/* Whether widechar is allowed for comp.*/
	} DN_COMPONENT_INFO;

static const DN_COMPONENT_INFO FAR_BSS certInfoOIDs[] = {
	/* Useful components */
	{ CRYPT_CERTINFO_COMMONNAME, MKDNOID( "\x55\x04\x03" ), 
	  "cn", "oid.2.5.4.3", CRYPT_MAX_TEXTSIZE, FALSE, TRUE },
	{ CRYPT_CERTINFO_COUNTRYNAME, MKDNOID( "\x55\x04\x06" ), 
	  "c", "oid.2.5.4.6", 2, FALSE, FALSE },
	{ CRYPT_CERTINFO_LOCALITYNAME, MKDNOID( "\x55\x04\x07" ), 
	  "l", "oid.2.5.4.7", 128, FALSE, TRUE },
	{ CRYPT_CERTINFO_STATEORPROVINCENAME, MKDNOID( "\x55\x04\x08" ), 
	  "sp", "oid.2.5.4.8", 128, FALSE, TRUE },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, MKDNOID( "\x55\x04\x0A" ), 
	  "o", "oid.2.5.4.10", CRYPT_MAX_TEXTSIZE, FALSE, TRUE },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, MKDNOID( "\x55\x04\x0B" ), 
	  "ou", "oid.2.5.4.11", CRYPT_MAX_TEXTSIZE, FALSE, TRUE },

	/* Non-useful components */
	{ 1, MKDNOID( "\x55\x04\x01" ),		/* aliasObjectName (2 5 4 1) */
	  "oid.2.5.4.1", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 2, MKDNOID( "\x55\x04\x02" ),		/* knowledgeInformation (2 5 4 2) */
	  "oid.2.5.4.2", NULL, MAX_ATTRIBUTE_SIZE /*32768*/, FALSE, FALSE },
	{ 3, MKDNOID( "\x55\x04\x04" ),		/* surname (2 5 4 4) */
	  "s", "oid.2.5.4.4", CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 4, MKDNOID( "\x55\x04\x05" ),		/* serialNumber (2 5 4 5) */
	  "sn", "oid.2.5.4.5", CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 5, MKDNOID( "\x55\x04\x09" ),		/* streetAddress (2 5 4 9) */
	  "st", "oid.2.5.4.9", 128, FALSE, FALSE },
	{ 6, MKDNOID( "\x55\x04\x0C" ),		/* title (2 5 4 12) */
	  "t", "oid.2.5.4.12", CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 7, MKDNOID( "\x55\x04\x0D" ),		/* description (2 5 4 13) */
	  "d", "oid.2.5.4.13", 1024, FALSE, FALSE },
	{ 8, MKDNOID( "\x55\x04\x0E" ),		/* searchGuide (2 5 4 14) */
	  "oid.2.5.4.14", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 9, MKDNOID( "\x55\x04\x0F" ),		/* businessCategory (2 5 4 15) */
	  "bc", "oid.2.5.4.15", 128, FALSE, FALSE },
	{ 10, MKDNOID( "\x55\x04\x10" ),	/* postalAddress (2 5 4 16) */
	  "oid.2.5.4.16", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 11, MKDNOID( "\x55\x04\x11" ),	/* postalCode (2 5 4 17) */
	  "oid.2.5.4.17", NULL, 40, FALSE, FALSE },
	{ 12, MKDNOID( "\x55\x04\x12" ),	/* postOfficeBox (2 5 4 18) */
	  "oid.2.5.4.18", NULL, 40, FALSE, FALSE },
	{ 13, MKDNOID( "\x55\x04\x13" ),	/* physicalDeliveryOfficeName (2 5 4 19) */
	  "oid.2.5.4.19", NULL, 128, FALSE, FALSE },
	{ 14, MKDNOID( "\x55\x04\x14" ),	/* telephoneNumber (2 5 4 20) */
	  "oid.2.5.4.20", NULL, 32, FALSE, FALSE },
	{ 15, MKDNOID( "\x55\x04\x15" ),	/* telexNumber (2 5 4 21) */
	  "oid.2.5.4.21", NULL, 14, FALSE, FALSE },
	{ 16, MKDNOID( "\x55\x04\x16" ),	/* teletexTerminalIdentifier (2 5 4 22) */
	  "oid.2.5.4.22", NULL, 24, FALSE, FALSE },
	{ 17, MKDNOID( "\x55\x04\x17" ),	/* facsimileTelephoneNumber (2 5 4 23) */
	  "oid.2.5.4.23", NULL, 32, FALSE, FALSE },
	{ 18, MKDNOID( "\x55\x04\x18" ),	/* x121Address (2 5 4 24) */
	  "oid.2.5.4.24", NULL, 15, FALSE, FALSE },
	{ 19, MKDNOID( "\x55\x04\x19" ),	/* internationalISDNNumber (2 5 4 25) */
	  "isdn", "oid.2.5.4.25", 16, FALSE, FALSE },
	{ 20, MKDNOID( "\x55\x04\x1A" ),	/* registeredAddress (2 5 4 26) */
	  "oid.2.5.4.26", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 21, MKDNOID( "\x55\x04\x1B" ),	/* destinationIndicator (2 5 4 27) */
	  "oid.2.5.4.27", NULL, 128, FALSE, FALSE },
	{ 22, MKDNOID( "\x55\x04\x1C" ),	/* preferredDeliveryMethod (2 5 4 28) */
	  "oid.2.5.4.28", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 23, MKDNOID( "\x55\x04\x1D" ),	/* presentationAddress (2 5 4 29) */
	  "oid.2.5.4.29", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 24, MKDNOID( "\x55\x04\x1E" ),	/* supportedApplicationContext (2 5 4 30) */
	  "oid.2.5.4.30", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 25, MKDNOID( "\x55\x04\x1F" ),	/* member (2 5 4 31) */
	  "oid.2.5.4.31", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 26, MKDNOID( "\x55\x04\x20" ),	/* owner (2 5 4 32) */
	  "oid.2.5.4.32", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 27, MKDNOID( "\x55\x04\x21" ),	/* roleOccupant (2 5 4 33) */
	  "oid.2.5.4.33", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 28, MKDNOID( "\x55\x04\x22" ),	/* seeAlso (2 5 4 34) */
	  "oid.2.5.4.34", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	  /* 0x23-0x28 are certificates/CRLs and some weird encrypted directory components */
	{ 29, MKDNOID( "\x55\x04\x29" ),	/* name (2 5 4 41) */
	  "oid.2.5.4.41", NULL, MAX_ATTRIBUTE_SIZE /*32768*/, FALSE, FALSE },
	{ 30, MKDNOID( "\x55\x04\x2A" ),	/* givenName (2 5 4 42) */
	  "g", "oid.2.5.4.42", CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 31, MKDNOID( "\x55\x04\x2B" ),	/* initials (2 5 4 43) */
	  "i", "oid.2.5.4.43", CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 32, MKDNOID( "\x55\x04\x2C" ),	/* generationQualifier (2 5 4 44) */
	  "oid.2.5.4.44", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 33, MKDNOID( "\x55\x04\x2D" ),	/* uniqueIdentifier (2 5 4 45) */
	  "oid.2.5.4.45", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 34, MKDNOID( "\x55\x04\x2E" ),	/* dnQualifier (2 5 4 46) */
	  "oid.2.5.4.46", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	  /* 0x2F-0x30 are directory components */
	{ 35, MKDNOID( "\x55\x04\x31" ),	/* distinguishedName (2 5 4 49) */
	  "oid.2.5.4.49", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 36, MKDNOID( "\x55\x04\x32" ),	/* uniqueMember (2 5 4 50) */
	  "oid.2.5.4.50", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 37, MKDNOID( "\x55\x04\x33" ),	/* houseIdentifier (2 5 4 51) */
	  "oid.2.5.4.51", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	  /* 0x34-0x3A are more certificates and weird encrypted directory components */
	{ 38, MKDNOID( "\x55\x04\x41" ),	/* pseudonym (2 5 4 65) */
	  "oid.2.5.4.65", NULL, 128, FALSE, FALSE },
	{ 39, MKDNOID( "\x55\x04\x42" ),	/* communicationsService (2 5 4 66) */
	  "oid.2.5.4.66", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	{ 40, MKDNOID( "\x55\x04\x43" ),	/* communicationsNetwork (2 5 4 67) */
	  "oid.2.5.4.67", NULL, CRYPT_MAX_TEXTSIZE, FALSE, FALSE },
	  /* 0x44-0x49 are more PKI-related attributes */
	{ 41, MKOID( "\x06\x0A\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x01" ),	/* userid (0 9 2342 19200300 100 1 1) */
	  "uid", NULL, CRYPT_MAX_TEXTSIZE, TRUE, FALSE },
	{ 42, MKOID( "\x06\x0A\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x03" ),	/* rfc822Mailbox (0 9 2342 19200300 100 1 3) */
	  "oid.0.9.2342.19200300.100.1.3", NULL, CRYPT_MAX_TEXTSIZE, TRUE, FALSE },
	{ 43, MKOID( "\x06\x0A\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x19" ),	/* domainComponent (0 9 2342 19200300 100 1 25) */
	  "dc", "oid.0.9.2342.19200300.100.1.25", CRYPT_MAX_TEXTSIZE, TRUE, FALSE },
	{ 44, MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01" ),		/* emailAddress (1 2 840 113549 1 9 1) */
	  "email", "oid.1.2.840.113549.1.9.1", CRYPT_MAX_TEXTSIZE, TRUE, FALSE },
	{ 45, MKOID( "\x06\x07\x02\x82\x06\x01\x0A\x07\x14" ),				/* nameDistinguisher (0 2 262 1 10 7 20) */
	  "oid.0.2.262.1.10.7.20", NULL, CRYPT_MAX_TEXTSIZE, TRUE, FALSE },

	{ CRYPT_ATTRIBUTE_NONE, NULL }, { CRYPT_ATTRIBUTE_NONE, NULL }
	};

/* Check that a country code is valid */

#define xA	( 1 << 0 )
#define xB	( 1 << 1 )
#define xC	( 1 << 2 )
#define xD	( 1 << 3 )
#define xE	( 1 << 4 )
#define xF	( 1 << 5 )
#define xG	( 1 << 6 )
#define xH	( 1 << 7 )
#define xI	( 1 << 8 )
#define xJ	( 1 << 9 )
#define xK	( 1 << 10 )
#define xL	( 1 << 11 )
#define xM	( 1 << 12 )
#define xN	( 1 << 13 )
#define xO	( 1 << 14 )
#define xP	( 1 << 15 )
#define xQ	( 1 << 16 )
#define xR	( 1 << 17 )
#define xS	( 1 << 18 )
#define xT	( 1 << 19 )
#define xU	( 1 << 20 )
#define xV	( 1 << 21 )
#define xW	( 1 << 22 )
#define xX	( 1 << 23 )
#define xY	( 1 << 24 )
#define xZ	( 1 << 25 )

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN checkCountryCode( IN_BUFFER( 2 ) const char *countryCode )
	{
	static const long countryCodes[] = {	/* ISO 3166 code table */
	/*	 A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z */
  /*A*/			 xD|xE|xF|xG|	xI|		 xL|xM|xN|xO|	xQ|xR|xS|xT|xU|	  xW|	   xZ,
  /*B*/	xA|xB|	 xD|xE|xF|xG|xH|xI|xJ|		xM|xN|xO|	   xR|xS|xT|   xV|xW|	xY|xZ,
  /*C*/	xA|	  xC|xD|   xF|xG|xH|xI|	  xK|xL|xM|xN|xO|	   xR|		xU|xV|	 xX|xY|xZ,
  /*D*/				xE|			   xJ|xK|	xM|	  xO|							   xZ,
  /*E*/		  xC|	xE|	  xG|xH|						   xR|xS|xT,
  /*F*/							xI|xJ|xK|	xM|	  xO|	   xR,
  /*G*/	xA|xB|	 xD|xE|xF|	 xH|xI|		 xL|xM|xN|	 xP|xQ|xR|xS|xT|xU|	  xW|	xY,
  /*H*/								  xK|	xM|xN|		   xR|	 xT|xU,
  /*I*/			 xD|xE|					 xL|   xN|xO|	xQ|xR|xS|xT,
  /*J*/										xM|	  xO|xP,
  /*K*/				xE|	  xG|xH|xI|			xM|xN|	 xP|   xR|			  xW|	xY|xZ,
  /*L*/	xA|xB|xC|				xI|	  xK|				   xR|xS|xT|xU|xV|		xY,
  /*M*/	xA|	  xC|xD|	  xG|xH|	  xK|xL|xM|xN|xO|xP|xQ|xR|xS|xT|xU|xV|xW|xX|xY|xZ,
  /*N*/	xA|	  xC|	xE|xF|xG|	xI|		 xL|	  xO|xP|   xR|		xU|			   xZ,
  /*O*/										xM,
  /*P*/	xA|			xE|xF|xG|xH|	  xK|xL|xM|xN|		   xR|xS|xT|	  xW|	xY,
  /*Q*/	xA,
  /*R*/				xE|							  xO|				xU|	  xW,
  /*S*/	xA|xB|xC|xD|xE|	  xG|xH|xI|xJ|xK|xL|xM|xN|xO|	   xR|	 xT|   xV|		xY|xZ,
  /*T*/		  xC|xD|   xF|xG|xH|   xJ|xK|xL|xM|xN|xO|	   xR|	 xT|   xV|xW|	   xZ,
  /*U*/	xA|				  xG|				xM|				  xS|				xY|xZ,
  /*V*/	xA|	  xC|	xE|	  xG|	xI|			   xN|					xU,
  /*W*/				   xF|									  xS,
  /*X*/	0,
  /*Y*/				xE|											 xT|xU,
  /*Z*/	xA|									xM|							  xW,
		0, 0	/* Catch overflows */
		};
	const int cc0 = countryCode[ 0 ] - 'A';
	const int cc1 = countryCode[ 1 ] - 'A';

	assert( isReadPtr( countryCode, 2 ) );

	/* Check that the country code is present in the table of valid ISO 3166
	   codes.  Note the explicit declaration of the one-bit as '1L', this is
	   required because the shift amount can be greater than the word size on
	   16-bit systems */
	if( cc0 < 0 || cc0 > 25 || cc1 < 0 || cc1 > 25 )
		return( FALSE );
	return( ( countryCodes[ cc0 ] & ( 1L << cc1 ) ) ? TRUE : FALSE );
	}

/* Determine the sort priority for DN components */

CHECK_RETVAL_RANGE( MAX_ERROR, 10 ) \
static int dnSortOrder( const CRYPT_ATTRIBUTE_TYPE type )
	{
	typedef struct {
		const CRYPT_ATTRIBUTE_TYPE type;
		const int sortOrder;
		} DN_SORT_ORDER;
	static const DN_SORT_ORDER dnSortOrderTbl[] = {
		{ CRYPT_CERTINFO_COUNTRYNAME, 0 },
		{ CRYPT_CERTINFO_STATEORPROVINCENAME, 1 },
		{ CRYPT_CERTINFO_LOCALITYNAME, 2 },
		{ CRYPT_CERTINFO_ORGANIZATIONNAME, 3 },
		{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, 4 },
		{ CRYPT_CERTINFO_COMMONNAME, 5 },
		{ CRYPT_ATTRIBUTE_NONE, 0 }, { CRYPT_ATTRIBUTE_NONE, 0 }
		};
	int i;

	REQUIRES( type >= CRYPT_CERTINFO_FIRST_DN && \
			  type <= CRYPT_CERTINFO_LAST_DN );

	for( i = 0; dnSortOrderTbl[ i ].type != type && \
				dnSortOrderTbl[ i ].type != CRYPT_ATTRIBUTE_NONE && \
				i < FAILSAFE_ARRAYSIZE( dnSortOrderTbl, DN_SORT_ORDER );
		 i++ );
	ENSURES( i < FAILSAFE_ARRAYSIZE( dnSortOrderTbl, DN_SORT_ORDER ) );
	ENSURES( dnSortOrderTbl[ i ].type != CRYPT_ATTRIBUTE_NONE );

	return( i );
	}

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Find a DN component in a DN component list by type and by OID */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
static DN_COMPONENT *findDNComponent( const DN_COMPONENT *dnComponentList,
									  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type,
									  IN_BUFFER_OPT( valueLength ) const void *value,
									  IN_LENGTH_SHORT_Z const int valueLength )
	{
	const DN_COMPONENT *listPtr;
	int iterationCount;

	assert( isReadPtr( dnComponentList, sizeof( DN_COMPONENT ) ) );
	assert( ( value == NULL && valueLength == 0 ) || \
			isReadPtr( value, valueLength ) );
			/* We may be doing the lookup purely by type */

	REQUIRES_N( type >= CRYPT_CERTINFO_FIRST_DN && \
				type <= CRYPT_CERTINFO_LAST_DN );
	REQUIRES_N( ( value == NULL && valueLength == 0 ) || \
				( value != NULL && \
				  valueLength > 0 && valueLength < MAX_INTLENGTH_SHORT ) );

	/* Find the position of this component in the list */
	for( listPtr = dnComponentList, iterationCount = 0; 
		 listPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED;
		 listPtr = listPtr->next, iterationCount++ )
		{
		assert( isReadPtr( listPtr, sizeof( DN_COMPONENT ) ) );

		if( listPtr->type == type && \
			( ( value == NULL ) || \
			  ( listPtr->valueLength == valueLength && \
				!memcmp( listPtr->value, value, valueLength ) ) ) )
			break;
		}
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( ( DN_COMPONENT * ) listPtr );
	}

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 2 ) ) \
static DN_COMPONENT *findDNComponentByOID( const DN_COMPONENT *dnComponentList,
										   IN_BUFFER( oidLength ) const BYTE *oid, 
										   IN_LENGTH_OID const int oidLength )
	{
	const DN_COMPONENT *listPtr;
	int iterationCount;

	assert( isReadPtr( dnComponentList, sizeof( DN_COMPONENT ) ) );
	assert( isReadPtr( oid, oidLength ) );

	REQUIRES_N( oidLength >= MIN_OID_SIZE && oidLength <= MAX_OID_SIZE && \
				oidLength == sizeofOID( oid ) );

	/* Find the position of this component in the list */
	for( listPtr = dnComponentList, iterationCount = 0; 
		 listPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED;
		 listPtr = listPtr->next, iterationCount++ )
		{
		const DN_COMPONENT_INFO *dnComponentInfo = listPtr->typeInfo;

		if( oidLength == sizeofOID( dnComponentInfo->oid ) && \
			!memcmp( dnComponentInfo->oid, oid, oidLength ) )
			break;
		}
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( ( DN_COMPONENT * ) listPtr );
	}

/****************************************************************************
*																			*
*								Insert/Delete DNs							*
*																			*
****************************************************************************/

/* Insert a DN component into a list.  The type can be either a 
   CRYPT_CERTINFO_xxx value, indicating that it's a standard DN component,
   or a small integer denoting a recognised but nonstandard DN component.  
   In the latter case we don't try to sort the component into the correct 
   position */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 3, 6 ) ) \
static int insertDNstring( /*?*/ DN_COMPONENT **dnComponentListPtrPtr, 
						   IN_INT const int type,
						   IN_BUFFER( valueLength ) const void *value, 
						   IN_LENGTH_SHORT const int valueLength,
						   IN_FLAGS_Z( DN ) const int flags, 
						   OUT_ENUM_OPT( CRYPT_ERRTYPE_TYPE ) \
								CRYPT_ERRTYPE_TYPE *errorType )
	{
	const DN_COMPONENT_INFO *dnComponentInfo = NULL;
	DN_COMPONENT *listHeadPtr = *dnComponentListPtrPtr;
	DN_COMPONENT *newElement, *insertPoint;
	int i, iterationCount;

	assert( isWritePtr( dnComponentListPtrPtr, sizeof( DN_COMPONENT * ) ) );
	assert( listHeadPtr == NULL || \
			isWritePtr( listHeadPtr, sizeof( DN_COMPONENT ) ) );
	assert( isReadPtr( value, valueLength ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( ( type > CRYPT_CERTINFO_FIRST && \
				type < CRYPT_CERTINFO_LAST ) || \
			  ( type > 0 && type < 50 ) );
	REQUIRES( flags >= DN_FLAG_NONE && flags <= DN_FLAG_MAX );
	REQUIRES( valueLength > 0 && valueLength < MAX_INTLENGTH_SHORT );

	/* If the DN is locked against modification we can't make any further
	   updates */
	if( listHeadPtr != NULL && ( listHeadPtr->flags & DN_FLAG_LOCKED ) )
		return( CRYPT_ERROR_INITED );

	/* Find the type information for this component */
	for( i = 0; certInfoOIDs[ i ].oid != NULL && \
				i < FAILSAFE_ARRAYSIZE( certInfoOIDs, DN_COMPONENT_INFO ); 
		 i++ )
		{
		if( certInfoOIDs[ i ].type == type )
			{
			dnComponentInfo = &certInfoOIDs[ i ];
			break;
			}
		}
	ENSURES( i < FAILSAFE_ARRAYSIZE( certInfoOIDs, DN_COMPONENT_INFO ) );
	ENSURES( dnComponentInfo != NULL );

	/* Make sure that the length is valid.  If it's being read from an
	   encoded form we allow abnormally-long lengths (although we still keep
	   them within a sensible limit) since this is better than failing to
	   read a certificate because it contains a broken DN.  In addition if a 
	   widechar string is OK we allow a range up to the maximum byte count
	   defined by the widechar size, this is only valid for standard DN
	   components, when they're coming from the user the exact check has
	   already been performed by the kernel */
#ifdef USE_WIDECHARS
	if( valueLength > ( ( flags & DN_FLAG_NOCHECK ) ? \
							MAX_ATTRIBUTE_SIZE : \
						( dnComponentInfo->wcsOK ) ? \
							( WCSIZE * dnComponentInfo->maxLength ) : \
							dnComponentInfo->maxLength ) )
#else
	if( valueLength > ( ( flags & DN_FLAG_NOCHECK ) ? \
							MAX_ATTRIBUTE_SIZE : dnComponentInfo->maxLength ) )
#endif /* USE_WIDECHARS */
		{
		if( errorType != NULL )
			*errorType = CRYPT_ERRTYPE_ATTR_SIZE;
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* Find the correct place in the list to insert the new element */
	if( listHeadPtr != NULL )
		{
		DN_COMPONENT *prevElement = NULL;

		/* If it's being read from an external certificate item just append 
		   it to the end of the list */
		if( flags & DN_FLAG_NOCHECK )
			{
			for( insertPoint = listHeadPtr, iterationCount = 0; 
				 insertPoint->next != NULL && \
					iterationCount < FAILSAFE_ITERATIONS_MED;
				 insertPoint = insertPoint->next, iterationCount++ );
			ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );
			}
		else
			{
			const int newValueSortOrder = dnSortOrder( type );

			/* Make sure that the sort order for the new value is valid */
			if( cryptStatusError( newValueSortOrder ) )
				return( newValueSortOrder );
			
			for( insertPoint = listHeadPtr, iterationCount = 0; 
				 insertPoint != NULL && \
					newValueSortOrder >= dnSortOrder( insertPoint->type ) && \
					iterationCount < FAILSAFE_ITERATIONS_MED; 
				 insertPoint = insertPoint->next, iterationCount++ )
				{
				/* Make sure that this component isn't already present.  For 
				   now we only allow a single DN component of any type to 
				   keep things simple for the user, if it's necessary to 
				   allow multiple components of the same type then we'll 
				   need to check the value and valueLength as well */
				if( insertPoint->type == type )
					{
					if( errorType != NULL )
						*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
					return( CRYPT_ERROR_INITED );
					}

				prevElement = insertPoint;
				}
			ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );
			insertPoint = prevElement;
			}
		}
	else
		{
		/* It's an empty list, insert the new element at the start */
		insertPoint = NULL;
		}

	/* Allocate memory for the new element and copy over the information */
	if( ( newElement = ( DN_COMPONENT * ) \
				clAlloc( "insertDNstring", sizeof( DN_COMPONENT ) + \
										   valueLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	initVarStruct( newElement, DN_COMPONENT, valueLength );
	newElement->type = type;
	newElement->typeInfo = dnComponentInfo;
	memcpy( newElement->value, value, valueLength );
	newElement->valueLength = valueLength;
	newElement->flags = flags;

	/* If it's a country code, force it to uppercase as per ISO 3166 */
	if( type == CRYPT_CERTINFO_COUNTRYNAME )
		{
		BYTE *dnStrPtr = newElement->value;

		/* Note: When the code is run under BoundsChecker 6.x the toUpper() 
		   conversion will produce garbage on any call after the first one 
		   resulting in the following checks failing */
		dnStrPtr[ 0 ] = toUpper( dnStrPtr[ 0 ] );
		dnStrPtr[ 1 ] = toUpper( dnStrPtr[ 1 ] );
		if( flags & DN_FLAG_NOCHECK )
			{
			/* 'UK' isn't an ISO 3166 country code but may be found in some
			   certificates.  If we find this we quietly convert it to the
			   correct value */
			if( !memcmp( dnStrPtr, "UK", 2 ) )
				memcpy( dnStrPtr, "GB", 2 );
			}
		else
			{
			/* Make sure that the country code is valid */
			if( !checkCountryCode( dnStrPtr ) )
				{
				endVarStruct( newElement, DN_COMPONENT );
				clFree( "insertDNstring", newElement );
				if( errorType != NULL )
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( CRYPT_ERROR_INVALID );
				}
			}
		}

	/* Link it into the list */
	insertDoubleListElement( ( DN_COMPONENT ** ) dnComponentListPtrPtr, 
							 insertPoint, newElement );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 5 ) ) \
int insertDNComponent( INOUT_PTR void **dnComponentListPtrPtr,
					   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE componentType,
					   IN_BUFFER( valueLength ) const void *value, 
					   IN_LENGTH_SHORT const int valueLength,
					   OUT_ENUM_OPT( CRYPT_ERRTYPE_TYPE ) \
							CRYPT_ERRTYPE_TYPE *errorType )
	{
	assert( isWritePtr( dnComponentListPtrPtr, 
						sizeof( DN_COMPONENT_INFO * ) ) );
	assert( isReadPtr( value, valueLength ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	REQUIRES( componentType > CRYPT_CERTINFO_FIRST && \
			  componentType < CRYPT_CERTINFO_LAST );
	REQUIRES( valueLength > 0 && valueLength < MAX_INTLENGTH_SHORT );

	return( insertDNstring( ( DN_COMPONENT ** ) dnComponentListPtrPtr, 
							componentType, value, valueLength, 0, 
							errorType ) );
	}

/* Delete a DN component from a list */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int deleteComponent( /*?*/ DN_COMPONENT **dnComponentListPtrPtr, 
							INOUT DN_COMPONENT *theElement )
	{
	assert( isWritePtr( dnComponentListPtrPtr, sizeof( DN_COMPONENT * ) ) );
	assert( isWritePtr( theElement, sizeof( DN_COMPONENT ) ) );

	/* Remove the item from the list */
	deleteDoubleListElement( dnComponentListPtrPtr, theElement );

	/* Clear all data in the list item and free the memory */
	endVarStruct( theElement, DN_COMPONENT );
	clFree( "deleteComponent", theElement );

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int deleteDNComponent( INOUT_PTR void **dnComponentListPtrPtr, 
					   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type,
					   IN_BUFFER_OPT( valueLength ) const void *value, 
					   IN_LENGTH_SHORT const int valueLength )
	{
	DN_COMPONENT *listHeadPtr = *dnComponentListPtrPtr;
	DN_COMPONENT *itemToDelete;

	assert( isWritePtr( dnComponentListPtrPtr, sizeof( DN_COMPONENT * ) ) );
	assert( listHeadPtr == NULL || \
			isWritePtr( listHeadPtr, sizeof( DN_COMPONENT ) ) );
	assert( ( value == NULL && valueLength == 0 ) ||
			isReadPtr( value, valueLength ) );
			/* We may be doing the delete purely by type */

	REQUIRES( type > CRYPT_CERTINFO_FIRST && type < CRYPT_CERTINFO_LAST );
	REQUIRES( valueLength >= 0 && valueLength < MAX_INTLENGTH_SHORT );

	/* If the DN is locked against modification we can't make any further
	   updates */
	if( listHeadPtr != NULL && ( listHeadPtr->flags & DN_FLAG_LOCKED ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Find the component in the list and delete it */
	itemToDelete = findDNComponent( listHeadPtr, type, value, valueLength );
	if( itemToDelete == NULL )
		return( CRYPT_ERROR_NOTFOUND );
	return( deleteComponent( ( DN_COMPONENT ** ) dnComponentListPtrPtr, 
							 itemToDelete ) );
	}

/* Delete a DN */

STDC_NONNULL_ARG( ( 1 ) ) \
void deleteDN( void **dnComponentListPtrPtr )
	{
	DN_COMPONENT *listPtr;
	int iterationCount;

	assert( isWritePtr( dnComponentListPtrPtr, sizeof( DN_COMPONENT * ) ) );

	/* Destroy all DN items */
	for( listPtr = *dnComponentListPtrPtr, iterationCount = 0;
		 listPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED;
		 iterationCount++ )
		{
		DN_COMPONENT *itemToFree = listPtr;

		/* Another gcc bug, this time in gcc 4.x for 64-bit architectures 
		   (confirmed for x86-64 and ppc64) in which it removes an empty-
		   list check in deleteDoubleListElement() (in fact the emitted 
		   code bears only a passing resemblance to the actual source code). 
		   The only possible workaround seems to be to omit the call to 
		   deleteComponent() and just delete the item directly */
		listPtr = listPtr->next;
#if defined( __GNUC__ ) && ( __GNUC__ == 4 )
		endVarStruct( itemToFree, DN_COMPONENT );
		clFree( "deleteComponent", itemToFree );
#else
		( void ) deleteComponent( &itemToFree, itemToFree );
#endif /* gcc 4.x on 64-bit architectures bug workaround */
		}
	ENSURES_V( iterationCount < FAILSAFE_ITERATIONS_MED );

	/* Mark the list as being empty */
	*dnComponentListPtrPtr = NULL;
	}

/* Get the value of a DN component */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 5 ) ) \
int getDNComponentValue( INOUT_PTR const void *dnComponentList,
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE type,
						 OUT_BUFFER_OPT( valueMaxLength, \
										 valueLengthlength ) void *value, 
						 IN_LENGTH_SHORT_Z const int valueMaxLength, 
						 OUT_LENGTH_SHORT_Z int *valueLength )
	{
	const DN_COMPONENT *dnComponent;

	assert( isReadPtr( dnComponentList, sizeof( DN_COMPONENT ) ) );
	assert( ( value == NULL && valueMaxLength == 0 ) || \
			( isWritePtr( value, valueMaxLength ) ) );
	assert( isWritePtr( valueLength, sizeof( int ) ) );

	REQUIRES( type > CRYPT_CERTINFO_FIRST && type < CRYPT_CERTINFO_LAST );
	REQUIRES( ( value == NULL && valueMaxLength == 0 ) || \
			  ( value != NULL && \
				valueMaxLength >= 0 && \
				valueMaxLength < MAX_INTLENGTH_SHORT ) );

	/* Clear return values */
	*valueLength = 0;
	if( value != NULL )
		memset( value, 0, min( 16, valueMaxLength ) );

	dnComponent = findDNComponent( dnComponentList, type, NULL, 0 );
	if( dnComponent == NULL )
		return( CRYPT_ERROR_NOTFOUND );
	*valueLength = dnComponent->valueLength;
	if( value == NULL )
		return( CRYPT_OK );
	if( dnComponent->valueLength > valueMaxLength )
		return( CRYPT_ERROR_OVERFLOW );
	if( !isWritePtr( value, dnComponent->valueLength ) )
		return( CRYPT_ARGERROR_STR1 );
	memcpy( value, dnComponent->value, dnComponent->valueLength );

	return( CRYPT_OK );
	}

/* Compare two DNs.  Since this is used for constraint comparisons as well
   as just strict equality checks we provide a flag which, if set, returns
   a match if the first DN is a proper substring of the second DN */

CHECK_RETVAL_BOOL \
BOOLEAN compareDN( IN_OPT const void *dnComponentList1,
				   IN_OPT const void *dnComponentList2,
				   const BOOLEAN dn1substring )
	{
	DN_COMPONENT *dn1ptr, *dn2ptr;
	int iterationCount;

	assert( dnComponentList1 == NULL || \
			isReadPtr( dnComponentList1, sizeof( DN_COMPONENT * ) ) );
	assert( dnComponentList2 == NULL || \
			isReadPtr( dnComponentList2, sizeof( DN_COMPONENT * ) ) );

	/* Check each DN component for equality */
	for( dn1ptr = ( DN_COMPONENT * ) dnComponentList1, \
			dn2ptr = ( DN_COMPONENT * ) dnComponentList2,
			iterationCount = 0;
		 dn1ptr != NULL && dn2ptr != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_MED;
		 dn1ptr = dn1ptr->next, dn2ptr = dn2ptr->next, iterationCount++ )
		{
		/* If the RDN types differ, the DNs don't match */
		if( dn1ptr->type != dn2ptr->type )
			return( FALSE );

		/* Compare the current RDNs.  In theory we should be using the
		   complex and arcane X.500 name comparison rules but no-one in 
		   their right mind actually does this since they're almost 
		   impossible to get right.  Since everyone else uses memcpy()/
		   memcmp() to handle DN components it's safe to use it here (sic 
		   faciunt omnes).  This also avoids any potential security problems 
		   arising from the complexity of the code necessary to implement 
		   the X.500 matching rules */
		if( dn1ptr->valueLength != dn2ptr->valueLength || \
			memcmp( dn1ptr->value, dn2ptr->value, dn1ptr->valueLength ) )
			return( FALSE );
		}
	ENSURES_B( iterationCount < FAILSAFE_ITERATIONS_MED );

	/* If we've reached the end of both DNs or we're looking for a substring
	   match, the two match */
	return( ( ( dn1ptr == NULL && dn2ptr == NULL ) || dn1substring ) ? \
			TRUE : FALSE );
	}

/* Copy a DN */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int copyDN( OUT_PTR void **dnDest, IN_OPT const void *dnSrc )
	{
	const DN_COMPONENT *srcPtr;
	DN_COMPONENT **dnDestPtrPtr = ( DN_COMPONENT ** ) dnDest;
	DN_COMPONENT *destPtr = NULL;
	int iterationCount;

	assert( isWritePtr( dnDest, sizeof( DN_COMPONENT * ) ) );
	assert( dnSrc == NULL || isReadPtr( dnSrc, sizeof( DN_COMPONENT * ) ) );

	/* Clear return value */
	*dnDest = NULL;

	/* Copy each element in the source DN */
	for( srcPtr = dnSrc, iterationCount= 0; 
		 srcPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED; 
		 srcPtr = srcPtr->next, iterationCount++ )
		{
		DN_COMPONENT *newElement;

		/* Allocate memory for the new element and copy over the 
		   information.  Since we're copying over the contents of an 
		   existing DN_COMPONENT structure we have to zero the list links 
		   after the copy */
		if( ( newElement = ( DN_COMPONENT * ) \
					clAlloc( "copyDN", \
					sizeofVarStruct( srcPtr, DN_COMPONENT ) ) ) == NULL )
			{
			deleteDN( dnDest );
			return( CRYPT_ERROR_MEMORY );
			}
		copyVarStruct( newElement, srcPtr, DN_COMPONENT );
		newElement->prev = newElement->next = NULL;

		/* Link it into the list */
		insertDoubleListElement( dnDestPtrPtr, destPtr, newElement );
		destPtr = newElement;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( CRYPT_OK );
	}

/* Check the validity of a DN.  The check for the bottom of the DN (common
   name) and top (country) are made configurable, DNs that act as filters
   (e.g. path constraints) may not have the lower DN parts present and 
   certificate requests submitted to CAs that set the country themselves 
   may not have the country present */

CHECK_RETVAL STDC_NONNULL_ARG( ( 4, 5 ) ) \
int checkDN( IN_OPT const void *dnComponentList,
			 const BOOLEAN checkCN, const BOOLEAN checkC,
			 OUT_ENUM_OPT( CRYPT_ATTRIBUTE ) \
				CRYPT_ATTRIBUTE_TYPE *errorLocus,
			 OUT_ENUM_OPT( CRYPT_ERRTYPE ) \
				CRYPT_ERRTYPE_TYPE *errorType )
	{
	DN_COMPONENT *dnComponentListPtr;
	BOOLEAN hasCountry = FALSE, hasCommonName = FALSE;

	assert( dnComponentList == NULL || \
			isReadPtr( dnComponentList, sizeof( DN_COMPONENT ) ) );
	assert( isWritePtr( errorLocus, sizeof( CRYPT_ATTRIBUTE_TYPE ) ) );
	assert( isWritePtr( errorType, sizeof( CRYPT_ERRTYPE_TYPE ) ) );

	/* Clear the return values */
	*errorType = CRYPT_OK;
	*errorLocus = CRYPT_ATTRIBUTE_NONE;

	/* Perform a special-case check for a null DN */
	if( dnComponentList == NULL )
		return( CRYPT_ERROR_NOTINITED );

	/* Make sure that certain critical components are present */
	for( dnComponentListPtr = ( DN_COMPONENT * ) dnComponentList;
		 dnComponentListPtr != NULL;
		 dnComponentListPtr = dnComponentListPtr->next )
		{
		if( dnComponentListPtr->type == CRYPT_CERTINFO_COUNTRYNAME )
			{
			if( !checkCountryCode( ( char * ) dnComponentListPtr->value ) )
				{
				*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				*errorLocus = CRYPT_CERTINFO_COUNTRYNAME;
				return( CRYPT_ERROR_INVALID );
				}
			hasCountry = TRUE;
			}
		if( dnComponentListPtr->type == CRYPT_CERTINFO_COMMONNAME )
			hasCommonName = TRUE;
		}
	if( ( checkC && !hasCountry ) || ( checkCN && !hasCommonName ) )
		{
		*errorType = CRYPT_ERRTYPE_ATTR_ABSENT;
		*errorLocus = ( hasCountry ) ? CRYPT_CERTINFO_COMMONNAME : \
									   CRYPT_CERTINFO_COUNTRYNAME;
		return( CRYPT_ERROR_NOTINITED );
		}

	return( CRYPT_OK );
	}

/* Convert a DN component containing a PKCS #9 emailAddress or an RFC 1274
   rfc822Mailbox into an rfc822Name */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int convertEmail( INOUT CERT_INFO *certInfoPtr, 
				  /*?*/ void **dnComponentListPtrPtr,
				  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE altNameType )
	{
	DN_COMPONENT *emailComponent;
	SELECTION_STATE selectionState;
	void *certDataPtr;
	int status;

	assert( isWritePtr( certInfoPtr, sizeof( CERT_INFO ) ) );
	assert( isWritePtr( dnComponentListPtrPtr, sizeof( DN_COMPONENT ) ) );
	assert( *dnComponentListPtrPtr == NULL || \
			isWritePtr( *dnComponentListPtrPtr, sizeof( DN_COMPONENT ) ) );

	REQUIRES( altNameType == CRYPT_CERTINFO_SUBJECTALTNAME || \
			  altNameType == CRYPT_CERTINFO_ISSUERALTNAME );

	/* If there's no PKCS #9 email address present, try for an RFC 1274 one.
	   If that's not present either, exit */
	if( *dnComponentListPtrPtr == NULL )
		{
		/* If there's an empty DN present, there's nothing to do */
		return( CRYPT_OK );
		}
	emailComponent = findDNComponentByOID( *dnComponentListPtrPtr,
			( const BYTE * ) "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01", 11 );
	if( emailComponent == NULL )
		{
		emailComponent = findDNComponentByOID( *dnComponentListPtrPtr,
			( const BYTE * ) "\x06\x09\x09\x92\x26\x89\x93\xF2\x2C\x01\x03", 11 );
		if( emailComponent == NULL )
			return( CRYPT_OK );
		}

	/* Try and add the email address component as an rfc822Name.  Since this
	   changes the current GeneralName selection we have to be careful about
	   saving and restoring the state.  In addition since we're changing the
	   internal state of an object which is technically in the high state we 
	   have to temporarily disconnect the certificate data from the 
	   certificate object to make it appear as a mutable object.  This is an 
	   unfortunate consequence of the fact that what we're doing is a 
	   behind-the-scenes switch to move a certificate component from where it 
	   is to where it really should be */
	saveSelectionState( selectionState, certInfoPtr );
	certDataPtr = certInfoPtr->certificate;
	certInfoPtr->certificate = NULL;
	status = addCertComponent( certInfoPtr, CRYPT_ATTRIBUTE_CURRENT,
							   &altNameType, 0 );
	ENSURES( cryptStatusOK( status ) );
	status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_RFC822NAME,
							   emailComponent->value,
							   emailComponent->valueLength );
	if( cryptStatusOK( status ) )
		{
		/* It was successfully copied over, delete the copy in the DN */
		( void ) deleteComponent( ( DN_COMPONENT ** ) dnComponentListPtrPtr, 
								  emailComponent );
		}
	else
		{
		/* If it's already present (which is somewhat odd since the presence
		   of an email address in the DN implies that the implementation
		   doesn't know about rfc822Name) we can't do anything about it */
		if( status == CRYPT_ERROR_INITED )
			status = CRYPT_OK;
		else
			{
			/* Some certificates can contain garbage in the (supposed) email 
			   address, normally the certificate would be rejected because 
			   of this but if we're running in oblivious mode we can import 
			   it successfully but then get an internal error code when we 
			   try and perform this sideways add.  To catch this we check 
			   for invalid email addresses here and ignore an error status 
			   if we get one */
			if( cryptArgError( status ) )
				status = CRYPT_OK;
			}
		}
	certInfoPtr->certificate = certDataPtr;
	restoreSelectionState( selectionState, certInfoPtr );

	return( status );
	}

/****************************************************************************
*																			*
*									Read a DN								*
*																			*
****************************************************************************/

/* Parse an AVA.   This determines the AVA type and leaves the stream pointer
   at the start of the data value */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3, 4 ) ) \
static int readAVA( INOUT STREAM *stream, 
					OUT_INT_Z int *type, 
					OUT_LENGTH_SHORT_Z int *length, 
					OUT_INT_Z int *stringTag )
	{
	BYTE oid[ MAX_OID_SIZE + 8 ];
	int oidLength, tag, i, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( type, sizeof( int ) ) );
	assert( isWritePtr( length, sizeof( int ) ) );
	assert( isWritePtr( stringTag, sizeof( int ) ) );

	/* Clear return values */
	*type = 0;
	*length = 0;
	*stringTag = 0;

	/* Read the start of the AVA and determine the type from the 
	   AttributeType field.  If we find something that we don't recognise we 
	   indicate it as a non-component type that can be read or written but 
	   not directly accessed by the user (although it can still be accessed 
	   using the cursor functions) */
	readSequence( stream, NULL );
	status = readEncodedOID( stream, oid, MAX_OID_SIZE, &oidLength, 
							 BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	for( i = 0; certInfoOIDs[ i ].oid != NULL && \
				i < FAILSAFE_ARRAYSIZE( certInfoOIDs, DN_COMPONENT_INFO ); 
		 i++ )
		{
		const DN_COMPONENT_INFO *certInfoOID = &certInfoOIDs[ i ];

		/* Perform a quick check of the OID.  The majority of all DN OIDs
		   are of the form (2 5 4 n), encoded as 0x06 0x03 0x55 0x04 0xnn,
		   so we compare the byte at offset 4 for the quick-reject match 
		   before we go for the full OID match */
		if( certInfoOID->oid[ 4 ] == oid[ 4 ] && \
			!memcmp( certInfoOID->oid, oid, oidLength ) )
			{
			*type = certInfoOID->type;
			break;
			}
		}
	ENSURES( i < FAILSAFE_ARRAYSIZE( certInfoOIDs, DN_COMPONENT_INFO ) );
	if( certInfoOIDs[ i ].oid == NULL )
		{
		/* If we don't recognise the component type, skip it */
		readUniversal( stream );
		return( OK_SPECIAL );
		}

	/* We've reached the data value, make sure that it's in order.  When we
	   read the wrapper around the string type we have to allow a minimum
	   length of zero instead of one because of broken AVAs with zero-length
	   strings */
	tag = peekTag( stream );
	if( cryptStatusError( tag ) )
		return( tag );
	if( tag == BER_BITSTRING )
		{
		/* Bitstrings are used for uniqueIdentifiers, however these usually
		   encapsulate something else so we dig one level deeper to find the
		   encapsulated string */
		readBitStringHole( stream, NULL, 2, DEFAULT_TAG );
		tag = peekTag( stream );
		if( cryptStatusError( tag ) )
			return( tag );
		}
	*stringTag = tag;
	return( readGenericHole( stream, length, 0, tag ) );
	}

/* Read an RDN component */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int readRDNcomponent( INOUT STREAM *stream, 
							 /*?*/ DN_COMPONENT **dnComponentListPtrPtr,
							 IN_LENGTH_SHORT const int rdnDataLeft )
	{	
	CRYPT_ERRTYPE_TYPE dummy;
	BYTE stringBuffer[ MAX_ATTRIBUTE_SIZE + 8 ];
	void *value;
	const int rdnStart = stell( stream );
	int type, valueLength, stringTag;
	int flags = DN_FLAG_NOCHECK, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( dnComponentListPtrPtr, sizeof( DN_COMPONENT * ) ) );

	REQUIRES( rdnDataLeft > 0 && rdnDataLeft < MAX_INTLENGTH_SHORT );

	/* Read the type information for this AVA */
	status = readAVA( stream, &type, &valueLength, &stringTag );
	if( cryptStatusError( status ) )
		return( status );
	if( valueLength <= 0 )
		{
		/* Skip broken AVAs with zero-length strings */
		return( CRYPT_OK );
		}
	status = sMemGetDataBlock( stream, &value, valueLength );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, valueLength );
	if( cryptStatusError( status ) )
		return( status );

	/* If there's room for another AVA, mark this one as being continued.  The
	   +10 is the minimum length for an AVA: SEQ { OID, value } (2-bytes SEQ +
	   5-bytes OID + 2-bytes tag + len + 1 byte min-length data).  We don't do
	   a simple =/!= check to get around incorrectly encoded lengths */
	if( rdnDataLeft >= ( stell( stream ) - rdnStart ) + 10 )
		flags |= DN_FLAG_CONTINUED;

	/* Convert the string into the local character set */
	status = copyFromAsn1String( stringBuffer, MAX_ATTRIBUTE_SIZE, 
								 &valueLength, value, valueLength,
								 stringTag );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the DN component to the DN.  If we hit a non-memory related error
	   we turn it into a generic CRYPT_ERROR_BADDATA error since the other
	   codes are somewhat too specific for this case (e.g. CRYPT_ERROR_INITED
	   or an arg error isn't too useful for the caller) */
	status = insertDNstring( ( DN_COMPONENT ** ) dnComponentListPtrPtr, type, 
							 stringBuffer, valueLength, flags, &dummy );
	return( ( cryptStatusError( status ) && status != CRYPT_ERROR_MEMORY ) ? \
			CRYPT_ERROR_BADDATA : status );
	}

/* Read a DN */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readDN( INOUT STREAM *stream, 
			INOUT_PTR void **dnComponentListPtrPtr )
	{
	int length, iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( dnComponentListPtrPtr, sizeof( DN_COMPONENT * ) ) );

	status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	for( iterationCount = 0;
		 length > 0 && iterationCount < FAILSAFE_ITERATIONS_MED;
		 iterationCount++ )
		{
		const int startPos = stell( stream );
		int rdnLength, innerIterationCount;

		/* Read the start of the RDN */
		status = readSet( stream, &rdnLength );
		if( cryptStatusError( status ) )
			return( status );

		/* Read each RDN component */
		for( innerIterationCount = 0;
			 rdnLength > 0 && innerIterationCount < FAILSAFE_ITERATIONS_MED;
			 innerIterationCount++ )
			{
			const int rdnStart = stell( stream );

			status = readRDNcomponent( stream, 
								( DN_COMPONENT ** ) dnComponentListPtrPtr,
								rdnLength );
			if( cryptStatusError( status ) && status != OK_SPECIAL )
				return( status );

			rdnLength -= stell( stream ) - rdnStart;
			}
		if( rdnLength < 0 || \
			innerIterationCount >= FAILSAFE_ITERATIONS_MED )
			return( CRYPT_ERROR_BADDATA );

		length -= stell( stream ) - startPos;
		}
	if( length < 0 || iterationCount >= FAILSAFE_ITERATIONS_MED )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*									Write a DN								*
*																			*
****************************************************************************/

/* Perform the pre-encoding processing for a DN */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int preEncodeDN( INOUT DN_COMPONENT *dnComponentPtr, 
						OUT_LENGTH_SHORT_Z int *length )
	{
	int size = 0, iterationCount;

	assert( isWritePtr( dnComponentPtr, sizeof( DN_COMPONENT ) ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	/* Clear return value */
	*length = 0;

	assert( isReadPtr( dnComponentPtr, sizeof( DN_COMPONENT ) ) );

	/* If we're being fed an entry in the middle of a DN, move back to the
	   start */
	for( iterationCount = 0;
		 dnComponentPtr->prev != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_MED;
		 dnComponentPtr = dnComponentPtr->prev, iterationCount++ );
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	/* Walk down the DN pre-encoding each AVA */
	for( iterationCount = 0;
		 dnComponentPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED; 
		 iterationCount++ )
		{
		DN_COMPONENT *rdnStartPtr = dnComponentPtr;
		BOOLEAN isContinued;
		int innerIterationCount;

		/* If this component has already had pre-encoding processing applied 
		   there's no need to do it again */
		if( dnComponentPtr->flags & DN_FLAG_PREENCODED )
			{
			if( dnComponentPtr->encodedRDNdataSize > 0 )
				size += ( int ) sizeofObject( dnComponentPtr->encodedRDNdataSize );
			dnComponentPtr = dnComponentPtr->next;
			continue;
			}

		/* Calculate the size of every AVA in this RDN */
		for( isContinued = TRUE, innerIterationCount = 0;
			 isContinued && dnComponentPtr != NULL && \
				innerIterationCount < FAILSAFE_ITERATIONS_MED;
			 dnComponentPtr = dnComponentPtr->next, innerIterationCount++ )
			{
			const DN_COMPONENT_INFO *dnComponentInfo = dnComponentPtr->typeInfo;
			int dnStringLength, status;

			status = getAsn1StringInfo( dnComponentPtr->value, 
										dnComponentPtr->valueLength,
										&dnComponentPtr->valueStringType, 
										&dnComponentPtr->encodedStringType,
										&dnStringLength );
			if( cryptStatusError( status ) )
				return( status );
			dnComponentPtr->encodedAVAdataSize = ( int ) \
										sizeofOID( dnComponentInfo->oid ) + \
										sizeofObject( dnStringLength );
			dnComponentPtr->encodedRDNdataSize = 0;
			dnComponentPtr->flags |= DN_FLAG_PREENCODED;
			rdnStartPtr->encodedRDNdataSize += ( int ) \
						sizeofObject( dnComponentPtr->encodedAVAdataSize );
			isContinued = ( dnComponentPtr->flags & DN_FLAG_CONTINUED ) ? \
						  TRUE : FALSE;
			}
		ENSURES( innerIterationCount < FAILSAFE_ITERATIONS_MED );

		/* Calculate the overall size of the RDN */
		size += ( int ) sizeofObject( rdnStartPtr->encodedRDNdataSize );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );
	*length = size;

	return( CRYPT_OK );
	}

CHECK_RETVAL \
int sizeofDN( INOUT_OPT void *dnComponentList )
	{
	int length, status;

	assert( dnComponentList == NULL || \
			isWritePtr( dnComponentList, sizeof( DN_COMPONENT ) ) );

	/* Null DNs produce a zero-length SEQUENCE */
	if( dnComponentList == NULL )
		return( sizeofObject( 0 ) );

	status = preEncodeDN( dnComponentList, &length );
	if( cryptStatusError( status ) )
		return( status );
	return( sizeofObject( length ) );
	}

/* Write a DN */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeDN( INOUT STREAM *stream, 
			 IN_OPT const void *dnComponentList,
			 IN_TAG const int tag )
	{
	DN_COMPONENT *dnComponentPtr;
	int size, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( dnComponentList == NULL || \
			isReadPtr( dnComponentList, sizeof( DN_COMPONENT ) ) );

	REQUIRES_S( tag == DEFAULT_TAG || ( tag >= 0 && tag < MAX_TAG_VALUE ) );

	/* Special case for emptry DNs */
	if( dnComponentList == NULL )
		return( writeConstructed( stream, 0, tag ) );

	status = preEncodeDN( ( DN_COMPONENT * ) dnComponentList, &size );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the DN */
	writeConstructed( stream, size, tag );
	for( dnComponentPtr = ( DN_COMPONENT * ) dnComponentList;
		 dnComponentPtr != NULL && cryptStatusOK( status );
		 dnComponentPtr = dnComponentPtr->next )
		{
		const DN_COMPONENT_INFO *dnComponentInfo = dnComponentPtr->typeInfo;
		BYTE dnString[ MAX_ATTRIBUTE_SIZE + 8 ];
		int dnStringLength;

		/* Write the RDN wrapper */
		if( dnComponentPtr->encodedRDNdataSize > 0 )
			{
			/* If it's the start of an RDN, write the RDN header */
			writeSet( stream, dnComponentPtr->encodedRDNdataSize );
			}
		writeSequence( stream, dnComponentPtr->encodedAVAdataSize );
		swrite( stream, dnComponentInfo->oid, \
				sizeofOID( dnComponentInfo->oid ) );

		/* Convert the string to an ASN.1-compatible format and write it
		   out */
		status = copyToAsn1String( dnString, MAX_ATTRIBUTE_SIZE, 
								   &dnStringLength, dnComponentPtr->value,
								   dnComponentPtr->valueLength,
								   dnComponentPtr->valueStringType );
		if( cryptStatusError( status ) )
			return( status );
		if( dnComponentPtr->encodedStringType == BER_STRING_IA5 && \
			!dnComponentInfo->ia5OK )
			{
			/* If an IA5String isn't allowed in this instance, use a
			   T61String instead */
			dnComponentPtr->encodedStringType = BER_STRING_T61;
			}
		status = writeCharacterString( stream, dnString, dnStringLength,
									   dnComponentPtr->encodedStringType );
		}

	return( status );
	}

/****************************************************************************
*																			*
*								DN String Routines							*
*																			*
****************************************************************************/

/* Read a DN in string form.  Note that the ability to specify free-form DNs
   means that users can create arbitrarily garbled and broken DNs (the 
   creation of weird nonstandard DNs is pretty much the main reason why the 
   DN-string capability exists).  This includes DNs that can't be easily
   handled through normal cryptlib facilities, for example ones where the CN
   component consists of illegal characters or is in a form that isn't 
   usable as a search key for functions like cryptGetPublicKey().  If users
   want to use this oddball-DN facility, it's up to them to make sure that
   the resulting DN information works with whatever environment they're
   intending to use it in */

typedef struct {
	BUFFER_FIXED( labelLen ) \
	const char *label;
	BUFFER_FIXED( textLen ) \
	const char *text;
	int labelLen, textLen;			/* DN component label and value */
	BOOLEAN isContinued;			/* Whether further AVAs in this RDN */
	} DN_STRING_INFO;

#define MAX_DNSTRING_COMPONENTS 64

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static BOOLEAN parseDNString( INOUT_ARRAY( MAX_DNSTRING_COMPONENTS + 1 ) \
									DN_STRING_INFO *dnStringInfo,
							  IN_BUFFER( stringLength ) const char *string, 
							  IN_LENGTH_ATTRIBUTE const int stringLength )
	{
	int stringPos = 0, stringInfoIndex = 0, i;

	assert( isWritePtr( dnStringInfo, sizeof( DN_STRING_INFO ) * \
									  ( MAX_DNSTRING_COMPONENTS + 1 ) ) );
	assert( isReadPtr( string, stringLength ) );

	REQUIRES( stringLength > 0 && stringLength <= MAX_ATTRIBUTE_SIZE );

	memset( dnStringInfo, 0,
			sizeof( DN_STRING_INFO ) * ( MAX_DNSTRING_COMPONENTS + 1 ) );

	/* Make sure that there are no control characters in the string */
	for( i = 0; i < stringLength; i++ )
		{
		if( ( string[ i ] & 0x7F ) < ' ' )
			return( FALSE );
		}

	/* Verify that a DN string is of the form:

		dnString ::= assignment '\0' | assignment ',' assignment
		assignment ::= label '=' text */
	do
		{
		DN_STRING_INFO *dnStringInfoPtr = &dnStringInfo[ stringInfoIndex ];

		/* Check for label '=' ... */
		for( i = stringPos; i < stringLength; i++ )
			{
			const int ch = string[ i ];

			if( ch == '\\' )
				return( FALSE );/* No escapes in the label component */
			if( ch == '=' || ch == ',' || ch == '+' )
				break;
			}
		if( i <= stringPos || i >= stringLength || \
			string[ i ] == ',' || string[ i ] == '+' )
			return( FALSE );	/* No text or no '=' or spurious ',' */
		dnStringInfoPtr->label = string + stringPos;
		dnStringInfoPtr->labelLen = i - stringPos;
		stringPos = i + 1;		/* Skip text + '=' */

		/* Check for ... text { '\0' | ',' ... | '+' ... } */
		for( i = stringPos;
			 i < stringLength && \
			 !( string[ i - 1 ] != '\\' && \
				( string[ i ] == ',' || string[ i ] == '+' || \
				  string[ i ] == '=' ) ); i++ );
		if( i <= stringPos || string[ i ] == '=' )
			return( FALSE );	/* No text or spurious '=' */
		dnStringInfoPtr->text = string + stringPos;
		dnStringInfoPtr->textLen = i - stringPos;
		dnStringInfoPtr->isContinued = ( i < stringLength && \
										 string[ i ] == '+' ) ? TRUE : FALSE;
		stringPos = i;			/* Skip text + optional ',' */
		if( stringPos != stringLength && ++stringPos >= stringLength )
			/* Trailing ',' */
			return( FALSE );

		/* Strip leading and trailing whitespace on the label and text */
		for( i = 0; i < dnStringInfoPtr->labelLen && \
					dnStringInfoPtr->label[ i ] == ' '; i++ );
		dnStringInfoPtr->label += i;
		dnStringInfoPtr->labelLen -= i;
		for( i = dnStringInfoPtr->labelLen; i > 0 && \
					dnStringInfoPtr->label[ i - 1 ] == ' '; i-- );
		dnStringInfoPtr->labelLen = i;
		for( i = 0; i < dnStringInfoPtr->textLen && \
					dnStringInfoPtr->text[ i ] == ' '; i++ );
		dnStringInfoPtr->text += i;
		dnStringInfoPtr->textLen -= i;
		for( i = dnStringInfoPtr->textLen; i > 0 && \
					dnStringInfoPtr->text[ i - 1 ] == ' '; i-- );
		dnStringInfoPtr->textLen = i;
		if( dnStringInfoPtr->labelLen <= 0 || dnStringInfoPtr->textLen <= 0 )
			return( FALSE );

		if( ++stringInfoIndex >= MAX_DNSTRING_COMPONENTS )
			return( FALSE );
		}
	while( stringPos < stringLength );

	return( TRUE );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int readDNstring( INOUT_PTR void **dnComponentListPtrPtr,
				  IN_BUFFER( stringLength ) const char *string, 
				  IN_LENGTH_ATTRIBUTE const int stringLength )
	{
	DN_STRING_INFO dnStringInfo[ MAX_DNSTRING_COMPONENTS + 1 + 8 ];
	DN_COMPONENT *dnComponentPtr;
	int stringInfoIndex;

	assert( isWritePtr( dnComponentListPtrPtr, sizeof( DN_COMPONENT * ) ) );
	assert( isReadPtr( string, stringLength ) );

	REQUIRES( stringLength > 0 && stringLength <= MAX_ATTRIBUTE_SIZE );

	/* We have to perform the text string to DN translation in two stages
	   thanks to the backwards encoding required by RFC 1779, first we parse
	   it forwards to separate out the RDN components, then we move through
	   the parsed information backwards adding it to the RDN (with special
	   handling for multi-AVA RDNs as for writeDNstring()).  Overall this
	   isn't so bad because it means that we can perform a general firewall 
	   check to make sure that the DN string is well-formed and then leave 
	   the encoding as a separate pass */
	if( !parseDNString( dnStringInfo, string, stringLength ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Find the end of the DN components */
	for( stringInfoIndex = 0;
		 dnStringInfo[ stringInfoIndex + 1 ].label != NULL && \
			stringInfoIndex < MAX_DNSTRING_COMPONENTS;
		 stringInfoIndex++ );
	ENSURES( stringInfoIndex < MAX_DNSTRING_COMPONENTS );

	do
		{
		const DN_STRING_INFO *dnStringInfoPtr;
		BOOLEAN isContinued;
		int iterationCount = 0;

		/* Find the start of the RDN */
		while( stringInfoIndex > 0 && \
			   dnStringInfo[ stringInfoIndex - 1 ].isContinued )
			stringInfoIndex--;
		dnStringInfoPtr = &dnStringInfo[ stringInfoIndex ];

		do
			{
			CRYPT_ERRTYPE_TYPE dummy;
			const DN_COMPONENT_INFO *dnComponentInfo = NULL;
			BYTE textBuffer[ MAX_ATTRIBUTE_SIZE + 1 + 8 ];
			CRYPT_ATTRIBUTE_TYPE type;
			int i, textIndex = 0, status;

			/* Look up the DN component information */
			for( i = 0; certInfoOIDs[ i ].oid != NULL && \
						i < FAILSAFE_ARRAYSIZE( certInfoOIDs, DN_COMPONENT_INFO ); 
				 i++ )
				{
				if( ( strlen( certInfoOIDs[ i ].name ) == \
										dnStringInfoPtr->labelLen && \
					  !strCompare( certInfoOIDs[ i ].name, dnStringInfoPtr->label,
								   dnStringInfoPtr->labelLen ) ) || \
					( certInfoOIDs[ i ].altName != NULL && \
					  strlen( certInfoOIDs[ i ].altName ) == \
										dnStringInfoPtr->labelLen && \
					  !strCompare( certInfoOIDs[ i ].altName, dnStringInfoPtr->label,
								   dnStringInfoPtr->labelLen ) ) )
					{
					dnComponentInfo = &certInfoOIDs[ i ];
					break;
					}
				}
			ENSURES( i < FAILSAFE_ARRAYSIZE( certInfoOIDs, DN_COMPONENT_INFO ) );
			if( dnComponentInfo == NULL )
				return( CRYPT_ARGERROR_STR1 );
			type = dnComponentInfo->type;

			/* Convert the text to canonical form, removing any escapes for
			   special characters */
			for( i = 0; i < dnStringInfoPtr->textLen; i++ )
				{
				int ch = dnStringInfoPtr->text[ i ];

				if( ch == '\\' )
					{
					if( ++i >= dnStringInfoPtr->textLen )
						return( CRYPT_ARGERROR_STR1 );
					ch = dnStringInfoPtr->text[ i ];
					}
				textBuffer[ textIndex++ ] = ch;
				}

			/* Add the AVA to the DN */
			if( type == CRYPT_CERTINFO_COUNTRYNAME )
				{
				/* If it's a country code, force it to uppercase as per ISO 3166 */
				if( textIndex != 2 )
					return( CRYPT_ARGERROR_STR1 );
				textBuffer[ 0 ] = toUpper( textBuffer[ 0 ] );
				textBuffer[ 1 ] = toUpper( textBuffer[ 1 ] );
				status = insertDNstring( ( DN_COMPONENT ** ) dnComponentListPtrPtr,
									type, textBuffer, 2,
									( dnStringInfoPtr->isContinued ) ? \
										DN_FLAG_CONTINUED | DN_FLAG_NOCHECK : \
										DN_FLAG_NOCHECK, &dummy );
				}
			else
				{
				status = insertDNstring( ( DN_COMPONENT ** ) dnComponentListPtrPtr,
									type, textBuffer, textIndex,
									( dnStringInfoPtr->isContinued ) ? \
										DN_FLAG_CONTINUED | DN_FLAG_NOCHECK :
										DN_FLAG_NOCHECK, &dummy );
				}
			if( cryptStatusError( status ) )
				{
				deleteDN( dnComponentListPtrPtr );
				return( status );
				}

			/* Move on to the next AVA */
			isContinued = dnStringInfoPtr->isContinued;
			dnStringInfoPtr++;
			}
		while( isContinued && iterationCount++ < FAILSAFE_ITERATIONS_LARGE );
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
		}
	while( --stringInfoIndex >= 0 );

	/* We're done, lock the DN against further updates */
	for( dnComponentPtr = *dnComponentListPtrPtr; dnComponentPtr != NULL;
		 dnComponentPtr = dnComponentPtr->next )
		dnComponentPtr->flags |= DN_FLAG_LOCKED;

	return( CRYPT_OK );
	}

/* Write a DN in string form */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeDNstring( INOUT STREAM *stream, 
				   IN_OPT const void *dnComponentList )
	{
	const DN_COMPONENT *dnComponentPtr = dnComponentList;
	int iterationCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( dnComponentList == NULL || \
			isReadPtr( dnComponentList, sizeof( DN_COMPONENT ) ) );

	/* If it's an empty DN there's nothing to write */
	if( dnComponentPtr == NULL )
		return( CRYPT_OK );

	/* Find the end of the DN string.  We have to print the RDNs backwards
	   because of ISODE's JANET memorial backwards encoding */
	for( iterationCount = 0;
		 dnComponentPtr->next != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_MED;
		 dnComponentPtr = dnComponentPtr->next, iterationCount++ );
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	do
		{
		const DN_COMPONENT *dnComponentCursor;
		BOOLEAN isContinued;

		/* Find the start of the RDN */
		for( iterationCount = 0;
			 dnComponentPtr->prev != NULL && \
				( dnComponentPtr->prev->flags & DN_FLAG_CONTINUED ) && \
				iterationCount < FAILSAFE_ITERATIONS_MED;
			 dnComponentPtr = dnComponentPtr->prev, iterationCount++ );
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );
		dnComponentCursor = dnComponentPtr;
		dnComponentPtr = dnComponentPtr->prev;

		/* Print the current RDN */
		for( isContinued = TRUE, status = CRYPT_OK, iterationCount = 0;
			 isContinued && cryptStatusOK( status ) && \
				iterationCount < FAILSAFE_ITERATIONS_MAX;
			 iterationCount++ )
			{
			const DN_COMPONENT_INFO *componentInfoPtr = \
										dnComponentCursor->typeInfo;
			int i;

			/* Print the current AVA */
			swrite( stream, componentInfoPtr->name,
					strlen( componentInfoPtr->name ) );
			status = sputc( stream, '=' );
			for( i = 0; cryptStatusOK( status ) && \
				 i < dnComponentCursor->valueLength; i++ )
				{
				const int ch = ( ( BYTE * ) dnComponentCursor->value )[ i ];

				if( ch == ',' || ch == '=' || ch == '+' || ch == ';' || \
					ch == '\\' || ch == '"' )
					sputc( stream, '\\' );
				status = sputc( stream, ch );
				}
			if( cryptStatusError( status ) )
				return( status );

			/* If there are more AVAs in this RDN print a continuation
			   indicator and move on to the next AVA */
			isContinued = ( dnComponentCursor->flags & DN_FLAG_CONTINUED ) ? \
						  TRUE : FALSE;
			if( isContinued )
				{
				status = swrite( stream, " + ", 3 );
				dnComponentCursor = dnComponentCursor->next;
				}
			}
		ENSURES( iterationCount < FAILSAFE_ITERATIONS_MAX );
		if( cryptStatusError( status ) )
			return( status );

		/* If there are more components to come, print an RDN separator */
		if( dnComponentPtr != NULL )
			{
			status = swrite( stream, ", ", 2 );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	while( dnComponentPtr != NULL );

	return( CRYPT_OK );
	}
