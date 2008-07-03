/****************************************************************************
*																			*
*							User Routines Header File						*
*						 Copyright Peter Gutmann 1999-2007					*
*																			*
****************************************************************************/

#ifndef _USER_DEFINED

#define _USER_DEFINED

/* Initialisation states for the user object */

typedef enum {
	USER_STATE_NONE,				/* No initialisation state */
	USER_STATE_SOINITED,			/* SSO inited, not usable */
	USER_STATE_USERINITED,			/* User inited, usable */
	USER_STATE_LOCKED,				/* Disabled, not usable */
	USER_STATE_LAST					/* Last possible state */
	} USER_STATE_TYPE;

/* User information flags.  These are:

	FLAG_ZEROISE: Zeroise in progress, further messages (except destroy) are 
			bounced, and all files are deleted on destroy */

#define USER_FLAG_NONE			0x00	/* No flag */
#define USER_FLAG_ZEROISE		0x01	/* Zeroise in progress */

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* User information as stored in the user info file */

typedef struct {
	CRYPT_USER_TYPE type;			/* User type */
	USER_STATE_TYPE state;			/* User state */
	BUFFER( CRYPT_MAX_TEXTSIZE, userNameLength ) \
	BYTE userName[ CRYPT_MAX_TEXTSIZE + 8 ];
	int userNameLength;				/* User name */
	BUFFER_FIXED( KEYID_SIZE ) \
	BYTE userID[ KEYID_SIZE + 8 ];
	BUFFER_FIXED( KEYID_SIZE ) \
	BYTE creatorID[ KEYID_SIZE + 8 ];/* ID of user and creator of this user */
	int fileRef;					/* User info file reference */
	} USER_FILE_INFO;

/* The structure that stores the information on a user */

typedef struct UI {
	/* Control and status information */
	int flags;						/* User flags */
	USER_FILE_INFO userFileInfo;	/* General user info */

	/* User index information for the default user */
	void *userIndexPtr;

	/* Configuration options for this user.  These are managed through the 
	   user config code, so they're just treated as a dynamically-allocated 
	   blob within the user object */
	void *configOptions;

	/* Certificate trust information for this user, and a flag indicating
	   whether the trust info has changed and potentially needs to be
	   committed to disk.  This requires access to cert-internal details
	   so it's handled externally via the cert code, the user object just
	   sees the info as an opaque blob */
	void *trustInfoPtr;
	BOOLEAN trustInfoChanged;

	/* The user object contains an associated keyset which is used to store
	   user information to disk.  In addition for SOs and CAs it also 
	   contains an associated encryption context, either a private key (for 
	   an SO) or a conventional key (for a CA) */
	CRYPT_KEYSET iKeyset;			/* Keyset */
	CRYPT_CONTEXT iCryptContext;	/* Private/secret key */

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* The object's handle, used when sending messages to the object when
	   only the xxx_INFO is available */
	CRYPT_HANDLE objectHandle;
	} USER_INFO;

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* User attribute handling functions */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getUserAttribute( INOUT USER_INFO *userInfoPtr,
					  OUT_INT_Z int *valuePtr, 
					  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getUserAttributeS( INOUT USER_INFO *userInfoPtr,
					   INOUT MESSAGE_DATA *msgData, 
					   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setUserAttribute( INOUT USER_INFO *userInfoPtr,
					  IN_INT_Z const int value, 
					  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int setUserAttributeS( INOUT USER_INFO *userInfoPtr,
					   IN_BUFFER( dataLength ) const void *data,
					   IN_LENGTH const int dataLength,
					   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int deleteUserAttribute( INOUT USER_INFO *userInfoPtr,
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute );

/* Prototypes for functions in user.c */

CHECK_RETVAL \
const USER_FILE_INFO *getPrimarySoUserInfo( void );
CHECK_RETVAL \
BOOLEAN isZeroisePassword( IN_BUFFER( passwordLen ) \
						   const char *password, const int passwordLen ) \
						   STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL \
int zeroiseUsers( INOUT USER_INFO *userInfoPtr ) \
				  STDC_NONNULL_ARG( ( 1 ) );
CHECK_RETVAL \
int setUserPassword( INOUT USER_INFO *userInfoPtr, 
					 IN_BUFFER( passwordLen ) \
					 const char *password, const int passwordLength ) \
					 STDC_NONNULL_ARG( ( 1, 2 ) );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initUserIndex( OUT_PTR void **userIndexPtrPtr );
STDC_NONNULL_ARG( ( 1 ) ) \
void endUserIndex( INOUT void *userIndexPtr );

/* Prototypes for functions in user_cfg.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initOptions( OUT_PTR void **configOptionsPtr );
STDC_NONNULL_ARG( ( 1 ) ) \
void endOptions( INOUT void *configOptions );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setOption( INOUT void *configOptions, 
			   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE option,
			   IN_INT const int value );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setOptionSpecial( INOUT void *configOptions, 
					  IN_RANGE( CRYPT_OPTION_SELFTESTOK, CRYPT_OPTION_SELFTESTOK ) \
					  const CRYPT_ATTRIBUTE_TYPE option,
					  IN_INT const int value );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int setOptionString( void *configOptions, 
					 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE option,
					 IN_BUFFER( valueLength ) \
					 const char *value, 
					 IN_LENGTH_SHORT const int valueLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3 ) ) \
int getOption( const void *configOptions, 
			   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE option,
			   OUT_INT_Z int *value );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
int getOptionString( const void *configOptions,
					 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE option,
					 OUT_PTR const void **strPtrPtr, 
					 OUT_LENGTH_SHORT_Z int *strLen );
CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int deleteOption( INOUT void *configOptions, 
				  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE option );

/* Prototypes for functions in user_rw.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int readConfig( IN_HANDLE const CRYPT_USER iCryptUser, 
				IN_STRING const char *fileName, INOUT void *trustInfoPtr );
CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 5 ) ) \
int prepareConfigData( INOUT void *configOptions, 
					   IN_STRING const char *fileName,
					   INOUT void *trustInfoPtr, 
					   OUT_BUFFER_ALLOC( *dataLength ) void **dataPtrPtr, 
					   OUT_LENGTH_Z int *dataLength );
CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int commitConfigData( IN_HANDLE const CRYPT_USER cryptUser, 
					  IN_STRING const char *fileName,
					  IN_BUFFER_OPT( dataLength ) \
					  const void *data, IN_LENGTH_Z const int dataLength );

#endif /* _USER_DEFINED */
