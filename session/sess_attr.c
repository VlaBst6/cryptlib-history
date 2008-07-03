/****************************************************************************
*																			*
*						cryptlib Session Attribute Routines					*
*						Copyright Peter Gutmann 1998-2007					*
*																			*
****************************************************************************/

#include <stdio.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "session.h"
#else
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef USE_SESSIONS

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitError( INOUT SESSION_INFO *sessionInfoPtr,
					  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  IN_ENUM( CRYPT_ERRTYPE ) const CRYPT_ERRTYPE_TYPE errorType, 
					  IN_ERROR const int status )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );
	REQUIRES( errorType > CRYPT_ERRTYPE_NONE && \
			  errorType < CRYPT_ERRTYPE_LAST );
	REQUIRES( cryptStatusError( status ) );

	setErrorInfo( sessionInfoPtr, errorLocus, errorType );
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorInited( INOUT SESSION_INFO *sessionInfoPtr,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT,
					   CRYPT_ERROR_INITED ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorNotInited( INOUT SESSION_INFO *sessionInfoPtr,
							   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTINITED ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int exitErrorNotFound( INOUT SESSION_INFO *sessionInfoPtr,
							  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isAttribute( errorLocus ) || \
			  isInternalAttribute( errorLocus ) );

	return( exitError( sessionInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT,
					   CRYPT_ERROR_NOTFOUND ) );
	}

/* Add the contents of an encoded URL to a session.  This requires parsing
   the individual session attribute components out of the URL and then 
   adding each one in turn */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int addUrl( INOUT SESSION_INFO *sessionInfoPtr, 
				   IN_BUFFER( urlLength ) const void *url,
				   IN_LENGTH_DNS const int urlLength )
	{
	const PROTOCOL_INFO *protocolInfoPtr = sessionInfoPtr->protocolInfo;
	URL_INFO urlInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( url, urlLength ) );
	
	REQUIRES( urlLength > 0 && urlLength < MAX_URL_SIZE );

	/* If there's already a transport session or network socket specified, 
	   we can't set a server name as well */
	if( sessionInfoPtr->transportSession != CRYPT_ERROR )
		return( exitErrorInited( sessionInfoPtr, CRYPT_SESSINFO_SESSION ) );
	if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
		return( exitErrorInited( sessionInfoPtr, 
								 CRYPT_SESSINFO_NETWORKSOCKET ) );

	/* Parse the server name.  The PKI protocols all use HTTP as their 
	   substrate so if it's not SSH or SSL/TLS we require HTTP.  For TSP
	   and CMP the user can also specify the braindamaged "TCP transport"
	   protocol but luckily this seems to have mostly sunk without trace,
	   other portions of the session-handling code also discourage its
	   use so we don't encourate it here */
	status = sNetParseURL( &urlInfo, url, urlLength,
						   ( sessionInfoPtr->type == CRYPT_SESSION_SSH ) ? \
								URL_TYPE_SSH : \
						   ( sessionInfoPtr->type == CRYPT_SESSION_SSL ) ? \
								URL_TYPE_HTTPS : URL_TYPE_HTTP );
	if( cryptStatusError( status ) )
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );

	/* We can only use autodetection with PKI services */
	if( !strCompare( url, "[Autodetect]", urlLength ) && \
		!protocolInfoPtr->isReqResp )
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );

	/* Remember the server name */
	if( urlInfo.hostLen + urlInfo.locationLen >= MAX_URL_SIZE )
		{
		/* This should never happen since the overall URL size has to be 
		   less than MAX_URL_SIZE */
		assert( INTERNAL_ERROR );
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );
		}
	if( urlInfo.locationLen <= 0 )
		{
		status = addSessionInfo( &sessionInfoPtr->attributeList,
								 CRYPT_SESSINFO_SERVER_NAME, 
								 urlInfo.host, urlInfo.hostLen );
		}
	else
		{
		char urlBuffer[ MAX_URL_SIZE + 8 ];

		memcpy( urlBuffer, urlInfo.host, urlInfo.hostLen );
		memcpy( urlBuffer + urlInfo.hostLen, urlInfo.location, 
				urlInfo.locationLen );
		status = addSessionInfo( &sessionInfoPtr->attributeList,
								 CRYPT_SESSINFO_SERVER_NAME, urlBuffer, 
								 urlInfo.hostLen + urlInfo.locationLen );
		}
	if( cryptStatusError( status ) )
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );

	/* If there's a port or user name specified in the URL, remember them.  
	   We have to add the user name after we add any other attributes 
	   because it's paired with a password, so adding the user name and then 
	   following it with something that isn't a password will cause an error 
	   return */
	if( urlInfo.port > 0 )
		{
		( void ) krnlSendMessage( sessionInfoPtr->objectHandle, 
								  IMESSAGE_DELETEATTRIBUTE, NULL,
								  CRYPT_SESSINFO_SERVER_PORT );
		status = krnlSendMessage( sessionInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE, &urlInfo.port,
								  CRYPT_SESSINFO_SERVER_PORT );
		}
	if( cryptStatusOK( status ) && urlInfo.userInfoLen > 0 )
		{
		MESSAGE_DATA userInfoMsgData;

		( void ) krnlSendMessage( sessionInfoPtr->objectHandle, 
								  IMESSAGE_DELETEATTRIBUTE, NULL,
								  CRYPT_SESSINFO_USERNAME );
		setMessageData( &userInfoMsgData, ( void * ) urlInfo.userInfo, 
						urlInfo.userInfoLen );
		status = krnlSendMessage( sessionInfoPtr->objectHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &userInfoMsgData,
								  CRYPT_SESSINFO_USERNAME );
		}
	if( cryptStatusError( status ) )
		return( exitError( sessionInfoPtr, CRYPT_SESSINFO_SERVER_NAME, 
						   CRYPT_ERRTYPE_ATTR_VALUE, CRYPT_ARGERROR_STR1 ) );

	/* Remember the transport type */
	if( protocolInfoPtr->altProtocolInfo != NULL && \
		urlInfo.schemaLen == \
					protocolInfoPtr->altProtocolInfo->uriTypeLen && \
		!strCompare( urlInfo.schema, 
					 protocolInfoPtr->altProtocolInfo->uriType,
					 protocolInfoPtr->altProtocolInfo->uriTypeLen ) )
		{
		/* The caller has specified the use of the alternate transport 
		   protocol type, switch to that instead of HTTP */
		sessionInfoPtr->flags &= ~protocolInfoPtr->altProtocolInfo->oldFlagsMask;
		sessionInfoPtr->flags |= protocolInfoPtr->altProtocolInfo->newFlags;
		}
	else
		{
		if( sessionInfoPtr->protocolInfo->flags & SESSION_ISHTTPTRANSPORT )
			{
			sessionInfoPtr->flags &= ~SESSION_USEALTTRANSPORT;
			sessionInfoPtr->flags |= SESSION_ISHTTPTRANSPORT;
			}
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Get Attributes								*
*																			*
****************************************************************************/

/* Get a numeric/boolean attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getSessionAttribute( INOUT SESSION_INFO *sessionInfoPtr,
						 OUT_INT_Z int *valuePtr, 
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( valuePtr, sizeof( int ) ) );

	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Clear return value */
	*valuePtr = 0;

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
			{
			int value, status;

			status = getSessionAttributeCursor( sessionInfoPtr->attributeList,
									sessionInfoPtr->attributeListCurrent, 
									attribute, &value );
			if( status == OK_SPECIAL )
				{
				/* The attribute list wasn't initialised yet, initialise it 
				   now */
				sessionInfoPtr->attributeListCurrent = \
										sessionInfoPtr->attributeList;
				}
			else
				{
				if( cryptStatusError( status ) )
					return( exitError( sessionInfoPtr, attribute, 
									   CRYPT_ERRTYPE_ATTR_ABSENT, status ) );
				}
			*valuePtr = value;

			return( CRYPT_OK );
			}

		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_OPTION_NET_CONNECTTIMEOUT ) );
			*valuePtr = sessionInfoPtr->connectTimeout;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			if( sessionInfoPtr->readTimeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_OPTION_NET_READTIMEOUT ) );
			*valuePtr = sessionInfoPtr->readTimeout;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			if( sessionInfoPtr->writeTimeout == CRYPT_ERROR )
				return( exitErrorNotInited( sessionInfoPtr,
											CRYPT_OPTION_NET_WRITETIMEOUT ) );
			*valuePtr = sessionInfoPtr->writeTimeout;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORTYPE:
			*valuePtr = sessionInfoPtr->errorType;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_ERRORLOCUS:
			*valuePtr = sessionInfoPtr->errorLocus;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			*valuePtr = sessionInfoPtr->receiveBufSize;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_INT_ERRORCODE:
			{
			ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;

			*valuePtr = errorInfo ->errorCode;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_ACTIVE:
			/* Only secure transport sessions can be persistently active,
			   request/response sessions are only active while the 
			   transaction is in progress.  Note that this differs from the
			   connection-active state, which records the fact that there's 
			   a network-level connection established but no messages or
			   secure session active across it.  See the comment in 
			   setSessionAttribute() for more on this */
			*valuePtr = sessionInfoPtr->iCryptInContext != CRYPT_ERROR && \
						( sessionInfoPtr->flags & SESSION_ISOPEN ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_CONNECTIONACTIVE:
			*valuePtr = ( sessionInfoPtr->flags & SESSION_ISOPEN ) ? \
						TRUE : FALSE;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SERVER_PORT:
		case CRYPT_SESSINFO_CLIENT_PORT:
			{
			const ATTRIBUTE_LIST *attributeListPtr = \
						findSessionInfo( sessionInfoPtr->attributeList,
											  attribute );
			if( attributeListPtr == NULL )
				return( exitErrorNotInited( sessionInfoPtr, attribute ) );
			*valuePtr = attributeListPtr->intValue;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_VERSION:
			*valuePtr = sessionInfoPtr->version;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_AUTHRESPONSE:
			*valuePtr = sessionInfoPtr->authResponse;
			return( CRYPT_OK );
		}

	retIntError();
	}

/* Get a string attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getSessionAttributeS( INOUT SESSION_INFO *sessionInfoPtr,
						  INOUT MESSAGE_DATA *msgData, 
						  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	const ATTRIBUTE_LIST *attributeListPtr;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( msgData, sizeof( MESSAGE_DATA ) ) );

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_OPTION_NET_SOCKS_SERVER:
		case CRYPT_OPTION_NET_SOCKS_USERNAME:
		case CRYPT_OPTION_NET_HTTP_PROXY:
			/* These aren't implemented on a per-session level yet since 
			   they're almost never user */
			return( exitErrorNotFound( sessionInfoPtr, attribute ) );

		case CRYPT_ATTRIBUTE_INT_ERRORMESSAGE:
			{
			ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;

			if( errorInfo->errorStringLength <= 0 )
				{
				/* We don't set extended error information for this atribute
				   because it's usually read in response to an existing error, 
				   which would overwrite the existing error information */
				return( CRYPT_ERROR_NOTFOUND );
				}
			return( attributeCopy( msgData, errorInfo->errorString,
								   errorInfo->errorStringLength ) );
			}

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
		case CRYPT_SESSINFO_SERVER_FINGERPRINT:
		case CRYPT_SESSINFO_SERVER_NAME:
		case CRYPT_SESSINFO_CLIENT_NAME:
			attributeListPtr = findSessionInfo( sessionInfoPtr->attributeList,
												attribute );
			if( attributeListPtr == NULL )
				return( exitErrorNotInited( sessionInfoPtr, attribute ) );
			return( attributeCopy( msgData, attributeListPtr->value,
								   attributeListPtr->valueLength ) );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*								Set Attributes								*
*																			*
****************************************************************************/

/* Set a numeric/boolean attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int setSessionAttribute( INOUT SESSION_INFO *sessionInfoPtr,
						 IN_INT_Z const int value, 
						 IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( ( attribute == CRYPT_ATTRIBUTE_CURRENT_GROUP || \
				attribute == CRYPT_ATTRIBUTE_CURRENT ) || 
				/* CURRENT = cursor positioning code */
			  ( value >= 0 && value < MAX_INTLENGTH ) );
	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* If we're in the middle of a paired-attribute add, make sure that the 
	   conditions under which it's occurring are valid.  In theory since 
	   non-string attributes are never part of any paired attributes we 
	   shouldn't really allow them to be added if we're in the middle of a 
	   paired-attribute add but in practice this isn't such a big deal 
	   because the only attribute add that can affect an attribute pair is 
	   an attempt to move the attribute cursor, so we only disallow cursor- 
	   affecting attribute adds.  This leniency makes it less difficult to 
	   add related attributes like a server URL, user name, and port */
	if( sessionInfoPtr->lastAddedAttributeID != CRYPT_ATTRIBUTE_NONE && \
		( attribute == CRYPT_ATTRIBUTE_CURRENT || \
		  attribute == CRYPT_ATTRIBUTE_CURRENT_GROUP ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_ATTRIBUTE_CURRENT:
		case CRYPT_ATTRIBUTE_CURRENT_GROUP:
			{
			ATTRIBUTE_LIST *attributeListPtr = \
									sessionInfoPtr->attributeListCurrent;

			status = setSessionAttributeCursor( sessionInfoPtr->attributeList,
										&attributeListPtr, attribute, value );
			if( cryptStatusError( status ) )
				return( exitError( sessionInfoPtr, attribute, 
								   CRYPT_ERRTYPE_ATTR_ABSENT, status ) );
			sessionInfoPtr->attributeListCurrent = attributeListPtr;
			return( status );
			}

		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			sessionInfoPtr->connectTimeout = value;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			sessionInfoPtr->readTimeout = value;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			sessionInfoPtr->writeTimeout = value;
			return( CRYPT_OK );

		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			REQUIRES( !( sessionInfoPtr->flags & SESSION_ISOPEN ) );

			sessionInfoPtr->receiveBufSize = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_ACTIVE:
			{
			CRYPT_ATTRIBUTE_TYPE missingInfo;

			/* Session state and persistent sessions are handled as follows:
			   The CRYPT_SESSINFO_ACTIVE attribute records the active state
			   of the session as a whole, and the CRYPT_SESSINFO_-
			   CONNECTIONACTIVE attribute records the state of the 
			   underlying comms session.  Setting CRYPT_SESSINFO_ACTIVE for 
			   the first time activates the comms session, and leaves it 
			   active if the underlying mechanism (e.g. HTTP 1.1 persistent 
			   connections) supports it.  The CRYPT_SESSINFO_ACTIVE 
			   attribute is reset once the transaction completes, and 
			   further transactions can be initiated as long as 
			   CRYPT_SESSINFO_CONNECTIONACTIVE is set:

										Obj.state	_active		_connactive
										---------	-------		-----------
				create						0			0			0
				setattr						0			0			0
					(clear out_param)
				activate					1		0 -> 1 -> 0		1
					(clear in_param)
				setattr						1			0			1
					(clear out_param)
				activate					1		0 -> 1 -> 0		1
					(clear in_param)
					(peer closes conn)		1			0			0
				setattr							CRYPT_ERROR_COMPLETE */
			if( value == FALSE )
				return( CRYPT_OK );	/* No-op */

			/* If the session is in the partially-open state while we wait 
			   for the caller to allow or disallow the session 
			   authentication, they have to provide a clear yes or no 
			   indication by setting the CRYPT_SESSINFO_AUTHRESPONSE to TRUE 
			   or FALSE before they can try to continue the session 
			   activation */
			if( ( sessionInfoPtr->flags & SESSION_PARTIALOPEN ) && \
				sessionInfoPtr->authResponse == CRYPT_UNUSED )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_AUTHRESPONSE ) );

			/* Make sure that all of the information that we need to proceed 
			   is present */
			missingInfo = checkMissingInfo( sessionInfoPtr->attributeList,
								isServer( sessionInfoPtr ) ? TRUE : FALSE );
			if( missingInfo != CRYPT_ATTRIBUTE_NONE )
				return( exitErrorNotInited( sessionInfoPtr, missingInfo ) );

			status = activateSession( sessionInfoPtr );
			if( cryptArgError( status ) )
				{
				/* Catch leaked low-level status values.  The session 
				   management code does a large amount of work involving 
				   other cryptlib objects so it's possible that an 
				   unexpected failure at some point will leak through an 
				   inappropriate status value */
				assert( DEBUG_WARN );
				status = CRYPT_ERROR_FAILED;
				}
			return( status );
			}

		case CRYPT_SESSINFO_SERVER_PORT:
			/* If there's already a transport session or network socket 
			   specified we can't set a port as well */
			if( sessionInfoPtr->transportSession != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SESSION ) );
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );

			return( addSessionInfo( &sessionInfoPtr->attributeList,
									CRYPT_SESSINFO_SERVER_PORT, NULL,
									value ) );

		case CRYPT_SESSINFO_VERSION:
			if( value < sessionInfoPtr->protocolInfo->minVersion || \
				value > sessionInfoPtr->protocolInfo->maxVersion )
				return( CRYPT_ARGERROR_VALUE );
			sessionInfoPtr->version = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_PRIVATEKEY:
			{
			const int requiredAttributeFlags = isServer( sessionInfoPtr ) ? \
								sessionInfoPtr->serverReqAttrFlags : \
								sessionInfoPtr->clientReqAttrFlags;

			/* Make sure that it's a private key */
			status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
									  MESSAGE_CHECK_PKC_PRIVATE );
			if( cryptStatusError( status ) )
				{
				if( sessionInfoPtr->type != CRYPT_SESSION_SSL )
					return( CRYPT_ARGERROR_NUM1 );

				/* SSL can also do key agreement-based key exchange so we 
				   fall back to this if key transport-based exchange isn't 
				   possible */
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_KA_EXPORT );
				if( cryptStatusError( status ) )
					return( CRYPT_ARGERROR_NUM1 );
				}

			/* If we need a private key with certain capabilities, make sure 
			   that it has these capabilities.  This is a more specific check 
			   than that allowed by the kernel ACLs */
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYSIGN )
				{
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_SIGN );
				if( cryptStatusError( status ) )
					{
					setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE, 
								  CRYPT_ERRTYPE_ATTR_VALUE );
					return( CRYPT_ARGERROR_NUM1 );
					}
				}
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCRYPT )
				{
				status = krnlSendMessage( value, IMESSAGE_CHECK, NULL,
										  MESSAGE_CHECK_PKC_DECRYPT );
				if( cryptStatusError( status ) )
					{
					setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE, 
								  CRYPT_ERRTYPE_ATTR_VALUE );
					return( CRYPT_ARGERROR_NUM1 );
					}
				}

			/* If we need a private key with a certificate, make sure that 
			   the appropriate type of initialised certificate object is 
			   present.  This is a more specific check than that allowed by 
			   the kernel ACLs */
			if( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCERT )
				{
				int attrValue;

				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, 
									&attrValue, CRYPT_CERTINFO_IMMUTABLE );
				if( cryptStatusError( status ) || !attrValue )
					return( CRYPT_ARGERROR_NUM1 );
				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, 
									&attrValue, CRYPT_CERTINFO_CERTTYPE );
				if( cryptStatusError( status ) ||
					( attrValue != CRYPT_CERTTYPE_CERTIFICATE && \
					  attrValue != CRYPT_CERTTYPE_CERTCHAIN ) )
					return( CRYPT_ARGERROR_NUM1 );
				}
			if( ( requiredAttributeFlags & SESSION_NEEDS_PRIVKEYCACERT ) && \
				cryptStatusError( \
					krnlSendMessage( value, IMESSAGE_CHECK, NULL,
									 MESSAGE_CHECK_CA ) ) )
					return( CRYPT_ARGERROR_NUM1 );

			/* Make sure that the key meets the mininum height requirements.  
			   We only perform this check if we're explicitly being asked to
			   perform the check and it's a server session (which has certain
			   minimum length requirements for private keys), for client
			   sessions the permitted length/security level is controlled by
			   the server so we can't really perform much checking */
			if( sessionInfoPtr->protocolInfo->requiredPrivateKeySize && \
				isServer( sessionInfoPtr ) )
				{
				int length;

				status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
										  &length, CRYPT_CTXINFO_KEYSIZE );
				if( cryptStatusError( status ) || \
					length < sessionInfoPtr->protocolInfo->requiredPrivateKeySize )
					return( exitError( sessionInfoPtr,
									   CRYPT_SESSINFO_PRIVATEKEY,
									   CRYPT_ERRTYPE_ATTR_SIZE,
									   CRYPT_ARGERROR_NUM1 ) );
				}

			/* Perform any protocol-specific additional checks if necessary */
			if( sessionInfoPtr->checkAttributeFunction != NULL )
				{
				status = sessionInfoPtr->checkAttributeFunction( sessionInfoPtr,
														value, attribute );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* Add the private key and increment its reference count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->privateKey = value;

			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_KEYSET:
			{
			int type;

			/* Make sure that it's either a certificate store (rather than 
			   just a generic keyset) if required, or specifically not a 
			   certificate store if not required.  This is to prevent a 
			   session running with unnecessary privileges, we should only 
			   be using a certificate store if it's actually required.  The 
			   checking is already performed by the kernel, but we do it 
			   again here just to be safe */
			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, &type, 
									  CRYPT_IATTRIBUTE_SUBTYPE );
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_NUM1 );
			if( sessionInfoPtr->serverReqAttrFlags & SESSION_NEEDS_CERTSTORE )
				{
				if( type != SUBTYPE_KEYSET_DBMS_STORE )
					return( CRYPT_ARGERROR_NUM1 );
				}
			else
				{
				if( type != SUBTYPE_KEYSET_DBMS )
					return( CRYPT_ARGERROR_NUM1 );
				}

			/* Add the keyset and increment its reference count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->cryptKeyset = value;

			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_AUTHRESPONSE:
			sessionInfoPtr->authResponse = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SESSION:
			/* If there's already a host or network socket specified we 
			   can't set a transport session as well */
			if( findSessionInfo( sessionInfoPtr->attributeList,
								 CRYPT_SESSINFO_SERVER_NAME ) != NULL )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );
			if( sessionInfoPtr->networkSocket != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_NETWORKSOCKET ) );

			/* Add the transport mechanism and increment its reference
			   count */
			krnlSendNotifier( value, IMESSAGE_INCREFCOUNT );
			sessionInfoPtr->transportSession = value;

			return( CRYPT_OK );

		case CRYPT_SESSINFO_NETWORKSOCKET:
			{
			NET_CONNECT_INFO connectInfo;
			STREAM stream;

			/* If there's already a host or session specified we can't set a 
			   network socket as well */
			if( findSessionInfo( sessionInfoPtr->attributeList,
								 CRYPT_SESSINFO_SERVER_NAME ) != NULL )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SERVER_NAME ) );
			if( sessionInfoPtr->transportSession != CRYPT_ERROR )
				return( exitErrorInited( sessionInfoPtr,
										 CRYPT_SESSINFO_SESSION ) );

			/* Create a dummy network stream to make sure that the network 
			   socket is OK */
			initNetConnectInfo( &connectInfo, sessionInfoPtr->ownerHandle, 
								sessionInfoPtr->readTimeout, 
								sessionInfoPtr->connectTimeout,
								NET_OPTION_NETWORKSOCKET_DUMMY );
			connectInfo.networkSocket = value;
			status = sNetConnect( &stream, STREAM_PROTOCOL_TCPIP, 
								  &connectInfo, &sessionInfoPtr->errorInfo );
			if( cryptStatusError( status ) )
				return( status );
			sNetDisconnect( &stream );

			/* Add the network socket */
			sessionInfoPtr->networkSocket = value;

			return( CRYPT_OK );
			}
		}

	retIntError();
	}

/* Set a string attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int setSessionAttributeS( INOUT SESSION_INFO *sessionInfoPtr,
						  IN_BUFFER( dataLength ) const void *data,
						  IN_LENGTH const int dataLength,
						  IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( data, dataLength ) );

	/* If we're in the middle of a paired-attribute add, make sure that the
	   conditions under which it's occurring are valid */
	if( sessionInfoPtr->lastAddedAttributeID != CRYPT_ATTRIBUTE_NONE )
		{
		switch( sessionInfoPtr->lastAddedAttributeID )
			{
			case CRYPT_SESSINFO_USERNAME:
				/* Username must be followed by a password */
				if( attribute != CRYPT_SESSINFO_PASSWORD )
					return( CRYPT_ARGERROR_VALUE );
				break;

			default:
				retIntError();
			}
		}

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_OPTION_NET_SOCKS_SERVER:
		case CRYPT_OPTION_NET_SOCKS_USERNAME:
		case CRYPT_OPTION_NET_HTTP_PROXY:
			/* These aren't implemented on a per-session level yet since 
			   they're almost never used */
			return( CRYPT_ARGERROR_VALUE );

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
			{
			int flags = isServer( sessionInfoPtr ) ? \
						ATTR_FLAG_MULTIVALUED : ATTR_FLAG_NONE;
			int status;

			REQUIRES( dataLength > 0 && dataLength <= CRYPT_MAX_TEXTSIZE );

			/* If this is a client session we can only have a single 
			   instance of this attribute */
			if( !isServer( sessionInfoPtr ) && \
				findSessionInfo( sessionInfoPtr->attributeList, 
								 attribute ) != NULL )
				return( exitErrorInited( sessionInfoPtr, attribute ) );
				
			/* If it's a username, make sure that it doesn't duplicate an
			   existing one */
			if( attribute == CRYPT_SESSINFO_USERNAME )
				{
				if( findSessionInfoEx( sessionInfoPtr->attributeList, 
									   attribute, data, dataLength ) != NULL )
					return( exitError( sessionInfoPtr, attribute,
									   CRYPT_ERRTYPE_ATTR_PRESENT, 
									   CRYPT_ERROR_DUPLICATE ) );
				}
			else
				{
				/* It's a password, make sure that there's an associated
				   username to go with it.  There are two approaches that
				   we can take here, the first simply requires that the
				   current cursor position is a username, implying that
				   the last-added attribute was a username.  The other is
				   to try and move the cursor to the last username in the
				   attribute list and check that the next attribute isn't
				   a password and then add it there, however this is doing
				   a bit too much behind the user's back, is somewhat 
				   difficult to back out of, and leads to exceptions to
				   exceptions, so we keep it simple and only allow passwords
				   to be added if there's an immediately preceding
				   username */
				if( sessionInfoPtr->lastAddedAttributeID != CRYPT_SESSINFO_USERNAME )
					return( exitErrorNotInited( sessionInfoPtr, 
												CRYPT_SESSINFO_USERNAME ) );
				}

			/* If it could be an encoded PKI value, check its validity */
			if( dataLength >= 15 && isPKIUserValue( data, dataLength ) )
				{
				BYTE decodedValue[ CRYPT_MAX_TEXTSIZE + 8 ];
				int decodedValueLen;

				/* It's an encoded value, make sure that it's in order */
				status = decodePKIUserValue( decodedValue, 
											 CRYPT_MAX_TEXTSIZE, 
											 &decodedValueLen, data, 
											 dataLength );
				zeroise( decodedValue, CRYPT_MAX_TEXTSIZE );
				if( cryptStatusError( status ) )
					return( status );
				flags = ATTR_FLAG_ENCODEDVALUE;
				}

			/* Remember the value */
			status = addSessionInfoEx( &sessionInfoPtr->attributeList,
									   attribute, data, dataLength, flags );
			if( cryptStatusError( status ) )
				return( status );
			sessionInfoPtr->lastAddedAttributeID = \
							( attribute == CRYPT_SESSINFO_USERNAME ) ? \
							CRYPT_SESSINFO_USERNAME : CRYPT_ATTRIBUTE_NONE;
			return( CRYPT_OK );
			}

		case CRYPT_SESSINFO_SERVER_FINGERPRINT:
			/* Remember the value */
			return( addSessionInfo( &sessionInfoPtr->attributeList,
									attribute, data, dataLength ) );

		case CRYPT_SESSINFO_SERVER_NAME:
			return( addUrl( sessionInfoPtr, data, dataLength ) );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*								Delete Attributes							*
*																			*
****************************************************************************/

/* Delete an attribute */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int deleteSessionAttribute( INOUT SESSION_INFO *sessionInfoPtr,
							IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attribute )
	{
	const ATTRIBUTE_LIST *attributeListPtr;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	REQUIRES( isAttribute( attribute ) || \
			  isInternalAttribute( attribute ) );

	/* Handle the various information types */
	switch( attribute )
		{
		case CRYPT_OPTION_NET_CONNECTTIMEOUT:
			if( sessionInfoPtr->connectTimeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_OPTION_NET_CONNECTTIMEOUT ) );
			sessionInfoPtr->connectTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_READTIMEOUT:
			if( sessionInfoPtr->readTimeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_OPTION_NET_READTIMEOUT ) );
			sessionInfoPtr->readTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_OPTION_NET_WRITETIMEOUT:
			if( sessionInfoPtr->writeTimeout == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_OPTION_NET_WRITETIMEOUT ) );
			sessionInfoPtr->writeTimeout = CRYPT_ERROR;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_USERNAME:
		case CRYPT_SESSINFO_PASSWORD:
		case CRYPT_SESSINFO_SERVER_NAME:
		case CRYPT_SESSINFO_SERVER_PORT:
			/* Make sure that the attribute to delete is actually present */
			attributeListPtr = \
				findSessionInfo( sessionInfoPtr->attributeList, attribute );
			if( attributeListPtr == NULL )
				return( exitErrorNotFound( sessionInfoPtr, attribute ) );

			/* If we're in the middle of a paired-attribute add and the 
			   delete affects the paired attribute, delete it.  This can
			   get quite complex because the user could (for example) add
			   a { username, password } pair, then add a second username
			   (but not password), and then delete the first password, which
			   will reset the lastAddedAttributeID, leaving an orphaned
			   password followed by an orphaned username.  There isn't any
			   easy way to fix this short of forcing some form of group 
			   delete of paired attributes, but this gets too complicated
			   both to implement and to explain to the user in an error
			   status.  What we do here is handle the simple case and let
			   the pre-session-activation sanity check catch situations 
			   where the user's gone out of their way to be difficult */
			if( sessionInfoPtr->lastAddedAttributeID == attribute )
				sessionInfoPtr->lastAddedAttributeID = CRYPT_ATTRIBUTE_NONE;

			/* Delete the attribute */
			deleteSessionInfo( &sessionInfoPtr->attributeList,
							   &sessionInfoPtr->attributeListCurrent,
							   ( ATTRIBUTE_LIST * ) attributeListPtr );
			return( CRYPT_OK );

		case CRYPT_SESSINFO_REQUEST:
			if( sessionInfoPtr->iCertRequest == CRYPT_ERROR )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_REQUEST ) );
			krnlSendNotifier( sessionInfoPtr->iCertRequest,
							  IMESSAGE_DECREFCOUNT );
			sessionInfoPtr->iCertRequest = CRYPT_ERROR;

			return( CRYPT_OK );

		case CRYPT_SESSINFO_TSP_MSGIMPRINT:
			if( sessionInfoPtr->sessionTSP->imprintAlgo == CRYPT_ALGO_NONE || \
				sessionInfoPtr->sessionTSP->imprintSize <= 0 )
				return( exitErrorNotFound( sessionInfoPtr,
										   CRYPT_SESSINFO_TSP_MSGIMPRINT ) );
			sessionInfoPtr->sessionTSP->imprintAlgo = CRYPT_ALGO_NONE;
			sessionInfoPtr->sessionTSP->imprintSize = 0;

			return( CRYPT_OK );
		}

	retIntError();
	}

#endif /* USE_SESSIONS */
