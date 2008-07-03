/****************************************************************************
*																			*
*					 cryptlib Configuration Read/Write Routines				*
*						Copyright Peter Gutmann 1994-2008					*
*																			*
****************************************************************************/

#include "crypt.h"
#ifdef INC_ALL
  #include "trustmgr.h"
  #include "asn1.h"
  #include "user_int.h"
  #include "user.h"
#else
  #include "cert/trustmgr.h"
  #include "misc/asn1.h"
  #include "misc/user_int.h"
  #include "misc/user.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Utility Functions								*
*																			*
****************************************************************************/

/* Read an individual configuration option */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int readConfigOption( INOUT STREAM *stream, 
							 IN_HANDLE CRYPT_USER iCryptUser )
	{
	CRYPT_ATTRIBUTE_TYPE attributeType;
	const BUILTIN_OPTION_INFO *builtinOptionInfoPtr;
	MESSAGE_DATA msgData;
	void *dataPtr = DUMMY_INIT_PTR;
	long optionCode;
	int value, tag, length, status;

	/* Read the wrapper and option index and map it to the actual option.  
	   If we find an unknown index or one that shouldn't be writeable to 
	   persistent storage, we skip it and continue.  This is done to handle 
	   new options that may have been added after this version of cryptlib 
	   was built (for unknown indices) and because the stored configuration 
	   options are an untrusted source so we have to check for attempts to 
	   feed in bogus values (for non-writeable options) */
	readSequence( stream, NULL );
	status = readShortInteger( stream, &optionCode );
	if( cryptStatusError( status ) )
		return( status );
	if( optionCode < 0 || optionCode > LAST_STORED_OPTION )
		{
		/* Unknown option, ignore it */
		return( readUniversal( stream ) );
		}
	builtinOptionInfoPtr = getBuiltinOptionInfoByCode( optionCode );
	if( builtinOptionInfoPtr == NULL || \
		builtinOptionInfoPtr->index < 0 || \
		builtinOptionInfoPtr->index > LAST_STORED_OPTION || \
		builtinOptionInfoPtr->index == CRYPT_UNUSED )
		{
		/* Unknown option, ignore it */
		return( readUniversal( stream ) );
		}
	attributeType = builtinOptionInfoPtr->option;

	/* Read the option value and set the option.  We don't treat a failure 
	   to set the option as a problem since the user probably doesn't want 
	   the entire system to fail because of a bad configuration option, and 
	   in any case we'll fall back to a safe default value */
	tag = peekTag( stream );
	if( cryptStatusError( tag ) )
		return( tag );
	if( tag == BER_BOOLEAN || tag == BER_INTEGER )
		{
		/* It's a numeric value, read the appropriate type and try and set 
		   the option */
		if( tag == BER_BOOLEAN )
			status = readBoolean( stream, &value );
		else
			{
			long integer;

			status = readShortInteger( stream, &integer );
			if( cryptStatusOK( status ) )
				value = ( int ) integer;
			}
		if( cryptStatusError( status ) )
			return( status );
		( void ) krnlSendMessage( iCryptUser, IMESSAGE_SETATTRIBUTE, 
								  &value, attributeType );
		return( CRYPT_OK );
		}

	/* It's a string value, set the option straight from the encoded data */
	status = readGenericHole( stream, &length, 1, BER_STRING_UTF8 );
	if( cryptStatusOK( status ) )
		status = sMemGetDataBlock( stream, &dataPtr, length );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, length );
	if( cryptStatusError( status ) )
		return( status );
	setMessageData( &msgData, dataPtr, length );
	( void ) krnlSendMessage( iCryptUser, IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, attributeType );

	return( CRYPT_OK );
	}

/* Rumble through the configuration options to determine the total encoded 
   length of the ones that don't match the default setting.  We can't just 
   check the isDirty flag because if a value is reset to its default setting 
   the encoded size will be zero even though the isDirty flag is set */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int sizeofConfigData( IN_ARRAY( CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST ) \
						const OPTION_INFO *optionList, 
					  OUT_LENGTH_Z int *length )
	{
	int dataLength = 0, i;

	assert( isReadPtr( optionList, 
						sizeof( OPTION_INFO ) * \
							( CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST ) ) );
	assert( isWritePtr( length, sizeof( int ) ) );

	/* Clear return value */
	*length = 0;

	/* Check each option to see whether it needs to be written to disk.  If 
	   it does, determine its length */
	for( i = 0; 
		 optionList[ i ].builtinOptionInfo->option <= LAST_STORED_OPTION && \
			i < FAILSAFE_ITERATIONS_MED; i++ )
		{
		const BUILTIN_OPTION_INFO *builtinOptionInfoPtr = \
									optionList[ i ].builtinOptionInfo;
		const OPTION_INFO *optionInfoPtr = &optionList[ i ];
		int lengthValue;

		/* If it's an option that can't be written to disk, skip it */
		if( builtinOptionInfoPtr->index == CRYPT_UNUSED )
			continue;

		if( builtinOptionInfoPtr->type == OPTION_STRING )
			{
			/* If the string value is the same as the default, there's
			   nothing to do */
			if( optionInfoPtr->strValue == NULL || \
				optionInfoPtr->strValue == builtinOptionInfoPtr->strDefault )
				continue;
			lengthValue = ( int ) \
					sizeofObject( \
						sizeofShortInteger( builtinOptionInfoPtr->index ) + \
						sizeofObject( optionInfoPtr->intValue ) );
			}
		else
			{
			/* If the integer/boolean value that's currently set isn't the
			   default setting, update it */
			if( optionInfoPtr->intValue == builtinOptionInfoPtr->intDefault )
				continue;
			lengthValue = ( int ) \
					sizeofObject( \
						sizeofShortInteger( builtinOptionInfoPtr->index ) + \
						( builtinOptionInfoPtr->type == OPTION_NUMERIC ? \
						  sizeofShortInteger( optionInfoPtr->intValue ) : \
						  sizeofBoolean() ) );
			}
		ENSURES( lengthValue > 0 && lengthValue < MAX_INTLENGTH_SHORT );
		dataLength += lengthValue;
		}
	ENSURES( i < FAILSAFE_ITERATIONS_MED );
	ENSURES( dataLength >= 0 && dataLength < MAX_INTLENGTH );

	*length = dataLength;
	return( CRYPT_OK );
	}

/* Write the configuration data to a stream */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int writeConfigData( INOUT STREAM *stream, 
					 IN_ARRAY( CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST ) \
						const OPTION_INFO *optionList )
	{
	int i, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( optionList, 
						sizeof( OPTION_INFO ) * \
							( CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST ) ) );

	/* Write each option that needs to be written to the stream */
	for( i = 0; 
		 optionList[ i ].builtinOptionInfo->option <= LAST_STORED_OPTION && \
			i < FAILSAFE_ITERATIONS_MED; i++ )
		{
		const BUILTIN_OPTION_INFO *builtinOptionInfoPtr = \
									optionList[ i ].builtinOptionInfo;
		const OPTION_INFO *optionInfoPtr = &optionList[ i ];

		/* If it's an option that can't be written to disk, skip it */
		if( builtinOptionInfoPtr->index == CRYPT_UNUSED )
			continue;

		if( builtinOptionInfoPtr->type == OPTION_STRING )
			{
			if( optionInfoPtr->strValue == NULL || \
				optionInfoPtr->strValue == builtinOptionInfoPtr->strDefault )
				continue;
			writeSequence( stream,
						   sizeofShortInteger( builtinOptionInfoPtr->index ) + \
						   sizeofObject( strlen( optionInfoPtr->strValue ) ) );
			writeShortInteger( stream, builtinOptionInfoPtr->index,
							   DEFAULT_TAG );
			status = writeCharacterString( stream, optionInfoPtr->strValue,
										   strlen( optionInfoPtr->strValue ),
										   BER_STRING_UTF8 );
			if( cryptStatusError( status ) )
				return( status );
			continue;
			}

		if( optionInfoPtr->intValue == builtinOptionInfoPtr->intDefault )
			continue;
		if( builtinOptionInfoPtr->type == OPTION_NUMERIC )
			{
			writeSequence( stream,
						   sizeofShortInteger( builtinOptionInfoPtr->index ) + \
						   sizeofShortInteger( optionInfoPtr->intValue ) );
			writeShortInteger( stream, builtinOptionInfoPtr->index,
							   DEFAULT_TAG );
			status = writeShortInteger( stream, optionInfoPtr->intValue,
										DEFAULT_TAG );
			}
		else
			{
			writeSequence( stream,
						   sizeofShortInteger( builtinOptionInfoPtr->index ) + \
						   sizeofBoolean() );
			writeShortInteger( stream, builtinOptionInfoPtr->index,
							   DEFAULT_TAG );
			status = writeBoolean( stream, optionInfoPtr->intValue, 
								   DEFAULT_TAG );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	ENSURES( i < FAILSAFE_ITERATIONS_MED );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read Configuration Options 						*
*																			*
****************************************************************************/

/* Read any user-defined configuration options.  Since the configuration 
   file is an untrusted source we set the values in it via external messages 
   rather than manipulating the configuration info directly, which means 
   that everything read is subject to the usual ACL checks */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2 ) ) \
static int readTrustedCerts( IN_HANDLE const CRYPT_KEYSET iCryptKeyset,
							 INOUT void *trustInfoPtr )
	{
	MESSAGE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_PKCSIZE + 1536 + 8 ];
	int iterationCount, status;

	assert( trustInfoPtr != NULL );

	REQUIRES( isHandleRangeValid( iCryptKeyset ) );

	/* Read each trusted cert from the keyset */
	setMessageData( &msgData, buffer, CRYPT_MAX_PKCSIZE + 1536 );
	status = krnlSendMessage( iCryptKeyset, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_TRUSTEDCERT );
	for( iterationCount = 0;
		 cryptStatusOK( status ) && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		/* Add the cert data as a trusted cert item and look for the next
		   one */
		status = addTrustEntry( trustInfoPtr, CRYPT_UNUSED, msgData.data,
								msgData.length, TRUE );
		if( cryptStatusOK( status ) )
			{
			setMessageData( &msgData, buffer, CRYPT_MAX_PKCSIZE + 1536 );
			status = krnlSendMessage( iCryptKeyset, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, 
									  CRYPT_IATTRIBUTE_TRUSTEDCERT_NEXT );
			}
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );

	return( ( status == CRYPT_ERROR_NOTFOUND ) ? CRYPT_OK : status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int readConfig( IN_HANDLE const CRYPT_USER iCryptUser, 
				IN_STRING const char *fileName, INOUT void *trustInfoPtr )
	{
	CRYPT_KEYSET iCryptKeyset;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM stream;
	DYNBUF configDB;
	char configFilePath[ MAX_PATH_LENGTH + 8 ];
	int configFilePathLen, iterationCount, status;

	assert( fileName != NULL );
	assert( trustInfoPtr != NULL );

	REQUIRES( iCryptUser == DEFAULTUSER_OBJECT_HANDLE || \
			  isHandleRangeValid( iCryptUser ) );

	/* Try and open the configuration file.  If we can't open it it merely 
	   means that the file doesn't exist, which isn't an error, we'll go 
	   with the built-in defaults */
	status = fileBuildCryptlibPath( configFilePath, MAX_PATH_LENGTH, 
									&configFilePathLen, fileName, 
									strlen( fileName ), BUILDPATH_GETPATH );
	if( cryptStatusError( status ) )
		return( CRYPT_OK );		/* Can't build configuration path */
	setMessageCreateObjectInfo( &createInfo, CRYPT_KEYSET_FILE );
	createInfo.arg2 = CRYPT_KEYOPT_READONLY;
	createInfo.strArg1 = configFilePath;
	createInfo.strArgLen1 = configFilePathLen;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_KEYSET );
	if( cryptStatusError( status ) )
		return( CRYPT_OK );		/* No configuration data present */
	iCryptKeyset = createInfo.cryptHandle;

	/* Get the configuration info from the keyset */
	status = dynCreate( &configDB, iCryptKeyset,
						CRYPT_IATTRIBUTE_CONFIGDATA );
	if( cryptStatusError( status ) )
		{
		/* If there were no configuration options present there may still be 
		   trusted certs so we try and read those before exiting */
		if( status == CRYPT_ERROR_NOTFOUND )
			status = readTrustedCerts( iCryptKeyset, trustInfoPtr );
		krnlSendNotifier( iCryptKeyset, IMESSAGE_DECREFCOUNT );
		return( status );
		}
	status = readTrustedCerts( iCryptKeyset, trustInfoPtr );
	krnlSendNotifier( iCryptKeyset, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		dynDestroy( &configDB );
		return( status );
		}

	/* Read each configuration option */
	sMemConnect( &stream, dynData( configDB ), dynLength( configDB ) );
	for( iterationCount = 0;
		 cryptStatusOK( status ) && \
			stell( &stream ) < dynLength( configDB ) && \
			iterationCount < FAILSAFE_ITERATIONS_LARGE;
		 iterationCount++ )
		{
		status = readConfigOption( &stream, iCryptUser );
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_LARGE );
	sMemDisconnect( &stream );

	/* Clean up */
	dynDestroy( &configDB );
	return( status );
	}

/****************************************************************************
*																			*
*							Write Configuration Options 					*
*																			*
****************************************************************************/

/* Write any user-defined configuration options.  This is performed in two 
   phases, a first phase that encodes the configuration data and a second 
   phase that writes the data to disk.  The reason for the split is that the 
   second phase doesn't require the use of the user object data any more 
   and can be a somewhat lengthy process due to disk accesses and other bits 
   and pieces, because of this the caller is expected to unlock the user 
   object between the two phases to ensure that the second phase doesn't 
   stall all other operations that require it */

CHECK_RETVAL_SPECIAL STDC_NONNULL_ARG( ( 1, 2, 3, 4, 5 ) ) \
int prepareConfigData( INOUT void *configOptions, 
					   IN_STRING const char *fileName,
					   INOUT void *trustInfoPtr, 
					   OUT_BUFFER_ALLOC( *dataLength ) void **dataPtrPtr, 
					   OUT_LENGTH_Z int *dataLength )
	{
	STREAM stream;
	const BOOLEAN trustedCertsPresent = \
						cryptStatusOK( \
							enumTrustedCerts( trustInfoPtr, CRYPT_UNUSED,
											  CRYPT_UNUSED ) ) ? \
					TRUE : FALSE;
	void *dataPtr;
	int length, status;

	assert( isReadPtr( configOptions, 
						sizeof( OPTION_INFO ) * \
							( CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST ) ) );
	assert( fileName != NULL );
	assert( trustInfoPtr != NULL );
	assert( isWritePtr( dataPtrPtr, sizeof( void * ) ) );
	assert( isWritePtr( dataLength, sizeof( int ) ) );

	/* Clear return values */
	*dataPtrPtr = NULL;
	*dataLength = 0;

	/* If neither the configuration options nor any cert trust settings have
	   changed, there's nothing to do */
	if( !checkConfigChanged( configOptions ) && !trustedCertsPresent )
		return( CRYPT_OK );

	/* Determine the total encoded length of the configuration options */
	status = sizeofConfigData( configOptions, &length );
	if( cryptStatusError( status ) )
		return( status );

	/* If we've gone back to all default values from having non-default ones
	   stored, we either have to write only trusted certs or nothing at all */
	if( length <= 0 )
		{
		char configFilePath[ MAX_PATH_LENGTH + 1 + 8 ];
		int configFilePathLen;

		/* There's no data to write, if there are trusted certs present
		   notify the caller */
		if( trustedCertsPresent )
			return( OK_SPECIAL );

		/* There's nothing to write, delete the configuration file */
		status = fileBuildCryptlibPath( configFilePath, MAX_PATH_LENGTH, 
										&configFilePathLen, fileName, 
										strlen( fileName ), 
										BUILDPATH_GETPATH );
		if( cryptStatusOK( status ) )
			{
			configFilePath[ configFilePathLen ] = '\0';
			fileErase( configFilePath );
			}
		return( CRYPT_OK );
		}

	ENSURES( length > 0 && length < MAX_INTLENGTH );

	/* Allocate a buffer to hold the encoded values */
	if( ( dataPtr = clAlloc( "prepareConfigData", length ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Write the configuration options */
	sMemOpen( &stream, dataPtr, length );
	status = writeConfigData( &stream, configOptions );
	if( cryptStatusOK( status ) )
		length = stell( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		assert( DEBUG_WARN );
		return( status );
		}

	/* We've written the configuration data to the memory buffer, let the 
	   caller know that they can unlock it and commit it to permanent 
	   storage */
	*dataPtrPtr = dataPtr;
	*dataLength = length;
	return( OK_SPECIAL );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
int commitConfigData( IN_HANDLE const CRYPT_USER cryptUser, 
					  IN_STRING const char *fileName,
					  IN_BUFFER_OPT( length ) const void *data, 
					  IN_LENGTH_Z const int dataLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	char configFilePath[ MAX_PATH_LENGTH + 8 ];
	int configFilePathLen, status;

	assert( isHandleRangeValid( cryptUser ) );
	assert( fileName != NULL );
	assert( ( data == NULL && dataLength == 0 ) || \
			isReadPtr( data, dataLength ) );

	REQUIRES( ( data == NULL && dataLength == 0 ) || \
			  ( dataLength > 0 && dataLength < MAX_INTLENGTH ) );

	/* Build the path to the configuration file and try and create it */
	status = fileBuildCryptlibPath( configFilePath, MAX_PATH_LENGTH, 
									&configFilePathLen, fileName, 
									strlen( fileName ), 
									BUILDPATH_CREATEPATH );
	if( cryptStatusError( status ) )
		{
		/* Map the lower-level filesystem-specific error into a more 
		   meaningful generic error */
		return( CRYPT_ERROR_OPEN );
		}
	setMessageCreateObjectInfo( &createInfo, CRYPT_KEYSET_FILE );
	createInfo.arg2 = CRYPT_KEYOPT_CREATE;
	createInfo.strArg1 = configFilePath;
	createInfo.strArgLen1 = configFilePathLen;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_KEYSET );
	if( cryptStatusError( status ) )
		{
		/* Map the lower-level keyset-specific error into a more meaningful
		   generic error */
		return( CRYPT_ERROR_OPEN );
		}

	/* Send the configuration data (if there is any) and any trusted certs 
	   to the keyset.  dataLength can be zero if there are only trusted 
	   certs to write */
	if( dataLength > 0 )
		{
		setMessageData( &msgData, ( void * ) data, dataLength );
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_CONFIGDATA );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( cryptUser, IMESSAGE_SETATTRIBUTE,
								  &createInfo.cryptHandle,
								  CRYPT_IATTRUBUTE_CERTKEYSET );
		}
	krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		fileErase( configFilePath );
		return( CRYPT_ERROR_WRITE );
		}
	return( CRYPT_OK );
	}
