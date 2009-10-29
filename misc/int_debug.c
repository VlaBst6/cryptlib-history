/****************************************************************************
*																			*
*						cryptlib Internal Debugging API						*
*						Copyright Peter Gutmann 1992-2008					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

/* The following functions are intended purely for diagnostic purposes 
   during development.  They perform minimal checking (for example using 
   assertions rather than returning error codes, since the calling code 
   can't hardwire in tests for their return status), and should only
   be used with a debugger */

#ifndef NDEBUG

/* Older versions of the WinCE runtime don't provide complete stdio
   support so we have to emulate it using wrappers for native 
   functions */

#if defined( __WINCE__ ) && _WIN32_WCE < 500

int remove( const char *pathname )
	{
	wchar_t wcBuffer[ _MAX_PATH + 1 ];

	mbstowcs( wcBuffer, pathname, strlen( pathname ) + 1 );
	DeleteFile( wcBuffer );

	return( 0 );
	}
#endif /* WinCE < 5.x doesn't have remove() */

/* Dump a PDU to disk */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void debugDumpFile( IN_STRING const char *fileName, 
					IN_BUFFER( dataLength ) const void *data, 
					IN_LENGTH_SHORT const int dataLength )
	{
	FILE *filePtr;
	char filenameBuffer[ 1024 ];
	int count = DUMMY_INIT;

	assert( isReadPtr( fileName, 2 ) );
	assert( isReadPtr( data, dataLength ) );

#if defined( __WIN32__ )
	GetTempPath( 512, filenameBuffer );
#else
	strlcpy_s( filenameBuffer, 1024, "/tmp/" );
#endif /* __WIN32__ */
	strlcat_s( filenameBuffer, 1024, fileName );
	strlcat_s( filenameBuffer, 1024, ".der" );

#ifdef __STDC_LIB_EXT1__
	if( fopen_s( &filePtr, filenameBuffer, "wb" ) != 0 )
		filePtr = NULL;
#else
	filePtr = fopen( filenameBuffer, "wb" );
#endif /* __STDC_LIB_EXT1__ */
	assert( filePtr != NULL );
	if( filePtr == NULL )
		return;
	if( dataLength > 0 )
		{
		count = fwrite( data, 1, dataLength, filePtr );
		assert( count == dataLength );
		}
	fclose( filePtr );
	if( dataLength > 0 && count < dataLength )
		remove( filenameBuffer );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void debugDumpFileCert( IN_STRING const char *fileName, 
						IN_HANDLE const CRYPT_CERTIFICATE iCryptCert )
	{
	MESSAGE_DATA msgData;
	FILE *filePtr;
	BYTE certData[ 2048 ];
	char filenameBuffer[ 1024 ];
	int count = DUMMY_INIT, status;

	assert( isReadPtr( fileName, 2 ) );
	assert( isHandleRangeValid( iCryptCert ) );

#if defined( __WIN32__ )
	GetTempPath( 512, filenameBuffer );
#else
	strlcpy_s( filenameBuffer, 1024, "/tmp/" );
#endif /* __WIN32__ */
	strlcat_s( filenameBuffer, 1024, fileName );
	strlcat_s( filenameBuffer, 1024, ".der" );

#ifdef __STDC_LIB_EXT1__
	if( fopen_s( &filePtr, filenameBuffer, "wb" ) != 0 )
		filePtr = NULL;
#else
	filePtr = fopen( filenameBuffer, "wb" );
#endif /* __STDC_LIB_EXT1__ */
	assert( filePtr != NULL );
	if( filePtr == NULL )
		return;
	setMessageData( &msgData, certData, 2048 );
	status = krnlSendMessage( iCryptCert, IMESSAGE_CRT_EXPORT, &msgData, 
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		count = fwrite( msgData.data, 1, msgData.length, filePtr );
		assert( count == msgData.length );
		}
	fclose( filePtr );
	if( cryptStatusError( status ) || count < msgData.length )
		remove( filenameBuffer );
	}

/* Create a hex dump of the first n bytes of a buffer along with the length 
   and a checksum of the entire buffer, used to output a block of hex data 
   along with checksums for debugging things like client/server sessions 
   where it can be used to detect data corruption.  The use of a memory 
   buffer is to allow the hex dump to be performed from multiple threads 
   without them fighting over stdout */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void debugDumpHex( IN_STRING const char *prefixString, 
				   IN_BUFFER( dataLength ) const void *data, 
				   IN_LENGTH_SHORT const int dataLength )
	{
	char dumpBuffer[ 128 ];
	int offset, i, j;

	offset = sprintf_s( dumpBuffer, 128, "%3s %4d %04X ", prefixString, 
						dataLength, checksumData( data, dataLength ) );
	for( i = 0; i < dataLength; i += 16 )
		{
		const int innerLen = min( dataLength - i, 16 );

		if( i > 0 )
			offset = sprintf_s( dumpBuffer, 128, "%3s           ",
								prefixString );
		for( j = 0; j < innerLen; j++ )
			offset += sprintf_s( dumpBuffer + offset, 128 - offset, "%02X ",
								 ( ( BYTE * ) data )[ i + j ] );
		for( ; j < 16; j++ )
			offset += sprintf_s( dumpBuffer + offset, 128 - offset, "   " );
		for( j = 0; j < innerLen; j++ )
			{
			const BYTE ch = ( ( BYTE * ) data )[ i + j ];

			offset += sprintf_s( dumpBuffer + offset, 128 - offset, "%c",
								 isprint( ch ) ? ch : '.' );
			}
		strcpy_s( dumpBuffer + offset, 128 - offset, "\n" );
		DEBUG_OUT( dumpBuffer );
		}

#if !defined( __WIN32__ ) || defined( __WINCE__ ) || defined( __ECOS__ )
	fflush( stdout );
#endif /* Systems where output doesn't to go stdout */
	}

/* A variant of debugDumpHex() that only outputs the raw hex data, to be 
   used in conjunction with PRINT() to output other information about the
   data */

STDC_NONNULL_ARG( ( 1 ) ) \
void debugDumpData( IN_BUFFER( dataLength ) const void *data, 
					IN_LENGTH_SHORT const int dataLength )
	{
	char dumpBuffer[ 128 ];
	int offset, i, j;

	for( i = 0; i < dataLength; i += 16 )
		{
		const int innerLen = min( dataLength - i, 16 );

		offset = sprintf_s( dumpBuffer, 128, "%04d: ", i );
		for( j = 0; j < innerLen; j++ )
			offset += sprintf_s( dumpBuffer + offset, 128 - offset, "%02X ",
								 ( ( BYTE * ) data )[ i + j ] );
		for( ; j < 16; j++ )
			offset += sprintf_s( dumpBuffer + offset, 128 - offset, "   " );
		for( j = 0; j < innerLen; j++ )
			{
			const BYTE ch = ( ( BYTE * ) data )[ i + j ];

			offset += sprintf_s( dumpBuffer + offset, 128 - offset, "%c",
								 isprint( ch ) ? ch : '.' );
			}
		strcpy_s( dumpBuffer + offset, 128 - offset, "\n" );
		DEBUG_OUT( dumpBuffer );
		}

#if !defined( __WIN32__ ) || defined( __WINCE__ ) || defined( __ECOS__ )
	fflush( stdout );
#endif /* Systems where output doesn't to go stdout */
	}
#endif /* !NDEBUG */
