/****************************************************************************
*																			*
*						  cryptlib HTTP Write Routines						*
*						Copyright Peter Gutmann 1998-2007					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "http.h"
#else
  #include "crypt.h"
  #include "io/http.h"
#endif /* Compiler-specific includes */

#ifdef USE_HTTP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Encode a string as per RFC 1866 (although the list of characters that 
   need to be escaped is itself given in RFC 2396).  Characters that are 
   permitted/not permitted are:

	 !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
	x..x.xx....x...xxxxxxxxxxxx.xxxxx

   Because of this it's easier to check for the most likely permitted
   characters (alphanumerics), and then to check for any special-case
   chars */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void encodeRFC1866( INOUT STREAM *headerStream, 
						   IN_BUFFER( stringLength) const char *string, 
						   IN_LENGTH_SHORT const int stringLength )
	{
	static const char allowedChars[] = "$-_.!*'(),\"/\x00\x00";	/* RFC 1738 + '/' */
	int index = 0;

	assert( isWritePtr( headerStream, sizeof( STREAM ) ) );
	assert( isReadPtr( string, stringLength ) );

	REQUIRES_V( stringLength > 0 && stringLength < MAX_INTLENGTH_SHORT );

	while( index < stringLength )
		{
		const int ch = byteToInt( string[ index++ ] );
		int i;

		if( isAlnum( ch ) )
			{
			sputc( headerStream, ch );
			continue;
			}
		if( ch == ' ' )
			{
			sputc( headerStream, '+' );
			continue;
			}
		for( i = 0; allowedChars[ i ] != '\0' && ch != allowedChars[ i ] && \
					i < FAILSAFE_ARRAYSIZE( allowedChars, char ); i++ );
		ENSURES_V( i < FAILSAFE_ARRAYSIZE( allowedChars, char ) );
		if( allowedChars[ i ] != '\0' )
			{
			/* It's in the allowed-chars list, output it verbatim */
			sputc( headerStream, ch );
			}
		else
			{
			char escapeString[ 16 ];
			int escapeStringLen;

			/* It's a special char, escape it */
			escapeStringLen = sprintf_s( escapeString, 8, "%%%02X", ch );
			swrite( headerStream, escapeString, escapeStringLen );
			}
		}
	}

/* If we time out when sending HTTP header data this would usually be 
   reported as a CRYPT_ERROR_TIMEOUT by the lower-level network I/O 
   routines, however due to the multiple layers of I/O and special case 
   timeout handling when (for example) a cryptlib transport session is 
   layered over the network I/O layer and the fact that to the caller the
   write of the out-of-band HTTP header data (which can occur as part of a 
   standard HTTP write, but also in a GET or when sending an error
   response) is invisible, we have to perform an explicit check to make 
   sure that we sent everything */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int sendHTTPData( INOUT STREAM *stream, 
				  IN_BUFFER( length ) void *buffer, 
				  IN_LENGTH const int length, 
				  IN_FLAGS( HTTP ) const int flags )
	{
	NET_STREAM_INFO *netStream = ( NET_STREAM_INFO * ) stream->netStreamInfo;
	int bytesWritten, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( buffer, length ) );

	REQUIRES( length > 0 && length < MAX_INTLENGTH );
	REQUIRES( flags >= HTTP_FLAG_NONE && flags <= HTTP_FLAG_MAX );

	status = netStream->bufferedTransportWriteFunction( stream, buffer, 
														length, 
														&bytesWritten, flags );
	if( cryptStatusError( status ) )
		{
		/* Network-level error, the lower-level layers have reported the 
		   error details */
		return( status );
		}
	if( bytesWritten < length )
		{
		/* The write timed out, convert the incomplete HTTP header write to 
		   the appropriate timeout error */
		retExt( CRYPT_ERROR_TIMEOUT, 
				( CRYPT_ERROR_TIMEOUT, NETSTREAM_ERRINFO, 
				  "HTTP write timed out before all data could be written" ) );
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Write Request/Response Header					*
*																			*
****************************************************************************/

/* Write an HTTP request header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int writeRequestHeader( INOUT STREAM *stream, 
						IN_OPT const HTTP_URI_INFO *httpReqInfo,
						IN_BUFFER_OPT( contentTypeLen ) const char *contentType, 
						IN_LENGTH_SHORT_Z const int contentTypeLen, 
						IN_LENGTH_Z const int contentLength )
	{
	NET_STREAM_INFO *netStream = ( NET_STREAM_INFO * ) stream->netStreamInfo;
	STREAM headerStream;
	char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ];
	const int transportFlag = ( contentLength > 0 ) ? TRANSPORT_FLAG_NONE : \
													  TRANSPORT_FLAG_FLUSH;
	int headerLength = DUMMY_INIT, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( httpReqInfo == NULL ) || \
			isReadPtr( httpReqInfo, sizeof( HTTP_URI_INFO * ) ) );
	assert( ( contentLength == 0 && contentType == NULL && \
			  contentTypeLen == 0 ) || \
			( contentLength >= 1 && \
			  isReadPtr( contentType, contentTypeLen ) ) );
	
	REQUIRES( ( contentLength == 0 && contentType == NULL && \
				contentTypeLen == 0 ) || \
			  ( contentLength > 0 && contentLength < MAX_INTLENGTH && \
			    contentType != NULL && \
				contentTypeLen > 0 && contentTypeLen < MAX_INTLENGTH ) );
	REQUIRES( ( httpReqInfo == NULL ) || \
			  ( httpReqInfo->attributeLen == 0 && \
				httpReqInfo->valueLen == 0 ) || \
			  ( httpReqInfo->attributeLen > 0 && \
				httpReqInfo->valueLen > 0 ) );

	sMemOpen( &headerStream, headerBuffer, HTTP_LINEBUF_SIZE );
	if( netStream->nFlags & STREAM_NFLAG_HTTPTUNNEL )
		swrite( &headerStream, "CONNECT ", 8 );
	else
		{
		if( contentLength > 0 )
			swrite( &headerStream, "POST ", 5 );
		else
			swrite( &headerStream, "GET ", 4 );
		}
	if( netStream->nFlags & ( STREAM_NFLAG_HTTPPROXY | STREAM_NFLAG_HTTPTUNNEL ) )
		{
		/* If we're going through an HTTP proxy/tunnel, send an absolute URL 
		   rather than just the relative location */
		if( netStream->nFlags & STREAM_NFLAG_HTTPPROXY )
			swrite( &headerStream, "http://", 7 );
		swrite( &headerStream, netStream->host, netStream->hostLen );
		if( netStream->port != 80 )
			{
			char portString[ 16 + 8 ];
			int portStringLength;

			portStringLength = sprintf_s( portString, 16, ":%d", 
										  netStream->port );
			swrite( &headerStream, portString, portStringLength );
			}
		}
	if( !( netStream->nFlags & STREAM_NFLAG_HTTPTUNNEL ) )
		{
		if( netStream->path != NULL && netStream->pathLen > 0 )
			swrite( &headerStream, netStream->path, netStream->pathLen );
		else
			sputc( &headerStream, '/' );
		}
	if( httpReqInfo != NULL )
		{
		if( httpReqInfo->attributeLen > 0 && httpReqInfo->valueLen > 0 )
			{
			sputc( &headerStream, '?' );
			swrite( &headerStream, httpReqInfo->attribute, 
					httpReqInfo->attributeLen );
			sputc( &headerStream, '=' );
			encodeRFC1866( &headerStream, httpReqInfo->value, 
						   httpReqInfo->valueLen );
			}
		if( httpReqInfo->extraDataLen > 0 )
			{
			sputc( &headerStream, '&' );
			swrite( &headerStream, httpReqInfo->extraData, 
					httpReqInfo->extraDataLen );
			}
		}
	if( isHTTP10( stream ) )
		swrite( &headerStream, " HTTP/1.0\r\n", 11 );
	else
		{
		swrite( &headerStream, " HTTP/1.1\r\nHost: ", 17 );
		swrite( &headerStream, netStream->host, netStream->hostLen );
		swrite( &headerStream, "\r\n", 2 );
		if( netStream->nFlags & STREAM_NFLAG_LASTMSG )
			swrite( &headerStream, "Connection: close\r\n", 19 );
		}
	if( contentLength > 0 )
		{
		char lengthString[ 8 + 8 ];
		int lengthStringLength;

		swrite( &headerStream, "Content-Type: ", 14 );
		swrite( &headerStream, contentType, contentTypeLen );
		swrite( &headerStream, "\r\nContent-Length: ", 18 );
		lengthStringLength = sprintf_s( lengthString, 8, "%d", 
										contentLength );
		swrite( &headerStream, lengthString, lengthStringLength );
		swrite( &headerStream, "\r\nCache-Control: no-cache\r\n", 27 );
		}
	status = swrite( &headerStream, "\r\n", 2 );
	if( cryptStatusOK( status ) )
		headerLength = stell( &headerStream );
	sMemDisconnect( &headerStream );
	ENSURES( cryptStatusOK( status ) );
	return( sendHTTPData( stream, headerBuffer, headerLength, 
						  transportFlag ) );
	}

/* Write an HTTP response header */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int writeResponseHeader( INOUT STREAM *stream, 
								IN_BUFFER( contentTypeLen ) const char *contentType, 
								IN_LENGTH_SHORT const int contentTypeLen, 
								IN_LENGTH const int contentLength )
	{
	NET_STREAM_INFO *netStream = ( NET_STREAM_INFO * ) stream->netStreamInfo;
	STREAM headerStream;
	char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ], lengthString[ 8 + 8 ];
	int headerLength = DUMMY_INIT, lengthStringLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contentType, contentTypeLen ) );

	REQUIRES( contentTypeLen > 0 && contentTypeLen < MAX_INTLENGTH );
	REQUIRES( contentLength > 0 && contentLength < MAX_INTLENGTH );

	sMemOpen( &headerStream, headerBuffer, HTTP_LINEBUF_SIZE );
	if( isHTTP10( stream ) )
		swrite( &headerStream, "HTTP/1.0 200 OK\r\n", 17 );
	else
		{
		swrite( &headerStream, "HTTP/1.1 200 OK\r\n", 17 );
		if( netStream->nFlags & STREAM_NFLAG_LASTMSG )
			swrite( &headerStream, "Connection: close\r\n", 19 );
		}
	swrite( &headerStream, "Content-Type: ", 14 );
	swrite( &headerStream, contentType, contentTypeLen );
	swrite( &headerStream, "\r\nContent-Length: ", 18 );
	lengthStringLength = sprintf_s( lengthString, 8, "%d", 
									contentLength );
	swrite( &headerStream, lengthString, lengthStringLength );
	swrite( &headerStream, "\r\nCache-Control: no-cache\r\n", 27 );
	if( isHTTP10( stream ) )
		swrite( &headerStream, "Pragma: no-cache\r\n", 18 );
	status = swrite( &headerStream, "\r\n", 2 );
	if( cryptStatusOK( status ) )
		headerLength = stell( &headerStream );
	sMemDisconnect( &headerStream );
	ENSURES( cryptStatusOK( status ) );
	return( sendHTTPData( stream, headerBuffer, headerLength,
						  TRANSPORT_FLAG_NONE ) );
	}

/****************************************************************************
*																			*
*							HTTP Access Functions							*
*																			*
****************************************************************************/

/* Write data to an HTTP stream */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int writeFunction( INOUT STREAM *stream, 
						  IN_BUFFER( length ) const void *buffer, 
						  IN_LENGTH_FIXED( sizeof( HTTP_DATA_INFO ) ) \
							const int maxLength, 
						  OUT_LENGTH_Z int *length )
	{
	NET_STREAM_INFO *netStream = ( NET_STREAM_INFO * ) stream->netStreamInfo;
	HTTP_DATA_INFO *httpDataInfo = ( HTTP_DATA_INFO * ) buffer;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( buffer, maxLength ) );
	assert( isWritePtr( length, sizeof( int ) ) );
	
	REQUIRES( maxLength == sizeof( HTTP_DATA_INFO ) );

	/* Clear return value */
	*length = 0;

	/* Send the out-of-band HTTP header data to the client or server */
	if( netStream->nFlags & STREAM_NFLAG_ISSERVER )
		{
		/* If it's an error status response, send the translated error 
		   status and exit */
		if( cryptStatusError( httpDataInfo->reqStatus ) )
			{
			char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ];

			status = sendHTTPError( stream, headerBuffer, HTTP_LINEBUF_SIZE,
						( httpDataInfo->reqStatus == CRYPT_ERROR_NOTFOUND ) ? \
							404 : \
						( httpDataInfo->reqStatus == CRYPT_ERROR_PERMISSION ) ? \
							401 : 400 );
			if( cryptStatusError( status ) )
				return( status );
			*length = maxLength;

			return( CRYPT_OK );
			}

		status = writeResponseHeader( stream, httpDataInfo->contentType,
									  httpDataInfo->contentTypeLen,
									  httpDataInfo->bufSize );
		}
	else
		{
		REQUIRES( ( netStream->nFlags & STREAM_NFLAG_HTTPTUNNEL ) || \
				  httpDataInfo->contentTypeLen > 0 );
		REQUIRES( !( ( netStream->nFlags & STREAM_NFLAG_HTTPPROXY ) && 
					 ( netStream->nFlags & STREAM_NFLAG_HTTPTUNNEL ) ) );
		REQUIRES( netStream->host != NULL && netStream->hostLen > 0 );

		status = writeRequestHeader( stream, httpDataInfo->reqInfo, 
									 httpDataInfo->contentType,
									 httpDataInfo->contentTypeLen,
									 httpDataInfo->bufSize );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Send the payload data to the client/server */
	status = netStream->bufferedTransportWriteFunction( stream, 
							httpDataInfo->buffer, httpDataInfo->bufSize,
							&httpDataInfo->bytesTransferred, 
							TRANSPORT_FLAG_FLUSH );
	if( cryptStatusError( status ) )
		return( status );
	*length = maxLength;

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void setStreamLayerHTTPwrite( INOUT NET_STREAM_INFO *netStream )
	{
	/* Set the remaining access method pointers */
	netStream->writeFunction = writeFunction;
	}
#endif /* USE_HTTP */