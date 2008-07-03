/****************************************************************************
*																			*
*					cryptlib Internal Memory Management API					*
*						Copyright Peter Gutmann 1992-2007					*
*																			*
****************************************************************************/

#include <stdarg.h>
#if defined( INC_ALL )
  #include "crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Dynamic Buffer Management Routines					*
*																			*
****************************************************************************/

/* Dynamic buffer management functions.  When reading variable-length
   object data we can usually fit the data into a small fixed-length buffer 
   but occasionally we have to cope with larger data amounts that require a 
   dynamically-allocated buffer.  The following routines manage this 
   process, dynamically allocating and freeing a larger buffer if required */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int getDynData( INOUT DYNBUF *dynBuf, 
					   IN_HANDLE const CRYPT_HANDLE cryptHandle,
					   IN_MESSAGE const MESSAGE_TYPE message, 
					   IN_INT const int messageParam )
	{
	MESSAGE_DATA msgData;
	void *dataPtr = NULL;
	int status;

	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );

	REQUIRES( isHandleRangeValid( cryptHandle ) );
	REQUIRES( ( message == IMESSAGE_GETATTRIBUTE_S && \
				( isAttribute( messageParam ) || \
				  isInternalAttribute( messageParam ) ) ) || \
			  ( message == IMESSAGE_CRT_EXPORT && \
		 		messageParam == CRYPT_CERTFORMAT_CERTIFICATE ) );

	/* Clear return values.  Note that we don't use the usual memset() to 
	   clear the value since the structure contains the storage for the 
	   fixed-size portion of the buffer appended to it, and using memset() 
	   to clear that is just unnecessary overhead */
	dynBuf->data = dynBuf->dataBuffer;
	dynBuf->length = 0;

	/* Get the data from the object */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( cryptHandle, message, &msgData, messageParam );
	if( cryptStatusError( status ) )
		return( status );
	if( msgData.length > DYNBUF_SIZE )
		{
		/* The data is larger than the built-in buffer size, dynamically
		   allocate a larger buffer */
		if( ( dataPtr = clDynAlloc( "dynCreate", msgData.length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		msgData.data = dataPtr;
		status = krnlSendMessage( cryptHandle, message, &msgData,
								  messageParam );
		if( cryptStatusError( status ) )
			{
			clFree( "dynCreate", dataPtr );
			return( status );
			}
		dynBuf->data = dataPtr;
		}
	else
		{
		/* The data will fit into the built-in buffer, read it directly into
		   the buffer */
		msgData.data = dynBuf->data;
		status = krnlSendMessage( cryptHandle, message, &msgData,
								  messageParam );
		if( cryptStatusError( status ) )
			return( status );
		}
	dynBuf->length = msgData.length;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int dynCreate( OUT DYNBUF *dynBuf, 
			   IN_HANDLE const CRYPT_HANDLE cryptHandle,
			   IN_ATTRIBUTE const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );

	REQUIRES( isHandleRangeValid( cryptHandle ) );
	REQUIRES( isAttribute( attributeType ) || \
			  isInternalAttribute( attributeType ) );

	return( getDynData( dynBuf, cryptHandle, IMESSAGE_GETATTRIBUTE_S,
						attributeType ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int dynCreateCert( OUT DYNBUF *dynBuf, 
				   IN_HANDLE const CRYPT_HANDLE cryptHandle,
				   IN_ENUM( CRYPT_CERTFORMAT ) \
				   const CRYPT_CERTFORMAT_TYPE formatType )
	{
	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );

	REQUIRES( isHandleRangeValid( cryptHandle ) );
	REQUIRES( formatType == CRYPT_CERTFORMAT_CERTIFICATE );

	return( getDynData( dynBuf, cryptHandle, IMESSAGE_CRT_EXPORT, 
						formatType ) );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void dynDestroy( INOUT DYNBUF *dynBuf )
	{
	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );
	assert( isWritePtr( dynBuf->data, dynBuf->length ) );

	REQUIRES_V( dynBuf->length > 0 && dynBuf->length < MAX_INTLENGTH );

	zeroise( dynBuf->data, dynBuf->length );
	if( dynBuf->data != dynBuf->dataBuffer )
		clFree( "dynDestroy", dynBuf->data );
	}

/****************************************************************************
*																			*
*						Memory Pool Management Routines						*
*																			*
****************************************************************************/

/* Memory pool management functions.  When allocating many small blocks of
   memory, especially in resource-constrained systems, it's better if we pre-
   allocate a small memory pool ourselves and grab chunks of it as required,
   falling back to dynamically allocating memory later on if we exhaust the
   pool.  The following functions implement the custom memory pool
   management */

typedef struct {
	BUFFER( storageSize, storagePos ) 
	void *storage;					/* Memory pool */
	int storageSize, storagePos;	/* Current usage and total size of pool */
	} MEMPOOL_INFO;

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheck( const MEMPOOL_INFO *state )
	{
	/* Make sure that the overall pool size information is in order */
	if( state->storageSize < 64 || \
		state->storageSize >= MAX_INTLENGTH_SHORT )
		return( FALSE );

	/* Make sure that the pool allocation information is in order */
	if( state->storagePos < 0 || \
		state->storagePos >= MAX_INTLENGTH_SHORT || \
		state->storagePos > state->storageSize )
		return( FALSE );

	return( TRUE );
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void initMemPool( OUT void *statePtr, 
				  IN_BUFFER( memPoolSize ) void *memPool, 
				  IN_LENGTH_SHORT_MIN( 64 ) const int memPoolSize )
	{
	MEMPOOL_INFO *state = ( MEMPOOL_INFO * ) statePtr;

	assert( isWritePtr( state, sizeof( MEMPOOL_INFO ) ) );
	assert( isWritePtr( memPool, memPoolSize ) );

	REQUIRES_V( sizeof( MEMPOOL_STATE ) >= sizeof( MEMPOOL_INFO ) );
	REQUIRES_V( memPoolSize >= 64 && memPoolSize < MAX_INTLENGTH_SHORT );

	memset( state, 0, sizeof( MEMPOOL_INFO ) );
	state->storage = memPool;
	state->storageSize = memPoolSize;
	}

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
void *getMemPool( INOUT void *statePtr, IN_LENGTH_SHORT const int size )
	{
	MEMPOOL_INFO *state = ( MEMPOOL_INFO * ) statePtr;
	BYTE *allocPtr;
	const int allocSize = roundUp( size, sizeof( int ) );

	assert( isWritePtr( state, sizeof( MEMPOOL_INFO ) ) );
	assert( isWritePtr( state->storage, state->storageSize ) );

	REQUIRES_N( size > 0 && size < MAX_INTLENGTH_SHORT );
	REQUIRES_N( allocSize >= sizeof( int ) && \
				allocSize < MAX_INTLENGTH_SHORT );
	REQUIRES_N( sanityCheck( state ) );

	/* If we can't satisfy the request from the memory pool we have to
	   allocate the memory block dynamically */
	if( state->storagePos + allocSize > state->storageSize )
		return( clDynAlloc( "getMemPool", size ) );

	/* We can satisfy the request from the pool:

	 memPool
		|
		v		 <- size -->
		+-------+-----------+-------+
		|		|			|		|
		+-------+-----------+-------+
				^			^
				|			|
			storagePos	storagePos' */
	allocPtr = ( BYTE * ) state->storage + state->storagePos;
	state->storagePos += allocSize;
	ENSURES_N( sanityCheck( state ) );

	return( allocPtr );
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void freeMemPool( INOUT void *statePtr, IN void *memblock )
	{
	MEMPOOL_INFO *state = ( MEMPOOL_INFO * ) statePtr;

	assert( isWritePtr( state, sizeof( MEMPOOL_INFO ) ) );
	assert( isWritePtr( state->storage, state->storageSize ) );

	REQUIRES_V( sanityCheck( state ) );

	/* If the memory block to free lies within the pool, there's nothing to 
	   do */
	if( memblock >= state->storage && \
		memblock < ( void * ) ( ( BYTE * ) state->storage + \
										   state->storageSize ) )
		return;

	/* It's outside the pool and therefore dynamically allocated, free it */
	clFree( "freeMemPool", memblock );
	}

/****************************************************************************
*																			*
*							Debugging Malloc Support						*
*																			*
****************************************************************************/

/* Debugging malloc() that dumps memory usage diagnostics to stdout.  Note
   that these functions are only intended to be used during interactive 
   debugging sessions since they throw exceptions under error conditions 
   rather than returning an error status (the fact that they dump 
   diagnostics to stdout during operation should be a clue as to their
   intended status and usage) */

#ifdef CONFIG_DEBUG_MALLOC

#ifdef __WIN32__
  #include <direct.h>
#endif /* __WIN32__ */

#ifdef __WINCE__

CHECK_RETVAL_RANGE( -1, MAX_INTLENGTH_STRING ) STDC_NONNULL_ARG( ( 1 ) ) \
static int wcPrintf( FORMAT_STRING const char *format, ... )
	{
	wchar_t wcBuffer[ 1024 + 8 ];
	char buffer[ 1024 + 8 ];
	va_list argPtr;
	int length;

	va_start( argPtr, format );
	length = vsprintf_s( buffer, 1024, format, argPtr );
	va_end( argPtr );
	if( length < 1 )
		return( length );
	mbstowcs( wcBuffer, buffer, length + 1 );
	NKDbgPrintfW( wcBuffer );

	return( length );
	}

#define printf		wcPrintf

#endif /* __WINCE__ */

static int clAllocIndex = 0;

void *clAllocFn( const char *fileName, const char *fnName,
				 const int lineNo, size_t size )
	{
#ifdef CONFIG_MALLOCTEST
	static int mallocCount = 0, mallocFailCount = 0;
#endif /* CONFIG_MALLOCTEST */
	char buffer[ 512 + 8 ];
	BYTE *memPtr;
	int length;

	assert( fileName != NULL );
	assert( fnName != NULL );
	assert( lineNo > 0 );
	assert( size > 0 && size < MAX_INTLENGTH );

	/* Strip off the leading path components if we can to reduce the amount
	   of noise in the output */
#if defined( __WIN32__ ) || defined( __UNIX__ )
	if( getcwd( buffer, 512 ) != NULL )
		{
		const int pathLen = strlen( buffer ) + 1;	/* Leading path + '/' */

		assert( pathLen < strlen( fileName ) );
		fileName += pathLen;
		}
#endif /* __WIN32__ || __UNIX__ */

	length = printf( "ALLOC: %s:%s:%d", fileName, fnName, lineNo );
	while( length < 46 )
		{
		putchar( ' ' );
		length++;
		}
	printf( " %4d - %d bytes.\n", clAllocIndex, size );
#ifdef CONFIG_MALLOCTEST
	/* If we've exceeded the allocation count, make the next attempt to 
	   allocate memory fail */
	if( mallocCount >= mallocFailCount )
		{
		mallocCount = 0;
		mallocFailCount++;

		return( NULL );
		}
	mallocCount++;
#endif /* CONFIG_MALLOCTEST */
	if( ( memPtr = malloc( size + sizeof( LONG ) ) ) == NULL )
		return( NULL );
	mputLong( memPtr, clAllocIndex );	/* Implicit memPtr += sizeof( LONG ) */
	clAllocIndex++;
	return( memPtr );
	}

void clFreeFn( const char *fileName, const char *fnName,
			   const int lineNo, void *memblock )
	{
	char buffer[ 512 + 8 ];
	BYTE *memPtr = ( BYTE * ) memblock - sizeof( LONG );
	int index;

	assert( fileName != NULL );
	assert( fnName != NULL );
	assert( lineNo > 0 );

	/* Strip off the leading path components if we can to reduce the amount
	   of noise in the output */
#if defined( __WIN32__ ) || defined( __UNIX__ )
	if( getcwd( buffer, 512 ) != NULL )
		{
		const int pathLen = strlen( buffer ) + 1;	/* Leading path + '/' */

		assert( pathLen < strlen( fileName ) );
		fileName += pathLen;
		}
#endif /* __WIN32__ || __UNIX__ */

	index = mgetLong( memPtr );
	memPtr -= sizeof( LONG );		/* mgetLong() changes memPtr */
	length = printf( "FREE : %s:%s:%d", fileName, fnName, lineNo );
	while( length < 46 )
		{
		putchar( ' ' );
		length++;
		}
	printf( " %4d.\n", index );
	free( memPtr );
	}
#endif /* CONFIG_DEBUG_MALLOC */
