/****************************************************************************
*																			*
*							cryptlib Session Scoreboard						*
*						Copyright Peter Gutmann 1998-2008					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "ssl.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/ssl.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSL

/* The minimum and maximum permitted scoreboard size */

#define SCOREBOARD_MIN_SIZE		16
#define SCOREBOARD_MAX_SIZE		8192

/* The maximum size of any data value to be stored in the scoreboard.  
   Currently this is SSL_SECRET_SIZE, 48 bytes */

#define SCOREBOARD_DATA_SIZE	SSL_SECRET_SIZE

/* Scoreboard data and index information.  This is stored in separate memory 
   blocks because one is allocated in secure nonpageable storage and the 
   other isn't, with scoreboardIndex[] containing pointers into corresponding
   entries in scoreboardData[] */

typedef BYTE SCOREBOARD_DATA[ SCOREBOARD_DATA_SIZE ];
typedef struct {
	/* Identification information: The checksum and hash of the session ID */
	int checkValue;
	BUFFER_FIXED( HASH_DATA_SIZE ) \
	BYTE hashValue[ HASH_DATA_SIZE + 4 ];

	/* The scoreboard data, just a pointer into the secure SCOREBOARD_DATA 
	   memory.  The dataLength variable records how much data is actually
	   present out of the SCOREBOARD_DATA_SIZE bytes that are available for
	   use */
	BUFFER( SCOREBOARD_DATA_SIZE, dataLength ) \
	void *data;
	int dataLength;

	/* Miscellaneous information */
	time_t timeStamp;		/* Time entry was added to the scoreboard */
	int uniqueID;			/* Unique ID for this entry */
	} SCOREBOARD_INDEX;

/* The maximum amount of time that an entry is retained in the scoreboard,
   1 hour */

#define SCOREBOARD_TIMEOUT		3600

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Sanity-check the scoreboard state */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN sanityCheck( const SCOREBOARD_INFO *scoreboardInfo )
	{
	assert( isReadPtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );

	/* Make sure that the general state is in order */
	if( scoreboardInfo->size < SCOREBOARD_MIN_SIZE || \
		scoreboardInfo->size > SCOREBOARD_MAX_SIZE )
		return( FALSE );
	if( scoreboardInfo->lastEntry < 0 || \
		scoreboardInfo->lastEntry > scoreboardInfo->size )
		return( FALSE );
	if( scoreboardInfo->uniqueID < 0 )
		return( FALSE );

	return( TRUE );
	}

/* Clear a scoreboard entry */

STDC_NONNULL_ARG( ( 1 ) ) \
static void clearScoreboardEntry( SCOREBOARD_INDEX *scoreboardIndexEntry )
	{
	void *savedDataPtr = scoreboardIndexEntry->data;

	assert( isWritePtr( scoreboardIndexEntry, \
						sizeof( SCOREBOARD_INDEX ) ) );
	assert( isWritePtr( scoreboardIndexEntry->data, SCOREBOARD_DATA_SIZE ) );

	REQUIRES_V( scoreboardIndexEntry->data != NULL );

	zeroise( scoreboardIndexEntry->data, SCOREBOARD_DATA_SIZE );
	memset( scoreboardIndexEntry, 0, sizeof( SCOREBOARD_INDEX ) );
	scoreboardIndexEntry->data = savedDataPtr;
	scoreboardIndexEntry->dataLength = 0;
	}

/****************************************************************************
*																			*
*						Scoreboard Management Functions						*
*																			*
****************************************************************************/

/* Find an entry, returning its position in the scoreboard.  This function 
   currently uses a straightforward linear search with entries clustered 
   towards the start of the scoreboard.  Although this may seem somewhat 
   suboptimal, since cryptlib isn't running as a high-performance web server 
   the scoreboard will rarely contain more than a handful of entries (if 
   any).  In any case a quick scan through a small number of integers is 
   probably still faster than the complex in-memory database lookup schemes 
   used by many servers, and is also required to handle things like 
   scoreboard LRU management */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 5 ) ) \
static int findEntry( INOUT SCOREBOARD_INFO *scoreboardInfo,
					  IN_BUFFER( keyLength ) const void *key, 
					  IN_LENGTH_SHORT_MIN( 8 ) const int keyLength, 
					  const time_t currentTime, 
					  OUT_INT_SHORT_Z int *position )
	{
	SCOREBOARD_INDEX *scoreboardIndex = scoreboardInfo->index;
	BYTE hashValue[ HASH_DATA_SIZE + 8 ];
	BOOLEAN dataHashed = FALSE;
	time_t oldestTime = currentTime;
	const int checkValue = checksumData( key, keyLength );
	int nextFreeEntry = CRYPT_ERROR, lastUsedEntry = 0, oldestEntry = 0;
	int matchPosition = CRYPT_ERROR, i;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) && keyLength >= 8 );
	assert( isWritePtr( position, sizeof( int ) ) );
	assert( isWritePtr( scoreboardIndex,
						scoreboardInfo->size * sizeof( SCOREBOARD_INDEX ) ) );

	REQUIRES( keyLength >= 8 && keyLength < MAX_INTLENGTH_SHORT);
	REQUIRES( currentTime > MIN_TIME_VALUE );

	/* Clear return value */
	*position = CRYPT_ERROR;

	/* Scan the scoreboard expiring old entries, looking for a match 
	   (indicated by matchPosition), and keeping a record of the oldest 
	   entry (recorded by oldestEntry) in case we need to expire an entry to
	   make room for a new one */
	for( i = 0; i < scoreboardInfo->lastEntry && \
				i < FAILSAFE_ITERATIONS_MAX; i++ )
		{
		SCOREBOARD_INDEX *scoreboardIndexEntry = &scoreboardIndex[ i ];

		/* If this entry has expired, delete it */
		if( scoreboardIndexEntry->timeStamp + SCOREBOARD_TIMEOUT < currentTime )
			clearScoreboardEntry( scoreboardIndexEntry );

		/* Check for a free entry and the oldest non-free entry.  We could
		   perform an early-out once we find a free entry but this would
		   prevent any following expired entries from being deleted */
		if( scoreboardIndexEntry->timeStamp <= MIN_TIME_VALUE )
			{
			/* We've found a free entry, remember it for future use if
			   required and continue */
			if( nextFreeEntry == CRYPT_ERROR )
				nextFreeEntry = i;
			continue;
			}
		lastUsedEntry = i;
		if( scoreboardIndexEntry->timeStamp < oldestTime )
			{
			/* We've found an older entry than the current oldest entry,
			   remember it */
			oldestTime = scoreboardIndexEntry->timeStamp;
			oldestEntry = i;
			}

		/* Perform a quick check using a checksum of the name to weed out
		   most entries */
		if( matchPosition == CRYPT_ERROR && \
			scoreboardIndexEntry->checkValue == checkValue )
			{
			if( !dataHashed )
				{
				hashData( hashValue, HASH_DATA_SIZE, key, keyLength );
				dataHashed = TRUE;
				}
			if( !memcmp( scoreboardIndexEntry->hashValue, hashValue, 
						 HASH_DATA_SIZE ) )
				{
				/* Remember the match position.  We can't immediately exit 
				   at this point because we still need to look for the last 
				   used entry and potentually shrink the scoreboard-used 
				   size */
				matchPosition = i;
				}
			}
		}
	ENSURES( i < FAILSAFE_ITERATIONS_MAX );

	/* If the total number of entries has shrunk due to old entries expiring,
	   reduce the overall scoreboard-used size */
	if( lastUsedEntry + 1 < scoreboardInfo->lastEntry )
		scoreboardInfo->lastEntry = lastUsedEntry + 1;

	/* If we've found a match, we're done */
	if( matchPosition >= 0 )
		{
		*position = matchPosition;
		return( CRYPT_OK );
		}

	/* The entry wasn't found, return the location where we can add a new 
	   entry */
	if( nextFreeEntry >= 0 )
		{
		/* We've found a freed-up existing position (which will be before 
		   any remaining free entries), add the new entry there */
		*position = nextFreeEntry;
		}
	else
		{
		/* If there are still free positions in the scoreboard, use the next
		   available one */
		if( scoreboardInfo->lastEntry < scoreboardInfo->size )
			*position = scoreboardInfo->lastEntry;
		else
			{
			/* There are no free positions, overwrite the oldest entry */
			*position = oldestEntry;
			}
		}
	ENSURES( *position >= 0 && *position < scoreboardInfo->size );

	return( OK_SPECIAL );
	}

/* Add an entry to the scoreboard */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
static int addEntry( INOUT SCOREBOARD_INFO *scoreboardInfo, 
					 IN_BUFFER( keyLength ) const void *key, 
					 IN_LENGTH_SHORT_MIN( 8 ) const int keyLength, 
					 IN_BUFFER( valueLength ) const void *value, 
					 IN_LENGTH_SHORT const int valueLength,
					 OUT_INT_Z int *uniqueID )
	{
	SCOREBOARD_INDEX *scoreboardIndex = scoreboardInfo->index;
	SCOREBOARD_INDEX *scoreboardIndexEntry;
	const time_t currentTime = getTime();
	const int checkValue = checksumData( key, keyLength );
	int position, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) );
	assert( isReadPtr( value, valueLength ) );
	assert( isWritePtr( uniqueID, sizeof( int ) ) );
	assert( isWritePtr( scoreboardIndex,
						scoreboardInfo->size * sizeof( SCOREBOARD_INDEX ) ) );

	REQUIRES( keyLength >= 8 && keyLength < MAX_INTLENGTH_SHORT );
	REQUIRES( valueLength > 0 && valueLength <= SCOREBOARD_DATA_SIZE );
	REQUIRES( sanityCheck( scoreboardInfo ) );

	/* Clear return value */
	*uniqueID = CRYPT_ERROR;

	/* If there's something wrong with the time then we can't perform (time-
	   based) scoreboard management */
	if( currentTime <= MIN_TIME_VALUE )
		return( CRYPT_ERROR_NOTFOUND );

	/* Try and find this entry in the scoreboard */
	status = findEntry( scoreboardInfo, key, keyLength, currentTime, 
						&position );
	if( cryptStatusError( status ) && status != OK_SPECIAL )
		return( status );
	ENSURES( position >= 0 && position < scoreboardInfo->size );
	scoreboardIndexEntry = &scoreboardIndex[ position ];

	/* An OK status means that we've found an entry matching the supplied 
	   key, which means that something suspicious is going on, clear the 
	   existing entry and don't add the new one.  If we simply ignore the 
	   add attempt then it'll appear to the caller that we've added the new 
	   value when in fact we've retained the existing one.  If on the other 
	   hand we overwrite the old value with the new one then it'll allow an 
	   attacker to replace existing scoreboard contents with attacker-
	   controlled ones */
	if( cryptStatusOK( status ) )
		{
		clearScoreboardEntry( scoreboardIndexEntry );
		return( CRYPT_ERROR_NOTFOUND );
		}

	/* The OK_SPECIAL status means that the search found an unused entry 
	   position that we can use.  First we clear the entry (this should 
	   already be done, but we make it explicit here just in case) */
	clearScoreboardEntry( scoreboardIndexEntry );

	/* Copy across the key and value (Amicitiae nostrae memoriam spero 
	   sempiternam fore - Cicero) */
	scoreboardIndexEntry->checkValue = checkValue;
	hashData( scoreboardIndexEntry->hashValue, HASH_DATA_SIZE, 
			  key, keyLength );
	memcpy( scoreboardIndexEntry->data, value, valueLength );
	scoreboardIndexEntry->dataLength = valueLength;
	scoreboardIndexEntry->timeStamp = currentTime;
	*uniqueID = scoreboardIndexEntry->uniqueID = scoreboardInfo->uniqueID++;

	/* If we've used a new entry, update the position-used index */
	if( position >= scoreboardInfo->lastEntry )
		scoreboardInfo->lastEntry = position + 1;

	return( CRYPT_OK );
	}

/* Look up data in the scoreboard */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 6 ) ) \
static int lookupScoreboard( INOUT SCOREBOARD_INFO *scoreboardInfo,
							 IN_BUFFER( keyLength ) const void *key, 
							 IN_LENGTH_SHORT_MIN( 8 ) const int keyLength, 
							 OUT_BUFFER_OPT( valueMaxLength, *valueLength ) \
								void *value, 
							 IN_LENGTH_SHORT_Z const int valueMaxLength,
							 OUT_LENGTH_SHORT_Z int *valueLength,
							 OUT_INT_Z int *uniqueID )
	{
	SCOREBOARD_INDEX *scoreboardIndex = scoreboardInfo->index;
	SCOREBOARD_INDEX *scoreboardIndexEntry;
	const time_t currentTime = getTime();
	int position, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) );
	assert( ( value == NULL && valueMaxLength == 0 ) || \
			isWritePtr( value, valueMaxLength ) );
	assert( isWritePtr( valueLength, sizeof( int ) ) );
	assert( isWritePtr( uniqueID, sizeof( int ) ) );
	assert( isWritePtr( scoreboardIndex,
						scoreboardInfo->size * sizeof( SCOREBOARD_INDEX ) ) );

	REQUIRES( keyLength >= 8 && keyLength < MAX_INTLENGTH_SHORT );
	REQUIRES( ( value == NULL && valueMaxLength == 0 ) || \
			  ( value != NULL && \
				valueMaxLength > 0 && valueMaxLength <= SCOREBOARD_DATA_SIZE ) );
	REQUIRES( sanityCheck( scoreboardInfo ) );

	/* Clear return values */
	if( value != NULL )
		memset( value, 0, min( 16, valueMaxLength ) );
	*valueLength = 0;
	*uniqueID = CRYPT_ERROR;

	/* If there's something wrong with the time then we can't perform (time-
	   based) scoreboard management */
	if( currentTime <= MIN_TIME_VALUE )
		return( CRYPT_ERROR_NOTFOUND );

	/* Try and find this entry in the scoreboard */
	status = findEntry( scoreboardInfo, key, keyLength, currentTime, 
						&position );
	if( cryptStatusError( status ) )
		{
		/* An OK_SPECIAL status means that the search found an unused entry 
		   position but not a matching entry (this is used by addEntry()), 
		   anything else is an error */
		return( ( status == OK_SPECIAL ) ? CRYPT_ERROR_NOTFOUND : status );
		}
	ENSURES( position >= 0 && position < scoreboardInfo->size );
	scoreboardIndexEntry = &scoreboardIndex[ position ];

	/* We've found a match, if we're looking up an entry return its data and 
	   update the last-access date */
	if( value != NULL )
		{
		status = attributeCopyParams( value, valueMaxLength, valueLength,
									  scoreboardIndexEntry->data, 
									  scoreboardIndexEntry->dataLength );
		if( cryptStatusError( status ) )
			{
			DEBUG_DIAG(( "Couldn't copy scoreboard data to caller" ));
			assert( DEBUG_WARN );	/* Should never happen */
			return( status );
			}
		scoreboardIndexEntry->timeStamp = currentTime;
		}
	*uniqueID = scoreboardIndexEntry->uniqueID;
	ENSURES( sanityCheck( scoreboardInfo ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Scoreboard Access Functions						*
*																			*
****************************************************************************/

/* Add and delete entries to/from the scoreboard.  These are just wrappers
   for the local scoreboard-access function, for use by external code */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4, 6 ) ) \
int findScoreboardEntry( INOUT SCOREBOARD_INFO *scoreboardInfo,
						 IN_BUFFER( keyLength ) const void *key, 
						 IN_LENGTH_SHORT_MIN( 8 ) const int keyLength, 
						 OUT_BUFFER( maxValueLength, *valueLength ) void *value, 
						 IN_LENGTH_SHORT_MIN( 16 ) const int maxValueLength,
						 OUT_LENGTH_Z int *valueLength )
	{
	int uniqueID, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) );
	assert( isWritePtr( value, maxValueLength ) );
	assert( isWritePtr( valueLength, sizeof( int ) ) );

	REQUIRES( keyLength >= 8 && keyLength < MAX_INTLENGTH_SHORT );
	REQUIRES( maxValueLength >= 16 && maxValueLength < MAX_INTLENGTH_SHORT );

	/* Clear return values */
	memset( value, 0, min( 16, maxValueLength ) );
	*valueLength = 0;

	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return( status );
	status = lookupScoreboard( scoreboardInfo, key, keyLength, value, 
							   maxValueLength, valueLength, &uniqueID );
	krnlExitMutex( MUTEX_SCOREBOARD );
	return( cryptStatusError( status ) ? status : uniqueID );
	}

#if 0	/* 7/11/08 Unused by any other code */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int findScoreboardEntryID( INOUT SCOREBOARD_INFO *scoreboardInfo,
						   IN_BUFFER( keyLength ) const void *key, 
						   IN_LENGTH_SHORT_MIN( 8 ) const int keyLength )
	{
	int uniqueID, dummy, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) );

	REQUIRES( keyLength >= 8 && keyLength < MAX_INTLENGTH_SHORT );

	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return( status );
	uniqueID = lookupScoreboard( scoreboardInfo, key, keyLength, 
								 NULL, 0, &dummy );
	krnlExitMutex( MUTEX_SCOREBOARD );
	return( uniqueID );
	}
#endif /* 0 */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 4 ) ) \
int addScoreboardEntry( INOUT SCOREBOARD_INFO *scoreboardInfo,
						IN_BUFFER( keyLength ) const void *key, 
						IN_LENGTH_SHORT_MIN( 8 ) const int keyLength, 
						IN_BUFFER( valueLength ) const void *value, 
						IN_LENGTH_SHORT const int valueLength )
	{
	int uniqueID, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) );
	assert( isReadPtr( value, valueLength ) );

	REQUIRES( keyLength >= 8 && keyLength < MAX_INTLENGTH_SHORT );
	REQUIRES( valueLength > 0 && valueLength <= SCOREBOARD_DATA_SIZE );

	/* Add the entry to the scoreboard */
	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return( status );
	status = addEntry( scoreboardInfo, key, keyLength, 
						 ( void * ) value, valueLength, &uniqueID );
	krnlExitMutex( MUTEX_SCOREBOARD );
	return( cryptStatusError( status ) ? status : uniqueID );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void deleteScoreboardEntry( INOUT SCOREBOARD_INFO *scoreboardInfo, 
							IN_INT_Z const int uniqueID )
	{
	SCOREBOARD_INDEX *scoreboardIndex = scoreboardInfo->index;
	int lastUsedEntry = -1, i, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	
	REQUIRES_V( uniqueID >= 0 && \
				uniqueID < MAX_INTLENGTH );

	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return;

	/* Search the scoreboard for the entry with the given ID */
	for( i = 0; i < scoreboardInfo->lastEntry && \
				i < FAILSAFE_ITERATIONS_MAX; i++ )
		{
		SCOREBOARD_INDEX *scoreboardIndexEntry = &scoreboardIndex[ i ];

		/* If it's an empty entry (due to it having expired or being 
		   deleted), skip it and continue */
		if( scoreboardIndexEntry->timeStamp <= MIN_TIME_VALUE )
			continue;

		/* If we've found the entry that we're after, clear it and exit */
		if( scoreboardIndexEntry->uniqueID == uniqueID )
			{
			clearScoreboardEntry( scoreboardIndexEntry );
			continue;
			}

		/* Remember how far we got */
		lastUsedEntry = i;
		}
	ENSURES_V( i < FAILSAFE_ITERATIONS_MAX );

	/* Since we may have deleted entries at the end of the scoreboard, we 
	   can reduce the lastEntry value to the highest remaining entry */
	scoreboardInfo->lastEntry = lastUsedEntry + 1;

	krnlExitMutex( MUTEX_SCOREBOARD );
	}

/****************************************************************************
*																			*
*							Scoreboard Init/Shutdown						*
*																			*
****************************************************************************/

/* Perform a self-test of the scoreboard functions */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
static BOOLEAN selfTest( INOUT SCOREBOARD_INFO *scoreboardInfo )
	{
	BYTE buffer[ 16 + 8 ];
	int uniqueID1, uniqueID2, foundUniqueID, length;

	uniqueID1 = addScoreboardEntry( scoreboardInfo, "test key 1", 10,
									"test value 1", 12 );
	if( cryptStatusError( uniqueID1 ) )
		return( FALSE );
	uniqueID2 = addScoreboardEntry( scoreboardInfo, "test key 2", 10,
									"test value 2", 12 );
	if( cryptStatusError( uniqueID2 ) )
		return( FALSE );
	foundUniqueID = findScoreboardEntry( scoreboardInfo, "test key 1", 10,
										 buffer, 16, &length );
	if( cryptStatusError( foundUniqueID ) )
		return( FALSE );
	if( foundUniqueID != uniqueID1 || \
		length != 12 || memcmp( buffer, "test value 1", 12 ) )
		return( FALSE );
	deleteScoreboardEntry( scoreboardInfo, uniqueID1 );
	foundUniqueID = findScoreboardEntry( scoreboardInfo, "test key 1", 10,
										 buffer, 16, &length );
	if( foundUniqueID != CRYPT_ERROR_NOTFOUND )
		return( FALSE );
	deleteScoreboardEntry( scoreboardInfo, uniqueID2 );
	if( scoreboardInfo->lastEntry != 0 || \
		scoreboardInfo->uniqueID != 2 )
		return( FALSE );

	return( TRUE );
	}

/* Initialise and shut down the scoreboard */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initScoreboard( INOUT SCOREBOARD_INFO *scoreboardInfo, 
					IN_LENGTH_SHORT_MIN( SCOREBOARD_MIN_SIZE ) \
						const int scoreboardSize )
	{
	SCOREBOARD_INDEX *scoreboardIndex;
	SCOREBOARD_DATA *scoreboardData;
	int i, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	
	REQUIRES( scoreboardSize >= SCOREBOARD_MIN_SIZE && \
			  scoreboardSize <= SCOREBOARD_MAX_SIZE );

	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return( status );

	/* Initialise the scoreboard */
	memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );
	scoreboardInfo->uniqueID = 0;
	scoreboardInfo->lastEntry = 0;
	scoreboardInfo->size = scoreboardSize;

	/* Initialise the scoreboard data */
	if( ( scoreboardInfo->index = clAlloc( "initScoreboard", \
				scoreboardSize * sizeof( SCOREBOARD_INDEX ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	status = krnlMemalloc( &scoreboardInfo->data, \
						   scoreboardSize * sizeof( SCOREBOARD_DATA ) );
	if( cryptStatusError( status ) )
		{
		clFree( "initScoreboard", scoreboardInfo->index );
		memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );
		return( status );
		}
	scoreboardIndex = scoreboardInfo->index;
	scoreboardData = scoreboardInfo->data;
	memset( scoreboardIndex, 0, \
			scoreboardSize * sizeof( SCOREBOARD_INDEX ) );
	for( i = 0; i < scoreboardSize; i++ )
		{
		scoreboardIndex[ i ].data = &scoreboardData[ i ];
		scoreboardIndex[ i ].dataLength = 0;
		}
	memset( scoreboardInfo->data, 0, scoreboardSize * \
									 sizeof( SCOREBOARD_DATA ) );

	/* Make sure that everything's working as intended */
	if( !selfTest( scoreboardInfo ) )
		{
		krnlMemfree( ( void ** ) &scoreboardInfo->data );
		clFree( "initScoreboard", scoreboardInfo->index );
		memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );

		retIntError();
		}

	krnlExitMutex( MUTEX_SCOREBOARD );
	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void endScoreboard( INOUT SCOREBOARD_INFO *scoreboardInfo )
	{
	int status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );

	/* Shut down the scoreboard.  We acquire the mutex while we're doing 
	   this to ensure that any threads still using it have exited before we 
	   destroy it.  Exactly what to do if we can't acquire the mutex is a 
	   bit complicated because failing to acquire the mutex is a special-
	   case exception condition so it's not even possible to plan for this 
	   since it's uncertain under which conditions (if ever) it would 
	   occur.  For now we play it by the book and don't do anything if we 
	   can't acquire the mutex, which is at least consistent */
	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	ENSURES_V( cryptStatusOK( status ) );

	/* Clear and free the scoreboard */
	krnlMemfree( ( void ** ) &scoreboardInfo->data );
	zeroise( scoreboardInfo->index, \
			 scoreboardInfo->size * sizeof( SCOREBOARD_INDEX ) );
	clFree( "endScoreboard", scoreboardInfo->index );
	memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );

	krnlExitMutex( MUTEX_SCOREBOARD );
	}
#endif /* USE_SSL */
