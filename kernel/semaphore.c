/****************************************************************************
*																			*
*							Semaphores and Mutexes							*
*						Copyright Peter Gutmann 1997-2004					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "acl.h"
  #include "kernel.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "acl.h"
  #include "kernel.h"
#else
  #include "crypt.h"
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */

/* A pointer to the kernel data block */

static KERNEL_DATA *krnlData = NULL;

/****************************************************************************
*																			*
*							Init/Shutdown Functions							*
*																			*
****************************************************************************/

/* A template to initialise the semaphore table */

static const SEMAPHORE_INFO SEMAPHORE_INFO_TEMPLATE = \
				{ SEMAPHORE_STATE_UNINITED, 0, 0 };

/* Create and destroy the semaphores and mutexes.  Since mutexes usually 
   aren't scalar values and are declared and accessed via macros that 
   manipulate various fields, we have to handle a pile of them individually 
   rather than using an array of mutexes */

int initSemaphores( KERNEL_DATA *krnlDataPtr )
	{
	int i;

	assert( MUTEX_LAST == 4 );

	/* Set up the reference to the kernel data block */
	krnlData = krnlDataPtr;

	/* Clear the semaphore table */
	for( i = 0; i < SEMAPHORE_LAST; i++ )
		krnlData->semaphoreInfo[ i ] = SEMAPHORE_INFO_TEMPLATE;

	/* Initialize any data structures required to make the semaphore table
	   thread-safe */
	MUTEX_CREATE( semaphore );

	/* Initialize the mutexes */
	MUTEX_CREATE( mutex1 );
	MUTEX_CREATE( mutex2 );
	MUTEX_CREATE( mutex3 );

	return( CRYPT_OK );
	}

void endSemaphores( void )
	{
	/* Shut down the mutexes */
	MUTEX_DESTROY( mutex3 );
	MUTEX_DESTROY( mutex2 );
	MUTEX_DESTROY( mutex1 );

	/* Destroy any data structures required to make the semaphore table
	   thread-safe */
	MUTEX_DESTROY( semaphore );
	}

/****************************************************************************
*																			*
*							Semaphore Functions								*
*																			*
****************************************************************************/

/* Under multithreaded OSes, we often need to wait for certain events before
   we can continue (for example when asynchronously accessing system
   objects anything that depends on the object being available needs to
   wait for the access to complete) or handle mutual exclusion when accessing
   a shared resource.  The following functions abstract this handling,
   providing a lightweight semaphore mechanism via mutexes, which is used 
   before checking a system synchronisation object (mutexes usually don't
   require a kernel entry, while semaphores usually do).  The semaphore 
   function works a bit like the Win32 Enter/LeaveCriticalSection() 
   routines, which perform a quick check on a user-level lock and only call 
   the kernel-level handler if necessary (in most cases this isn't 
   necessary).  A useful side-effect is that since they work with 
   lightweight local locks instead of systemwide locking objects, they 
   aren't vulnerable to security problems where (for example) another 
   process can mess with a globally visible object handle.  This is 
   particularly problematic under Windows, where (for example) CreateMutex()
   can return a handle to an already-existing object of the same name rather
   than a newly-created object (there's no O_EXCL functionality).

   Semaphores are one-shots, so that once set and cleared they can't be
   reset.  This is handled by enforcing the following state transitions:

	Uninited -> Set | Clear
	Set -> Set | Clear
	Clear -> Clear

   The handling is complicated somewhat by the fact that on some systems the
   semaphore has to be explicitly deleted, but only the last thread to use it
   can safely delete it.  In order to handle this, we reference-count the
   semaphore and let the last thread out delete it.  This is handled by
   introducing an additional state preClear, which indicates that while the
   semaphore object is still present, the last thread out should delete it,
   bringing it to the true clear state */

void setSemaphore( const SEMAPHORE_TYPE semaphore,
				   const MUTEX_HANDLE object )
	{
	SEMAPHORE_INFO *semaphoreInfo;

	/* Make sure that the selected semaphore is valid */
	if( semaphore <= SEMAPHORE_NONE || semaphore >= SEMAPHORE_LAST )
		{
		assert( NOTREACHED );
		return;
		}
	semaphoreInfo = &krnlData->semaphoreInfo[ semaphore ];

	/* Lock the semaphore table, set the semaphore, and unlock it again */
	MUTEX_LOCK( semaphore );
	if( semaphoreInfo->state == SEMAPHORE_STATE_UNINITED )
		{
		/* The semaphore can only be set if it's currently in the uninited 
		   state */
		*semaphoreInfo = SEMAPHORE_INFO_TEMPLATE;
		semaphoreInfo->state = SEMAPHORE_STATE_SET;
		semaphoreInfo->object = object;
		}
	MUTEX_UNLOCK( semaphore );
	}

void clearSemaphore( const SEMAPHORE_TYPE semaphore )
	{
	SEMAPHORE_INFO *semaphoreInfo;

	/* Make sure that the selected semaphore is valid */
	if( semaphore <= SEMAPHORE_NONE || semaphore >= SEMAPHORE_LAST )
		{
		assert( NOTREACHED );
		return;
		}
	semaphoreInfo = &krnlData->semaphoreInfo[ semaphore ];

	/* Lock the semaphore table, clear the semaphore, and unlock it again */
	MUTEX_LOCK( semaphore );
	if( semaphoreInfo->state == SEMAPHORE_STATE_SET )
		{
		/* Precondition: The reference count is valid */
#if !( defined( __WINCE__ ) && _WIN32_WCE < 400 )
		PRE( semaphoreInfo[ semaphore ].refCount >= 0 );
#endif /* Fix for bug in PocketPC 2002 emulator with eVC++ 3.0 */

		/* If there are threads waiting on this semaphore, tell the last
		   thread out to turn out the lights */
		if( semaphoreInfo->refCount > 0 )
			semaphoreInfo->state = SEMAPHORE_STATE_PRECLEAR;
		else
			{
			/* No threads waiting on the semaphore, we can delete it */
			THREAD_CLOSE( semaphoreInfo->object );
			*semaphoreInfo = SEMAPHORE_INFO_TEMPLATE;
			}
		}
	MUTEX_UNLOCK( semaphore );
	}

/* Wait for a semaphore.  This occurs in two phases, first we extract the
   information that we need from the semaphore table, then we unlock it and 
   wait on the semaphore if necessary.  This is necessary because the wait 
   can take an indeterminate amount of time and we don't want to tie up the 
   other semaphores while this occurs.  Note that this type of waiting on 
   local (rather than system) semaphores where possible greatly improves
   performance, in some cases the wait on a signalled system semaphore can
   take several seconds whereas waiting on the local semaphore only takes a
   few ms.  Once the wait has completed, we update the semaphore state as
   per the longer description above */

void krnlWaitSemaphore( const SEMAPHORE_TYPE semaphore )
	{
	SEMAPHORE_INFO *semaphoreInfo;
	MUTEX_HANDLE object;
	BOOLEAN semaphoreSet = FALSE;

	/* Make sure that the selected semaphore is valid */
	if( semaphore <= SEMAPHORE_NONE || semaphore >= SEMAPHORE_LAST )
		{
		assert( NOTREACHED );
		return;
		}
	semaphoreInfo = &krnlData->semaphoreInfo[ semaphore ];

	/* Lock the semaphore table, extract the information we need, and unlock
	   it again */
	MUTEX_LOCK( semaphore );
	if( semaphoreInfo->state == SEMAPHORE_STATE_SET )
		{
		/* Precondition: The reference count is valid */
		PRE( semaphoreInfo->refCount >= 0 );

		/* The semaphore is set and not in use, extract the information we
		   require and mark is as being in use */
		object = semaphoreInfo->object;
		semaphoreInfo->refCount++;
		semaphoreSet = TRUE;
		}
	MUTEX_UNLOCK( semaphore );

	/* If the semaphore wasn't set or is in use, exit now */
	if( !semaphoreSet )
		return;

	/* Wait on the object */
	assert( memcmp( &object, &SEMAPHORE_INFO_TEMPLATE.object,
					sizeof( MUTEX_HANDLE ) ) );
	THREAD_WAIT( object );

	/* Lock the semaphore table, update the information, and unlock it
	   again */
	MUTEX_LOCK( semaphore );
	if( semaphoreInfo->state == SEMAPHORE_STATE_SET || \
		semaphoreInfo->state == SEMAPHORE_STATE_PRECLEAR )
		{
		/* The semaphore is still set, update the reference count */
		semaphoreInfo->refCount--;

		/* Inner precondition: The reference count is valid */
		PRE( semaphoreInfo->refCount >= 0 );

		/* If the object owner has signalled that it's done with the object
		   and the reference count has reached zero, we can delete it */
		if( semaphoreInfo->state == SEMAPHORE_STATE_PRECLEAR || \
			semaphoreInfo->refCount <= 0 )
			{
			/* No threads waiting on the semaphore, we can delete it */
			THREAD_CLOSE( object );
			*semaphoreInfo = SEMAPHORE_INFO_TEMPLATE;
			}
		}
	MUTEX_UNLOCK( semaphore );
	}

/****************************************************************************
*																			*
*								Mutex Functions								*
*																			*
****************************************************************************/

/* Enter and exit a mutex */

void krnlEnterMutex( const MUTEX_TYPE mutex )
	{
	/* Make sure that the selected mutex is valid */
	if( mutex <= MUTEX_NONE || mutex >= MUTEX_LAST )
		{
		assert( NOTREACHED );
		return;
		}

	switch( mutex )
		{
		case MUTEX_SESSIONCACHE:
			MUTEX_LOCK( mutex1 );
			break;

		case MUTEX_SOCKETPOOL:
			MUTEX_LOCK( mutex2 );
			break;

		case MUTEX_RANDOMPOLLING:
			MUTEX_LOCK( mutex3 );
			break;

		default:
			assert( NOTREACHED );
		}
	}

void krnlExitMutex( const MUTEX_TYPE mutex )
	{
	/* Make sure that the selected mutex is valid */
	if( mutex <= MUTEX_NONE || mutex >= MUTEX_LAST )
		{
		assert( NOTREACHED );
		return;
		}

	switch( mutex )
		{
		case MUTEX_SESSIONCACHE:
			MUTEX_UNLOCK( mutex1 );
			break;

		case MUTEX_SOCKETPOOL:
			MUTEX_UNLOCK( mutex2 );
			break;

		case MUTEX_RANDOMPOLLING:
			MUTEX_UNLOCK( mutex3 );
			break;

		default:
			assert( NOTREACHED );
		}
	}