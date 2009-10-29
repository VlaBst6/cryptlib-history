/****************************************************************************
*																			*
*								Kernel Initialisation						*
*						Copyright Peter Gutmann 1997-2005					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "acl.h"
  #include "kernel.h"
#else
  #include "crypt.h"
  #include "kernel/acl.h"
  #include "kernel/kernel.h"
#endif /* Compiler-specific includes */

/* The kernel data block.  All other kernel modules maintain a pointer to
   this data */

static KERNEL_DATA krnlDataBlock = { 0 }, *krnlData;

/****************************************************************************
*																			*
*								Thread Functions							*
*																			*
****************************************************************************/

/* Execute a function in a background thread.  This takes a pointer to the
   function to execute in the background thread, a set of parameters to pass
   to the function, and an optional semaphore ID to set once the thread is
   started.  A function is run via a background thread as follows:

	void threadFunction( const THREAD_FUNCTION_PARAMS *threadParams )
		{
		}

	initThreadParams( &threadParams, ptrParam, intParam );
	krnlDispatchThread( threadFunction, &threadParams, SEMAPHORE_ID ) */

#ifdef USE_THREADS

/* The function that's run as a thread.  This calls the user-supplied
   service function with the user-supplied parameters */

THREADFUNC_DEFINE( threadServiceFunction, threadInfoPtr )
	{
	const THREAD_INFO *threadInfo = ( THREAD_INFO * ) threadInfoPtr;
	ORIGINAL_INT_VAR( intParam, threadInfo->threadParams.intParam );
	ORIGINAL_INT_VAR( semaphore, threadInfo->semaphore );

	PRE( threadServiceFunction != NULL );
	PRE( isReadPtr( threadInfoPtr, sizeof( THREAD_INFO ) ) );

	/* We're running as a thread, call the thread service function and clear
	   the associated semaphore (if there is one) when we're done.  We check
	   to make sure that the thread params are unchanged to catch erroneous
	   use of stack-based storage for the parameter data */
	threadInfo->threadFunction( &threadInfo->threadParams );
	assert( threadInfo->threadParams.intParam == ORIGINAL_VALUE( intParam ) );
	assert( threadInfo->semaphore == ORIGINAL_VALUE( semaphore ) );
	if( threadInfo->semaphore != SEMAPHORE_NONE )
		clearSemaphore( threadInfo->semaphore );
	THREAD_EXIT( threadInfo->syncHandle );
	}

/* Dispatch a function in a background thread.  If the threadParams value
   is NULL we use the kernel's thread data storage, otherwise we use the
   caller-provided storage */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int krnlDispatchThread( THREAD_FUNCTION threadFunction,
						THREAD_STATE threadState, void *ptrParam, 
						const int intParam, const SEMAPHORE_TYPE semaphore )
	{
	THREAD_INFO *threadInfo = \
			( threadState == NULL ) ? &krnlData->threadInfo : \
									  ( THREAD_INFO * ) threadState;
	THREAD_HANDLE dummy;
	int status;

	/* Preconditions: The parameters appear valid, and it's a valid
	   semaphore (SEMAPHORE_NONE is valid since it indicates that the caller
	   doesn't want a semaphore set) */
	PRE( sizeof( THREAD_STATE ) >= sizeof( THREAD_INFO ) );
	PRE( threadFunction != NULL );
	PRE( threadState == NULL || \
		 isWritePtr( threadState, sizeof( THREAD_STATE ) ) );
	PRE( semaphore >= SEMAPHORE_NONE && semaphore < SEMAPHORE_LAST );

	/* Initialise the thread parameters */
	memset( threadInfo, 0, sizeof( THREAD_INFO ) );
	threadInfo->threadFunction = threadFunction;
	threadInfo->threadParams.ptrParam = ptrParam;
	threadInfo->threadParams.intParam = intParam;
	threadInfo->semaphore = semaphore;

	/* Fire up the thread and set the associated semaphore if required.
	   There's no problem with the thread exiting before we set the
	   semaphore because it's a one-shot, so if the thread gets there first
	   the attempt to set the semaphore below is ignored */
	THREAD_CREATE( threadServiceFunction, threadInfo, dummy,
				   threadInfo->syncHandle, status );
	if( cryptStatusOK( status ) && semaphore != SEMAPHORE_NONE )
		setSemaphore( semaphore, threadInfo->syncHandle );
	return( status );
	}
#endif /* USE_THREADS */

/****************************************************************************
*																			*
*							Pre-initialisation Functions					*
*																			*
****************************************************************************/

/* Correct initialisation of the kernel is handled by having the object
   management functions check the state of the initialisation flag before
   they do anything and returning CRYPT_ERROR_NOTINITED if cryptlib hasn't
   been initialised.  Since everything in cryptlib depends on the creation
   of objects, any attempt to use cryptlib without it being properly
   initialised are caught.

   Reading the initialisation flag presents something of a chicken-and-egg
   problem since the read should be protected by the intialisation mutex,
   but we can't try and grab it unless the mutex has been initialised.  If
   we just read the flag directly and rely on the object map mutex to
   protect access we run into a potential race condition on shutdown:

	thread1								thread2

	inited = T							read inited = T
	inited = F, destroy objects
										lock objects, die

   The usual way to avoid this is to perform an interlocked mutex lock, but
   this isn't possible here since the initialisation mutex may not be
   initialised.

   If possible we use dynamic initialisation of the kernel to resolve this,
   taking advantage of stubs that the compiler inserts into the code to
   perform initialisation functions when cryptlib is loaded.  If the
   compiler doesn't support this, we have to use static initialisation.
   This has a slight potential race condition if two threads call the init
   function at the same time, but in practice the only thing that can happen
   is that the initialisation mutex gets initialised twice, leading to a
   small resource leak when cryptlib shuts down */

#if defined( __WIN32__ ) || defined( __WINCE__ )
  /* Windows supports dynamic initialisation by allowing the init/shutdown
	 functions to be called from DllMain(), however if we're building a
	 static library there won't be a DllMain() so we have to do a static
	 init */
  #ifdef STATIC_LIB
	#define STATIC_INIT
  #endif /* STATIC_LIB */
#elif defined( __GNUC__ ) && defined( __PIC__ ) && defined( USE_THREADS )
  /* If we're being built as a shared library with gcc, we can use
	 constructor and destructor functions to automatically perform pre-init
	 and post-shutdown functions in a thread-safe manner.  By telling gcc
	 to put the preInit() and postShutdown() functions in the __CTOR_LIST__
	 and __DTOR_LIST__, they're called automatically before dlopen/dlclose
	 return */
  void preInit( void ) __attribute__ ((constructor));
  void postShutdown( void ) __attribute__ ((destructor));
#elif defined( __SUNPRO_C ) && ( __SUNPRO_C >= 0x570 )
  /* The value of __SUNPRO_C bears no relation whatsoever to the actual 
	 version number of the compiler and even Sun's docs give different 
	 values in different places for the same compiler version, but 0x570 
	 seems to work */
  #pragma init ( preInit )
  #pragma fini ( postShutdown )
#elif defined( __PALMOS__ )
  /* PalmOS supports dynamic initialisation by allowing the init/shutdown
	 functions to be called from PilotMain */
#else
  #define STATIC_INIT
#endif /* Systems not supporting dynamic initialisation */

/* Before we can begin and end the initialisation process, we need to
   initialise the initialisation lock.  This gets a bit complex, and is
   handled in the following order of preference:

	A. Systems where the OS contacts a module to tell it to initialise itself
	   before it's called directly for the first time.

	B. Systems where statically initialising the lock to an all-zero value is
	   equivalent to intialising it at runtime.

	C. Systems where the lock must be statically initialised at runtime.

   A and B are thread-safe, C isn't thread-safe but unlikely to be a problem
   except in highly unusual situations (two different threads entering
   krnlBeginInit() at the same time) and not something that we can fix
   without OS support.

   To handle this pre-initialisation, we provide the following functions for
   use with case A, statically initialise the lock to handle case B, and
   initialise it if required in krnlBeginInit() to handle case C */

#ifndef STATIC_INIT

void preInit( void )
	{
	int status;

	krnlData = &krnlDataBlock;
	memset( krnlData, 0, sizeof( KERNEL_DATA ) );
	MUTEX_CREATE( initialisation, status );
	if( cryptStatusError( status ) )
		{
		/* Error handling at this point gets a bit complicated since these 
		   functions are called before the main() is called or dlopen()
		   returns, so there's no way to react to an error status.  Even
		   the debug exception thrown by retIntError() may be dangerous,
		   but it's only used in the debug version when (presumably) some
		   sort of debugging support is present.  In any case if the mutex
		   create fails at this point (a) something is seriously wrong and 
		   (b) presumably successive mutex creations will fail as well, at
		   which point they can be detected */
		retIntError_Void();
		}
	}

void postShutdown( void )
	{
	MUTEX_DESTROY( initialisation );
	memset( krnlData, 0, sizeof( KERNEL_DATA ) );
	}
#endif /* !STATIC_INIT */

/****************************************************************************
*																			*
*							Initialisation Functions						*
*																			*
****************************************************************************/

/* Begin and complete the kernel initialisation, leaving the initialisation
   mutex locked between the two calls to allow external initialisation of
   further, non-kernel-related items */

CHECK_RETVAL \
int krnlBeginInit( void )
	{
	int status;

#ifdef STATIC_INIT
	/* If the krnlData hasn't been set up yet, set it up now */
	if( krnlDataBlock.initLevel <= INIT_LEVEL_NONE )
		{
		/* We're starting up, set up the initialisation lock */
		krnlData = &krnlDataBlock;
		memset( krnlData, 0, sizeof( KERNEL_DATA ) );
		MUTEX_CREATE( initialisation, status );
		ENSURES( cryptStatusOK( status ) );
		}
#endif /* STATIC_INIT */

	/* Lock the initialisation mutex to make sure that other threads don't
	   try to access it */
	MUTEX_LOCK( initialisation );

	/* If we're already initialised, don't to anything */
	if( krnlData->initLevel > INIT_LEVEL_NONE )
		{
		MUTEX_UNLOCK( initialisation );
		return( CRYPT_ERROR_INITED );
		}

#ifndef USE_EMBEDDED_OS
	/* If the time is screwed up we can't safely do much since so many
	   protocols and operations depend on it, however since embedded 
	   systems may not have RTCs or if they have them they're inevitably 
	   not set right, we don't perform this sanity-check if it's an
	   embedded build */
	if( getTime() <= MIN_TIME_VALUE )
		{
		MUTEX_UNLOCK( initialisation );
		DEBUG_PRINT(( "System time is severely messed up, cannot continue "
					  "without a correctly set system clock" ));
		retIntError();
		}
#endif /* USE_EMBEDDED_OS */

	/* Initialise the ephemeral portions of the kernel data block.  Since
	   the shutdown level value is non-ephemeral (it has to persist across
	   shutdowns to handle threads that may still be active inside cryptlib
	   when a shutdown occurs), we have to clear this explicitly */
	CLEAR_KERNEL_DATA();
	krnlData->shutdownLevel = SHUTDOWN_LEVEL_NONE;

	/* Initialise all of the kernel modules.  Except for the allocation of
	   the kernel object table this is all straight static initialistion
	   and self-checking, so we should never fail at this stage */
	status = initAllocation( krnlData );
	if( cryptStatusOK( status ) )
		status = initAttributeACL( krnlData );
	if( cryptStatusOK( status ) )
		status = initCertMgmtACL( krnlData );
	if( cryptStatusOK( status ) )
		status = initInternalMsgs( krnlData );
	if( cryptStatusOK( status ) )
		status = initKeymgmtACL( krnlData );
	if( cryptStatusOK( status ) )
		status = initMechanismACL( krnlData );
	if( cryptStatusOK( status ) )
		status = initMessageACL( krnlData );
	if( cryptStatusOK( status ) )
		status = initObjects( krnlData );
	if( cryptStatusOK( status ) )
		status = initObjectAltAccess( krnlData );
	if( cryptStatusOK( status ) )
		status = initSemaphores( krnlData );
	if( cryptStatusOK( status ) )
		status = initSendMessage( krnlData );
	if( cryptStatusError( status ) )
		{
		MUTEX_UNLOCK( initialisation );
		retIntError();
		}

	/* The kernel data block has been initialised */
	krnlData->initLevel = INIT_LEVEL_KRNLDATA;

	return( TRUE );
	}

void krnlCompleteInit( void )
	{
	/* We've completed the initialisation process */
	krnlData->initLevel = INIT_LEVEL_FULL;

	MUTEX_UNLOCK( initialisation );
	}

/* Begin and complete the kernel shutdown, leaving the initialisation
   mutex locked between the two calls to allow external shutdown of
   further, non-kernel-related items.  The shutdown proceeds as follows:

	lock initialisation mutex;
	signal internal worker threads (async.init, randomness poll)
		to exit (shutdownLevel = SHUTDOWN_LEVEL_THREADS);
	signal all non-destroy messages to fail
		(shutdownLevel = SHUTDOWN_LEVEL_MESSAGES in destroyObjects());
	destroy objects (via destroyObjects());
	shut down kernel modules;
	shut down kernel mechanisms (semaphores, messages)
		(shutdownLevel = SHUTDOWN_LEVEL_MUTEXES);
	clear kernel data; */

CHECK_RETVAL \
int krnlBeginShutdown( void )
	{
	/* Lock the initialisation mutex to make sure that other threads don't
	   try to access it */
	MUTEX_LOCK( initialisation );

	/* We can only begin a shutdown if we're fully initialised */
	PRE( krnlData->initLevel == INIT_LEVEL_FULL );

	/* If we're already shut down, don't to anything */
	if( krnlData->initLevel <= INIT_LEVEL_NONE )
		{
		MUTEX_UNLOCK( initialisation );
		return( CRYPT_ERROR_NOTINITED );
		}
	krnlData->initLevel = INIT_LEVEL_KRNLDATA;

	/* Signal all remaining internal threads to exit (dum differtur, vita 
	   transcurrit) */
	krnlData->shutdownLevel = SHUTDOWN_LEVEL_THREADS;

	return( CRYPT_OK );
	}

int krnlCompleteShutdown( void )
	{
#if 0	/* The object destruction has to be performed between two phases of
		   the external shutdown, so we can't currently do it here */
	destroyObjects();
#endif /* 0 */

	/* Once the kernel objects have been destroyed, we're in the closing-down
	   state in which no more messages are processed.  There are a few 
	   special-case situations such as a shutdown that occurs because of a
	   failure to initialise that we also need to handle */
	PRE( ( krnlData->initLevel == INIT_LEVEL_KRNLDATA && \
		   krnlData->shutdownLevel == SHUTDOWN_LEVEL_NONE ) || \
		 ( krnlData->initLevel == INIT_LEVEL_KRNLDATA && \
		   krnlData->shutdownLevel == SHUTDOWN_LEVEL_MESSAGES ) || \
		 ( krnlData->initLevel == INIT_LEVEL_FULL && \
		   krnlData->shutdownLevel >= SHUTDOWN_LEVEL_MESSAGES ) );

	/* Shut down all of the kernel modules */
	endAllocation();
	endAttributeACL();
	endCertMgmtACL();
	endInternalMsgs();
	endKeymgmtACL();
	endMechanismACL();
	endMessageACL();
	endObjects();
	endObjectAltAccess();
	endSemaphores();
	endSendMessage();

	/* At this point all kernel services have been shut down */
	POST( krnlData->shutdownLevel >= SHUTDOWN_LEVEL_MUTEXES );

	/* Turn off the lights on the way out.  Note that the kernel data-
	   clearing operation leaves the shutdown level set to handle any
	   threads that may still be active */
	CLEAR_KERNEL_DATA();
	krnlData->shutdownLevel = SHUTDOWN_LEVEL_ALL;
	MUTEX_UNLOCK( initialisation );

#ifdef STATIC_INIT
	/* We're shutting down, destroy the initialisation lock */
	MUTEX_DESTROY( initialisation );
	memset( krnlData, 0, sizeof( KERNEL_DATA ) );
#endif /* STATIC_INIT */

	return( CRYPT_OK );
	}

/* Indicate to a cryptlib-internal worker thread that the kernel is shutting
   down and the thread should exit as quickly as possible.  We don't protect
   this check with a mutex since it can be called after the kernel mutexes
   have been destroyed.  This lack of mutex protection for the flag isn't a
   serious problem, it's checked at regular intervals by worker threads so
   if the thread misses the flag update it'll bve caught at the next check */

CHECK_RETVAL_BOOL \
BOOLEAN krnlIsExiting( void )
	{
	return( krnlData->shutdownLevel >= SHUTDOWN_LEVEL_THREADS );
	}

/****************************************************************************
*																			*
*							Extended Self-test Functions					*
*																			*
****************************************************************************/

/* Self-test code for several general crypto algorithms that are used
   internally all over cryptlib: MD5, SHA-1, and 3DES (and by extension
   DES) */

#if defined( INC_ALL )
  #include "capabil.h"
#else
  #include "device/capabil.h"
#endif /* Compiler-specific includes */

CHECK_RETVAL_BOOL \
static BOOLEAN testGeneralAlgorithms( void )
	{
	const CAPABILITY_INFO *capabilityInfo;
	int status;

	/* Test the MD5 functionality */
#ifdef USE_MD5
	capabilityInfo = getMD5Capability();
	status = capabilityInfo->selfTestFunction();
	if( cryptStatusError( status ) )
		return( FALSE );
#endif /* USE_MD5 */

	/* Test the SHA-1 functionality */
	capabilityInfo = getSHA1Capability();
	status = capabilityInfo->selfTestFunction();
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Test the 3DES (and DES) functionality */
	capabilityInfo = get3DESCapability();
	status = capabilityInfo->selfTestFunction();
	if( cryptStatusError( status ) )
		return( FALSE );

	return( TRUE );
	}

/* Test the kernel mechanisms to make sure that everything's working as
   expected.  This performs the following tests:

   General:

	Object creation.

   Access checks:

	Inability to access internal object or attribute via external message.
	Inability to perform an internal-only action externally, ability to
		perform an internal-only action internally

   Attribute checks:

	Attribute range checking for numeric, string, boolean, and time
		attributes.
	Inability to write a read-only attribute, read a write-only attribute,
		or delete a non-deletable attribute.

   Object state checks:

	Ability to perform standard operation on object, ability to transition a
		state = low object to state = high.
	Inability to perform state = high operation on state = low object,
		inability to perform state = low operation on state = high object.

   Object property checks:

	Ability to use an object with a finite usage count, inability to
		increment the count, ability to decrement the count, inability to
		exceed the usage count.
	Ability to lock an object, inability to change security parameters once
		it's locked */

CHECK_RETVAL_BOOL \
static BOOLEAN checkNumericRange( IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	int value;

	REQUIRES_B( isHandleRangeValid( iCryptContext ) );

	/* Verify kernel range checking of numeric values */
	value = -10;		/* Below (negative) */
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
	value = 0;			/* Lower bound fencepost error */
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
	value = 1;			/* Lower bound */
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_OK )
		return( FALSE );
	value = 10000;		/* Mid-range */
	krnlSendMessage( iCryptContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_OK )
		return( FALSE );
	value = 20000;		/* Upper bound */
	krnlSendMessage( iCryptContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_OK )
		return( FALSE );
	value = 20001;		/* Upper bound fencepost error */
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
	value = 32767;		/* High */
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CTXINFO_KEYING_ITERATIONS ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );

	return( TRUE );
	}

CHECK_RETVAL_BOOL \
static BOOLEAN checkStringRange( IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	MESSAGE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_HASHSIZE + 1 + 8 ];

	REQUIRES_B( isHandleRangeValid( iCryptContext ) );

	/* Verify kernel range checking of string values.  We have to disable 
	   the more outrageous out-of-bounds values in the debug version since 
	   they'll cause the debug kernel to throw an exception if it sees 
	   them */
	memset( buffer, '*', CRYPT_MAX_HASHSIZE + 1 );
#ifdef NDEBUG
	/* Below (negative) */
	setMessageData( &msgData, buffer, -10 );
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
#endif /* NDEBUG */
	/* Lower bound fencepost error */
	setMessageData( &msgData, buffer, 7 );
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
	/* Lower bound */
	setMessageData( &msgData, buffer, 8 );
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_OK )
		return( FALSE );
	/* Mid-range */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE / 2 );
	krnlSendMessage( iCryptContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_KEYING_SALT );
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_OK )
		return( FALSE );
	/* Upper bound */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE );
	krnlSendMessage( iCryptContext, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CTXINFO_KEYING_SALT );
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_OK )
		return( FALSE );
	/* Upper bound fencepost error */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE + 1 );
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
#ifdef NDEBUG
	/* High */
	setMessageData( &msgData, buffer, 32767 );
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEYING_SALT ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
#endif /* NDEBUG */

	return( TRUE );
	}

CHECK_RETVAL_BOOL \
static BOOLEAN checkUsageCount( IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	BYTE buffer[ 16 + 8 ];
	int value;

	REQUIRES_B( isHandleRangeValid( iCryptContext ) );

	/* Verify the ability to use an object with a finite usage count, the
	   inability to increment the count, the ability to decrement the count,
	   and the inability to exceed the usage count */
	value = 10;
	memset( buffer, 0, 16 );
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_PROPERTY_USAGECOUNT ) != CRYPT_OK )
		return( FALSE );
	if( krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT,
						 buffer, 8 ) != CRYPT_OK )
		return( FALSE );
	value = 20;
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_PROPERTY_USAGECOUNT ) != CRYPT_ERROR_PERMISSION )
		return( FALSE );
	value = 1;
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_PROPERTY_USAGECOUNT ) != CRYPT_OK )
		return( FALSE );
	if( krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT,
						 buffer, 8 ) != CRYPT_OK || \
		krnlSendMessage( iCryptContext, IMESSAGE_CTX_ENCRYPT,
						 buffer, 8 ) != CRYPT_ERROR_PERMISSION )
		return( FALSE );

	return( TRUE );
	}

CHECK_RETVAL_BOOL \
static BOOLEAN checkLocking( IN_HANDLE const CRYPT_CONTEXT iCryptContext )
	{
	int value;

	REQUIRES_B( isHandleRangeValid( iCryptContext ) );

	/* Verify the ability to lock an object and the inability to change
	   security parameters once it's locked */
	value = 5;
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_PROPERTY_FORWARDCOUNT ) != CRYPT_OK || \
		krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_TRUE,
						 CRYPT_PROPERTY_HIGHSECURITY ) != CRYPT_OK )
		return( FALSE );
	if( krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, &value,
						 CRYPT_PROPERTY_LOCKED ) != CRYPT_OK || \
		value != TRUE || \
		krnlSendMessage( iCryptContext, IMESSAGE_GETATTRIBUTE, &value,
						 CRYPT_PROPERTY_FORWARDCOUNT ) != CRYPT_ERROR_PERMISSION )
		{
		/* Object should be locked, forwardcount should be inaccessible */
		return( FALSE );
		}
	value = 1;
	if( krnlSendMessage( iCryptContext, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_PROPERTY_FORWARDCOUNT ) != CRYPT_ERROR_PERMISSION )
		{
		/* Security parameters shouldn't be writeable */
		return( FALSE );
		}

	return( TRUE );
	}

#ifdef USE_CERTIFICATES

CHECK_RETVAL_BOOL \
static BOOLEAN checkBooleanRange( IN_HANDLE const CRYPT_CONTEXT iCryptCertificate )
	{
	int value;

	REQUIRES_B( isHandleRangeValid( iCryptCertificate ) );

	/* Verify functioning of the kernel range checking, phase 3: Boolean
	   values.  Any value should be OK, with conversion to TRUE/FALSE */
	value = 0;		/* FALSE */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK )
		return( FALSE );
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_GETATTRIBUTE, &value,
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK || \
		value != FALSE )
		return( FALSE );
	value = 1;		/* TRUE */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK )
		return( FALSE );
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_GETATTRIBUTE, &value,
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK || \
		value != TRUE )
		return( FALSE );
	value = 10000;	/* Positive true-equivalent */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK )
		return( FALSE );
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_GETATTRIBUTE, &value,
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK || \
		value != TRUE )
		return( FALSE );
	value = -1;		/* Negative true-equivalent */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK )
		return( FALSE );
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_GETATTRIBUTE, &value,
						 CRYPT_CERTINFO_SELFSIGNED ) != CRYPT_OK || \
		value != TRUE )
		return( FALSE );

	return( TRUE );
	}

CHECK_RETVAL_BOOL \
static BOOLEAN checkTimeRange( IN_HANDLE const CRYPT_CONTEXT iCryptCertificate )
	{
	MESSAGE_DATA msgData;
	time_t timeVal;

	REQUIRES_B( isHandleRangeValid( iCryptCertificate ) );

	/* Verify kernel range checking of time values.  Any value above the 
	   initial cutoff date should be OK */
	setMessageData( &msgData, &timeVal, sizeof( time_t ) );
	timeVal = 10;					/* Below */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CERTINFO_VALIDFROM ) != CRYPT_ARGERROR_STR1 )
		return( FALSE );
	timeVal = MIN_TIME_VALUE;		/* Lower bound fencepost error */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CERTINFO_VALIDFROM ) != CRYPT_ARGERROR_STR1 )
		return( FALSE );
	timeVal = MIN_TIME_VALUE + 1;	/* Lower bound */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CERTINFO_VALIDFROM ) != CRYPT_OK )
		return( FALSE );
	timeVal = roundUp( timeVal, 0x10000000L );	/* Mid-range */
	krnlSendMessage( iCryptCertificate, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CERTINFO_VALIDFROM );
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CERTINFO_VALIDFROM ) != CRYPT_OK )
		return( FALSE );

	return( TRUE );
	}

CHECK_RETVAL_BOOL \
static BOOLEAN checkAllowedValuesRange( IN_HANDLE const CRYPT_CONTEXT iCryptCertificate )
	{
	MESSAGE_DATA msgData;
	BYTE buffer[ 16 + 8 ];
	int value;

	REQUIRES_B( isHandleRangeValid( iCryptCertificate ) );

	/* Verify kernel range checking of special-case allowed values.  Valid 
	   values are either a 4-byte IPv4 address or a 16-byte IPv6 address */
	value = CRYPT_CERTINFO_SUBJECTALTNAME;
	memset( buffer, 0, 16 );
	setMessageData( &msgData, buffer, 3 );	/* Below, allowed value 1 */
	krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
					 CRYPT_ATTRIBUTE_CURRENT );
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CERTINFO_IPADDRESS ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
	setMessageData( &msgData, buffer, 4 );	/* Equal, allowed value 1 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CERTINFO_IPADDRESS ) != CRYPT_OK )
		return( FALSE );
	krnlSendMessage( iCryptCertificate, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CERTINFO_IPADDRESS );
	krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
					 CRYPT_ATTRIBUTE_CURRENT );
	setMessageData( &msgData, buffer, 5 );	/* Above, allowed value 1 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CERTINFO_IPADDRESS ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
	setMessageData( &msgData, buffer, 15 );	/* Below, allowed value 2 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CERTINFO_IPADDRESS ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
	setMessageData( &msgData, buffer, 16 );	/* Equal, allowed value 2 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CERTINFO_IPADDRESS ) != CRYPT_OK )
		return( FALSE );
	krnlSendMessage( iCryptCertificate, IMESSAGE_DELETEATTRIBUTE, NULL,
					 CRYPT_CERTINFO_IPADDRESS );
	krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
					 CRYPT_ATTRIBUTE_CURRENT );
	setMessageData( &msgData, buffer, 17 );	/* Above, allowed value 2 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CERTINFO_IPADDRESS ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );

	return( TRUE );
	}

CHECK_RETVAL_BOOL \
static BOOLEAN checkSubrangeRange( IN_HANDLE const CRYPT_CONTEXT iCryptCertificate )
	{
	int value;

	REQUIRES_B( isHandleRangeValid( iCryptCertificate ) );

	/* Verify kernel range checking of special-case subranges.  Valid values 
	   are either CRYPT_CURSOR_FIRST ... CRYPT_CURSOR_LAST or an extension 
	   ID.  Since the cursor movement codes are negative values an out-of-
	   bounds value is MIN + 1 or MAX - 1, not the other way round */
	value = CRYPT_CURSOR_FIRST + 1;			/* Below, subrange 1 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_ATTRIBUTE_CURRENT_GROUP ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
	value = CRYPT_CURSOR_FIRST;				/* Low bound, subrange 1 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_ATTRIBUTE_CURRENT_GROUP ) != CRYPT_ERROR_NOTFOUND )
		return( FALSE );
	value = CRYPT_CURSOR_LAST;				/* High bound, subrange 1 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_ATTRIBUTE_CURRENT_GROUP ) != CRYPT_ERROR_NOTFOUND )
		return( FALSE );
	value = CRYPT_CURSOR_LAST - 1;			/* Above, subrange 1 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_ATTRIBUTE_CURRENT_GROUP ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
	value = CRYPT_CERTINFO_FIRST_EXTENSION - 1;	/* Below, subrange 2 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_ATTRIBUTE_CURRENT_GROUP ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );
	value = CRYPT_CERTINFO_FIRST_EXTENSION;		/* Low bound, subrange 2 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_ATTRIBUTE_CURRENT_GROUP ) != CRYPT_ERROR_NOTFOUND )
		return( FALSE );
	value = CRYPT_CERTINFO_LAST_EXTENSION;		/* High bound, subrange 2 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_ATTRIBUTE_CURRENT_GROUP ) != CRYPT_ERROR_NOTFOUND )
		return( FALSE );
	value = CRYPT_CERTINFO_LAST_EXTENSION + 1;	/* Above, subrange 2 */
	if( krnlSendMessage( iCryptCertificate, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_ATTRIBUTE_CURRENT_GROUP ) != CRYPT_ARGERROR_NUM1 )
		return( FALSE );

	return( TRUE );
	}
#endif /* USE_CERTIFICATES */

CHECK_RETVAL \
static BOOLEAN testKernelMechanisms( void )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	CRYPT_CONTEXT iCryptHandle;
	static const BYTE FAR_BSS key[] = { 0x10, 0x46, 0x91, 0x34, 0x89, 0x98, 0x01, 0x31 };
	BYTE buffer[ 128 + 8 ];
	int value, status;

	/* Verify object creation */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( FALSE );
	iCryptHandle = createInfo.cryptHandle;

	/* Verify the inability to access an internal object or attribute using
	   an external message.  The attribute access will be stopped by the
	   object access check before it even gets to the attribute access check,
	   so we also re-do the check further on when the object is made
	   externally visible to verify the attribute-level checks as well */
	if( krnlSendMessage( iCryptHandle, MESSAGE_GETATTRIBUTE, &value,
						 CRYPT_CTXINFO_ALGO ) != CRYPT_ARGERROR_OBJECT || \
		krnlSendMessage( iCryptHandle, MESSAGE_GETATTRIBUTE, &value,
						 CRYPT_IATTRIBUTE_TYPE ) != CRYPT_ARGERROR_VALUE )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify the ability to perform standard operations and the inability
	   to perform a state = high operation on a state = low object */
	setMessageData( &msgData, ( MESSAGE_CAST ) key, 8 );
	memset( buffer, 0, 16 );
	if( krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_IV ) != CRYPT_OK || \
		krnlSendMessage( iCryptHandle, IMESSAGE_CTX_ENCRYPT,
						 buffer, 8 ) != CRYPT_ERROR_NOTINITED )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify the functioning of kernel range checking, phase 1: Numeric
	   values */
	if( !checkNumericRange( iCryptHandle ) )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify the functioning of kernel range checking, phase 2: String
	   values */
	if( !checkStringRange( iCryptHandle ) )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify the ability to transition a state = low object to state =
	   high */
	setMessageData( &msgData, ( MESSAGE_CAST ) key, 8 );
	if( krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEY ) != CRYPT_OK )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify the inability to write a read-only attribute, read a write-
	   only attribute, or delete a non-deletable attribute */
	value = CRYPT_MODE_CBC;
	setMessageData( &msgData, NULL, 0 );
	if( krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE, &value,
						 CRYPT_CTXINFO_BLOCKSIZE ) != CRYPT_ERROR_PERMISSION || \
		krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEY ) != CRYPT_ERROR_PERMISSION || \
		krnlSendMessage( iCryptHandle, IMESSAGE_DELETEATTRIBUTE, NULL,
						 CRYPT_CTXINFO_MODE ) != CRYPT_ERROR_PERMISSION )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify the inability to perform state = low operations on a state =
	   high object */
	setMessageData( &msgData, ( MESSAGE_CAST ) key, 8 );
	if( krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_KEY ) != CRYPT_ERROR_PERMISSION || \
		krnlSendNotifier( iCryptHandle, 
						  IMESSAGE_CTX_GENKEY ) != CRYPT_ERROR_PERMISSION )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify the inability to perform an internal-only action externally
	   but still perform it internally.  We also repeat the internal-only
	   attribute test from earlier on, this access is now stopped at the
	   attribute check level rather than the object-check level.

	   The object will become very briefly visible externally at this point,
	   but there's nothing that can be done with it because of the
	   permission settings */
	value = \
		MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL );
	memset( buffer, 0, 16 );
	krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE, &value,
					 CRYPT_IATTRIBUTE_ACTIONPERMS );
	krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_INTERNAL );
	if( krnlSendMessage( iCryptHandle, MESSAGE_CTX_ENCRYPT,
						 buffer, 8 ) != CRYPT_ERROR_PERMISSION || \
		krnlSendMessage( iCryptHandle, IMESSAGE_CTX_ENCRYPT,
						 buffer, 8 ) != CRYPT_OK )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}
	if( krnlSendMessage( iCryptHandle, MESSAGE_GETATTRIBUTE, &value,
						 CRYPT_IATTRIBUTE_TYPE ) != CRYPT_ARGERROR_VALUE )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}
	krnlSendMessage( iCryptHandle, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_INTERNAL );

	/* Verify the ability to use an object with a finite usage count, the
	   inability to increment the count, the ability to decrement the count,
	   and the inability to exceed the usage count */
	if( !checkUsageCount( iCryptHandle ) )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify the ability to lock an object and the inability to change
	   security parameters once it's locked */
	if( !checkLocking( iCryptHandle ) )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}
	krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );

	/* The following checks require that use of certificates be enabled in
	   order to perform them.  This is because these attribute types are
	   only valid for certificates (or, by extension, certificate-using
	   object types like envelopes and sessions).  So although these
	   attribute ACLs won't be tested if certificates aren't enabled, they
	   also won't be used if certificates aren't enabled */
#ifdef USE_CERTIFICATES

	/* Create a cert object for the remaining kernel range checks */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( FALSE );
	iCryptHandle = createInfo.cryptHandle;

	/* Verify functioning of the kernel range checking, phase 3: Boolean
	   values */
	if( !checkBooleanRange( iCryptHandle ) )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify functioning of the kernel range checking, phase 4: Time
	   values */
	if( !checkTimeRange( iCryptHandle ) )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify functioning of kernel range-checking, phase 6: Special-case
	   checks, allowed values */
	if( !checkAllowedValuesRange( iCryptHandle ) )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify functioning of kernel range-checking, phase 6: Special-case
	   checks, subranges */
	if( !checkSubrangeRange( iCryptHandle ) )
		{
		krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}
	krnlSendNotifier( iCryptHandle, IMESSAGE_DECREFCOUNT );
#endif /* USE_CERTIFICATES */

	return( TRUE );
	}

CHECK_RETVAL \
int testKernel( void )
	{
	ENSURES( testGeneralAlgorithms() );
	ENSURES( testKernelMechanisms() );

	return( CRYPT_OK );
	}
