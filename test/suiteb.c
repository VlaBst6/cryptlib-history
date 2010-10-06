/****************************************************************************
*																			*
*						cryptlib Suite B Test Routines						*
*						Copyright Peter Gutmann 2009-2010					*
*																			*
****************************************************************************/

#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII. */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

#if defined( TEST_SESSION ) || defined( TEST_SESSION_LOOPBACK )

/****************************************************************************
*																			*
*							Suite B Test Definitions						*
*																			*
****************************************************************************/

typedef struct {
	const char *testName;

	const int clientOptions;
	const int clientKeySizeBits;

	const int serverOptions;
	const int serverKeySizeBits;

	const BOOLEAN result;
	} SUITEB_TEST_INFO;

static const SUITEB_TEST_INFO testInfo[] = {
		/* Test			Client params					Server params					Result */
/* 0*/	{ "A.1.1.1",	0, 0,							CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/* 1*/	{ "A.1.1.2",	CRYPT_SSLOPTION_SUITEB_256, 0,	CRYPT_SSLOPTION_SUITEB_128, 0,	FALSE },
/* 2*/	{ "A.1.2.1",	0, 0,							CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/* 3*/	{ "A.1.2.2",	CRYPT_SSLOPTION_SUITEB_128, 0,	CRYPT_SSLOPTION_SUITEB_256, 384,FALSE },
/* 4*/	{ "A.1.3.1",	0, 0,							CRYPT_SSLOPTION_SUITEB_128 | \
														CRYPT_SSLOPTION_SUITEB_256, 0,	TRUE },
/* 5*/	{ "A.1.4.1",	0, 0,							CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/* 6*/	{ "A.1.4.2",	0, 0,							CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/* 7*/	{ "A.1.6.1",	0, 0,							CRYPT_SSLOPTION_SUITEB_128 | \
														CRYPT_SSLOPTION_SUITEB_256, 0,	TRUE },
/* 8*/	{ "A.1.16.1",	0, 0,							CRYPT_SSLOPTION_MINVER_TLS12, 0,TRUE },
/* 9*/	{ "A.1.17.1",	CRYPT_SSLOPTION_SUITEB_128, 0,	CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/*10*/	{ "A.1.18.1",	CRYPT_SSLOPTION_SUITEB_256, 0,	CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/*11*/	{ "A.1.20.1",	CRYPT_SSLOPTION_SUITEB_128, 0,	CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/*12*/	{ "A.1.20.2",	CRYPT_SSLOPTION_SUITEB_256, 0,	CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/*13*/	{ "A.1.21.1",	CRYPT_SSLOPTION_SUITEB_128, 0,	CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/*14*/	{ "A.1.22.1",	CRYPT_SSLOPTION_SUITEB_256, 0,	CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/*15*/	{ "A.1.24.1",	CRYPT_SSLOPTION_SUITEB_128, 256,CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/*16*/	{ "A.1.24.2",	CRYPT_SSLOPTION_SUITEB_256, 384,CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
		{ NULL }, { NULL }, { NULL }, 

		/* Test			Client params					Server params					Result */
/*20*/	{ "A.2.1.1",	CRYPT_SSLOPTION_SUITEB_128, 0,	0, 0,							TRUE },
/*21*/	{ "A.2.1.2",	CRYPT_SSLOPTION_SUITEB_128, 0,	CRYPT_SSLOPTION_SUITEB_256, 0,	FALSE },
/*22*/	{ "A.2.2.1",	CRYPT_SSLOPTION_SUITEB_256, 0,	0, 384,							TRUE },
/*23*/	{ "A.2.2.2",	CRYPT_SSLOPTION_SUITEB_256, 0,	CRYPT_SSLOPTION_SUITEB_128, 384,FALSE },
/*24*/	{ "A.2.3.1",	CRYPT_SSLOPTION_SUITEB_128 | \
						CRYPT_SSLOPTION_SUITEB_256, 0,	0, 0,							TRUE },
/*25*/	{ "A.2.4.1",	CRYPT_SSLOPTION_SUITEB_128, 0,	0, 0,							TRUE },
/*26*/	{ "A.2.4.2",	CRYPT_SSLOPTION_SUITEB_256, 0,	0, 384,							TRUE },
/*27*/	{ "A.2.6.1",	CRYPT_SSLOPTION_SUITEB_128, 0,	CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/*28*/	{ "A.2.6.2",	CRYPT_SSLOPTION_SUITEB_128, 0,	CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/*29*/	{ "A.2.6.3",	CRYPT_SSLOPTION_SUITEB_256, 0,	CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/*30*/	{ "A.2.6.4",	CRYPT_SSLOPTION_SUITEB_256, 0,	CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/*31*/	{ "A.2.16.1",	CRYPT_SSLOPTION_SUITEB_128, 0,	CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/*32*/	{ "A.2.17.1",	CRYPT_SSLOPTION_SUITEB_256, 0,	CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/*33*/	{ "A.2.22.1",	0, 0,							CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/*34*/	{ "A.2.23.1",	0, 0,							CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/*35*/	{ "A.2.24.1",	CRYPT_SSLOPTION_SUITEB_256, 0,	CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/*36*/	{ "A.2.25.1",	CRYPT_SSLOPTION_SUITEB_256, 0,	CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/*37*/	{ "A.2.29.1",	CRYPT_SSLOPTION_SUITEB_128, 256,CRYPT_SSLOPTION_SUITEB_128, 0,	TRUE },
/*38*/	{ "A.2.29.2",	CRYPT_SSLOPTION_SUITEB_256, 384,CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },
/*39*/	{ "A.2.29.3",	CRYPT_SSLOPTION_SUITEB_256, 256,CRYPT_SSLOPTION_SUITEB_256, 384,TRUE },

	{ NULL }
	};

/****************************************************************************
*																			*
*							Suite B TLS Routines Test						*
*																			*
****************************************************************************/

/* Establish a Suite B server session */

static int suitebServer( const int testNo )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CONTEXT privateKey;
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
	void *fileNamePtr = filenameBuffer;
	int status;

	/* Acquire the init mutex */
	acquireMutex();

	printf( "SVR: Suite B test %s...\n", testInfo[ testNo ].testName );

	/* Create the SSL/TLS session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
								 CRYPT_SESSION_SSL_SERVER );
	if( status == CRYPT_ERROR_PARAM3 )	/* SSL/TLS session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_VERSION, 3 );
	if( cryptStatusOK( status ) && testInfo[ testNo ].serverOptions != 0 )
		{
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SSL_OPTIONS, 
									testInfo[ testNo ].serverOptions );
		}
	if( testInfo[ testNo ].clientKeySizeBits > 0 ) 
		{
		CRYPT_KEYSET cryptKeyset;

		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
								  DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME,
								  CRYPT_KEYOPT_READONLY );
		if( cryptStatusError( status ) )
			{
			printf( "SVR: Client certificate keyset open failed with error "
					"code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_KEYSET,
									cryptKeyset );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Set up the server information */
	if( !setLocalConnect( cryptSession, 443 ) )
		return( FALSE );

	/* Add the server key */
	filenameFromTemplate( filenameBuffer, SERVER_PRIVKEY_FILE_TEMPLATE, 
						  ( testInfo[ testNo ].serverKeySizeBits == 384 ) ? \
							3 : 2 );
#ifdef UNICODE_STRINGS
	mbstowcs( wcBuffer, filenameBuffer, strlen( filenameBuffer ) + 1 );
	fileNamePtr = wcBuffer;
#endif /* UNICODE_STRINGS */
	status = getPrivateKey( &privateKey, fileNamePtr, USER_PRIVKEY_LABEL,
							TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_PRIVATEKEY,
									privateKey );
		cryptDestroyContext( privateKey );
		}
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptSetAttribute/AttributeString() failed with error "
				"code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* For the loopback test we also increase the connection timeout to a 
	   higher-than-normal level, since this gives us more time for tracing 
	   through the code when debugging */
	cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_CONNECTTIMEOUT, 120 );

	/* Tell the client that we're ready to go */
	releaseMutex();

	/* Activate the session */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( ( testInfo[ testNo ].result && !cryptStatusOK( status ) ) || \
		( !testInfo[ testNo ].result && !cryptStatusError( status ) ) )
		{
		if( testInfo[ testNo ].result )
			printf( "SVR: Test %s failed, should have succeeded.\n",
					testInfo[ testNo ].testName );
		else
			printf( "SVR: Test %s succeeded, should have failed.\n",
					testInfo[ testNo ].testName );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptSession, "SVR: Failure reason is:", status, 
						   __LINE__ );
			}
		cryptDestroySession( cryptSession );

		return( FALSE );
		}

	/* Clean up */
	status = cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroySession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "SVR: Suite B test %s succeeded.\n", 
			testInfo[ testNo ].testName );

	return( TRUE );
	}

/* Establish a Suite B client session */

static int suitebClient( const int testNo )
	{
	CRYPT_SESSION cryptSession;
	int status;

	/* Wait for the server to finish initialising */
	if( waitMutex() == CRYPT_ERROR_TIMEOUT )
		{
		printf( "Timed out waiting for server to initialise, line %d.\n", 
				__LINE__ );
		return( FALSE );
		}

	printf( "Suite B test %s...\n", testInfo[ testNo ].testName );

	/* Create the SSL/TLS session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED, 
								 CRYPT_SESSION_SSL );
	if( status == CRYPT_ERROR_PARAM3 )	/* SSL/TLS session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_VERSION, 3 );
	if( cryptStatusOK( status ) && testInfo[ testNo ].clientOptions != 0 )
		{
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SSL_OPTIONS, 
									testInfo[ testNo ].clientOptions );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Set up the client information */
	if( !setLocalConnect( cryptSession, 443 ) )
		return( FALSE );
	if( cryptStatusOK( status ) && testInfo[ testNo ].clientKeySizeBits > 0 )
		{
		CRYPT_CONTEXT privateKey;
		char filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
		wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
		void *fileNamePtr = filenameBuffer;

		/* Depending on which server we're testing against we need to use 
		   different private keys */
		filenameFromTemplate( filenameBuffer, SERVER_PRIVKEY_FILE_TEMPLATE, 
							  ( testInfo[ testNo ].clientKeySizeBits == 384 ) ? \
								3 : 2 );
#ifdef UNICODE_STRINGS
		mbstowcs( wcBuffer, filenameBuffer, strlen( filenameBuffer ) + 1 );
		fileNamePtr = wcBuffer;
#endif /* UNICODE_STRINGS */
		status = getPrivateKey( &privateKey, fileNamePtr, USER_PRIVKEY_LABEL,
								TEST_PRIVKEY_PASSWORD );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttribute( cryptSession,
								CRYPT_SESSINFO_PRIVATEKEY, privateKey );
			cryptDestroyContext( privateKey );
			}
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute/AttributeString() failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* For the loopback test we also increase the connection timeout to a 
	   higher-than-normal level, since this gives us more time for tracing 
	   through the code when debugging */
	cryptSetAttribute( cryptSession, CRYPT_OPTION_NET_CONNECTTIMEOUT, 120 );

	/* Activate the session */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( ( testInfo[ testNo ].result && !cryptStatusOK( status ) ) || \
		( !testInfo[ testNo ].result && !cryptStatusError( status ) ) )
		{
		if( testInfo[ testNo ].result )
			printf( "Test %s failed, should have succeeded.\n",
					testInfo[ testNo ].testName );
		else
			printf( "Test %s succeeded, should have failed.\n",
					testInfo[ testNo ].testName );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptSession, "Failure reason is:", status, 
						   __LINE__ );
			}
		cryptDestroySession( cryptSession );

		return( FALSE );
		}

	/* Tests 33-37 / A.2.22.1-4 have special-case requirements in that they
	   check the handling of non-Suite B algorithms, so we have to check the
	   compliance manually */
	if( testNo >= 33 && testNo <= 37 )
		{
		int value;

		status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_ALGO, 
									&value );
		if( cryptStatusError( status ) || value != CRYPT_ALGO_AES )
			return( FALSE );
		status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_MODE, 
									&value );
		if( cryptStatusError( status ) || value != CRYPT_MODE_GCM )
			return( FALSE );
			/* Technically A.2.23.1 and A.2.25.1 should allow CBC since it
			   tests fallback to a non-Suite B but permitted-anyway mode,
			   but for now we don't allow it */
		}

	/* Clean up */
	status = cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroySession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Suite B test %s succeeded.\n", 
			testInfo[ testNo ].testName );

	return( TRUE );
	}

#ifdef WINDOWS_THREADS

unsigned __stdcall suitebServerThread( void *arg )
	{
	const int value = *( ( int * ) arg );

	suitebServer( value );
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionSuiteBClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int value = 33, status;

	/* Start the server */
	createMutex();
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, suitebServerThread,
										 &value, 0, &threadID );
	Sleep( 1000 );

	/* Connect to the local server */
	status = suitebClient( value );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}
#endif /* WINDOWS_THREADS */

#endif /* TEST_SESSION || TEST_SESSION_LOOPBACK */
