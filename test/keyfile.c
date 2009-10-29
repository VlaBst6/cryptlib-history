/****************************************************************************
*																			*
*						cryptlib File Keyset Test Routines					*
*						Copyright Peter Gutmann 1995-2009					*
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

/* External flags that indicate that the key read/update routines worked OK.
   This is set by earlier self-test code, if it isn't set some of the tests
   are disabled */

extern int keyReadOK, doubleCertOK;

#ifdef TEST_KEYSET

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Copy a source file to a destination file, corrupting a given byte in the 
   process.  This is used to test the ability of the keyset-processing code 
   to detect data manipulation in keyset data */

static int copyModifiedFile( const C_STR srcFileName, 
							 const C_STR destFileName, const int bytePos )
	{
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count = 0;

	/* Read the source file into the data buffer */
	if( ( filePtr = fopen( convertFileName( srcFileName ), "rb" ) ) != NULL )
		{
		count = fread( buffer, 1, BUFFER_SIZE, filePtr );
		if( count >= BUFFER_SIZE )
			count = 0;
		fclose( filePtr );
		}
	if( count <= 0 )
		return( FALSE );

	/* Corrupt a specific byte in the file */
	buffer[ bytePos ] ^= 0xFF;

	/* Write the changed result to the output buffer */
	if( ( filePtr = fopen( convertFileName( destFileName ), "wb" ) ) != NULL )
		{
		int writeCount;

		writeCount = fwrite( buffer, 1, count, filePtr );
		if( writeCount != count )
			count = 0;
		fclose( filePtr );
		}
	
	return( ( count > 0 ) ? TRUE : FALSE );
	}

/****************************************************************************
*																			*
*						PGP/PKCS #12 Key Read/Write Tests					*
*																			*
****************************************************************************/

/* Get a public key from a PGP keyring */

static int getPGPPublicKey( const KEYFILE_TYPE keyFileType,
							const C_STR keyFileTemplate,
							const char *description )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	char fileName[ BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
	const C_STR keysetName = getKeyfileName( keyFileType, FALSE );
	int status;

	/* If this is the first file read, check that the file actually exists
	   so we can return an appropriate error message */
	if( keyFileType == KEYFILE_PGP )
		{
		if( ( filePtr = fopen( convertFileName( keysetName ),
							   "rb" ) ) == NULL )
			return( CRYPT_ERROR_FAILED );
		fclose( filePtr );
		keyReadOK = FALSE;
		}

	/* If the caller has overridden the keyfile to use, use the caller-
	   supplied name */
	if( keyFileTemplate != NULL )
		{
		filenameFromTemplate( fileName, keyFileTemplate, 1 );
#ifdef UNICODE_STRINGS
		mbstowcs( wcBuffer, fileName, strlen( fileName ) + 1 );
		keysetName = wcBuffer;
#else
		keysetName = fileName;
#endif /* UNICODE_STRINGS */
		}

	printf( "Testing %s public key read...\n", description );

	/* Open the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key.  The read of the special-case PGP keyring tests the 
	   ability to handle over-long key packet groups so this should return
	   a not-found error due to the packets being skipped */
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								getKeyfileUserID( keyFileType, FALSE ) );
	if( ( keyFileType == KEYFILE_PGP_SPECIAL && \
		  status != CRYPT_ERROR_NOTFOUND ) || \
		( keyFileType != KEYFILE_PGP_SPECIAL && \
		  cryptStatusError( status ) ) )
		{
		printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	printf( "Read of public key from %s keyring succeeded.\n\n",
			description );
	return( TRUE );
	}

int testGetPGPPublicKey( void )
	{
	if( !getPGPPublicKey( KEYFILE_PGP, NULL, "PGP" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP, NULL, "OpenPGP (GPG)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_HASH, NULL, "OpenPGP (GPG/hashed key)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_AES, NULL, "OpenPGP (GPG/AES-256 key)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_OPENPGP_RSA, NULL, "OpenPGP (GPG/RSA key)" ) )
		return( FALSE );
	if( !getPGPPublicKey( KEYFILE_NAIPGP, NULL, "OpenPGP (NAI)" ) )
		return( FALSE );
	return( getPGPPublicKey( KEYFILE_PGP_SPECIAL, PGPKEY_FILE_TEMPLATE, "Complex PGP key" ) );
	}

/* Get a private key from a PGP keyring */

static int getPGPPrivateKey( const KEYFILE_TYPE keyFileType,
							 const char *description )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const C_STR keysetName = getKeyfileName( keyFileType, TRUE );
	const C_STR password = getKeyfilePassword( keyFileType );
	int status;

	printf( "Testing %s private key read...\n", description );

	/* Open the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key.  First we try it without a password, if that fails we
	   retry it with the password - this tests a lot of the private-key get
	   functionality including things like key cacheing */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								 getKeyfileUserID( keyFileType, TRUE ), NULL );
	if( status == CRYPT_ERROR_WRONGKEY )
		{
		/* We need a password for this private key, get it from the user and
		   get the key again */
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME,
									 getKeyfileUserID( keyFileType, TRUE ),
									 password );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can use the key that we've read.  We can only do this 
	   with PGP 2.x keys, OpenPGP's peculiar multi-keys identify two (or more) 
	   keys with the same label and we can't specify (at this level) which 
	   key we want to use (the enveloping code can be more specific and so 
	   doesn't run into this problem) */
	if( keyFileType == KEYFILE_PGP )
		{
		status = testCrypt( cryptContext, cryptContext, NULL, FALSE, FALSE );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* The public and private key reads worked, remember this for later when
	   we use the keys in other tests */
	keyReadOK = TRUE;

	printf( "Read of private key from %s keyring succeeded.\n\n",
			description );
	return( TRUE );
	}

int testGetPGPPrivateKey( void )
	{
	if( !getPGPPrivateKey( KEYFILE_PGP, "PGP" ) )
		return( FALSE );
	if( !getPGPPrivateKey( KEYFILE_OPENPGP, "OpenPGP (GPG)" ) )
		return( FALSE );
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_HASH, "OpenPGP (GPG/hashed key)" ) )
		return( FALSE );
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_AES, "OpenPGP (GPG/AES-256 key)" ) )
		return( FALSE );
	if( !getPGPPrivateKey( KEYFILE_OPENPGP_RSA, "OpenPGP (GPG/RSA key)" ) )
		return( FALSE );
	return( getPGPPrivateKey( KEYFILE_NAIPGP, "OpenPGP (NAI)" ) );
	}

/* Get a key from a PKCS #12 file.  Because of the security problems
   associated with this format, the code only checks the data format but
   doesn't try to read or use the keys.  If anyone wants this, they'll
   have to add the code themselves.  Your security warranty is void if you
   implement this */

int testGetBorkenKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	int status;

	/* Check that the file actually exists so we can return an appropriate
	   error message */
	if( ( filePtr = fopen( convertFileName( PKCS12_FILE ), "rb" ) ) == NULL )
		return( CRYPT_ERROR_FAILED );
	fclose( filePtr );

/*	puts( "Testing PKCS #12 key read..." ); */

	/* Open the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  PKCS12_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		/* If support for this isn't enabled (which is normal, since the code
		   doesn't exist), just exit quietly */
		if( status == CRYPT_ERROR_PARAM3 )
			return( TRUE );

		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key  - this is currently hardwired to CRYPT_ERROR_NOTAVAIL
	   after unwrapping the first dozen or so layers of PKCS #12 garbage */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								 TEXT( "test" ), NULL );
/*	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext ); */

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

/*	puts( "Read of key from PKCS #12 file succeeded.\n" ); */
	return( TRUE );
	}

/****************************************************************************
*																			*
*						Public/Private Key Read/Write Tests					*
*																			*
****************************************************************************/

/* Read/write a private key from a file */

static int readFileKey( const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	const char *description = \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? "RSA" : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? "DSA" : \
			( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? "Elgamal" : \
			( cryptAlgo == CRYPT_ALGO_ECDSA ) ? "ECDSA" : "<Unknown>";
	const C_STR label = \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? RSA_PRIVKEY_LABEL : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? DSA_PRIVKEY_LABEL : \
			( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? ELGAMAL_PRIVKEY_LABEL : \
			( cryptAlgo == CRYPT_ALGO_ECDSA ) ? ECDSA_PRIVKEY_LABEL : "<Unknown>";
	int status;

	printf( "Testing %s private key read from key file...\n", description );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, label,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Make sure that we can use the read key */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		status = testCrypt( cryptContext, cryptContext, NULL, FALSE, FALSE );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	printf( "Read of %s private key from key file succeeded.\n\n", description );
	return( TRUE );
	}

static int writeFileKey( const CRYPT_ALGO_TYPE cryptAlgo, 
						 const BOOLEAN useAltKeyfile,
						 const BOOLEAN generateKey )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT privateKeyContext;
	const char *description = \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? "RSA" : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? "DSA" : \
			( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? "Elgamal" : \
			( cryptAlgo == CRYPT_ALGO_ECDSA ) ? "ECDSA" : "<Unknown>";
	const C_STR label = \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? RSA_PRIVKEY_LABEL : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? DSA_PRIVKEY_LABEL : \
			( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? ELGAMAL_PRIVKEY_LABEL : \
			( cryptAlgo == CRYPT_ALGO_ECDSA ) ? ECDSA_PRIVKEY_LABEL : "<Unknown>";
	int status;

	printf( "Testing %s private key write to key file...\n", description );

	/* Create the private key context */
	if( generateKey )
		{
		status = cryptCreateContext( &privateKeyContext, CRYPT_UNUSED, 
									 cryptAlgo );
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( privateKeyContext, 
											  CRYPT_CTXINFO_LABEL, label, 
											  paramStrlen( label ) );
		if( cryptStatusOK( status ) )
			status = cryptGenerateKey( privateKeyContext );
		if( cryptStatusError( status ) )
			return( FALSE );
		}
	else
		{
		switch( cryptAlgo )
			{
			case CRYPT_ALGO_RSA:
				if( !loadRSAContexts( CRYPT_UNUSED, NULL, &privateKeyContext ) )
					return( FALSE );
				break;

			case CRYPT_ALGO_DSA:
				if( !loadDSAContexts( CRYPT_UNUSED, &privateKeyContext, NULL ) )
					return( FALSE );
				break;

			case CRYPT_ALGO_ELGAMAL:
				if( !loadElgamalContexts( NULL, &privateKeyContext ) )
					return( FALSE );
				break;

			case CRYPT_ALGO_ECDSA:
				if( !loadECDSAContexts( &privateKeyContext, NULL ) )
					return( FALSE );
				break;
			}
		}

	/* Create/open the file keyset.  For the first call (with RSA) we create
	   a new keyset, for subsequent calls we update the existing keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
					useAltKeyfile ? TEST_PRIVKEY_ALT_FILE : TEST_PRIVKEY_FILE,
					( cryptAlgo == CRYPT_ALGO_RSA ) ? CRYPT_KEYOPT_CREATE : \
													  CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		if( useAltKeyfile && status == CRYPT_ERROR_PARAM2 )
			{
			/* If the format isn't supported, this isn't a problem */
			puts( "Write of RSA private key to key file skipped.\n" );
			return( CRYPT_OK );
			}
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Write the key to the file */
	status = cryptAddPrivateKey( cryptKeyset, privateKeyContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( privateKeyContext );
	printf( "Write of %s private key to key file succeeded.\n\n", description );
	return( TRUE );
	}

int testReadWriteFileKey( void )
	{
	if( !writeFileKey( CRYPT_ALGO_RSA, FALSE, FALSE ) )
		return( FALSE );
	if( !readFileKey( CRYPT_ALGO_RSA ) )
		return( FALSE );
	if( !writeFileKey( CRYPT_ALGO_DSA, FALSE, FALSE ) )
		return( FALSE );
	if( !readFileKey( CRYPT_ALGO_DSA ) )
		return( FALSE );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ELGAMAL, NULL ) ) && \
		!writeFileKey( CRYPT_ALGO_ELGAMAL, FALSE, FALSE ) )
		return( FALSE );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ELGAMAL, NULL ) ) && \
		!readFileKey( CRYPT_ALGO_ELGAMAL ) )
		return( FALSE );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) ) && \
		!writeFileKey( CRYPT_ALGO_ECDSA, FALSE, FALSE ) )
		return( FALSE );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_ECDSA, NULL ) ) && \
		!readFileKey( CRYPT_ALGO_ECDSA ) )
		return( FALSE );
	return( TRUE );
	}

int testWriteAltFileKey( void )
	{
	return( writeFileKey( TRUE, TRUE, FALSE ) );
	}

int testReadBigFileKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	printf( "Testing private key read from large key file...\n" );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  BIG_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( status == CRYPT_ERROR_OVERFLOW )
		{
		/* Depending on the setting of MAX_PKCS15_OBJECTS this keyset may 
		   contain too many keys to be read, if we get an overflow error we
		   continue normally */
		printf( "Keyset contains too many items to read, line %d.\n  (This "
				"is an expected condition, continuing...).\n", __LINE__ );
		return( TRUE );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, TEXT( "John Smith 0" ),
								 TEXT( "password" ) );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Read of private key from large key file succeeded.\n" );
	return( TRUE );
	}

/* Read only the public key/certificate/certificate chain portion of a 
   keyset */

int testReadFilePublicKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int cryptAlgo, status;

	puts( "Testing public key read from key file..." );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the public key from the file and make sure that it really is a
	   public-key context */
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								RSA_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, &cryptAlgo );
	if( cryptStatusError( status ) || \
		cryptAlgo < CRYPT_ALGO_FIRST_PKC || cryptAlgo > CRYPT_ALGO_LAST_PKC )
		{
		puts( "Returned object isn't a public-key context." );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyContext( cryptContext );

	puts( "Read of public key from key file succeeded.\n" );
	return( TRUE );
	}

static int readCert( const char *certTypeName,
					 const CRYPT_CERTTYPE_TYPE certType,
					 const BOOLEAN readPrivateKey )
	{
	CRYPT_KEYSET cryptKeyset;
	int value, status;

	printf( "Testing %s read from key file...\n", certTypeName );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the certificate from the file and make sure that it really is a
	   certificate */
	if( readPrivateKey )
		{
		CRYPT_CONTEXT cryptContext;

		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
									 TEST_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
						   __LINE__ );
			return( FALSE );
			}
		status = cryptGetAttribute( cryptContext, CRYPT_CERTINFO_CERTTYPE,
									&value );
		if( cryptStatusError( status ) || value != certType )
			{
			printf( "Returned object isn't a %s, line %d.\n", certTypeName, 
					__LINE__ );
			return( FALSE );
			}

		/* Make sure that we can't use the read key (the certificate 
		   constrains it from being used externally) */
		status = testCrypt( cryptContext, cryptContext, NULL, FALSE, TRUE );
		if( status != CRYPT_ERROR_NOTAVAIL )
			{
			puts( "Attempt to perform external operation on context with "
				  "internal-only action\npermissions succeeded. " );
			return( FALSE );
			}
		cryptDestroyContext( cryptContext );
		}
	else
		{
		CRYPT_CERTIFICATE cryptCert;

		status = cryptGetPublicKey( cryptKeyset, &cryptCert, CRYPT_KEYID_NAME,
									( certType == CRYPT_CERTTYPE_CERTIFICATE ) ? \
									RSA_PRIVKEY_LABEL : USER_PRIVKEY_LABEL );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, "cryptGetPublicKey()", status, 
						   __LINE__ );
			return( FALSE );
			}
		status = cryptGetAttribute( cryptCert, CRYPT_CERTINFO_CERTTYPE, &value );
		if( cryptStatusError( status ) || value != certType )
			{
			printf( "Returned object isn't a %s, line %d.\n", certTypeName, 
					__LINE__ );
			return( FALSE );
			}
		cryptDestroyCert( cryptCert );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	printf( "Read of %s from key file succeeded.\n\n", certTypeName );
	return( TRUE );
	}

int testReadFileCert( void )
	{
	return( readCert( "certificate", CRYPT_CERTTYPE_CERTIFICATE, FALSE ) );
	}
int testReadFileCertPrivkey( void )
	{
	return( readCert( "private key with certificate", CRYPT_CERTTYPE_CERTIFICATE, TRUE ) );
	}
int testReadFileCertChain( void )
	{
	return( readCert( "certificate chain", CRYPT_CERTTYPE_CERTCHAIN, FALSE ) );
	}

/* Test the ability to detect key data corruption/modification */

int testReadCorruptedKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int i, status;

	puts( "Testing detection of key corruption in key file..." );
	for( i = 0; i < 4; i++ )
		{
		/* Copy the file to a temporary one, corrupting a data byte in the 
		   process */
		status = copyModifiedFile( TEST_PRIVKEY_FILE, TEST_PRIVKEY_TMP_FILE, 
								   256 );
		if( !status )
			{
			printf( "Couldn't copy keyset to temporary file, line %d.\n",
					__LINE__ );
			return( FALSE );
			}

		/* Try and read the key.  The open should succeed, the read should 
		   fail */
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, 
								  CRYPT_KEYSET_FILE, TEST_PRIVKEY_TMP_FILE, 
								  CRYPT_KEYOPT_READONLY );
		if( cryptStatusError( status ) )
			{
			printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
					status, __LINE__ );
			return( FALSE );
			}
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
									 TEST_PRIVKEY_PASSWORD );
		if( cryptStatusOK( status ) )
			{
			cryptDestroyContext( cryptContext );
			printf( "Read of corrupted key succeeded when it should have "
					"failed, line %d.\n", __LINE__ );
			return( FALSE );
			}
		cryptKeysetClose( cryptKeyset );
		}
	puts( "Detection of key corruption succeeded.\n" );

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Certificate Read/Write Tests					*
*																			*
****************************************************************************/

/* Update a keyset to contain a certificate */

int testAddTrustedCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE trustedCert;
	int value, status;

	puts( "Testing trusted certificate add to key file..." );

	/* Read the CA root certificate.  We have to make it explicitly non-
	   trusted since something else may have made it trusted previously */
	status = importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read certificate from file, skipping test of trusted "
			  "certificate write..." );
		return( TRUE );
		}
	cryptGetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT,
					   &value );
	if( value )
		cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT,
						   FALSE );

	/* Open the keyset, update it with the trusted certificate, and close it.
	   Before we make the certificate trusted, we try adding it as a standard 
	   certificate, which should fail */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, trustedCert );
	if( cryptStatusOK( status ) )
		{
		printf( "cryptAddPublicKey() of non-trusted certificate succeeded "
				"when it should have failed, line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );
	status = cryptAddPublicKey( cryptKeyset, trustedCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, value );
	cryptDestroyCert( trustedCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Trusted certificate add to key file succeeded.\n" );
	return( TRUE );
	}

int testAddGloballyTrustedCert( void )
	{
	CRYPT_CERTIFICATE trustedCert;
	int status;

	puts( "Testing globally trusted certificate add..." );

	/* Read the CA root certificate and make it trusted */
	status = importCertFromTemplate( &trustedCert, CERT_FILE_TEMPLATE, 1 );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read certificate from file, skipping test of trusted "
			  "certificate write..." );
		return( TRUE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );

	/* Update the config file with the globally trusted certificate */
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED,
								FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "Globally trusted certificate add failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Make the certificate untrusted and update the config again */
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, FALSE );
	status = cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED,
								FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "Globally trusted certificate delete failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	puts( "Globally trusted certificate add succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA FAR_BSS cACertData[] = {
	/* Identification information.  Note the non-heirarchical order of the
	   components to test the automatic arranging of the DN */
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers and CA" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Himself" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Certification Division" ) },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* CA key usage */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testUpdateFileCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT publicKeyContext, privateKeyContext;
	int status;

	puts( "Testing certificate update to key file ..." );

	/* Create a self-signed CA certificate using the in-memory key (which is
	   the same as the one in the keyset) */
	if( !loadRSAContexts( CRYPT_UNUSED, &publicKeyContext, &privateKeyContext ) )
		return( FALSE );
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, publicKeyContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCert, cACertData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, privateKeyContext );
	destroyContexts( CRYPT_UNUSED, publicKeyContext, privateKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		cryptDestroyCert( status );
		return( FALSE );
		}

	/* Open the keyset, update it with the certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Certificate update to key file succeeded.\n" );
	return( TRUE );
	}

/* Update a keyset to contain a certificate chain */

static int writeFileCertChain( const CERT_DATA *certRequestData,
							   const C_STR keyFileName,
							   const C_STR certFileName,
							   const BOOLEAN isTestRun,
							   const BOOLEAN writeLongChain )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCertChain;
	CRYPT_CONTEXT cryptCAKey, cryptKey;
	int status;

	if( isTestRun )
		{
		printf( "Testing %scert chain write to key file ...\n",
				writeLongChain ? "long " : "" );
		}

	/* Generate a key to certify.  We can't just reuse the built-in test key
	   because this has already been used as the CA key and the keyset code
	   won't allow it to be added to a keyset as both a CA key and user key,
	   so we have to generate a new one */
	status = cryptCreateContext( &cryptKey, CRYPT_UNUSED, CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptKey, CRYPT_CTXINFO_LABEL,
										  USER_PRIVKEY_LABEL,
										  paramStrlen( USER_PRIVKEY_LABEL ) );
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptKey );
	if( cryptStatusError( status ) )
		{
		printf( "Test key generation failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the CA's key.  The length of the chain is determined by the
	   number of certs attached to the CAs certificate, so handling long vs.
	   short chains is pretty simple */
	if( writeLongChain )
		status = getPrivateKey( &cryptCAKey, ICA_PRIVKEY_FILE,
								USER_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	else
		status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
								CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the keyset and add the private key to it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keyFileName, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptKey,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	/* Create the certificate chain for the new key */
	status = cryptCreateCert( &cryptCertChain, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTCHAIN );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCertChain,
							CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptKey );
	cryptDestroyContext( cryptKey );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCertChain, certRequestData, __LINE__ ) )
		return( FALSE );
#ifndef _WIN32_WCE	/* Windows CE doesn't support ANSI C time functions */
	if( cryptStatusOK( status ) && !isTestRun )
		{
		const time_t validity = time( NULL ) + ( 86400L * 365 * 3 );

		/* Make it valid for 5 years instead of 1 to avoid problems when 
		   users run the self-test with very old copies of the code */
		status = cryptSetAttributeString( cryptCertChain,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
		}
#endif /* WinCE */
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCertChain, cryptCAKey );
	cryptDestroyContext( cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate chain creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptCertChain );
		return( FALSE );
		}

	/* Add the certificate chain to the file */
	status = cryptAddPublicKey( cryptKeyset, cryptCertChain );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	if( certFileName != NULL )
		{
		FILE *filePtr;
		BYTE certBuffer[ BUFFER_SIZE ];
		int length;

		/* Save the certificate to disk for use in request/response 
		   protocols */
		status = cryptExportCert( certBuffer, BUFFER_SIZE, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, 
								  cryptCertChain );
		if( cryptStatusError( status ) )
			{
			printf( "cryptExportCert() failed with error code %d, "
					"line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		if( ( filePtr = fopen( convertFileName( certFileName ), \
							   "wb" ) ) != NULL )
			{
			int count;

			count = fwrite( certBuffer, 1, length, filePtr );
			fclose( filePtr );
			if( count < length )
				{
				remove( convertFileName( certFileName ) );
				puts( "Warning: Couldn't save certificate chain to disk, "
					  "this will cause later\n         tests to fail.  "
					  "Press a key to continue." );
				getchar();
				}
			}
		}
	cryptDestroyCert( cryptCertChain );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	if( isTestRun )
		puts( "Certificate chain write to key file succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA FAR_BSS certRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },
	{ CRYPT_CERTINFO_EMAIL, IS_STRING, 0, TEXT( "dave@wetaburgers.com" ) },
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTNAME },	/* Re-select subject DN */

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testWriteFileCertChain( void )
	{
	return( writeFileCertChain( certRequestData, TEST_PRIVKEY_FILE, NULL,
								TRUE, FALSE ) );
	}

int testWriteFileLongCertChain( void )
	{
	return( writeFileCertChain( certRequestData, TEST_PRIVKEY_FILE, NULL,
								TRUE, TRUE ) );
	}

/* Delete a key from a file */

int testDeleteFileKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing delete from key file..." );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Delete the key from the file.  Since we don't need the DSA key any
	   more we use it as the key to delete */
	status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME,
							 DSA_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptDeletePrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								DSA_PRIVKEY_LABEL );
	if( cryptStatusOK( status ) )
		{
		cryptDestroyContext( cryptContext );
		puts( "cryptDeleteKey() claimed the key was deleted but it's still "
			  "present." );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Delete from key file succeeded.\n" );
	return( TRUE );
	}

/* Change the password for a key in a file */

int testChangeFileKeyPassword( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing change of key password for key file..." );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key using the old password, delete it, and write it back
	   using the new password.  To keep things simple we just use the same
	   password (since the key will be used again later), the test of the
	   delete function earlier on has already confirmed that the old key
	   and password will be deleted so there's no chance of a false positive */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME,
								 RSA_PRIVKEY_LABEL );
	if( cryptStatusOK( status ) )
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "password change", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Password change for key in key file succeeded.\n" );
	return( TRUE );
	}

/* Write a key and certificate to a file in a single operation */

static int writeSingleStepFileCert( const BOOLEAN useAltKeyfile )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing single-step key+certificate write to key file ..." );

	/* Create a self-signed CA certificate */
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptContext ) )
		return( FALSE );
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCert, cACertData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		cryptDestroyCert( status );
		return( FALSE );
		}

	/* Open the keyset, write the key and certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
					useAltKeyfile ? TEST_PRIVKEY_ALT_FILE : TEST_PRIVKEY_FILE,
					CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );
	cryptDestroyCert( cryptCert );

	/* Try and read the key+certificate back before we close the keyset.  
	   This ensures that the in-memory data has been updated correctly.  We 
	   use the generic RSA key label to read it since this isn't a real user
	   key */
	if( !useAltKeyfile )
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
									 TEST_PRIVKEY_PASSWORD );
		cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, 
						   "private key read from in-memory cached keyset data", 
						   status, __LINE__ );
			return( FALSE );
			}
		}

	/* Close the keyset, which flushes the in-memory changes to disk.  The
	   cacheing of data in memory ensures that all keyset updates are atomic,
	   so that it's nearly impossible to corrupt a private key keyset during
	   an update */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Try and read the key+certificate back from disk rather than the 
	   cached, in-memory version */
	if( !useAltKeyfile )
		{
		status = getPrivateKey( &cryptContext, TEST_PRIVKEY_FILE,
								RSA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			{
			printExtError( cryptKeyset, 
						   "private key read from on-disk keyset data", 
						   status, __LINE__ );
			return( FALSE );
			}
		}

	puts( "Single-step key+certificate write to key file succeeded.\n" );
	return( TRUE );
	}

int testSingleStepFileCert( void )
	{
	return( writeSingleStepFileCert( FALSE ) );
	}

int testSingleStepAltFileCert( void )
	{
	return( writeSingleStepFileCert( TRUE ) );
	}

/* Write two keys and certs (signature + encryption) with the same DN to a
   file */

int testDoubleCertFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptSigCert, cryptEncryptCert;
	CRYPT_CONTEXT cryptCAKey, cryptSigContext, cryptEncryptContext;
	int status;

	puts( "Testing separate signature+encryption certificate write to key "
		  "file..." );
	doubleCertOK = FALSE;

	/* Get the CA's key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Generate two keys to certify.  We can't just use the built-in test key
	   because cryptlib will detect it being added to the keyset a second time
	   (if we reuse it for both keys) and because the label is a generic one
	   that doesn't work if there are two keys */
	status = cryptCreateContext( &cryptSigContext, CRYPT_UNUSED,
								 CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		{
		status = cryptSetAttributeString( cryptSigContext,
							CRYPT_CTXINFO_LABEL, DUAL_SIGNKEY_LABEL,
							paramStrlen( DUAL_SIGNKEY_LABEL ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptSigContext );
	if( cryptStatusError( status ) )
		{
		printf( "Test key generation failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCreateContext( &cryptEncryptContext, CRYPT_UNUSED,
								 CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptEncryptContext,
							CRYPT_CTXINFO_LABEL, DUAL_ENCRYPTKEY_LABEL,
							paramStrlen( DUAL_ENCRYPTKEY_LABEL ) );
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptEncryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Test key generation failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the certs containing the keys.  In order to avoid clashes with
	   other keys with the same CN in the public-key database, we give the
	   certs abnormal CNs.  This isn't necessary for cryptlib to manage them,
	   but because later code tries to delete leftover certs from previous
	   runs with the generic name used in the self-tests, which would also
	   delete these certs */
	status = cryptCreateCert( &cryptSigCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSigCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptSigContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptSigCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		status = cryptDeleteAttribute( cryptSigCert,
									   CRYPT_CERTINFO_COMMONNAME );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptSigCert,
					CRYPT_CERTINFO_COMMONNAME, TEXT( "Dave Smith (Dual)" ),
					paramStrlen( TEXT( "Dave Smith (Dual)" ) ) );
			}
		}
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSigCert,
					CRYPT_CERTINFO_KEYUSAGE, CRYPT_KEYUSAGE_DIGITALSIGNATURE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptSigCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Signature certificate creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptSigCert );
		return( FALSE );
		}
	status = cryptCreateCert( &cryptEncryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptEncryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptEncryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptEncryptCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		status = cryptDeleteAttribute( cryptEncryptCert,
									   CRYPT_CERTINFO_COMMONNAME );
		if( cryptStatusOK( status ) )
			{
			status = cryptSetAttributeString( cryptEncryptCert,
					CRYPT_CERTINFO_COMMONNAME, TEXT( "Dave Smith (Dual)" ),
					paramStrlen( TEXT( "Dave Smith (Dual)" ) ) );
			}
		}
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptEncryptCert,
					CRYPT_CERTINFO_KEYUSAGE, CRYPT_KEYUSAGE_KEYENCIPHERMENT );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptEncryptCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Encryption certificate creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptEncryptCert );
		return( FALSE );
		}
	cryptDestroyContext( cryptCAKey );

	/* Open the keyset, write the keys and certificates, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  DUAL_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptSigContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		status = cryptAddPrivateKey( cryptKeyset, cryptEncryptContext,
									 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptSigCert );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptEncryptCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Write the two certs to a public-key database if there's one available
	   (because it may not be present, we fail quietly if access to this
	   keyset type isn't available or the keyset isn't present, it'll be
	   picked up later by other tests).

	   This certificate write is needed later to test the encryption vs. 
	   signature certificate handling.  Since they may have been added 
	   earlier we try and delete them first (we can't use the existing 
	   version since the issuerAndSerialNumber won't match the ones in the 
	   private-key keyset) */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED,
							  DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME,
							  CRYPT_KEYOPT_NONE );
	if( status != CRYPT_ERROR_PARAM3 && status != CRYPT_ERROR_OPEN )
		{
		C_CHR name[ CRYPT_MAX_TEXTSIZE + 1 ];
		int length;

		if( cryptStatusError( status ) )
			{
			printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
					status, __LINE__ );
			if( status == CRYPT_ERROR_OPEN )
				return( CRYPT_ERROR_FAILED );
			return( FALSE );
			}
		cryptGetAttributeString( cryptSigCert, CRYPT_CERTINFO_COMMONNAME,
								 name, &length );
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		name[ length ] = TEXT( '\0' );
		do
			status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME, name );
		while( cryptStatusOK( status ) );
		if( status != CRYPT_ERROR_NOTFOUND )
			{
			/* Deletion of the existing keys failed for some reason, we can't
			   continue */
			return( extErrorExit( cryptKeyset, "cryptDeleteKey()",
								  status, __LINE__ ) );
			}
		status = cryptAddPublicKey( cryptKeyset, cryptSigCert );
		if( status != CRYPT_ERROR_NOTFOUND )
			{
			/* We can get a notfound if a database keyset is defined but
			   hasn't been initialised yet so the necessary tables don't
			   exist, it can be opened but an attempt to add a key will
			   return a not found error since it's the table itself rather
			   than any item within it that isn't being found */
			if( cryptStatusOK( status ) )
				status = cryptAddPublicKey( cryptKeyset, cryptEncryptCert );
			if( cryptStatusError( status ) )
				return( extErrorExit( cryptKeyset, "cryptAddPublicKey()",
									  status, __LINE__ ) );

			/* The double-certificate keyset is set up, remember this for 
			   later tests */
			doubleCertOK = TRUE;
			}
		cryptKeysetClose( cryptKeyset );
		}

	/* Clean up */
	cryptDestroyContext( cryptSigContext );
	cryptDestroyContext( cryptEncryptContext );
	cryptDestroyCert( cryptSigCert );
	cryptDestroyCert( cryptEncryptCert );

	/* Try and read the keys+certs back */
	status = getPrivateKey( &cryptSigContext, DUAL_PRIVKEY_FILE,
							DUAL_SIGNKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	cryptDestroyContext( cryptSigContext );
	if( cryptStatusOK( status ) )
		{
		status = getPrivateKey( &cryptEncryptContext, DUAL_PRIVKEY_FILE,
								DUAL_ENCRYPTKEY_LABEL, TEST_PRIVKEY_PASSWORD );
		cryptDestroyContext( cryptEncryptContext );
		}
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}

	puts( "Separate signature+encryption certificate write to key file "
		  "succeeded.\n" );
	return( TRUE );
	}

/* Write a key and two certs of different validity periods to a file */

#ifndef _WIN32_WCE	/* Windows CE doesn't support ANSI C time functions */

int testRenewedCertFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptOldCert, cryptNewCert;
	CRYPT_CONTEXT cryptCAKey, cryptContext;
	time_t writtenValidTo = 0 /* Dummy */, readValidTo;
	int dummy, status;

	puts( "Testing renewed certificate write to key file..." );

	/* Get the CA's key and the key to certify */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptContext ) )
		return( FALSE );

	/* Create the certs containing the keys */
	status = cryptCreateCert( &cryptOldCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptOldCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptOldCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		time_t validity = time( NULL );

		/* Valid for one month ending tomorrow (we can't make it already-
		   expired or cryptlib will complain) */
		validity += 86400;
		cryptSetAttributeString( cryptOldCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
		validity -= ( 86400 * 31 );
		status = cryptSetAttributeString( cryptOldCert,
					CRYPT_CERTINFO_VALIDFROM, &validity, sizeof( time_t ) );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptOldCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Signature certificate creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptOldCert );
		return( FALSE );
		}
	status = cryptCreateCert( &cryptNewCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptNewCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptNewCert, certRequestData, __LINE__ ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		{
		time_t validity = time( NULL );

		/* Valid for one month starting yesterday (it's actually valid for
		   one month + one day to sidestep the one-month sanity check in the
		   private key read code that warns of about-to-expire keys) */
		validity -= 86400;
		cryptSetAttributeString( cryptNewCert,
					CRYPT_CERTINFO_VALIDFROM, &validity, sizeof( time_t ) );
		validity += ( 86400 * 32 );
		status = cryptSetAttributeString( cryptNewCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
		writtenValidTo = validity;
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptNewCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Encryption certificate creation failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		printErrorAttributeInfo( cryptNewCert );
		return( FALSE );
		}
	cryptDestroyContext( cryptCAKey );

	/* First, open the keyset, write the key and certificates (using an
	   in-memory update), and close it.  This tests the ability to use
	   information cached in memory to handle the update */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptOldCert );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptNewCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, 
					   "cryptAddPublicKey() (in-memory update)", 
					   status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Then try again, but this time perform an on-disk update, closing the
	   keyset between the first and second update.  This tests the ability
	   to recover the information needed to handle the update from data in
	   the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptOldCert );
	if( cryptStatusOK( status ) )
		status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "Keyset creation in preparation for on-disk update failed "
				"with error code %d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  RENEW_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptNewCert );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptAddPublicKey() (on-disk update)", 
					   status, __LINE__ );
		return( FALSE );
		}
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( cryptContext );
	cryptDestroyCert( cryptOldCert );
	cryptDestroyCert( cryptNewCert );

	/* Try and read the (newest) key+certificate back */
	status = getPrivateKey( &cryptContext, RENEW_PRIVKEY_FILE,
							RSA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "Private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttributeString( cryptContext,
					CRYPT_CERTINFO_VALIDTO, &readValidTo, &dummy );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptContext, "cryptGetAttributeString",
							   status, __LINE__ ) );
	if( writtenValidTo != readValidTo )
		{
		const int diff = ( int ) ( readValidTo - writtenValidTo );
		const char *units = ( diff % 60 ) ? "seconds" : "minutes";

		printf( "Returned certificate != latest valid certificate, diff.= "
				"%d %s, line %d.\n", ( diff % 60 ) ? diff : diff / 60, 
				units, __LINE__ );
		if( diff == 3600 || diff ==  -3600 )
			{
			/* See the comment on DST issues in testcert.c */
			puts( "  (This is probably due to a difference between DST at "
				  "certificate creation and DST\n   now, and isn't a "
				  "serious problem)." );
			}
		else
			return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	puts( "Renewed certificate write to key file succeeded.\n" );
	return( TRUE );
	}

#else

int testRenewedCertFile( void )
	{
	/* Since the renewal is time-based, we can't easily test this under
	   WinCE */
	return( TRUE );
	}
#endif /* WinCE */

/* Test reading various non-cryptlib PKCS #15 files */

int testReadMiscFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
/*	CRYPT_CONTEXT cryptContext; */
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
	void *fileNamePtr = filenameBuffer;
	int status;

	puts( "Testing miscellaneous key file read..." );

	filenameFromTemplate( filenameBuffer, MISC_PRIVKEY_FILE_TEMPLATE, 1 );
#ifdef UNICODE_STRINGS
	mbstowcs( wcBuffer, filenameBuffer, strlen( filenameBuffer ) + 1 );
	fileNamePtr = wcBuffer;
#endif /* UNICODE_STRINGS */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  fileNamePtr, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't open/scan keyset, status %d, line %d.\n", 
				status, __LINE__ );
		return( FALSE );
		}
#if 0
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, 
								 CRYPT_KEYID_NAME, 
								 TEXT( "56303156793b318327b25a84808f2cb311c55b0b" ), 
								 TEXT( "PASSWORD" ) );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptKeyset, "cryptGetPrivateKey()", status, 
					   __LINE__ );
		return( FALSE );
		}
#endif /* 0 */
	cryptKeysetClose( cryptKeyset );

	puts( "Renewed certificate write to key file succeeded.\n" );
	return( TRUE );
	}

/****************************************************************************
*																			*
*								Test Key Generation							*
*																			*
****************************************************************************/

/* The code to generate test CA or other special-purpose certs enables 
   various special-case extensions such as extKeyUsages or protocol-specific 
   AIA entries, as well as using a validity period of 5 years instead of the 
   usual 1 year to avoid problems when users run the self-test on very old 
   copies of the code.  The keys generated are:

	File define			File			Description
	-----------			----			-----------
	CA_PRIVKEY_FILE		key_ca.p15		Root CA key.
										Also writes CMP_CA_FILE.
	ICA_PRIVKEY_FILE	key_ica.p15		Intermediate CA key + root CA cert.
	SCEPCA_PRIVKEY_FILE	key_sca.p15		SCEP CA key + root CA cert, SCEP CA
										keyUsage allows encryption + signing.
										Also writes SCEP_CA_FILE.
	SERVER_PRIVKEY_FILE	key_srv.p15		SSL server key + root CA cert, server
										cert has CN = localhost, OCSP AIA.
	SSH_PRIVKEY_FILE	key_ssh.p15		Raw SSH key.
	TSA_PRIVKEY_FILE	key_tsa.p15		TSA server key + root CA cert, TSA 
										cert has TSP extKeyUsage.
	USER_PRIVKEY_FILE	key_user.p15	User key + root CA cert, user cert 
										has email address.
										
										(OCSP_CA_FILE is written by the
										testCertManagement() code) */

#if 0

/* Create a standalone private key + certificate */

static int createCAKeyFile( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	BYTE certBuffer[ BUFFER_SIZE ];
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifndef _WIN32_WCE	/* Windows CE doesn't support ANSI C time functions */
	const time_t validity = time( NULL ) + ( 86400L * 365 * 3 );
#endif /* _WIN32_WCE */
	int length, status;

	/* Create a self-signed CA certificate */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, CRYPT_ALGO_RSA );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
										  CA_PRIVKEY_LABEL,
										  paramStrlen( CA_PRIVKEY_LABEL ) );
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	if( !addCertFields( cryptCert, cACertData, __LINE__ ) )
		return( CRYPT_ERROR_FAILED );

#ifndef _WIN32_WCE	/* Windows CE doesn't support ANSI C time functions */
	/* Make it valid for 5 years instead of 1 to avoid problems when users
	   run the self-test with very old copies of the code */
	cryptSetAttributeString( cryptCert,
					CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, cryptContext );
	if( cryptStatusError( status ) )
		return( status );
#endif /* _WIN32_WCE */

	/* Open the keyset, update it with the certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  CA_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptAddPrivateKey( cryptKeyset, cryptContext, 
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		return( status );

	/* Save the certificate to disk for use in request/response protocols */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &length,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( status );
	filenameFromTemplate( filenameBuffer, CMP_CA_FILE_TEMPLATE, 1 );
	if( ( filePtr = fopen( filenameBuffer, "wb" ) ) != NULL )
		{
		int count;

		count = fwrite( certBuffer, 1, length, filePtr );
		fclose( filePtr );
		if( count < length )
			{
			remove( fileName );
			puts( "Warning: Couldn't save CA certificate to disk, "
				  "this will cause later\n         tests to fail.  "
				  "Press a key to continue." );
			getchar();
			}
		}

	cryptDestroyCert( cryptCert );
	cryptDestroyContext( cryptContext );
	cryptKeysetClose( cryptKeyset );

	return( CRYPT_OK );
	}

/* Create a raw SSH private key */

static int createSSHKeyFile( const int keyNo )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
	int status;

	/* Create a private key */
	status = cryptCreateContext( &cryptContext, CRYPT_UNUSED, 
								 ( keyNo == 1 ) ? CRYPT_ALGO_RSA : \
												  CRYPT_ALGO_DSA );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
										  USER_PRIVKEY_LABEL,
										  paramStrlen( USER_PRIVKEY_LABEL ) );
	if( cryptStatusOK( status ) )
		status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Open the keyset, add the key, and close it */
	filenameFromTemplate( filenameBuffer, SSH_PRIVKEY_FILE_TEMPLATE, keyNo );
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  filenameBuffer, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptAddPrivateKey( cryptKeyset, cryptContext, 
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		return( status );
	cryptDestroyContext( cryptContext );
	cryptKeysetClose( cryptKeyset );

	return( CRYPT_OK );
	}

/* Create a private key + certificate + CA certificate */

static const CERT_DATA FAR_BSS serverCertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Server cert" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "localhost" ) },

	/* Add an OCSP AIA entry */
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_AUTHORITYINFO_OCSP },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://localhost" ) },
	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA FAR_BSS iCACertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Intermediate CA cert" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave's Spare CA" ) },

	/* Set the CA key usage extensions */
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYCERTSIGN },
	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA FAR_BSS scepCACertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "SCEP CA cert" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave's SCEP CA" ) },

	/* Set the CA as well as generic sign+encrypt key usage extensions */
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYCERTSIGN | \
										   CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
										   CRYPT_KEYUSAGE_KEYENCIPHERMENT },
	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA FAR_BSS tsaCertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "TSA Cert" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave's TSA" ) },

	/* Set the TSP extended key usage */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_TIMESTAMPING, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

static const CERT_DATA FAR_BSS userCertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },
	{ CRYPT_CERTINFO_EMAIL, IS_STRING, 0, TEXT( "dave@wetaburgers.com" ) },
	{ CRYPT_ATTRIBUTE_CURRENT, IS_NUMERIC, CRYPT_CERTINFO_SUBJECTNAME },	/* Re-select subject DN */

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int createTestKeys( void )
	{
	char filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */
	void *fileNamePtr = filenameBuffer;
	int status;

	puts( "Creating custom key files..." );

	printf( "CA root key... " );
	status = createCAKeyFile();
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nSSH RSA server key..." );
		status = createSSHKeyFile( 1 );
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nSSH DSA server key..." );
		status = createSSHKeyFile( 2 );
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nSSL server key..." );
		if( !writeFileCertChain( serverCertRequestData, SERVER_PRIVKEY_FILE,
								 NULL, FALSE, FALSE ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nIntermediate CA key..." );
		if( !writeFileCertChain( iCACertRequestData, ICA_PRIVKEY_FILE,
								 NULL, FALSE, FALSE ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nSCEP CA key..." );
		filenameFromTemplate( filenameBuffer, SCEP_CA_FILE_TEMPLATE, 1 );
#ifdef UNICODE_STRINGS
		mbstowcs( wcBuffer, filenameBuffer, strlen( filenameBuffer ) + 1 );
		fileNamePtr = wcBuffer;
#endif /* UNICODE_STRINGS */
		if( !writeFileCertChain( scepCACertRequestData, SCEPCA_PRIVKEY_FILE,
								 fileNamePtr, FALSE, FALSE ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nTSA key..." );
		if( !writeFileCertChain( tsaCertRequestData, TSA_PRIVKEY_FILE,
								 NULL, FALSE, FALSE ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		{
		printf( "done.\nUser key..." );
		if( !writeFileCertChain( userCertRequestData, USER_PRIVKEY_FILE,
								 NULL, FALSE, FALSE ) )
			status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusError( status ) )
		{
		puts( "\nCustom key file create failed.\n" );
		return( FALSE );
		}
	puts( "done." );

	puts( "Custom key file creation succeeded.\n" );
	return( TRUE );
	}
#endif /* 0 */

#endif /* TEST_KEYSET */
