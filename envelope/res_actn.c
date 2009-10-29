/****************************************************************************
*																			*
*						cryptlib Envelope Action Management					*
*						Copyright Peter Gutmann 1996-2008					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "envelope.h"
#else
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

/* The maximum number of actions that we can add to an action list */

#define MAX_ACTIONS		FAILSAFE_ITERATIONS_MED - 1

#ifdef USE_ENVELOPES

/****************************************************************************
*																			*
*								Find an Action								*
*																			*
****************************************************************************/

/* Find an action of a given type and the last action of a given type.
   Since the lists are sorted by action type, the generic findAction()
   finds the start of an action group.
   
   The casting to a non-const is a bit ugly but is necessitated by the fact 
   that while the functions don't change the action list entries, the caller 
   will */

CHECK_RETVAL_PTR \
ACTION_LIST *findAction( IN_OPT const ACTION_LIST *actionListPtr,
						 IN_ENUM( ACTION ) const ACTION_TYPE actionType )
	{
	int iterationCount;
	
	assert( actionListPtr == NULL || \
			isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );

	REQUIRES_N( actionType == ACTION_KEYEXCHANGE || \
				actionType == ACTION_KEYEXCHANGE_PKC || \
				actionType == ACTION_SIGN || \
				actionType == ACTION_HASH || \
				actionType == ACTION_MAC || \
				actionType == ACTION_CRYPT );

	for( iterationCount = 0;
		 actionListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED;
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		if( actionListPtr->action == actionType )
			return( ( ACTION_LIST * ) actionListPtr );
		}
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( NULL );
	}

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
ACTION_LIST *findLastAction( const ACTION_LIST *actionListPtr,
							 IN_ENUM( ACTION ) const ACTION_TYPE actionType )
	{
	int iterationCount;

	assert( actionListPtr == NULL || \
			isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );

	REQUIRES_N( actionType == ACTION_KEYEXCHANGE || \
				actionType == ACTION_KEYEXCHANGE_PKC || \
				actionType == ACTION_SIGN || \
				actionType == ACTION_HASH || \
				actionType == ACTION_MAC || \
				actionType == ACTION_CRYPT );

	/* Find the start of the action group */
	actionListPtr = findAction( actionListPtr, actionType );
	if( actionListPtr == NULL )
		return( NULL );

	/* Find the end of the action group */
	for( iterationCount = 0;
		 actionListPtr->next != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_MED;
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		if( actionListPtr->next->action != actionType )
			break;
		}
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( ( ACTION_LIST * ) actionListPtr );
	}

/* An indirect action-check function that uses a caller-supplied callback to 
   verify a match for an action */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1, 2 ) ) \
ACTION_LIST *findActionIndirect( const ACTION_LIST *actionListStart,
								 IN CHECKACTIONFUNCTION checkActionFunction,
								 IN_INT_Z const int intParam )
	{
	const ACTION_LIST *actionListPtr;
	int iterationCount;

	assert( isReadPtr( actionListStart, sizeof( ACTION_LIST ) ) );

	REQUIRES_N( checkActionFunction != NULL );

	for( actionListPtr = actionListStart, iterationCount = 0;
		 actionListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED; 
		 actionListPtr = actionListPtr->next, iterationCount++ )
		 {
		 const int status = checkActionFunction( actionListPtr, intParam );
		 if( cryptStatusOK( status ) )
			return( ( ACTION_LIST * ) actionListPtr );
		 }
	ENSURES_N( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( NULL );
	}

/****************************************************************************
*																			*
*								Add/Delete an Action						*
*																			*
****************************************************************************/

/* Check whether more actions can be added to an action list */

CHECK_RETVAL_BOOL \
BOOLEAN moreActionsPossible( IN_OPT const ACTION_LIST *actionListPtr )
	{
	int actionCount;

	assert( actionListPtr == NULL || \
			isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );

	for( actionCount = 0;
		 actionListPtr != NULL && actionCount < FAILSAFE_ITERATIONS_MED;
		 actionListPtr = actionListPtr->next, actionCount++ );
	ENSURES_B( actionCount < FAILSAFE_ITERATIONS_MED );

	return( ( actionCount < MAX_ACTIONS ) ? TRUE : FALSE );
	}

/* Add a new action to the end of an action group in an action list */

CHECK_RETVAL STDC_NONNULL_ARG( ( 2, 3 ) ) \
static int createNewAction( OUT_OPT_PTR ACTION_LIST **newActionPtrPtr,
							OUT_PTR ACTION_LIST **actionListHeadPtrPtr,
							INOUT MEMPOOL_STATE memPoolState,
							IN_ENUM( ACTION ) const ACTION_TYPE actionType,
							IN_HANDLE const CRYPT_HANDLE cryptHandle )							
	{
	ACTION_LIST *actionListPtr, *prevActionPtr = NULL;
	ACTION_LIST *newItem;
	int iterationCount;

	assert( newActionPtrPtr == NULL || \
			isWritePtr( newActionPtrPtr, sizeof( ACTION_LIST * ) ) );
	assert( isWritePtr( actionListHeadPtrPtr, sizeof( ACTION_LIST * ) ) );
	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );

	REQUIRES( actionType == ACTION_KEYEXCHANGE || \
			  actionType == ACTION_KEYEXCHANGE_PKC || \
			  actionType == ACTION_SIGN || \
			  actionType == ACTION_HASH || \
			  actionType == ACTION_MAC || \
			  actionType == ACTION_CRYPT );
	REQUIRES( isHandleRangeValid( cryptHandle ) );

	/* Clear return value */
	if( newActionPtrPtr != NULL )
		*newActionPtrPtr = NULL;

	/* Create the new action list item */
	if( ( newItem = getMemPool( memPoolState, \
								sizeof( ACTION_LIST ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newItem, 0, sizeof( ACTION_LIST ) );
	newItem->action = actionType;
	newItem->iCryptHandle = cryptHandle;
	newItem->iExtraData = CRYPT_ERROR;
	newItem->iTspSession = CRYPT_ERROR;

	/* Find the last action in the action group */
	for( actionListPtr = *actionListHeadPtrPtr, iterationCount = 0;
		 actionListPtr != NULL && actionListPtr->action <= actionType && \
			iterationCount < FAILSAFE_ITERATIONS_MED;
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		prevActionPtr = actionListPtr;
		}
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	/* Append the new action */
#if 0	/* 1/4/08 Changed to use insertSingleListElement() */
	if( prevActionPtr == NULL )
		*actionListHeadPtrPtr = newItem;
	else
		prevActionPtr->next = newItem;
	newItem->next = actionListPtr;
#else
	insertSingleListElement( actionListHeadPtrPtr, prevActionPtr, newItem );
#endif /* 0 */
	if( newActionPtrPtr != NULL )
		*newActionPtrPtr = newItem;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
int addActionEx( OUT_PTR ACTION_LIST **newActionPtrPtr,
				 OUT_PTR ACTION_LIST **actionListHeadPtrPtr,
				 INOUT MEMPOOL_STATE memPoolState,
				 IN_ENUM( ACTION ) const ACTION_TYPE actionType,
				 IN_HANDLE const CRYPT_HANDLE cryptHandle )
	{
	assert( isWritePtr( newActionPtrPtr, sizeof( ACTION_LIST * ) ) );
		/* Rest are checked in createNewAction() */

	return( createNewAction( newActionPtrPtr, actionListHeadPtrPtr, 
							 memPoolState, actionType, cryptHandle ) );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int addAction( OUT_PTR ACTION_LIST **actionListHeadPtrPtr,
			   INOUT MEMPOOL_STATE memPoolState,
			   IN_ENUM( ACTION ) const ACTION_TYPE actionType,
			   IN_HANDLE const CRYPT_HANDLE cryptHandle )
	{
	return( createNewAction( NULL, actionListHeadPtrPtr, memPoolState, 
							 actionType, cryptHandle ) );
	}

/* Delete an action from an action list */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
static void deleteActionListItem( INOUT MEMPOOL_STATE memPoolState,
								  INOUT ACTION_LIST *actionListItem )
	{
	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( isWritePtr( actionListItem, sizeof( ACTION_LIST ) ) );

	/* Destroy any attached objects and information if necessary and
	   clear the list item memory */
	if( actionListItem->iCryptHandle != CRYPT_ERROR )
		krnlSendNotifier( actionListItem->iCryptHandle, IMESSAGE_DECREFCOUNT );
	if( actionListItem->iExtraData != CRYPT_ERROR )
		krnlSendNotifier( actionListItem->iExtraData, IMESSAGE_DECREFCOUNT );
	if( actionListItem->iTspSession != CRYPT_ERROR )
		krnlSendNotifier( actionListItem->iTspSession, IMESSAGE_DECREFCOUNT );
	zeroise( actionListItem, sizeof( ACTION_LIST ) );
	freeMemPool( memPoolState, actionListItem );
	}

STDC_NONNULL_ARG( ( 1, 2, 3 ) ) \
void deleteAction( INOUT_PTR ACTION_LIST **actionListHeadPtrPtr, 
				   INOUT MEMPOOL_STATE memPoolState,	
				   INOUT ACTION_LIST *actionListItem )
	{
	ACTION_LIST *listPrevPtr;
	int iterationCount;

	assert( isWritePtr( actionListHeadPtrPtr, sizeof( ACTION_LIST * ) ) );
	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( isWritePtr( actionListItem, sizeof( ACTION_LIST ) ) );

	REQUIRES_V( *actionListHeadPtrPtr != NULL );
	REQUIRES_V( actionListItem != NULL );
				/* Without this explicit assertion static analysers may 
				   assume that deleteSingleListElement() will dereference a 
				   NULL pointer */

	/* Find the previons entry in the list */
	for( listPrevPtr = *actionListHeadPtrPtr, iterationCount = 0;
		 listPrevPtr != NULL && listPrevPtr->next != actionListItem && \
			iterationCount < FAILSAFE_ITERATIONS_MED;
		 listPrevPtr = listPrevPtr->next, iterationCount++ );
	ENSURES_V( iterationCount < FAILSAFE_ITERATIONS_MED );

	/* Remove the item from the list */
	deleteSingleListElement( actionListHeadPtrPtr, listPrevPtr, 
							 actionListItem );

	/* Clear all data in the list item and free the memory */
	deleteActionListItem( memPoolState, actionListItem );
	}

/* Delete an action list */

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void deleteActionList( INOUT MEMPOOL_STATE memPoolState,
					   INOUT ACTION_LIST *actionListPtr )
	{
	int iterationCount;

	assert( isWritePtr( memPoolState, sizeof( MEMPOOL_STATE ) ) );
	assert( isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );

	for( iterationCount = 0;
		 actionListPtr != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_MED;
		 iterationCount++ )
		{
		ACTION_LIST *actionListItem = actionListPtr;

		actionListPtr = actionListPtr->next;
		deleteActionListItem( memPoolState, actionListItem );
		}
	ENSURES_V( iterationCount < FAILSAFE_ITERATIONS_MED );
	}

/* Delete any orphaned actions, for example automatically-added hash actions
   that were overridden by user-supplied alternate actions */

STDC_NONNULL_ARG( ( 1 ) ) \
void deleteUnusedActions( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr;
	int iterationCount;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* Check for unattached hash/MAC or encryption actions and delete them */
	for( actionListPtr = envelopeInfoPtr->actionList, iterationCount = 0;
		 actionListPtr != NULL && \
			iterationCount < FAILSAFE_ITERATIONS_MED;
		 iterationCount++ )
		{
		ACTION_LIST *actionListCurrent = actionListPtr;

		actionListPtr = actionListPtr->next;
		if( ( actionListCurrent->action == ACTION_HASH || \
			  actionListCurrent->action == ACTION_MAC || \
			  actionListCurrent->action == ACTION_CRYPT ) && \
			( actionListCurrent->flags & ACTION_NEEDSCONTROLLER ) )
			{
			deleteAction( &envelopeInfoPtr->actionList,
						  envelopeInfoPtr->memPoolState, actionListCurrent );
			}
		}
	ENSURES_V( iterationCount < FAILSAFE_ITERATIONS_MED );
	}

/****************************************************************************
*																			*
*								Check an Action								*
*																			*
****************************************************************************/

/* Check a new action to make sure that it isn't already present in the
   action list, producing an ACTION_RESULT outcome */

CHECK_RETVAL_ENUM( ACTION ) \
ACTION_RESULT checkAction( IN_OPT const ACTION_LIST *actionListStart,
						   IN_ENUM( ACTION ) const ACTION_TYPE actionType, 
						   IN_HANDLE const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListPtr = ( ACTION_LIST * ) actionListStart;
	MESSAGE_DATA msgData;
	BYTE keyID[ KEYID_SIZE + 8 ];
	CRYPT_ALGO_TYPE cryptAlgo = DUMMY_INIT;
	int iterationCount, status;

	assert( actionListPtr == NULL || \
			isReadPtr( actionListPtr, sizeof( ACTION_LIST ) ) );

	REQUIRES_EXT( ( actionType == ACTION_KEYEXCHANGE || \
					actionType == ACTION_KEYEXCHANGE_PKC || \
					actionType == ACTION_SIGN || \
					actionType == ACTION_HASH || \
					actionType == ACTION_MAC || \
					actionType == ACTION_CRYPT ), ACTION_RESULT_ERROR );
	REQUIRES_EXT( isHandleRangeValid( cryptHandle ), ACTION_RESULT_ERROR );

	/* If the action list is empty, there's nothing to check */
	if( actionListPtr == NULL )
		return( ACTION_RESULT_EMPTY );

	/* Get identification information for the action object */
	switch( actionType )
		{
		case ACTION_KEYEXCHANGE:
			/* For conventional key wrap we can't really do much, for raw
			   action objects we'd check the algorithm for duplicates but
			   it's perfectly valid to wrap a single session/MAC key using
			   multiple key wrap objects with the same algorithm */
			status = CRYPT_OK;
			break;

		case ACTION_KEYEXCHANGE_PKC:
		case ACTION_SIGN:
			/* It's a PKC object, get the key ID */
			setMessageData( &msgData, keyID, KEYID_SIZE );
			status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_IATTRIBUTE_KEYID );
			break;

		case ACTION_HASH:
		case ACTION_MAC:
		case ACTION_CRYPT:
			/* It's a raw action object, get the algorithm */
			status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE,
									  &cryptAlgo, CRYPT_CTXINFO_ALGO );
			break;

		default:
			retIntError_Ext( ACTION_RESULT_ERROR );
		}
	if( cryptStatusError( status ) )
		return( ACTION_RESULT_ERROR );

	/* Walk down the list from the first to the last action in the action
	   group checking each one in turn */
	for( actionListPtr = findAction( actionListPtr, actionType ), \
			iterationCount = 0;
		 actionListPtr != NULL && actionListPtr->action == actionType && \
			iterationCount < FAILSAFE_ITERATIONS_MED;
		 actionListPtr = actionListPtr->next, iterationCount++ )
		{
		BOOLEAN isDuplicate = FALSE;
		int actionAlgo;

		/* Make sure that we haven't added this action already.  This can
		   get a bit tricky both because detecting some types of duplicates
		   is rather hard and because the definition of what's an invalid
		   duplicate varies somewhat.  For a hash, MAC, and encryption
		   action we only allow one action of a given algorithm type to
		   be added.  For a PKC key exchange or signature action we only
		   allow one action for a given key to be added.  For a conventional
		   key exchange action we should in theory check for duplicates in
		   some form but it's not certain what constitutes a duplicate (for
		   example are two otherwise identical actions with a different
		   number of key setup iterations considered duplicates or not?) so
		   for now we assume that the user won't do anything silly (in any 
		   case for any key exchange action the only thing that a duplicate 
		   will do is result in unnecessary bloating of the envelope 
		   header).

		   In addition to the more sophisticated checks we also perform a 
		   few more basic ones for the same object being added twice, which
		   doesn't catch e.g. inadvertent use of the same keying material
		   but does catch simple programming errors */
		if( actionListPtr->iCryptHandle == cryptHandle )
			return( ACTION_RESULT_INITED );
		switch( actionType )
			{
			case ACTION_KEYEXCHANGE:
				/* It's a conventional key exchange, there's not much that
				   we can check */
				break;

			case ACTION_KEYEXCHANGE_PKC:
			case ACTION_SIGN:
				/* It's a PKC key exchange or signature action, compare the
				   two objects by comparing their keys */
				setMessageData( &msgData, keyID, KEYID_SIZE );
				if( cryptStatusOK( \
						krnlSendMessage( actionListPtr->iCryptHandle,
										 IMESSAGE_COMPARE, &msgData,
										 MESSAGE_COMPARE_KEYID ) ) )
					isDuplicate = TRUE;
				break;

			case ACTION_HASH:
			case ACTION_MAC:
			case ACTION_CRYPT:
				/* It's a hash/MAC or session key object, compare the two
				   objects by comparing their algorithms */
				if( cryptStatusOK( \
					krnlSendMessage( actionListPtr->iCryptHandle,
									 IMESSAGE_GETATTRIBUTE, &actionAlgo,
									 CRYPT_CTXINFO_ALGO ) ) && \
					actionAlgo == cryptAlgo )
					isDuplicate = TRUE;
				break;

			}
		if( isDuplicate )
			{
			/* If the action was added automatically/implicitly as the
			   result of adding another action then the first attempt to add
			   it explicitly by the caller isn't an error.  The caller will
			   treat the ACTION_RESULT_PRESENT code as CRYPT_OK */
			if( actionListPtr->flags & ACTION_ADDEDAUTOMATICALLY )
				{
				actionListPtr->flags &= ~ACTION_ADDEDAUTOMATICALLY;
				return( ACTION_RESULT_PRESENT );
				}

			return( ACTION_RESULT_INITED );
			}
		}
	ENSURES_EXT( ( iterationCount < FAILSAFE_ITERATIONS_MED ), \
				 ACTION_RESULT_ERROR );

	return( ACTION_RESULT_OK );
	}

/* An indirect action-check function that uses a caller-supplied callback to 
   verify each action */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int checkActionIndirect( const ACTION_LIST *actionListStart,
						 IN CHECKACTIONFUNCTION checkActionFunction,
						 IN_INT_Z const int intParam )
	{
	const ACTION_LIST *actionListPtr;
	int iterationCount;

	assert( isReadPtr( actionListStart, sizeof( ACTION_LIST ) ) );

	REQUIRES( checkActionFunction != NULL );

	for( actionListPtr = actionListStart, iterationCount = 0;
		 actionListPtr != NULL && iterationCount < FAILSAFE_ITERATIONS_MED; 
		 actionListPtr = actionListPtr->next, iterationCount++ )
		 {
		 const int status = checkActionFunction( actionListPtr, intParam );
		 if( cryptStatusError( status ) )
			return( status );
		 }
	ENSURES( iterationCount < FAILSAFE_ITERATIONS_MED );

	return( CRYPT_OK );
	}

/* Perform a sanity-check to ensure that the actions in an envelope are
   consistent.  There are two approaches to this, take the envelope usage 
   and check that everything is consistent with it, or take the actions
   and make sure that they're consistent with the usage (and each other).  
   We perform the latter type of check, which is somewhat simpler.  The
   requirements that we enforce are:

			|	Pre		|	In		|	Post	|
	--------+-----------+-----------+-----------+-----
	  SIG	|	  -		|	Hash	|	 Sig	| CMS
			|	  -		| 1x Hash	|  1x Sig	| PGP
	--------+-----------+-----------+-----------+-----
	  MAC	| Keyex,PKC	|  1x MAC	|	  -		| CMS
			|	  -		|	  -		|	  -		| PGP
	--------+-----------+-----------+-----------+-----
	  COPR	|	  -		|	  -		|	  -		| CMS
			|	  -		|	  -		|	  -		| PGP
	--------+-----------+-----------+-----------+-----
	  ENCR	| Keyex,PKC	|	Crypt	|	  -		| CMS
			|	 PKC	| 1x Crypt	|	  -		| PGP

   In the case of ENCR the pre-actions can be absent if we're using raw 
   session-key encryption */

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN checkActions( INOUT ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr;
	int iterationCount;

	assert( isWritePtr( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) ) );

	/* If there are no pre-, post-, or main actions (i.e. it's a compressed
	   or data-only envelope), we're done */
	if( envelopeInfoPtr->actionList == NULL )
		{
		/* Make sure that the envelope has the appropriate usage for these 
		   actions */
		if( envelopeInfoPtr->usage != ACTION_COMPRESS && \
			envelopeInfoPtr->usage != ACTION_NONE )
			return( FALSE );

		/* There can be no pre- or post-actions present for this usage */
		if( envelopeInfoPtr->preActionList != NULL || \
			envelopeInfoPtr->postActionList != NULL )
			return( FALSE );

		return( TRUE );
		}

	/* If there are pre-actions it has to be a key exchange followed by 
	   encryption or MAC actions */
	if( envelopeInfoPtr->preActionList != NULL )
		{
		int actionCount = 0;

		/* Make sure that the envelope has the appropriate usage for these 
		   actions */
		if( envelopeInfoPtr->usage != ACTION_CRYPT && \
			envelopeInfoPtr->usage != ACTION_MAC )
			return( FALSE );

		/* Pre-actions can only be key exchange actions and have to be sorted 
		   by action group */
		for( actionListPtr = envelopeInfoPtr->preActionList, \
				iterationCount = 0;
			 actionListPtr != NULL && \
				actionListPtr->action == ACTION_KEYEXCHANGE_PKC && \
				iterationCount < FAILSAFE_ITERATIONS_MED;
			actionListPtr = actionListPtr->next, iterationCount++ );
		ENSURES_B( iterationCount < FAILSAFE_ITERATIONS_MED );
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
			actionListPtr != NULL )
			{
			/* PGP can't have any conventional keyex actions since the 
			   password is used to directly derive the session key */
			return( FALSE );
			}
		for( iterationCount = 0;
			 actionListPtr != NULL && \
				actionListPtr->action == ACTION_KEYEXCHANGE && \
				iterationCount < FAILSAFE_ITERATIONS_MED;
			 actionListPtr = actionListPtr->next, iterationCount++ );
		ENSURES_B( iterationCount < FAILSAFE_ITERATIONS_MED );
		if( actionListPtr != NULL )
			return( FALSE );
		ENSURES_B( envelopeInfoPtr->actionList != NULL );

		/* Key exchange must be followed by a single crypt or one or more
		   MAC actions */
		for( actionListPtr = envelopeInfoPtr->actionList, iterationCount = 0;
			 actionListPtr != NULL && \
				iterationCount < FAILSAFE_ITERATIONS_MED; 
			 actionListPtr = actionListPtr->next, iterationCount++ )
			{
			if( actionListPtr->action == ACTION_CRYPT )
				actionCount++;
			else
				{
				if( actionListPtr->action != ACTION_MAC )
					return( FALSE );
				if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
					{
					/* PGP doesn't support MAC'd envelopes */
					return( FALSE );
					}
				}
			}
		ENSURES_B( iterationCount < FAILSAFE_ITERATIONS_MED );
		if( actionCount > 1 )
			return( FALSE );

		/* There can't be any post-actions */
		if( envelopeInfoPtr->postActionList != NULL )
			return( FALSE );

		return( TRUE );
		}

	/* If there are post-actions it has to be a hash follwed by signature 
	   actions */
	if( envelopeInfoPtr->postActionList != NULL )
		{
		int hashActionCount = 0, sigActionCount = 0;

		/* Make sure that the envelope has the appropriate usage for these 
		   actions */
		if( envelopeInfoPtr->usage != ACTION_SIGN )
			return( FALSE );

		/* There can't be any pre-actions */
		if( envelopeInfoPtr->preActionList != NULL )
			return( FALSE );

		/* The signature must be preceded by one or more hash actions */
		if( envelopeInfoPtr->actionList == NULL )
			return( FALSE );
		for( actionListPtr = envelopeInfoPtr->actionList, iterationCount = 0;
			 actionListPtr != NULL && \
				iterationCount < FAILSAFE_ITERATIONS_MED; 
			 actionListPtr = actionListPtr->next, iterationCount++ )
			{
			if( actionListPtr->action != ACTION_HASH )
				return( FALSE );
			hashActionCount++;
			}
		ENSURES_B( iterationCount < FAILSAFE_ITERATIONS_MED );

		/* PGP can only have a single hash per signed envelope */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && hashActionCount > 1 )
			return( FALSE );

		/* Hash actions must be followed by one or more signature actions */
		for( actionListPtr = envelopeInfoPtr->postActionList, \
				iterationCount = 0;
			 actionListPtr != NULL && \
				iterationCount < FAILSAFE_ITERATIONS_MED; 
			 actionListPtr = actionListPtr->next, iterationCount++ )
			{
			if( actionListPtr->action != ACTION_SIGN )
				return( FALSE );
			sigActionCount++;
			}
		ENSURES_B( iterationCount < FAILSAFE_ITERATIONS_MED );

		/* PGP can only have a single signature, multiple signatures are 
		   handled by nesting envelopes */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && sigActionCount > 1 )
			return( FALSE );

		return( TRUE );
		}

	/* If there's a standalone session-key encryption action, it has to be
	   the only action present */
	actionListPtr = envelopeInfoPtr->actionList;
	ENSURES_B( actionListPtr != NULL );
	if( actionListPtr->action == ACTION_CRYPT )
		{
		/* Make sure that the envelope has the appropriate usage for these 
		   actions */
		if( envelopeInfoPtr->usage != ACTION_CRYPT )
			return( FALSE );

		/* There can only be one encryption action present */
		if( actionListPtr->next != NULL )
			return( FALSE );

		return( TRUE );
		}

	/* If we're processing PGP-encrypted data with an MDC at the end of the 
	   encrypted data then it's possible to have an encryption envelope with
	   a hash action (which must be followed by an encryption action) */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
		actionListPtr->action == ACTION_HASH && \
		actionListPtr->next != NULL && \
		actionListPtr->next->action == ACTION_CRYPT )
		{
		ACTION_LIST *nextActionPtr = actionListPtr->next;

		/* Make sure that the envelope has the appropriate usage for these 
		   actions */
		if( envelopeInfoPtr->usage != ACTION_CRYPT )
			return( FALSE );

		/* Make sure that the encryption action is the only other action */
		if( nextActionPtr->action != ACTION_CRYPT || \
			nextActionPtr->next != NULL )
			return( FALSE );

		return( TRUE );
		}

	/* If it's a MACd envelope there can only be a single MAC action 
	   present */
	if( envelopeInfoPtr->usage == ACTION_MAC )
		{
		/* Make sure that there's only a single MAC action present */
		if( actionListPtr->action != ACTION_MAC || \
			actionListPtr->next != NULL )
			return( FALSE );

		return( TRUE );
		}

	/* Anything else has to be a signing envelope */
	if( envelopeInfoPtr->usage != ACTION_SIGN )
		return( FALSE );

	/* When we're de-enveloping a signed envelope we can have standalone
	   hash actions before we get to the signature data and add post-
	   actions */
	if( ( envelopeInfoPtr->flags & ENVELOPE_ISDEENVELOPE ) && \
		actionListPtr->action == ACTION_HASH )
		{
		for( iterationCount = 0; \
			 actionListPtr != NULL && \
				iterationCount < FAILSAFE_ITERATIONS_MED;
			 actionListPtr = actionListPtr->next, iterationCount++ )
			{
			if( actionListPtr->action != ACTION_HASH )
				return( FALSE );
			}
		ENSURES_B( iterationCount < FAILSAFE_ITERATIONS_MED );

		return( TRUE );
		}

	/* Everything else is an error */
	return( FALSE );
	}
#endif /* USE_ENVELOPES */
