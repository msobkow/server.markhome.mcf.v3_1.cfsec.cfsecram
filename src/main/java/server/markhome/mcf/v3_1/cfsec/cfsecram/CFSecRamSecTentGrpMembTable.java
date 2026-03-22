
// Description: Java 25 in-memory RAM DbIO implementation for SecTentGrpMemb.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecTentGrpMembTable in-memory RAM DbIO implementation
 *	for SecTentGrpMemb.
 */
public class CFSecRamSecTentGrpMembTable
	implements ICFSecSecTentGrpMembTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecTentGrpMembPKey,
				CFSecBuffSecTentGrpMemb > dictByPKey
		= new HashMap< ICFSecSecTentGrpMembPKey,
				CFSecBuffSecTentGrpMemb >();
	private Map< CFSecBuffSecTentGrpMembByTentGrpIdxKey,
				Map< CFSecBuffSecTentGrpMembPKey,
					CFSecBuffSecTentGrpMemb >> dictByTentGrpIdx
		= new HashMap< CFSecBuffSecTentGrpMembByTentGrpIdxKey,
				Map< CFSecBuffSecTentGrpMembPKey,
					CFSecBuffSecTentGrpMemb >>();
	private Map< CFSecBuffSecTentGrpMembByUserIdxKey,
				Map< CFSecBuffSecTentGrpMembPKey,
					CFSecBuffSecTentGrpMemb >> dictByUserIdx
		= new HashMap< CFSecBuffSecTentGrpMembByUserIdxKey,
				Map< CFSecBuffSecTentGrpMembPKey,
					CFSecBuffSecTentGrpMemb >>();

	public CFSecRamSecTentGrpMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecTentGrpMemb ensureRec(ICFSecSecTentGrpMemb rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecTentGrpMemb.CLASS_CODE) {
				return( ((CFSecBuffSecTentGrpMembDefaultFactory)(schema.getFactorySecTentGrpMemb())).ensureRec((ICFSecSecTentGrpMemb)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecTentGrpMemb createSecTentGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMemb iBuff )
	{
		final String S_ProcName = "createSecTentGrpMemb";
		
		CFSecBuffSecTentGrpMemb Buff = (CFSecBuffSecTentGrpMemb)ensureRec(iBuff);
		CFSecBuffSecTentGrpMembPKey pkey = (CFSecBuffSecTentGrpMembPKey)(schema.getFactorySecTentGrpMemb().newPKey());
		pkey.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		Buff.setRequiredSecTentGrpId( pkey.getRequiredSecTentGrpId() );
		Buff.setRequiredSecUserId( pkey.getRequiredSecUserId() );
		CFSecBuffSecTentGrpMembByTentGrpIdxKey keyTentGrpIdx = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getFactorySecTentGrpMemb().newByTentGrpIdxKey();
		keyTentGrpIdx.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpMembByUserIdxKey keyUserIdx = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getFactorySecTentGrpMemb().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictTentGrpIdx;
		if( dictByTentGrpIdx.containsKey( keyTentGrpIdx ) ) {
			subdictTentGrpIdx = dictByTentGrpIdx.get( keyTentGrpIdx );
		}
		else {
			subdictTentGrpIdx = new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByTentGrpIdx.put( keyTentGrpIdx, subdictTentGrpIdx );
		}
		subdictTentGrpIdx.put( pkey, Buff );

		Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictUserIdx;
		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			subdictUserIdx = dictByUserIdx.get( keyUserIdx );
		}
		else {
			subdictUserIdx = new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByUserIdx.put( keyUserIdx, subdictUserIdx );
		}
		subdictUserIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecTentGrpMemb.CLASS_CODE) {
				CFSecBuffSecTentGrpMemb retbuff = ((CFSecBuffSecTentGrpMemb)(schema.getFactorySecTentGrpMemb().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecTentGrpMemb readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		CFLibDbKeyHash256 SecUserId )
	{
		{	CFLibDbKeyHash256 testSecTentGrpId = SecTentGrpId;
			if (testSecTentGrpId == null) {
				return( null );
			}
		}
		{	CFLibDbKeyHash256 testSecUserId = SecUserId;
			if (testSecUserId == null) {
				return( null );
			}
		}
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredSecUserId( SecUserId );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecTentGrpMemb readDerived( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readDerived";
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( PKey.getRequiredSecTentGrpId() );
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		ICFSecSecTentGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpMemb lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.lockDerived";
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( PKey.getRequiredSecTentGrpId() );
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		ICFSecSecTentGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readAllDerived";
		ICFSecSecTentGrpMemb[] retList = new ICFSecSecTentGrpMemb[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecTentGrpMemb > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecTentGrpMemb[] readDerivedByTentGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readDerivedByTentGrpIdx";
		CFSecBuffSecTentGrpMembByTentGrpIdxKey key = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getFactorySecTentGrpMemb().newByTentGrpIdxKey();

		key.setRequiredSecTentGrpId( SecTentGrpId );
		ICFSecSecTentGrpMemb[] recArray;
		if( dictByTentGrpIdx.containsKey( key ) ) {
			Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictTentGrpIdx
				= dictByTentGrpIdx.get( key );
			recArray = new ICFSecSecTentGrpMemb[ subdictTentGrpIdx.size() ];
			Iterator< CFSecBuffSecTentGrpMemb > iter = subdictTentGrpIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictTentGrpIdx
				= new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByTentGrpIdx.put( key, subdictTentGrpIdx );
			recArray = new ICFSecSecTentGrpMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentGrpMemb[] readDerivedByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readDerivedByUserIdx";
		CFSecBuffSecTentGrpMembByUserIdxKey key = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getFactorySecTentGrpMemb().newByUserIdxKey();

		key.setRequiredSecUserId( SecUserId );
		ICFSecSecTentGrpMemb[] recArray;
		if( dictByUserIdx.containsKey( key ) ) {
			Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictUserIdx
				= dictByUserIdx.get( key );
			recArray = new ICFSecSecTentGrpMemb[ subdictUserIdx.size() ];
			Iterator< CFSecBuffSecTentGrpMemb > iter = subdictUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdictUserIdx
				= new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByUserIdx.put( key, subdictUserIdx );
			recArray = new ICFSecSecTentGrpMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentGrpMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readDerivedByIdIdx() ";
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredSecUserId( SecUserId );
		ICFSecSecTentGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpMemb readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		CFLibDbKeyHash256 SecUserId )
	{
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredSecUserId( SecUserId );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecTentGrpMemb readRec( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readRec";
		ICFSecSecTentGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpMemb lockRec( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecTentGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpMemb[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readAllRec";
		ICFSecSecTentGrpMemb buff;
		ArrayList<ICFSecSecTentGrpMemb> filteredList = new ArrayList<ICFSecSecTentGrpMemb>();
		ICFSecSecTentGrpMemb[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrpMemb[0] ) );
	}

	/**
	 *	Read a page of all the specific SecTentGrpMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecTentGrpMemb instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecTentGrpMemb[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecTentGrpId,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecTentGrpMemb readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readRecByIdIdx() ";
		ICFSecSecTentGrpMemb buff = readDerivedByIdIdx( Authorization,
			SecTentGrpId,
			SecUserId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
			return( (ICFSecSecTentGrpMemb)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecTentGrpMemb[] readRecByTentGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readRecByTentGrpIdx() ";
		ICFSecSecTentGrpMemb buff;
		ArrayList<ICFSecSecTentGrpMemb> filteredList = new ArrayList<ICFSecSecTentGrpMemb>();
		ICFSecSecTentGrpMemb[] buffList = readDerivedByTentGrpIdx( Authorization,
			SecTentGrpId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrpMemb[0] ) );
	}

	@Override
	public ICFSecSecTentGrpMemb[] readRecByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMemb.readRecByUserIdx() ";
		ICFSecSecTentGrpMemb buff;
		ArrayList<ICFSecSecTentGrpMemb> filteredList = new ArrayList<ICFSecSecTentGrpMemb>();
		ICFSecSecTentGrpMemb[] buffList = readDerivedByUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrpMemb[0] ) );
	}

	/**
	 *	Read a page array of the specific SecTentGrpMemb buffer instances identified by the duplicate key TentGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecTentGrpId	The SecTentGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecTentGrpMemb[] pageRecByTentGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		CFLibDbKeyHash256 priorSecTentGrpId,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByTentGrpIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecTentGrpMemb buffer instances identified by the duplicate key UserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecTentGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecTentGrpMemb[] pageRecByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		CFLibDbKeyHash256 priorSecTentGrpId,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecTentGrpMemb updateSecTentGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMemb iBuff )
	{
		CFSecBuffSecTentGrpMemb Buff = (CFSecBuffSecTentGrpMemb)ensureRec(iBuff);
		CFSecBuffSecTentGrpMembPKey pkey = (CFSecBuffSecTentGrpMembPKey)(schema.getFactorySecTentGrpMemb().newPKey());
		pkey.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		CFSecBuffSecTentGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecTentGrpMemb",
				"Existing record not found",
				"Existing record not found",
				"SecTentGrpMemb",
				"SecTentGrpMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecTentGrpMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecTentGrpMembByTentGrpIdxKey existingKeyTentGrpIdx = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getFactorySecTentGrpMemb().newByTentGrpIdxKey();
		existingKeyTentGrpIdx.setRequiredSecTentGrpId( existing.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpMembByTentGrpIdxKey newKeyTentGrpIdx = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getFactorySecTentGrpMemb().newByTentGrpIdxKey();
		newKeyTentGrpIdx.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpMembByUserIdxKey existingKeyUserIdx = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getFactorySecTentGrpMemb().newByUserIdxKey();
		existingKeyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecTentGrpMembByUserIdxKey newKeyUserIdx = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getFactorySecTentGrpMemb().newByUserIdxKey();
		newKeyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Check unique indexes

		// Validate foreign keys

		// Update is valid

		Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByTentGrpIdx.get( existingKeyTentGrpIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTentGrpIdx.containsKey( newKeyTentGrpIdx ) ) {
			subdict = dictByTentGrpIdx.get( newKeyTentGrpIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByTentGrpIdx.put( newKeyTentGrpIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByUserIdx.get( existingKeyUserIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByUserIdx.containsKey( newKeyUserIdx ) ) {
			subdict = dictByUserIdx.get( newKeyUserIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb >();
			dictByUserIdx.put( newKeyUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecTentGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMemb iBuff )
	{
		final String S_ProcName = "CFSecRamSecTentGrpMembTable.deleteSecTentGrpMemb() ";
		CFSecBuffSecTentGrpMemb Buff = (CFSecBuffSecTentGrpMemb)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecTentGrpMembPKey pkey = (CFSecBuffSecTentGrpMembPKey)(Buff.getPKey());
		CFSecBuffSecTentGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecTentGrpMemb",
				pkey );
		}
		CFSecBuffSecTentGrpMembByTentGrpIdxKey keyTentGrpIdx = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getFactorySecTentGrpMemb().newByTentGrpIdxKey();
		keyTentGrpIdx.setRequiredSecTentGrpId( existing.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpMembByUserIdxKey keyUserIdx = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getFactorySecTentGrpMemb().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecTentGrpMembPKey, CFSecBuffSecTentGrpMemb > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTentGrpIdx.get( keyTentGrpIdx );
		subdict.remove( pkey );

		subdict = dictByUserIdx.get( keyUserIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecTentGrpMembByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		CFLibDbKeyHash256 SecUserId )
	{
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredSecUserId( SecUserId );
		deleteSecTentGrpMembByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpMembByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembPKey PKey )
	{
		CFSecBuffSecTentGrpMembPKey key = (CFSecBuffSecTentGrpMembPKey)(schema.getFactorySecTentGrpMemb().newPKey());
		key.setRequiredSecTentGrpId( PKey.getRequiredSecTentGrpId() );
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		CFSecBuffSecTentGrpMembPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecTentGrpMemb cur;
		LinkedList<CFSecBuffSecTentGrpMemb> matchSet = new LinkedList<CFSecBuffSecTentGrpMemb>();
		Iterator<CFSecBuffSecTentGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrpMemb)(schema.getTableSecTentGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId(),
				cur.getRequiredSecUserId() ));
			deleteSecTentGrpMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentGrpMembByTentGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecTentGrpId )
	{
		CFSecBuffSecTentGrpMembByTentGrpIdxKey key = (CFSecBuffSecTentGrpMembByTentGrpIdxKey)schema.getFactorySecTentGrpMemb().newByTentGrpIdxKey();
		key.setRequiredSecTentGrpId( argSecTentGrpId );
		deleteSecTentGrpMembByTentGrpIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpMembByTentGrpIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembByTentGrpIdxKey argKey )
	{
		CFSecBuffSecTentGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentGrpMemb> matchSet = new LinkedList<CFSecBuffSecTentGrpMemb>();
		Iterator<CFSecBuffSecTentGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrpMemb)(schema.getTableSecTentGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId(),
				cur.getRequiredSecUserId() ));
			deleteSecTentGrpMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentGrpMembByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecBuffSecTentGrpMembByUserIdxKey key = (CFSecBuffSecTentGrpMembByUserIdxKey)schema.getFactorySecTentGrpMemb().newByUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecTentGrpMembByUserIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpMembByUserIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpMembByUserIdxKey argKey )
	{
		CFSecBuffSecTentGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentGrpMemb> matchSet = new LinkedList<CFSecBuffSecTentGrpMemb>();
		Iterator<CFSecBuffSecTentGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrpMemb)(schema.getTableSecTentGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId(),
				cur.getRequiredSecUserId() ));
			deleteSecTentGrpMemb( Authorization, cur );
		}
	}
}
