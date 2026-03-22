
// Description: Java 25 in-memory RAM DbIO implementation for SecClusGrpMemb.

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
 *	CFSecRamSecClusGrpMembTable in-memory RAM DbIO implementation
 *	for SecClusGrpMemb.
 */
public class CFSecRamSecClusGrpMembTable
	implements ICFSecSecClusGrpMembTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecClusGrpMembPKey,
				CFSecBuffSecClusGrpMemb > dictByPKey
		= new HashMap< ICFSecSecClusGrpMembPKey,
				CFSecBuffSecClusGrpMemb >();
	private Map< CFSecBuffSecClusGrpMembByClusGrpIdxKey,
				Map< CFSecBuffSecClusGrpMembPKey,
					CFSecBuffSecClusGrpMemb >> dictByClusGrpIdx
		= new HashMap< CFSecBuffSecClusGrpMembByClusGrpIdxKey,
				Map< CFSecBuffSecClusGrpMembPKey,
					CFSecBuffSecClusGrpMemb >>();
	private Map< CFSecBuffSecClusGrpMembByUserIdxKey,
				Map< CFSecBuffSecClusGrpMembPKey,
					CFSecBuffSecClusGrpMemb >> dictByUserIdx
		= new HashMap< CFSecBuffSecClusGrpMembByUserIdxKey,
				Map< CFSecBuffSecClusGrpMembPKey,
					CFSecBuffSecClusGrpMemb >>();

	public CFSecRamSecClusGrpMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecClusGrpMemb ensureRec(ICFSecSecClusGrpMemb rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecClusGrpMemb.CLASS_CODE) {
				return( ((CFSecBuffSecClusGrpMembDefaultFactory)(schema.getFactorySecClusGrpMemb())).ensureRec((ICFSecSecClusGrpMemb)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecClusGrpMemb createSecClusGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpMemb iBuff )
	{
		final String S_ProcName = "createSecClusGrpMemb";
		
		CFSecBuffSecClusGrpMemb Buff = (CFSecBuffSecClusGrpMemb)ensureRec(iBuff);
		CFSecBuffSecClusGrpMembPKey pkey = (CFSecBuffSecClusGrpMembPKey)(schema.getFactorySecClusGrpMemb().newPKey());
		pkey.setRequiredSecClusGrpId( Buff.getRequiredSecClusGrpId() );
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		Buff.setRequiredSecClusGrpId( pkey.getRequiredSecClusGrpId() );
		Buff.setRequiredSecUserId( pkey.getRequiredSecUserId() );
		CFSecBuffSecClusGrpMembByClusGrpIdxKey keyClusGrpIdx = (CFSecBuffSecClusGrpMembByClusGrpIdxKey)schema.getFactorySecClusGrpMemb().newByClusGrpIdxKey();
		keyClusGrpIdx.setRequiredSecClusGrpId( Buff.getRequiredSecClusGrpId() );

		CFSecBuffSecClusGrpMembByUserIdxKey keyUserIdx = (CFSecBuffSecClusGrpMembByUserIdxKey)schema.getFactorySecClusGrpMemb().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb > subdictClusGrpIdx;
		if( dictByClusGrpIdx.containsKey( keyClusGrpIdx ) ) {
			subdictClusGrpIdx = dictByClusGrpIdx.get( keyClusGrpIdx );
		}
		else {
			subdictClusGrpIdx = new HashMap< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb >();
			dictByClusGrpIdx.put( keyClusGrpIdx, subdictClusGrpIdx );
		}
		subdictClusGrpIdx.put( pkey, Buff );

		Map< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb > subdictUserIdx;
		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			subdictUserIdx = dictByUserIdx.get( keyUserIdx );
		}
		else {
			subdictUserIdx = new HashMap< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb >();
			dictByUserIdx.put( keyUserIdx, subdictUserIdx );
		}
		subdictUserIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecClusGrpMemb.CLASS_CODE) {
				CFSecBuffSecClusGrpMemb retbuff = ((CFSecBuffSecClusGrpMemb)(schema.getFactorySecClusGrpMemb().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecClusGrpMemb readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		CFLibDbKeyHash256 SecUserId )
	{
		{	CFLibDbKeyHash256 testSecClusGrpId = SecClusGrpId;
			if (testSecClusGrpId == null) {
				return( null );
			}
		}
		{	CFLibDbKeyHash256 testSecUserId = SecUserId;
			if (testSecUserId == null) {
				return( null );
			}
		}
		CFSecBuffSecClusGrpMembPKey key = (CFSecBuffSecClusGrpMembPKey)(schema.getFactorySecClusGrpMemb().newPKey());
		key.setRequiredSecClusGrpId( SecClusGrpId );
		key.setRequiredSecUserId( SecUserId );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecClusGrpMemb readDerived( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMemb.readDerived";
		CFSecBuffSecClusGrpMembPKey key = (CFSecBuffSecClusGrpMembPKey)(schema.getFactorySecClusGrpMemb().newPKey());
		key.setRequiredSecClusGrpId( PKey.getRequiredSecClusGrpId() );
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		ICFSecSecClusGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrpMemb lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMemb.lockDerived";
		CFSecBuffSecClusGrpMembPKey key = (CFSecBuffSecClusGrpMembPKey)(schema.getFactorySecClusGrpMemb().newPKey());
		key.setRequiredSecClusGrpId( PKey.getRequiredSecClusGrpId() );
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		ICFSecSecClusGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrpMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecClusGrpMemb.readAllDerived";
		ICFSecSecClusGrpMemb[] retList = new ICFSecSecClusGrpMemb[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecClusGrpMemb > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecClusGrpMemb[] readDerivedByClusGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMemb.readDerivedByClusGrpIdx";
		CFSecBuffSecClusGrpMembByClusGrpIdxKey key = (CFSecBuffSecClusGrpMembByClusGrpIdxKey)schema.getFactorySecClusGrpMemb().newByClusGrpIdxKey();

		key.setRequiredSecClusGrpId( SecClusGrpId );
		ICFSecSecClusGrpMemb[] recArray;
		if( dictByClusGrpIdx.containsKey( key ) ) {
			Map< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb > subdictClusGrpIdx
				= dictByClusGrpIdx.get( key );
			recArray = new ICFSecSecClusGrpMemb[ subdictClusGrpIdx.size() ];
			Iterator< CFSecBuffSecClusGrpMemb > iter = subdictClusGrpIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb > subdictClusGrpIdx
				= new HashMap< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb >();
			dictByClusGrpIdx.put( key, subdictClusGrpIdx );
			recArray = new ICFSecSecClusGrpMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecClusGrpMemb[] readDerivedByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMemb.readDerivedByUserIdx";
		CFSecBuffSecClusGrpMembByUserIdxKey key = (CFSecBuffSecClusGrpMembByUserIdxKey)schema.getFactorySecClusGrpMemb().newByUserIdxKey();

		key.setRequiredSecUserId( SecUserId );
		ICFSecSecClusGrpMemb[] recArray;
		if( dictByUserIdx.containsKey( key ) ) {
			Map< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb > subdictUserIdx
				= dictByUserIdx.get( key );
			recArray = new ICFSecSecClusGrpMemb[ subdictUserIdx.size() ];
			Iterator< CFSecBuffSecClusGrpMemb > iter = subdictUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb > subdictUserIdx
				= new HashMap< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb >();
			dictByUserIdx.put( key, subdictUserIdx );
			recArray = new ICFSecSecClusGrpMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecClusGrpMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMemb.readDerivedByIdIdx() ";
		CFSecBuffSecClusGrpMembPKey key = (CFSecBuffSecClusGrpMembPKey)(schema.getFactorySecClusGrpMemb().newPKey());
		key.setRequiredSecClusGrpId( SecClusGrpId );
		key.setRequiredSecUserId( SecUserId );
		ICFSecSecClusGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrpMemb readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		CFLibDbKeyHash256 SecUserId )
	{
		CFSecBuffSecClusGrpMembPKey key = (CFSecBuffSecClusGrpMembPKey)(schema.getFactorySecClusGrpMemb().newPKey());
		key.setRequiredSecClusGrpId( SecClusGrpId );
		key.setRequiredSecUserId( SecUserId );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecClusGrpMemb readRec( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMemb.readRec";
		ICFSecSecClusGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecClusGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrpMemb lockRec( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpMembPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecClusGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecClusGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrpMemb[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMemb.readAllRec";
		ICFSecSecClusGrpMemb buff;
		ArrayList<ICFSecSecClusGrpMemb> filteredList = new ArrayList<ICFSecSecClusGrpMemb>();
		ICFSecSecClusGrpMemb[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrpMemb.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusGrpMemb[0] ) );
	}

	/**
	 *	Read a page of all the specific SecClusGrpMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecClusGrpMemb instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecClusGrpMemb[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecClusGrpId,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecClusGrpMemb readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMemb.readRecByIdIdx() ";
		ICFSecSecClusGrpMemb buff = readDerivedByIdIdx( Authorization,
			SecClusGrpId,
			SecUserId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrpMemb.CLASS_CODE ) ) {
			return( (ICFSecSecClusGrpMemb)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecClusGrpMemb[] readRecByClusGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMemb.readRecByClusGrpIdx() ";
		ICFSecSecClusGrpMemb buff;
		ArrayList<ICFSecSecClusGrpMemb> filteredList = new ArrayList<ICFSecSecClusGrpMemb>();
		ICFSecSecClusGrpMemb[] buffList = readDerivedByClusGrpIdx( Authorization,
			SecClusGrpId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecClusGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusGrpMemb[0] ) );
	}

	@Override
	public ICFSecSecClusGrpMemb[] readRecByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMemb.readRecByUserIdx() ";
		ICFSecSecClusGrpMemb buff;
		ArrayList<ICFSecSecClusGrpMemb> filteredList = new ArrayList<ICFSecSecClusGrpMemb>();
		ICFSecSecClusGrpMemb[] buffList = readDerivedByUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecClusGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusGrpMemb[0] ) );
	}

	/**
	 *	Read a page array of the specific SecClusGrpMemb buffer instances identified by the duplicate key ClusGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusGrpId	The SecClusGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusGrpMemb[] pageRecByClusGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		CFLibDbKeyHash256 priorSecClusGrpId,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByClusGrpIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecClusGrpMemb buffer instances identified by the duplicate key UserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecClusGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusGrpMemb[] pageRecByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		CFLibDbKeyHash256 priorSecClusGrpId,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecClusGrpMemb updateSecClusGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpMemb iBuff )
	{
		CFSecBuffSecClusGrpMemb Buff = (CFSecBuffSecClusGrpMemb)ensureRec(iBuff);
		CFSecBuffSecClusGrpMembPKey pkey = (CFSecBuffSecClusGrpMembPKey)(schema.getFactorySecClusGrpMemb().newPKey());
		pkey.setRequiredSecClusGrpId( Buff.getRequiredSecClusGrpId() );
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		CFSecBuffSecClusGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecClusGrpMemb",
				"Existing record not found",
				"Existing record not found",
				"SecClusGrpMemb",
				"SecClusGrpMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecClusGrpMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecClusGrpMembByClusGrpIdxKey existingKeyClusGrpIdx = (CFSecBuffSecClusGrpMembByClusGrpIdxKey)schema.getFactorySecClusGrpMemb().newByClusGrpIdxKey();
		existingKeyClusGrpIdx.setRequiredSecClusGrpId( existing.getRequiredSecClusGrpId() );

		CFSecBuffSecClusGrpMembByClusGrpIdxKey newKeyClusGrpIdx = (CFSecBuffSecClusGrpMembByClusGrpIdxKey)schema.getFactorySecClusGrpMemb().newByClusGrpIdxKey();
		newKeyClusGrpIdx.setRequiredSecClusGrpId( Buff.getRequiredSecClusGrpId() );

		CFSecBuffSecClusGrpMembByUserIdxKey existingKeyUserIdx = (CFSecBuffSecClusGrpMembByUserIdxKey)schema.getFactorySecClusGrpMemb().newByUserIdxKey();
		existingKeyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecClusGrpMembByUserIdxKey newKeyUserIdx = (CFSecBuffSecClusGrpMembByUserIdxKey)schema.getFactorySecClusGrpMemb().newByUserIdxKey();
		newKeyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Check unique indexes

		// Validate foreign keys

		// Update is valid

		Map< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByClusGrpIdx.get( existingKeyClusGrpIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusGrpIdx.containsKey( newKeyClusGrpIdx ) ) {
			subdict = dictByClusGrpIdx.get( newKeyClusGrpIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb >();
			dictByClusGrpIdx.put( newKeyClusGrpIdx, subdict );
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
			subdict = new HashMap< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb >();
			dictByUserIdx.put( newKeyUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecClusGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpMemb iBuff )
	{
		final String S_ProcName = "CFSecRamSecClusGrpMembTable.deleteSecClusGrpMemb() ";
		CFSecBuffSecClusGrpMemb Buff = (CFSecBuffSecClusGrpMemb)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecClusGrpMembPKey pkey = (CFSecBuffSecClusGrpMembPKey)(Buff.getPKey());
		CFSecBuffSecClusGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecClusGrpMemb",
				pkey );
		}
		CFSecBuffSecClusGrpMembByClusGrpIdxKey keyClusGrpIdx = (CFSecBuffSecClusGrpMembByClusGrpIdxKey)schema.getFactorySecClusGrpMemb().newByClusGrpIdxKey();
		keyClusGrpIdx.setRequiredSecClusGrpId( existing.getRequiredSecClusGrpId() );

		CFSecBuffSecClusGrpMembByUserIdxKey keyUserIdx = (CFSecBuffSecClusGrpMembByUserIdxKey)schema.getFactorySecClusGrpMemb().newByUserIdxKey();
		keyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecClusGrpMembPKey, CFSecBuffSecClusGrpMemb > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusGrpIdx.get( keyClusGrpIdx );
		subdict.remove( pkey );

		subdict = dictByUserIdx.get( keyUserIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecClusGrpMembByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		CFLibDbKeyHash256 SecUserId )
	{
		CFSecBuffSecClusGrpMembPKey key = (CFSecBuffSecClusGrpMembPKey)(schema.getFactorySecClusGrpMemb().newPKey());
		key.setRequiredSecClusGrpId( SecClusGrpId );
		key.setRequiredSecUserId( SecUserId );
		deleteSecClusGrpMembByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusGrpMembByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpMembPKey PKey )
	{
		CFSecBuffSecClusGrpMembPKey key = (CFSecBuffSecClusGrpMembPKey)(schema.getFactorySecClusGrpMemb().newPKey());
		key.setRequiredSecClusGrpId( PKey.getRequiredSecClusGrpId() );
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		CFSecBuffSecClusGrpMembPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecClusGrpMemb cur;
		LinkedList<CFSecBuffSecClusGrpMemb> matchSet = new LinkedList<CFSecBuffSecClusGrpMemb>();
		Iterator<CFSecBuffSecClusGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusGrpMemb)(schema.getTableSecClusGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusGrpId(),
				cur.getRequiredSecUserId() ));
			deleteSecClusGrpMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusGrpMembByClusGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusGrpId )
	{
		CFSecBuffSecClusGrpMembByClusGrpIdxKey key = (CFSecBuffSecClusGrpMembByClusGrpIdxKey)schema.getFactorySecClusGrpMemb().newByClusGrpIdxKey();
		key.setRequiredSecClusGrpId( argSecClusGrpId );
		deleteSecClusGrpMembByClusGrpIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusGrpMembByClusGrpIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpMembByClusGrpIdxKey argKey )
	{
		CFSecBuffSecClusGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusGrpMemb> matchSet = new LinkedList<CFSecBuffSecClusGrpMemb>();
		Iterator<CFSecBuffSecClusGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusGrpMemb)(schema.getTableSecClusGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusGrpId(),
				cur.getRequiredSecUserId() ));
			deleteSecClusGrpMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusGrpMembByUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecBuffSecClusGrpMembByUserIdxKey key = (CFSecBuffSecClusGrpMembByUserIdxKey)schema.getFactorySecClusGrpMemb().newByUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecClusGrpMembByUserIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusGrpMembByUserIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpMembByUserIdxKey argKey )
	{
		CFSecBuffSecClusGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusGrpMemb> matchSet = new LinkedList<CFSecBuffSecClusGrpMemb>();
		Iterator<CFSecBuffSecClusGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusGrpMemb)(schema.getTableSecClusGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusGrpId(),
				cur.getRequiredSecUserId() ));
			deleteSecClusGrpMemb( Authorization, cur );
		}
	}
}
