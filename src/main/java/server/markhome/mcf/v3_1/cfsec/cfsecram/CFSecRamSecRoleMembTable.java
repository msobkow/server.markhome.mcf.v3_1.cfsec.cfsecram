
// Description: Java 25 in-memory RAM DbIO implementation for SecRoleMemb.

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
 *	CFSecRamSecRoleMembTable in-memory RAM DbIO implementation
 *	for SecRoleMemb.
 */
public class CFSecRamSecRoleMembTable
	implements ICFSecSecRoleMembTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecRoleMembPKey,
				CFSecBuffSecRoleMemb > dictByPKey
		= new HashMap< ICFSecSecRoleMembPKey,
				CFSecBuffSecRoleMemb >();
	private Map< CFSecBuffSecRoleMembByRoleIdxKey,
				Map< CFSecBuffSecRoleMembPKey,
					CFSecBuffSecRoleMemb >> dictByRoleIdx
		= new HashMap< CFSecBuffSecRoleMembByRoleIdxKey,
				Map< CFSecBuffSecRoleMembPKey,
					CFSecBuffSecRoleMemb >>();
	private Map< CFSecBuffSecRoleMembByLoginIdxKey,
				Map< CFSecBuffSecRoleMembPKey,
					CFSecBuffSecRoleMemb >> dictByLoginIdx
		= new HashMap< CFSecBuffSecRoleMembByLoginIdxKey,
				Map< CFSecBuffSecRoleMembPKey,
					CFSecBuffSecRoleMemb >>();

	public CFSecRamSecRoleMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecRoleMemb ensureRec(ICFSecSecRoleMemb rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecRoleMemb.CLASS_CODE) {
				return( ((CFSecBuffSecRoleMembDefaultFactory)(schema.getFactorySecRoleMemb())).ensureRec((ICFSecSecRoleMemb)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecRoleMemb createSecRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecRoleMemb iBuff )
	{
		final String S_ProcName = "createSecRoleMemb";
		
		CFSecBuffSecRoleMemb Buff = (CFSecBuffSecRoleMemb)ensureRec(iBuff);
		CFSecBuffSecRoleMembPKey pkey = (CFSecBuffSecRoleMembPKey)(schema.getFactorySecRoleMemb().newPKey());
		pkey.setRequiredContainerRole( Buff.getRequiredSecRoleId() );
		pkey.setRequiredParentUser( Buff.getRequiredLoginId() );
		Buff.setRequiredContainerRole( pkey.getRequiredSecRoleId() );
		Buff.setRequiredParentUser( pkey.getRequiredLoginId() );
		CFSecBuffSecRoleMembByRoleIdxKey keyRoleIdx = (CFSecBuffSecRoleMembByRoleIdxKey)schema.getFactorySecRoleMemb().newByRoleIdxKey();
		keyRoleIdx.setRequiredSecRoleId( Buff.getRequiredSecRoleId() );

		CFSecBuffSecRoleMembByLoginIdxKey keyLoginIdx = (CFSecBuffSecRoleMembByLoginIdxKey)schema.getFactorySecRoleMemb().newByLoginIdxKey();
		keyLoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecRoleMembRole",
						"SecRoleMembRole",
						"SecRole",
						"SecRole",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb > subdictRoleIdx;
		if( dictByRoleIdx.containsKey( keyRoleIdx ) ) {
			subdictRoleIdx = dictByRoleIdx.get( keyRoleIdx );
		}
		else {
			subdictRoleIdx = new HashMap< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb >();
			dictByRoleIdx.put( keyRoleIdx, subdictRoleIdx );
		}
		subdictRoleIdx.put( pkey, Buff );

		Map< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb > subdictLoginIdx;
		if( dictByLoginIdx.containsKey( keyLoginIdx ) ) {
			subdictLoginIdx = dictByLoginIdx.get( keyLoginIdx );
		}
		else {
			subdictLoginIdx = new HashMap< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb >();
			dictByLoginIdx.put( keyLoginIdx, subdictLoginIdx );
		}
		subdictLoginIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecRoleMemb.CLASS_CODE) {
				CFSecBuffSecRoleMemb retbuff = ((CFSecBuffSecRoleMemb)(schema.getFactorySecRoleMemb().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecRoleMemb readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		String LoginId )
	{
		{	CFLibDbKeyHash256 testSecRoleId = SecRoleId;
			if (testSecRoleId == null) {
				return( null );
			}
		}
		{	String testLoginId = LoginId;
			if (testLoginId == null) {
				return( null );
			}
		}
		CFSecBuffSecRoleMembPKey key = (CFSecBuffSecRoleMembPKey)(schema.getFactorySecRoleMemb().newPKey());
		key.setRequiredContainerRole( SecRoleId );
		key.setRequiredParentUser( LoginId );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecRoleMemb readDerived( ICFSecAuthorization Authorization,
		ICFSecSecRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecRoleMemb.readDerived";
		CFSecBuffSecRoleMembPKey key = (CFSecBuffSecRoleMembPKey)(schema.getFactorySecRoleMemb().newPKey());
		key.setRequiredContainerRole( PKey.getRequiredSecRoleId() );
		key.setRequiredParentUser( PKey.getRequiredLoginId() );
		ICFSecSecRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRoleMemb lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecRoleMemb.lockDerived";
		CFSecBuffSecRoleMembPKey key = (CFSecBuffSecRoleMembPKey)(schema.getFactorySecRoleMemb().newPKey());
		key.setRequiredContainerRole( PKey.getRequiredSecRoleId() );
		key.setRequiredParentUser( PKey.getRequiredLoginId() );
		ICFSecSecRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRoleMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecRoleMemb.readAllDerived";
		ICFSecSecRoleMemb[] retList = new ICFSecSecRoleMemb[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecRoleMemb > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecRoleMemb[] readDerivedByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId )
	{
		final String S_ProcName = "CFSecRamSecRoleMemb.readDerivedByRoleIdx";
		CFSecBuffSecRoleMembByRoleIdxKey key = (CFSecBuffSecRoleMembByRoleIdxKey)schema.getFactorySecRoleMemb().newByRoleIdxKey();

		key.setRequiredSecRoleId( SecRoleId );
		ICFSecSecRoleMemb[] recArray;
		if( dictByRoleIdx.containsKey( key ) ) {
			Map< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb > subdictRoleIdx
				= dictByRoleIdx.get( key );
			recArray = new ICFSecSecRoleMemb[ subdictRoleIdx.size() ];
			Iterator< CFSecBuffSecRoleMemb > iter = subdictRoleIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb > subdictRoleIdx
				= new HashMap< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb >();
			dictByRoleIdx.put( key, subdictRoleIdx );
			recArray = new ICFSecSecRoleMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecRoleMemb[] readDerivedByLoginIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecRoleMemb.readDerivedByLoginIdx";
		CFSecBuffSecRoleMembByLoginIdxKey key = (CFSecBuffSecRoleMembByLoginIdxKey)schema.getFactorySecRoleMemb().newByLoginIdxKey();

		key.setRequiredLoginId( LoginId );
		ICFSecSecRoleMemb[] recArray;
		if( dictByLoginIdx.containsKey( key ) ) {
			Map< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb > subdictLoginIdx
				= dictByLoginIdx.get( key );
			recArray = new ICFSecSecRoleMemb[ subdictLoginIdx.size() ];
			Iterator< CFSecBuffSecRoleMemb > iter = subdictLoginIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb > subdictLoginIdx
				= new HashMap< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb >();
			dictByLoginIdx.put( key, subdictLoginIdx );
			recArray = new ICFSecSecRoleMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecRoleMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecRoleMemb.readDerivedByIdIdx() ";
		CFSecBuffSecRoleMembPKey key = (CFSecBuffSecRoleMembPKey)(schema.getFactorySecRoleMemb().newPKey());
		key.setRequiredContainerRole( SecRoleId );
		key.setRequiredParentUser( LoginId );
		ICFSecSecRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRoleMemb readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		String LoginId )
	{
		CFSecBuffSecRoleMembPKey key = (CFSecBuffSecRoleMembPKey)(schema.getFactorySecRoleMemb().newPKey());
		key.setRequiredContainerRole( SecRoleId );
		key.setRequiredParentUser( LoginId );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecRoleMemb readRec( ICFSecAuthorization Authorization,
		ICFSecSecRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecRoleMemb.readRec";
		ICFSecSecRoleMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecRoleMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRoleMemb lockRec( ICFSecAuthorization Authorization,
		ICFSecSecRoleMembPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecRoleMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecRoleMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRoleMemb[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecRoleMemb.readAllRec";
		ICFSecSecRoleMemb buff;
		ArrayList<ICFSecSecRoleMemb> filteredList = new ArrayList<ICFSecSecRoleMemb>();
		ICFSecSecRoleMemb[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRoleMemb.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecRoleMemb[0] ) );
	}

	/**
	 *	Read a page of all the specific SecRoleMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecRoleMemb instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecRoleMemb[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecRoleId,
		String priorLoginId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecRoleMemb readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecRoleMemb.readRecByIdIdx() ";
		ICFSecSecRoleMemb buff = readDerivedByIdIdx( Authorization,
			SecRoleId,
			LoginId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRoleMemb.CLASS_CODE ) ) {
			return( (ICFSecSecRoleMemb)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecRoleMemb[] readRecByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId )
	{
		final String S_ProcName = "CFSecRamSecRoleMemb.readRecByRoleIdx() ";
		ICFSecSecRoleMemb buff;
		ArrayList<ICFSecSecRoleMemb> filteredList = new ArrayList<ICFSecSecRoleMemb>();
		ICFSecSecRoleMemb[] buffList = readDerivedByRoleIdx( Authorization,
			SecRoleId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRoleMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecRoleMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecRoleMemb[0] ) );
	}

	@Override
	public ICFSecSecRoleMemb[] readRecByLoginIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecRoleMemb.readRecByLoginIdx() ";
		ICFSecSecRoleMemb buff;
		ArrayList<ICFSecSecRoleMemb> filteredList = new ArrayList<ICFSecSecRoleMemb>();
		ICFSecSecRoleMemb[] buffList = readDerivedByLoginIdx( Authorization,
			LoginId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRoleMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecRoleMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecRoleMemb[0] ) );
	}

	/**
	 *	Read a page array of the specific SecRoleMemb buffer instances identified by the duplicate key RoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecRoleId	The SecRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleMemb[] pageRecByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		CFLibDbKeyHash256 priorSecRoleId,
		String priorLoginId )
	{
		final String S_ProcName = "pageRecByRoleIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecRoleMemb buffer instances identified by the duplicate key LoginIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	LoginId	The SecRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleMemb[] pageRecByLoginIdx( ICFSecAuthorization Authorization,
		String LoginId,
		CFLibDbKeyHash256 priorSecRoleId,
		String priorLoginId )
	{
		final String S_ProcName = "pageRecByLoginIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecRoleMemb updateSecRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecRoleMemb iBuff )
	{
		CFSecBuffSecRoleMemb Buff = (CFSecBuffSecRoleMemb)ensureRec(iBuff);
		CFSecBuffSecRoleMembPKey pkey = (CFSecBuffSecRoleMembPKey)(schema.getFactorySecRoleMemb().newPKey());
		pkey.setRequiredContainerRole( Buff.getRequiredSecRoleId() );
		pkey.setRequiredParentUser( Buff.getRequiredLoginId() );
		CFSecBuffSecRoleMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecRoleMemb",
				"Existing record not found",
				"Existing record not found",
				"SecRoleMemb",
				"SecRoleMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecRoleMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecRoleMembByRoleIdxKey existingKeyRoleIdx = (CFSecBuffSecRoleMembByRoleIdxKey)schema.getFactorySecRoleMemb().newByRoleIdxKey();
		existingKeyRoleIdx.setRequiredSecRoleId( existing.getRequiredSecRoleId() );

		CFSecBuffSecRoleMembByRoleIdxKey newKeyRoleIdx = (CFSecBuffSecRoleMembByRoleIdxKey)schema.getFactorySecRoleMemb().newByRoleIdxKey();
		newKeyRoleIdx.setRequiredSecRoleId( Buff.getRequiredSecRoleId() );

		CFSecBuffSecRoleMembByLoginIdxKey existingKeyLoginIdx = (CFSecBuffSecRoleMembByLoginIdxKey)schema.getFactorySecRoleMemb().newByLoginIdxKey();
		existingKeyLoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecRoleMembByLoginIdxKey newKeyLoginIdx = (CFSecBuffSecRoleMembByLoginIdxKey)schema.getFactorySecRoleMemb().newByLoginIdxKey();
		newKeyLoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecRoleMemb",
						"Container",
						"Container",
						"SecRoleMembRole",
						"SecRoleMembRole",
						"SecRole",
						"SecRole",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByRoleIdx.get( existingKeyRoleIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByRoleIdx.containsKey( newKeyRoleIdx ) ) {
			subdict = dictByRoleIdx.get( newKeyRoleIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb >();
			dictByRoleIdx.put( newKeyRoleIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByLoginIdx.get( existingKeyLoginIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByLoginIdx.containsKey( newKeyLoginIdx ) ) {
			subdict = dictByLoginIdx.get( newKeyLoginIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb >();
			dictByLoginIdx.put( newKeyLoginIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecRoleMemb iBuff )
	{
		final String S_ProcName = "CFSecRamSecRoleMembTable.deleteSecRoleMemb() ";
		CFSecBuffSecRoleMemb Buff = (CFSecBuffSecRoleMemb)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecRoleMembPKey pkey = (CFSecBuffSecRoleMembPKey)(Buff.getPKey());
		CFSecBuffSecRoleMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecRoleMemb",
				pkey );
		}
		CFSecBuffSecRoleMembByRoleIdxKey keyRoleIdx = (CFSecBuffSecRoleMembByRoleIdxKey)schema.getFactorySecRoleMemb().newByRoleIdxKey();
		keyRoleIdx.setRequiredSecRoleId( existing.getRequiredSecRoleId() );

		CFSecBuffSecRoleMembByLoginIdxKey keyLoginIdx = (CFSecBuffSecRoleMembByLoginIdxKey)schema.getFactorySecRoleMemb().newByLoginIdxKey();
		keyLoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecRoleMembPKey, CFSecBuffSecRoleMemb > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByRoleIdx.get( keyRoleIdx );
		subdict.remove( pkey );

		subdict = dictByLoginIdx.get( keyLoginIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecRoleMembByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		String LoginId )
	{
		CFSecBuffSecRoleMembPKey key = (CFSecBuffSecRoleMembPKey)(schema.getFactorySecRoleMemb().newPKey());
		key.setRequiredContainerRole( SecRoleId );
		key.setRequiredParentUser( LoginId );
		deleteSecRoleMembByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecRoleMembByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecRoleMembPKey PKey )
	{
		CFSecBuffSecRoleMembPKey key = (CFSecBuffSecRoleMembPKey)(schema.getFactorySecRoleMemb().newPKey());
		key.setRequiredContainerRole( PKey.getRequiredSecRoleId() );
		key.setRequiredParentUser( PKey.getRequiredLoginId() );
		CFSecBuffSecRoleMembPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecRoleMemb cur;
		LinkedList<CFSecBuffSecRoleMemb> matchSet = new LinkedList<CFSecBuffSecRoleMemb>();
		Iterator<CFSecBuffSecRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecRoleMemb)(schema.getTableSecRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecRoleMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecRoleMembByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId )
	{
		CFSecBuffSecRoleMembByRoleIdxKey key = (CFSecBuffSecRoleMembByRoleIdxKey)schema.getFactorySecRoleMemb().newByRoleIdxKey();
		key.setRequiredSecRoleId( argSecRoleId );
		deleteSecRoleMembByRoleIdx( Authorization, key );
	}

	@Override
	public void deleteSecRoleMembByRoleIdx( ICFSecAuthorization Authorization,
		ICFSecSecRoleMembByRoleIdxKey argKey )
	{
		CFSecBuffSecRoleMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecRoleMemb> matchSet = new LinkedList<CFSecBuffSecRoleMemb>();
		Iterator<CFSecBuffSecRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecRoleMemb)(schema.getTableSecRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecRoleMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecRoleMembByLoginIdx( ICFSecAuthorization Authorization,
		String argLoginId )
	{
		CFSecBuffSecRoleMembByLoginIdxKey key = (CFSecBuffSecRoleMembByLoginIdxKey)schema.getFactorySecRoleMemb().newByLoginIdxKey();
		key.setRequiredLoginId( argLoginId );
		deleteSecRoleMembByLoginIdx( Authorization, key );
	}

	@Override
	public void deleteSecRoleMembByLoginIdx( ICFSecAuthorization Authorization,
		ICFSecSecRoleMembByLoginIdxKey argKey )
	{
		CFSecBuffSecRoleMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecRoleMemb> matchSet = new LinkedList<CFSecBuffSecRoleMemb>();
		Iterator<CFSecBuffSecRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecRoleMemb)(schema.getTableSecRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecRoleMemb( Authorization, cur );
		}
	}
}
