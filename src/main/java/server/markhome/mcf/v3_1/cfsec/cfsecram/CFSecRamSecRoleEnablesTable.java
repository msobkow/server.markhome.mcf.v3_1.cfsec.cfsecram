
// Description: Java 25 in-memory RAM DbIO implementation for SecRoleEnables.

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
 *	CFSecRamSecRoleEnablesTable in-memory RAM DbIO implementation
 *	for SecRoleEnables.
 */
public class CFSecRamSecRoleEnablesTable
	implements ICFSecSecRoleEnablesTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecRoleEnablesPKey,
				CFSecBuffSecRoleEnables > dictByPKey
		= new HashMap< ICFSecSecRoleEnablesPKey,
				CFSecBuffSecRoleEnables >();
	private Map< CFSecBuffSecRoleEnablesByRoleIdxKey,
				Map< CFSecBuffSecRoleEnablesPKey,
					CFSecBuffSecRoleEnables >> dictByRoleIdx
		= new HashMap< CFSecBuffSecRoleEnablesByRoleIdxKey,
				Map< CFSecBuffSecRoleEnablesPKey,
					CFSecBuffSecRoleEnables >>();
	private Map< CFSecBuffSecRoleEnablesByNameIdxKey,
				Map< CFSecBuffSecRoleEnablesPKey,
					CFSecBuffSecRoleEnables >> dictByNameIdx
		= new HashMap< CFSecBuffSecRoleEnablesByNameIdxKey,
				Map< CFSecBuffSecRoleEnablesPKey,
					CFSecBuffSecRoleEnables >>();

	public CFSecRamSecRoleEnablesTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecRoleEnables ensureRec(ICFSecSecRoleEnables rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecRoleEnables.CLASS_CODE) {
				return( ((CFSecBuffSecRoleEnablesDefaultFactory)(schema.getFactorySecRoleEnables())).ensureRec((ICFSecSecRoleEnables)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecRoleEnables createSecRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnables iBuff )
	{
		final String S_ProcName = "createSecRoleEnables";
		
		CFSecBuffSecRoleEnables Buff = (CFSecBuffSecRoleEnables)ensureRec(iBuff);
		CFSecBuffSecRoleEnablesPKey pkey = (CFSecBuffSecRoleEnablesPKey)(schema.getFactorySecRoleEnables().newPKey());
		pkey.setRequiredContainerRole( Buff.getRequiredSecRoleId() );
		pkey.setRequiredParentEnableGroup( Buff.getRequiredEnableName() );
		Buff.setRequiredContainerRole( pkey.getRequiredSecRoleId() );
		Buff.setRequiredParentEnableGroup( pkey.getRequiredEnableName() );
		CFSecBuffSecRoleEnablesByRoleIdxKey keyRoleIdx = (CFSecBuffSecRoleEnablesByRoleIdxKey)schema.getFactorySecRoleEnables().newByRoleIdxKey();
		keyRoleIdx.setRequiredSecRoleId( Buff.getRequiredSecRoleId() );

		CFSecBuffSecRoleEnablesByNameIdxKey keyNameIdx = (CFSecBuffSecRoleEnablesByNameIdxKey)schema.getFactorySecRoleEnables().newByNameIdxKey();
		keyNameIdx.setRequiredEnableName( Buff.getRequiredEnableName() );

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
						"SecRoleEnablesRole",
						"SecRoleEnablesRole",
						"SecRole",
						"SecRole",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables > subdictRoleIdx;
		if( dictByRoleIdx.containsKey( keyRoleIdx ) ) {
			subdictRoleIdx = dictByRoleIdx.get( keyRoleIdx );
		}
		else {
			subdictRoleIdx = new HashMap< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables >();
			dictByRoleIdx.put( keyRoleIdx, subdictRoleIdx );
		}
		subdictRoleIdx.put( pkey, Buff );

		Map< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables > subdictNameIdx;
		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			subdictNameIdx = dictByNameIdx.get( keyNameIdx );
		}
		else {
			subdictNameIdx = new HashMap< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables >();
			dictByNameIdx.put( keyNameIdx, subdictNameIdx );
		}
		subdictNameIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecRoleEnables.CLASS_CODE) {
				CFSecBuffSecRoleEnables retbuff = ((CFSecBuffSecRoleEnables)(schema.getFactorySecRoleEnables().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecRoleEnables readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		String EnableName )
	{
		{	CFLibDbKeyHash256 testSecRoleId = SecRoleId;
			if (testSecRoleId == null) {
				return( null );
			}
		}
		{	String testEnableName = EnableName;
			if (testEnableName == null) {
				return( null );
			}
		}
		CFSecBuffSecRoleEnablesPKey key = (CFSecBuffSecRoleEnablesPKey)(schema.getFactorySecRoleEnables().newPKey());
		key.setRequiredContainerRole( SecRoleId );
		key.setRequiredParentEnableGroup( EnableName );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecRoleEnables readDerived( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecRoleEnables.readDerived";
		CFSecBuffSecRoleEnablesPKey key = (CFSecBuffSecRoleEnablesPKey)(schema.getFactorySecRoleEnables().newPKey());
		key.setRequiredContainerRole( PKey.getRequiredSecRoleId() );
		key.setRequiredParentEnableGroup( PKey.getRequiredEnableName() );
		ICFSecSecRoleEnables buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRoleEnables lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecRoleEnables.lockDerived";
		CFSecBuffSecRoleEnablesPKey key = (CFSecBuffSecRoleEnablesPKey)(schema.getFactorySecRoleEnables().newPKey());
		key.setRequiredContainerRole( PKey.getRequiredSecRoleId() );
		key.setRequiredParentEnableGroup( PKey.getRequiredEnableName() );
		ICFSecSecRoleEnables buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRoleEnables[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecRoleEnables.readAllDerived";
		ICFSecSecRoleEnables[] retList = new ICFSecSecRoleEnables[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecRoleEnables > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecRoleEnables[] readDerivedByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId )
	{
		final String S_ProcName = "CFSecRamSecRoleEnables.readDerivedByRoleIdx";
		CFSecBuffSecRoleEnablesByRoleIdxKey key = (CFSecBuffSecRoleEnablesByRoleIdxKey)schema.getFactorySecRoleEnables().newByRoleIdxKey();

		key.setRequiredSecRoleId( SecRoleId );
		ICFSecSecRoleEnables[] recArray;
		if( dictByRoleIdx.containsKey( key ) ) {
			Map< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables > subdictRoleIdx
				= dictByRoleIdx.get( key );
			recArray = new ICFSecSecRoleEnables[ subdictRoleIdx.size() ];
			Iterator< CFSecBuffSecRoleEnables > iter = subdictRoleIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables > subdictRoleIdx
				= new HashMap< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables >();
			dictByRoleIdx.put( key, subdictRoleIdx );
			recArray = new ICFSecSecRoleEnables[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecRoleEnables[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String EnableName )
	{
		final String S_ProcName = "CFSecRamSecRoleEnables.readDerivedByNameIdx";
		CFSecBuffSecRoleEnablesByNameIdxKey key = (CFSecBuffSecRoleEnablesByNameIdxKey)schema.getFactorySecRoleEnables().newByNameIdxKey();

		key.setRequiredEnableName( EnableName );
		ICFSecSecRoleEnables[] recArray;
		if( dictByNameIdx.containsKey( key ) ) {
			Map< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables > subdictNameIdx
				= dictByNameIdx.get( key );
			recArray = new ICFSecSecRoleEnables[ subdictNameIdx.size() ];
			Iterator< CFSecBuffSecRoleEnables > iter = subdictNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables > subdictNameIdx
				= new HashMap< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables >();
			dictByNameIdx.put( key, subdictNameIdx );
			recArray = new ICFSecSecRoleEnables[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecRoleEnables readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		String EnableName )
	{
		final String S_ProcName = "CFSecRamSecRoleEnables.readDerivedByIdIdx() ";
		CFSecBuffSecRoleEnablesPKey key = (CFSecBuffSecRoleEnablesPKey)(schema.getFactorySecRoleEnables().newPKey());
		key.setRequiredContainerRole( SecRoleId );
		key.setRequiredParentEnableGroup( EnableName );
		ICFSecSecRoleEnables buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRoleEnables readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		String EnableName )
	{
		CFSecBuffSecRoleEnablesPKey key = (CFSecBuffSecRoleEnablesPKey)(schema.getFactorySecRoleEnables().newPKey());
		key.setRequiredContainerRole( SecRoleId );
		key.setRequiredParentEnableGroup( EnableName );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecRoleEnables readRec( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecRoleEnables.readRec";
		ICFSecSecRoleEnables buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecRoleEnables.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRoleEnables lockRec( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecRoleEnables buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecRoleEnables.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRoleEnables[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecRoleEnables.readAllRec";
		ICFSecSecRoleEnables buff;
		ArrayList<ICFSecSecRoleEnables> filteredList = new ArrayList<ICFSecSecRoleEnables>();
		ICFSecSecRoleEnables[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRoleEnables.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecRoleEnables[0] ) );
	}

	/**
	 *	Read a page of all the specific SecRoleEnables buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecRoleEnables instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecRoleEnables[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecRoleId,
		String priorEnableName )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecRoleEnables readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		String EnableName )
	{
		final String S_ProcName = "CFSecRamSecRoleEnables.readRecByIdIdx() ";
		ICFSecSecRoleEnables buff = readDerivedByIdIdx( Authorization,
			SecRoleId,
			EnableName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRoleEnables.CLASS_CODE ) ) {
			return( (ICFSecSecRoleEnables)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecRoleEnables[] readRecByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId )
	{
		final String S_ProcName = "CFSecRamSecRoleEnables.readRecByRoleIdx() ";
		ICFSecSecRoleEnables buff;
		ArrayList<ICFSecSecRoleEnables> filteredList = new ArrayList<ICFSecSecRoleEnables>();
		ICFSecSecRoleEnables[] buffList = readDerivedByRoleIdx( Authorization,
			SecRoleId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRoleEnables.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecRoleEnables)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecRoleEnables[0] ) );
	}

	@Override
	public ICFSecSecRoleEnables[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String EnableName )
	{
		final String S_ProcName = "CFSecRamSecRoleEnables.readRecByNameIdx() ";
		ICFSecSecRoleEnables buff;
		ArrayList<ICFSecSecRoleEnables> filteredList = new ArrayList<ICFSecSecRoleEnables>();
		ICFSecSecRoleEnables[] buffList = readDerivedByNameIdx( Authorization,
			EnableName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRoleEnables.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecRoleEnables)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecRoleEnables[0] ) );
	}

	/**
	 *	Read a page array of the specific SecRoleEnables buffer instances identified by the duplicate key RoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecRoleId	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleEnables[] pageRecByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		CFLibDbKeyHash256 priorSecRoleId,
		String priorEnableName )
	{
		final String S_ProcName = "pageRecByRoleIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecRoleEnables buffer instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EnableName	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleEnables[] pageRecByNameIdx( ICFSecAuthorization Authorization,
		String EnableName,
		CFLibDbKeyHash256 priorSecRoleId,
		String priorEnableName )
	{
		final String S_ProcName = "pageRecByNameIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecRoleEnables updateSecRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnables iBuff )
	{
		CFSecBuffSecRoleEnables Buff = (CFSecBuffSecRoleEnables)ensureRec(iBuff);
		CFSecBuffSecRoleEnablesPKey pkey = (CFSecBuffSecRoleEnablesPKey)(schema.getFactorySecRoleEnables().newPKey());
		pkey.setRequiredContainerRole( Buff.getRequiredSecRoleId() );
		pkey.setRequiredParentEnableGroup( Buff.getRequiredEnableName() );
		CFSecBuffSecRoleEnables existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecRoleEnables",
				"Existing record not found",
				"Existing record not found",
				"SecRoleEnables",
				"SecRoleEnables",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecRoleEnables",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecRoleEnablesByRoleIdxKey existingKeyRoleIdx = (CFSecBuffSecRoleEnablesByRoleIdxKey)schema.getFactorySecRoleEnables().newByRoleIdxKey();
		existingKeyRoleIdx.setRequiredSecRoleId( existing.getRequiredSecRoleId() );

		CFSecBuffSecRoleEnablesByRoleIdxKey newKeyRoleIdx = (CFSecBuffSecRoleEnablesByRoleIdxKey)schema.getFactorySecRoleEnables().newByRoleIdxKey();
		newKeyRoleIdx.setRequiredSecRoleId( Buff.getRequiredSecRoleId() );

		CFSecBuffSecRoleEnablesByNameIdxKey existingKeyNameIdx = (CFSecBuffSecRoleEnablesByNameIdxKey)schema.getFactorySecRoleEnables().newByNameIdxKey();
		existingKeyNameIdx.setRequiredEnableName( existing.getRequiredEnableName() );

		CFSecBuffSecRoleEnablesByNameIdxKey newKeyNameIdx = (CFSecBuffSecRoleEnablesByNameIdxKey)schema.getFactorySecRoleEnables().newByNameIdxKey();
		newKeyNameIdx.setRequiredEnableName( Buff.getRequiredEnableName() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecRoleEnables",
						"Container",
						"Container",
						"SecRoleEnablesRole",
						"SecRoleEnablesRole",
						"SecRole",
						"SecRole",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables > subdict;

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
			subdict = new HashMap< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables >();
			dictByRoleIdx.put( newKeyRoleIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByNameIdx.get( existingKeyNameIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
			subdict = dictByNameIdx.get( newKeyNameIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables >();
			dictByNameIdx.put( newKeyNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnables iBuff )
	{
		final String S_ProcName = "CFSecRamSecRoleEnablesTable.deleteSecRoleEnables() ";
		CFSecBuffSecRoleEnables Buff = (CFSecBuffSecRoleEnables)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecRoleEnablesPKey pkey = (CFSecBuffSecRoleEnablesPKey)(Buff.getPKey());
		CFSecBuffSecRoleEnables existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecRoleEnables",
				pkey );
		}
		CFSecBuffSecRoleEnablesByRoleIdxKey keyRoleIdx = (CFSecBuffSecRoleEnablesByRoleIdxKey)schema.getFactorySecRoleEnables().newByRoleIdxKey();
		keyRoleIdx.setRequiredSecRoleId( existing.getRequiredSecRoleId() );

		CFSecBuffSecRoleEnablesByNameIdxKey keyNameIdx = (CFSecBuffSecRoleEnablesByNameIdxKey)schema.getFactorySecRoleEnables().newByNameIdxKey();
		keyNameIdx.setRequiredEnableName( existing.getRequiredEnableName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecRoleEnablesPKey, CFSecBuffSecRoleEnables > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByRoleIdx.get( keyRoleIdx );
		subdict.remove( pkey );

		subdict = dictByNameIdx.get( keyNameIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecRoleEnablesByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId,
		String EnableName )
	{
		CFSecBuffSecRoleEnablesPKey key = (CFSecBuffSecRoleEnablesPKey)(schema.getFactorySecRoleEnables().newPKey());
		key.setRequiredContainerRole( SecRoleId );
		key.setRequiredParentEnableGroup( EnableName );
		deleteSecRoleEnablesByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecRoleEnablesByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesPKey PKey )
	{
		CFSecBuffSecRoleEnablesPKey key = (CFSecBuffSecRoleEnablesPKey)(schema.getFactorySecRoleEnables().newPKey());
		key.setRequiredContainerRole( PKey.getRequiredSecRoleId() );
		key.setRequiredParentEnableGroup( PKey.getRequiredEnableName() );
		CFSecBuffSecRoleEnablesPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecRoleEnables cur;
		LinkedList<CFSecBuffSecRoleEnables> matchSet = new LinkedList<CFSecBuffSecRoleEnables>();
		Iterator<CFSecBuffSecRoleEnables> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecRoleEnables> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecRoleEnables)(schema.getTableSecRoleEnables().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecRoleId(),
				cur.getRequiredEnableName() ));
			deleteSecRoleEnables( Authorization, cur );
		}
	}

	@Override
	public void deleteSecRoleEnablesByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId )
	{
		CFSecBuffSecRoleEnablesByRoleIdxKey key = (CFSecBuffSecRoleEnablesByRoleIdxKey)schema.getFactorySecRoleEnables().newByRoleIdxKey();
		key.setRequiredSecRoleId( argSecRoleId );
		deleteSecRoleEnablesByRoleIdx( Authorization, key );
	}

	@Override
	public void deleteSecRoleEnablesByRoleIdx( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesByRoleIdxKey argKey )
	{
		CFSecBuffSecRoleEnables cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecRoleEnables> matchSet = new LinkedList<CFSecBuffSecRoleEnables>();
		Iterator<CFSecBuffSecRoleEnables> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecRoleEnables> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecRoleEnables)(schema.getTableSecRoleEnables().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecRoleId(),
				cur.getRequiredEnableName() ));
			deleteSecRoleEnables( Authorization, cur );
		}
	}

	@Override
	public void deleteSecRoleEnablesByNameIdx( ICFSecAuthorization Authorization,
		String argEnableName )
	{
		CFSecBuffSecRoleEnablesByNameIdxKey key = (CFSecBuffSecRoleEnablesByNameIdxKey)schema.getFactorySecRoleEnables().newByNameIdxKey();
		key.setRequiredEnableName( argEnableName );
		deleteSecRoleEnablesByNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecRoleEnablesByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesByNameIdxKey argKey )
	{
		CFSecBuffSecRoleEnables cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecRoleEnables> matchSet = new LinkedList<CFSecBuffSecRoleEnables>();
		Iterator<CFSecBuffSecRoleEnables> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecRoleEnables> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecRoleEnables)(schema.getTableSecRoleEnables().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecRoleId(),
				cur.getRequiredEnableName() ));
			deleteSecRoleEnables( Authorization, cur );
		}
	}
}
