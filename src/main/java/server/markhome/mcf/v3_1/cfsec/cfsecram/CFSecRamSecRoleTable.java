
// Description: Java 25 in-memory RAM DbIO implementation for SecRole.

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
 *	CFSecRamSecRoleTable in-memory RAM DbIO implementation
 *	for SecRole.
 */
public class CFSecRamSecRoleTable
	implements ICFSecSecRoleTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffSecRole > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffSecRole >();
	private Map< CFSecBuffSecRoleByUNameIdxKey,
			CFSecBuffSecRole > dictByUNameIdx
		= new HashMap< CFSecBuffSecRoleByUNameIdxKey,
			CFSecBuffSecRole >();

	public CFSecRamSecRoleTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecRole ensureRec(ICFSecSecRole rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecRole.CLASS_CODE) {
				return( ((CFSecBuffSecRoleDefaultFactory)(schema.getFactorySecRole())).ensureRec((ICFSecSecRole)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecRole createSecRole( ICFSecAuthorization Authorization,
		ICFSecSecRole iBuff )
	{
		final String S_ProcName = "createSecRole";
		
		CFSecBuffSecRole Buff = (CFSecBuffSecRole)ensureRec(iBuff);
		CFLibDbKeyHash256 pkey;
		pkey = schema.nextSecSysGrpIdGen();
		Buff.setRequiredSecRoleId( pkey );
		CFSecBuffSecRoleByUNameIdxKey keyUNameIdx = (CFSecBuffSecRoleByUNameIdxKey)schema.getFactorySecRole().newByUNameIdxKey();
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecRoleUNameIdx",
				"SecRoleUNameIdx",
				keyUNameIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecRole.CLASS_CODE) {
				CFSecBuffSecRole retbuff = ((CFSecBuffSecRole)(schema.getFactorySecRole().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecRole readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecRole.readDerived";
		ICFSecSecRole buff;
		if( PKey == null ) {
			return( null );
		}
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRole lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecRole.lockDerived";
		ICFSecSecRole buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRole[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecRole.readAllDerived";
		ICFSecSecRole[] retList = new ICFSecSecRole[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecRole > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecRole readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecRole.readDerivedByUNameIdx";
		CFSecBuffSecRoleByUNameIdxKey key = (CFSecBuffSecRoleByUNameIdxKey)schema.getFactorySecRole().newByUNameIdxKey();

		key.setRequiredName( Name );
		ICFSecSecRole buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRole readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId )
	{
		final String S_ProcName = "CFSecRamSecRole.readDerivedByIdIdx() ";
		ICFSecSecRole buff;
		if( dictByPKey.containsKey( SecRoleId ) ) {
			buff = dictByPKey.get( SecRoleId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRole readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecRole.readRec";
		ICFSecSecRole buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecRole.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRole lockRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecRole buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecRole.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecRole[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecRole.readAllRec";
		ICFSecSecRole buff;
		ArrayList<ICFSecSecRole> filteredList = new ArrayList<ICFSecSecRole>();
		ICFSecSecRole[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRole.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecRole[0] ) );
	}

	@Override
	public ICFSecSecRole readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecRoleId )
	{
		final String S_ProcName = "CFSecRamSecRole.readRecByIdIdx() ";
		ICFSecSecRole buff = readDerivedByIdIdx( Authorization,
			SecRoleId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRole.CLASS_CODE ) ) {
			return( (ICFSecSecRole)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecRole readRecByUNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecRole.readRecByUNameIdx() ";
		ICFSecSecRole buff = readDerivedByUNameIdx( Authorization,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecRole.CLASS_CODE ) ) {
			return( (ICFSecSecRole)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecRole updateSecRole( ICFSecAuthorization Authorization,
		ICFSecSecRole iBuff )
	{
		CFSecBuffSecRole Buff = (CFSecBuffSecRole)ensureRec(iBuff);
		CFLibDbKeyHash256 pkey = Buff.getPKey();
		CFSecBuffSecRole existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecRole",
				"Existing record not found",
				"Existing record not found",
				"SecRole",
				"SecRole",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecRole",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecRoleByUNameIdxKey existingKeyUNameIdx = (CFSecBuffSecRoleByUNameIdxKey)schema.getFactorySecRole().newByUNameIdxKey();
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecRoleByUNameIdxKey newKeyUNameIdx = (CFSecBuffSecRoleByUNameIdxKey)schema.getFactorySecRole().newByUNameIdxKey();
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecRole",
					"SecRoleUNameIdx",
					"SecRoleUNameIdx",
					newKeyUNameIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffSecRole > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecRole( ICFSecAuthorization Authorization,
		ICFSecSecRole iBuff )
	{
		final String S_ProcName = "CFSecRamSecRoleTable.deleteSecRole() ";
		CFSecBuffSecRole Buff = (CFSecBuffSecRole)ensureRec(iBuff);
		int classCode;
		CFLibDbKeyHash256 pkey = (CFLibDbKeyHash256)(Buff.getPKey());
		CFSecBuffSecRole existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecRole",
				pkey );
		}
					schema.getTableSecRoleMemb().deleteSecRoleMembByRoleIdx( Authorization,
						existing.getRequiredSecRoleId() );
					schema.getTableSecRoleEnables().deleteSecRoleEnablesByRoleIdx( Authorization,
						existing.getRequiredSecRoleId() );
		CFSecBuffSecRoleByUNameIdxKey keyUNameIdx = (CFSecBuffSecRoleByUNameIdxKey)schema.getFactorySecRole().newByUNameIdxKey();
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffSecRole > subdict;

		dictByPKey.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	@Override
	public void deleteSecRoleByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecRole cur;
		LinkedList<CFSecBuffSecRole> matchSet = new LinkedList<CFSecBuffSecRole>();
		Iterator<CFSecBuffSecRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecRole)(schema.getTableSecRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecRoleId() ));
			deleteSecRole( Authorization, cur );
		}
	}

	@Override
	public void deleteSecRoleByUNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		CFSecBuffSecRoleByUNameIdxKey key = (CFSecBuffSecRoleByUNameIdxKey)schema.getFactorySecRole().newByUNameIdxKey();
		key.setRequiredName( argName );
		deleteSecRoleByUNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecRoleByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecRoleByUNameIdxKey argKey )
	{
		CFSecBuffSecRole cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecRole> matchSet = new LinkedList<CFSecBuffSecRole>();
		Iterator<CFSecBuffSecRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecRole)(schema.getTableSecRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecRoleId() ));
			deleteSecRole( Authorization, cur );
		}
	}
}
