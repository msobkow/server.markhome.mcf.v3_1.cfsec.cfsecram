
// Description: Java 25 in-memory RAM DbIO implementation for SecSysGrp.

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
 *	CFSecRamSecSysGrpTable in-memory RAM DbIO implementation
 *	for SecSysGrp.
 */
public class CFSecRamSecSysGrpTable
	implements ICFSecSecSysGrpTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffSecSysGrp > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffSecSysGrp >();
	private Map< CFSecBuffSecSysGrpByUNameIdxKey,
			CFSecBuffSecSysGrp > dictByUNameIdx
		= new HashMap< CFSecBuffSecSysGrpByUNameIdxKey,
			CFSecBuffSecSysGrp >();
	private Map< CFSecBuffSecSysGrpBySecLevelIdxKey,
			CFSecBuffSecSysGrp > dictBySecLevelIdx
		= new HashMap< CFSecBuffSecSysGrpBySecLevelIdxKey,
			CFSecBuffSecSysGrp >();
	private Map< CFSecBuffSecSysGrpBySecLevelNmIdxKey,
			CFSecBuffSecSysGrp > dictBySecLevelNmIdx
		= new HashMap< CFSecBuffSecSysGrpBySecLevelNmIdxKey,
			CFSecBuffSecSysGrp >();

	public CFSecRamSecSysGrpTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecSysGrp ensureRec(ICFSecSecSysGrp rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecSysGrp.CLASS_CODE) {
				return( ((CFSecBuffSecSysGrpDefaultFactory)(schema.getFactorySecSysGrp())).ensureRec((ICFSecSecSysGrp)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecSysGrp createSecSysGrp( ICFSecAuthorization Authorization,
		ICFSecSecSysGrp iBuff )
	{
		final String S_ProcName = "createSecSysGrp";
		
		CFSecBuffSecSysGrp Buff = (CFSecBuffSecSysGrp)ensureRec(iBuff);
		CFLibDbKeyHash256 pkey;
		pkey = schema.nextSecSysGrpIdGen();
		Buff.setRequiredSecSysGrpId( pkey );
		CFSecBuffSecSysGrpByUNameIdxKey keyUNameIdx = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getFactorySecSysGrp().newByUNameIdxKey();
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecSysGrpBySecLevelIdxKey keySecLevelIdx = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getFactorySecSysGrp().newBySecLevelIdxKey();
		keySecLevelIdx.setRequiredSecLevel( Buff.getRequiredSecLevel() );

		CFSecBuffSecSysGrpBySecLevelNmIdxKey keySecLevelNmIdx = (CFSecBuffSecSysGrpBySecLevelNmIdxKey)schema.getFactorySecSysGrp().newBySecLevelNmIdxKey();
		keySecLevelNmIdx.setRequiredSecLevel( Buff.getRequiredSecLevel() );
		keySecLevelNmIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecSysGrpUNameIdx",
				"SecSysGrpUNameIdx",
				keyUNameIdx );
		}

		if( dictBySecLevelIdx.containsKey( keySecLevelIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecSysGrpLevelIdx",
				"SecSysGrpLevelIdx",
				keySecLevelIdx );
		}

		if( dictBySecLevelNmIdx.containsKey( keySecLevelNmIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecSysGrpLevelNameIdx",
				"SecSysGrpLevelNameIdx",
				keySecLevelNmIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

		dictBySecLevelIdx.put( keySecLevelIdx, Buff );

		dictBySecLevelNmIdx.put( keySecLevelNmIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecSysGrp.CLASS_CODE) {
				CFSecBuffSecSysGrp retbuff = ((CFSecBuffSecSysGrp)(schema.getFactorySecSysGrp().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecSysGrp readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readDerived";
		ICFSecSecSysGrp buff;
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
	public ICFSecSecSysGrp lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.lockDerived";
		ICFSecSecSysGrp buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecSysGrp.readAllDerived";
		ICFSecSecSysGrp[] retList = new ICFSecSecSysGrp[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecSysGrp > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecSysGrp readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readDerivedByUNameIdx";
		CFSecBuffSecSysGrpByUNameIdxKey key = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getFactorySecSysGrp().newByUNameIdxKey();

		key.setRequiredName( Name );
		ICFSecSecSysGrp buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp readDerivedBySecLevelIdx( ICFSecAuthorization Authorization,
		ICFSecSchema.SecLevelEnum SecLevel )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readDerivedBySecLevelIdx";
		CFSecBuffSecSysGrpBySecLevelIdxKey key = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getFactorySecSysGrp().newBySecLevelIdxKey();

		key.setRequiredSecLevel( SecLevel );
		ICFSecSecSysGrp buff;
		if( dictBySecLevelIdx.containsKey( key ) ) {
			buff = dictBySecLevelIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp readDerivedBySecLevelNmIdx( ICFSecAuthorization Authorization,
		ICFSecSchema.SecLevelEnum SecLevel,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readDerivedBySecLevelNmIdx";
		CFSecBuffSecSysGrpBySecLevelNmIdxKey key = (CFSecBuffSecSysGrpBySecLevelNmIdxKey)schema.getFactorySecSysGrp().newBySecLevelNmIdxKey();

		key.setRequiredSecLevel( SecLevel );
		key.setRequiredName( Name );
		ICFSecSecSysGrp buff;
		if( dictBySecLevelNmIdx.containsKey( key ) ) {
			buff = dictBySecLevelNmIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSysGrpId )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readDerivedByIdIdx() ";
		ICFSecSecSysGrp buff;
		if( dictByPKey.containsKey( SecSysGrpId ) ) {
			buff = dictByPKey.get( SecSysGrpId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readRec";
		ICFSecSecSysGrp buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysGrp.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp lockRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecSysGrp buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysGrp.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readAllRec";
		ICFSecSecSysGrp buff;
		ArrayList<ICFSecSecSysGrp> filteredList = new ArrayList<ICFSecSecSysGrp>();
		ICFSecSecSysGrp[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrp.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysGrp[0] ) );
	}

	@Override
	public ICFSecSecSysGrp readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSysGrpId )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readRecByIdIdx() ";
		ICFSecSecSysGrp buff = readDerivedByIdIdx( Authorization,
			SecSysGrpId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrp.CLASS_CODE ) ) {
			return( (ICFSecSecSysGrp)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecSysGrp readRecByUNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readRecByUNameIdx() ";
		ICFSecSecSysGrp buff = readDerivedByUNameIdx( Authorization,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrp.CLASS_CODE ) ) {
			return( (ICFSecSecSysGrp)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecSysGrp readRecBySecLevelIdx( ICFSecAuthorization Authorization,
		ICFSecSchema.SecLevelEnum SecLevel )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readRecBySecLevelIdx() ";
		ICFSecSecSysGrp buff = readDerivedBySecLevelIdx( Authorization,
			SecLevel );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrp.CLASS_CODE ) ) {
			return( (ICFSecSecSysGrp)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecSysGrp readRecBySecLevelNmIdx( ICFSecAuthorization Authorization,
		ICFSecSchema.SecLevelEnum SecLevel,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readRecBySecLevelNmIdx() ";
		ICFSecSecSysGrp buff = readDerivedBySecLevelNmIdx( Authorization,
			SecLevel,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrp.CLASS_CODE ) ) {
			return( (ICFSecSecSysGrp)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecSysGrp updateSecSysGrp( ICFSecAuthorization Authorization,
		ICFSecSecSysGrp iBuff )
	{
		CFSecBuffSecSysGrp Buff = (CFSecBuffSecSysGrp)ensureRec(iBuff);
		CFLibDbKeyHash256 pkey = Buff.getPKey();
		CFSecBuffSecSysGrp existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecSysGrp",
				"Existing record not found",
				"Existing record not found",
				"SecSysGrp",
				"SecSysGrp",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecSysGrp",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecSysGrpByUNameIdxKey existingKeyUNameIdx = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getFactorySecSysGrp().newByUNameIdxKey();
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecSysGrpByUNameIdxKey newKeyUNameIdx = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getFactorySecSysGrp().newByUNameIdxKey();
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecSysGrpBySecLevelIdxKey existingKeySecLevelIdx = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getFactorySecSysGrp().newBySecLevelIdxKey();
		existingKeySecLevelIdx.setRequiredSecLevel( existing.getRequiredSecLevel() );

		CFSecBuffSecSysGrpBySecLevelIdxKey newKeySecLevelIdx = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getFactorySecSysGrp().newBySecLevelIdxKey();
		newKeySecLevelIdx.setRequiredSecLevel( Buff.getRequiredSecLevel() );

		CFSecBuffSecSysGrpBySecLevelNmIdxKey existingKeySecLevelNmIdx = (CFSecBuffSecSysGrpBySecLevelNmIdxKey)schema.getFactorySecSysGrp().newBySecLevelNmIdxKey();
		existingKeySecLevelNmIdx.setRequiredSecLevel( existing.getRequiredSecLevel() );
		existingKeySecLevelNmIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecSysGrpBySecLevelNmIdxKey newKeySecLevelNmIdx = (CFSecBuffSecSysGrpBySecLevelNmIdxKey)schema.getFactorySecSysGrp().newBySecLevelNmIdxKey();
		newKeySecLevelNmIdx.setRequiredSecLevel( Buff.getRequiredSecLevel() );
		newKeySecLevelNmIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecSysGrp",
					"SecSysGrpUNameIdx",
					"SecSysGrpUNameIdx",
					newKeyUNameIdx );
			}
		}

		if( ! existingKeySecLevelIdx.equals( newKeySecLevelIdx ) ) {
			if( dictBySecLevelIdx.containsKey( newKeySecLevelIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecSysGrp",
					"SecSysGrpLevelIdx",
					"SecSysGrpLevelIdx",
					newKeySecLevelIdx );
			}
		}

		if( ! existingKeySecLevelNmIdx.equals( newKeySecLevelNmIdx ) ) {
			if( dictBySecLevelNmIdx.containsKey( newKeySecLevelNmIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecSysGrp",
					"SecSysGrpLevelNameIdx",
					"SecSysGrpLevelNameIdx",
					newKeySecLevelNmIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffSecSysGrp > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

		dictBySecLevelIdx.remove( existingKeySecLevelIdx );
		dictBySecLevelIdx.put( newKeySecLevelIdx, Buff );

		dictBySecLevelNmIdx.remove( existingKeySecLevelNmIdx );
		dictBySecLevelNmIdx.put( newKeySecLevelNmIdx, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecSysGrp( ICFSecAuthorization Authorization,
		ICFSecSecSysGrp iBuff )
	{
		final String S_ProcName = "CFSecRamSecSysGrpTable.deleteSecSysGrp() ";
		CFSecBuffSecSysGrp Buff = (CFSecBuffSecSysGrp)ensureRec(iBuff);
		int classCode;
		CFLibDbKeyHash256 pkey = (CFLibDbKeyHash256)(Buff.getPKey());
		CFSecBuffSecSysGrp existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecSysGrp",
				pkey );
		}
					schema.getTableSecSysGrpMemb().deleteSecSysGrpMembBySysGrpIdx( Authorization,
						existing.getRequiredSecSysGrpId() );
					schema.getTableSecSysGrpInc().deleteSecSysGrpIncBySysGrpIdx( Authorization,
						existing.getRequiredSecSysGrpId() );
		CFSecBuffSecSysGrpByUNameIdxKey keyUNameIdx = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getFactorySecSysGrp().newByUNameIdxKey();
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecSysGrpBySecLevelIdxKey keySecLevelIdx = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getFactorySecSysGrp().newBySecLevelIdxKey();
		keySecLevelIdx.setRequiredSecLevel( existing.getRequiredSecLevel() );

		CFSecBuffSecSysGrpBySecLevelNmIdxKey keySecLevelNmIdx = (CFSecBuffSecSysGrpBySecLevelNmIdxKey)schema.getFactorySecSysGrp().newBySecLevelNmIdxKey();
		keySecLevelNmIdx.setRequiredSecLevel( existing.getRequiredSecLevel() );
		keySecLevelNmIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffSecSysGrp > subdict;

		dictByPKey.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

		dictBySecLevelIdx.remove( keySecLevelIdx );

		dictBySecLevelNmIdx.remove( keySecLevelNmIdx );

	}
	@Override
	public void deleteSecSysGrpByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecSysGrp cur;
		LinkedList<CFSecBuffSecSysGrp> matchSet = new LinkedList<CFSecBuffSecSysGrp>();
		Iterator<CFSecBuffSecSysGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrp)(schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId() ));
			deleteSecSysGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysGrpByUNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		CFSecBuffSecSysGrpByUNameIdxKey key = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getFactorySecSysGrp().newByUNameIdxKey();
		key.setRequiredName( argName );
		deleteSecSysGrpByUNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpByUNameIdxKey argKey )
	{
		CFSecBuffSecSysGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysGrp> matchSet = new LinkedList<CFSecBuffSecSysGrp>();
		Iterator<CFSecBuffSecSysGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrp)(schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId() ));
			deleteSecSysGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysGrpBySecLevelIdx( ICFSecAuthorization Authorization,
		ICFSecSchema.SecLevelEnum argSecLevel )
	{
		CFSecBuffSecSysGrpBySecLevelIdxKey key = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getFactorySecSysGrp().newBySecLevelIdxKey();
		key.setRequiredSecLevel( argSecLevel );
		deleteSecSysGrpBySecLevelIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpBySecLevelIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpBySecLevelIdxKey argKey )
	{
		CFSecBuffSecSysGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysGrp> matchSet = new LinkedList<CFSecBuffSecSysGrp>();
		Iterator<CFSecBuffSecSysGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrp)(schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId() ));
			deleteSecSysGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysGrpBySecLevelNmIdx( ICFSecAuthorization Authorization,
		ICFSecSchema.SecLevelEnum argSecLevel,
		String argName )
	{
		CFSecBuffSecSysGrpBySecLevelNmIdxKey key = (CFSecBuffSecSysGrpBySecLevelNmIdxKey)schema.getFactorySecSysGrp().newBySecLevelNmIdxKey();
		key.setRequiredSecLevel( argSecLevel );
		key.setRequiredName( argName );
		deleteSecSysGrpBySecLevelNmIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpBySecLevelNmIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpBySecLevelNmIdxKey argKey )
	{
		CFSecBuffSecSysGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysGrp> matchSet = new LinkedList<CFSecBuffSecSysGrp>();
		Iterator<CFSecBuffSecSysGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrp)(schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId() ));
			deleteSecSysGrp( Authorization, cur );
		}
	}
}
