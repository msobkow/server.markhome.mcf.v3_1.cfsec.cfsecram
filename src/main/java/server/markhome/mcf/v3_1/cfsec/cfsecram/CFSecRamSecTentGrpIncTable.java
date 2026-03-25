
// Description: Java 25 in-memory RAM DbIO implementation for SecTentGrpInc.

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
 *	CFSecRamSecTentGrpIncTable in-memory RAM DbIO implementation
 *	for SecTentGrpInc.
 */
public class CFSecRamSecTentGrpIncTable
	implements ICFSecSecTentGrpIncTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecTentGrpIncPKey,
				CFSecBuffSecTentGrpInc > dictByPKey
		= new HashMap< ICFSecSecTentGrpIncPKey,
				CFSecBuffSecTentGrpInc >();
	private Map< CFSecBuffSecTentGrpIncByTentGrpIdxKey,
				Map< CFSecBuffSecTentGrpIncPKey,
					CFSecBuffSecTentGrpInc >> dictByTentGrpIdx
		= new HashMap< CFSecBuffSecTentGrpIncByTentGrpIdxKey,
				Map< CFSecBuffSecTentGrpIncPKey,
					CFSecBuffSecTentGrpInc >>();
	private Map< CFSecBuffSecTentGrpIncByNameIdxKey,
				Map< CFSecBuffSecTentGrpIncPKey,
					CFSecBuffSecTentGrpInc >> dictByNameIdx
		= new HashMap< CFSecBuffSecTentGrpIncByNameIdxKey,
				Map< CFSecBuffSecTentGrpIncPKey,
					CFSecBuffSecTentGrpInc >>();

	public CFSecRamSecTentGrpIncTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecTentGrpInc ensureRec(ICFSecSecTentGrpInc rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecTentGrpInc.CLASS_CODE) {
				return( ((CFSecBuffSecTentGrpIncDefaultFactory)(schema.getFactorySecTentGrpInc())).ensureRec((ICFSecSecTentGrpInc)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecTentGrpInc createSecTentGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpInc iBuff )
	{
		final String S_ProcName = "createSecTentGrpInc";
		
		CFSecBuffSecTentGrpInc Buff = (CFSecBuffSecTentGrpInc)ensureRec(iBuff);
		CFSecBuffSecTentGrpIncPKey pkey = (CFSecBuffSecTentGrpIncPKey)(schema.getFactorySecTentGrpInc().newPKey());
		pkey.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );
		pkey.setRequiredInclName( Buff.getRequiredInclName() );
		Buff.setRequiredSecTentGrpId( pkey.getRequiredSecTentGrpId() );
		Buff.setRequiredInclName( pkey.getRequiredInclName() );
		CFSecBuffSecTentGrpIncByTentGrpIdxKey keyTentGrpIdx = (CFSecBuffSecTentGrpIncByTentGrpIdxKey)schema.getFactorySecTentGrpInc().newByTentGrpIdxKey();
		keyTentGrpIdx.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpIncByNameIdxKey keyNameIdx = (CFSecBuffSecTentGrpIncByNameIdxKey)schema.getFactorySecTentGrpInc().newByNameIdxKey();
		keyNameIdx.setRequiredInclName( Buff.getRequiredInclName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc > subdictTentGrpIdx;
		if( dictByTentGrpIdx.containsKey( keyTentGrpIdx ) ) {
			subdictTentGrpIdx = dictByTentGrpIdx.get( keyTentGrpIdx );
		}
		else {
			subdictTentGrpIdx = new HashMap< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc >();
			dictByTentGrpIdx.put( keyTentGrpIdx, subdictTentGrpIdx );
		}
		subdictTentGrpIdx.put( pkey, Buff );

		Map< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc > subdictNameIdx;
		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			subdictNameIdx = dictByNameIdx.get( keyNameIdx );
		}
		else {
			subdictNameIdx = new HashMap< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc >();
			dictByNameIdx.put( keyNameIdx, subdictNameIdx );
		}
		subdictNameIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecTentGrpInc.CLASS_CODE) {
				CFSecBuffSecTentGrpInc retbuff = ((CFSecBuffSecTentGrpInc)(schema.getFactorySecTentGrpInc().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecTentGrpInc readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		String InclName )
	{
		{	CFLibDbKeyHash256 testSecTentGrpId = SecTentGrpId;
			if (testSecTentGrpId == null) {
				return( null );
			}
		}
		{	String testInclName = InclName;
			if (testInclName == null) {
				return( null );
			}
		}
		CFSecBuffSecTentGrpIncPKey key = (CFSecBuffSecTentGrpIncPKey)(schema.getFactorySecTentGrpInc().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredInclName( InclName );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecTentGrpInc readDerived( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpIncPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrpInc.readDerived";
		CFSecBuffSecTentGrpIncPKey key = (CFSecBuffSecTentGrpIncPKey)(schema.getFactorySecTentGrpInc().newPKey());
		key.setRequiredSecTentGrpId( PKey.getRequiredSecTentGrpId() );
		key.setRequiredInclName( PKey.getRequiredInclName() );
		ICFSecSecTentGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpInc lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpIncPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrpInc.lockDerived";
		CFSecBuffSecTentGrpIncPKey key = (CFSecBuffSecTentGrpIncPKey)(schema.getFactorySecTentGrpInc().newPKey());
		key.setRequiredSecTentGrpId( PKey.getRequiredSecTentGrpId() );
		key.setRequiredInclName( PKey.getRequiredInclName() );
		ICFSecSecTentGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpInc[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecTentGrpInc.readAllDerived";
		ICFSecSecTentGrpInc[] retList = new ICFSecSecTentGrpInc[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecTentGrpInc > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecTentGrpInc[] readDerivedByTentGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpInc.readDerivedByTentGrpIdx";
		CFSecBuffSecTentGrpIncByTentGrpIdxKey key = (CFSecBuffSecTentGrpIncByTentGrpIdxKey)schema.getFactorySecTentGrpInc().newByTentGrpIdxKey();

		key.setRequiredSecTentGrpId( SecTentGrpId );
		ICFSecSecTentGrpInc[] recArray;
		if( dictByTentGrpIdx.containsKey( key ) ) {
			Map< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc > subdictTentGrpIdx
				= dictByTentGrpIdx.get( key );
			recArray = new ICFSecSecTentGrpInc[ subdictTentGrpIdx.size() ];
			Iterator< CFSecBuffSecTentGrpInc > iter = subdictTentGrpIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc > subdictTentGrpIdx
				= new HashMap< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc >();
			dictByTentGrpIdx.put( key, subdictTentGrpIdx );
			recArray = new ICFSecSecTentGrpInc[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentGrpInc[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String InclName )
	{
		final String S_ProcName = "CFSecRamSecTentGrpInc.readDerivedByNameIdx";
		CFSecBuffSecTentGrpIncByNameIdxKey key = (CFSecBuffSecTentGrpIncByNameIdxKey)schema.getFactorySecTentGrpInc().newByNameIdxKey();

		key.setRequiredInclName( InclName );
		ICFSecSecTentGrpInc[] recArray;
		if( dictByNameIdx.containsKey( key ) ) {
			Map< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc > subdictNameIdx
				= dictByNameIdx.get( key );
			recArray = new ICFSecSecTentGrpInc[ subdictNameIdx.size() ];
			Iterator< CFSecBuffSecTentGrpInc > iter = subdictNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc > subdictNameIdx
				= new HashMap< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc >();
			dictByNameIdx.put( key, subdictNameIdx );
			recArray = new ICFSecSecTentGrpInc[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecTentGrpInc readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		String InclName )
	{
		final String S_ProcName = "CFSecRamSecTentGrpInc.readDerivedByIdIdx() ";
		CFSecBuffSecTentGrpIncPKey key = (CFSecBuffSecTentGrpIncPKey)(schema.getFactorySecTentGrpInc().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredInclName( InclName );
		ICFSecSecTentGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpInc readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		String InclName )
	{
		CFSecBuffSecTentGrpIncPKey key = (CFSecBuffSecTentGrpIncPKey)(schema.getFactorySecTentGrpInc().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredInclName( InclName );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecTentGrpInc readRec( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpIncPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecTentGrpInc.readRec";
		ICFSecSecTentGrpInc buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentGrpInc.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpInc lockRec( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpIncPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecTentGrpInc buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecTentGrpInc.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecTentGrpInc[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecTentGrpInc.readAllRec";
		ICFSecSecTentGrpInc buff;
		ArrayList<ICFSecSecTentGrpInc> filteredList = new ArrayList<ICFSecSecTentGrpInc>();
		ICFSecSecTentGrpInc[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpInc.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrpInc[0] ) );
	}

	/**
	 *	Read a page of all the specific SecTentGrpInc buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecTentGrpInc instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecTentGrpInc[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecTentGrpId,
		String priorInclName )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecTentGrpInc readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		String InclName )
	{
		final String S_ProcName = "CFSecRamSecTentGrpInc.readRecByIdIdx() ";
		ICFSecSecTentGrpInc buff = readDerivedByIdIdx( Authorization,
			SecTentGrpId,
			InclName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpInc.CLASS_CODE ) ) {
			return( (ICFSecSecTentGrpInc)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecTentGrpInc[] readRecByTentGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId )
	{
		final String S_ProcName = "CFSecRamSecTentGrpInc.readRecByTentGrpIdx() ";
		ICFSecSecTentGrpInc buff;
		ArrayList<ICFSecSecTentGrpInc> filteredList = new ArrayList<ICFSecSecTentGrpInc>();
		ICFSecSecTentGrpInc[] buffList = readDerivedByTentGrpIdx( Authorization,
			SecTentGrpId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpInc.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrpInc[0] ) );
	}

	@Override
	public ICFSecSecTentGrpInc[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String InclName )
	{
		final String S_ProcName = "CFSecRamSecTentGrpInc.readRecByNameIdx() ";
		ICFSecSecTentGrpInc buff;
		ArrayList<ICFSecSecTentGrpInc> filteredList = new ArrayList<ICFSecSecTentGrpInc>();
		ICFSecSecTentGrpInc[] buffList = readDerivedByNameIdx( Authorization,
			InclName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecTentGrpInc.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecTentGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecTentGrpInc[0] ) );
	}

	/**
	 *	Read a page array of the specific SecTentGrpInc buffer instances identified by the duplicate key TentGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecTentGrpId	The SecTentGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecTentGrpInc[] pageRecByTentGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		CFLibDbKeyHash256 priorSecTentGrpId,
		String priorInclName )
	{
		final String S_ProcName = "pageRecByTentGrpIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecTentGrpInc buffer instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	InclName	The SecTentGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecTentGrpInc[] pageRecByNameIdx( ICFSecAuthorization Authorization,
		String InclName,
		CFLibDbKeyHash256 priorSecTentGrpId,
		String priorInclName )
	{
		final String S_ProcName = "pageRecByNameIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecTentGrpInc updateSecTentGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpInc iBuff )
	{
		CFSecBuffSecTentGrpInc Buff = (CFSecBuffSecTentGrpInc)ensureRec(iBuff);
		CFSecBuffSecTentGrpIncPKey pkey = (CFSecBuffSecTentGrpIncPKey)(schema.getFactorySecTentGrpInc().newPKey());
		pkey.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );
		pkey.setRequiredInclName( Buff.getRequiredInclName() );
		CFSecBuffSecTentGrpInc existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecTentGrpInc",
				"Existing record not found",
				"Existing record not found",
				"SecTentGrpInc",
				"SecTentGrpInc",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecTentGrpInc",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecTentGrpIncByTentGrpIdxKey existingKeyTentGrpIdx = (CFSecBuffSecTentGrpIncByTentGrpIdxKey)schema.getFactorySecTentGrpInc().newByTentGrpIdxKey();
		existingKeyTentGrpIdx.setRequiredSecTentGrpId( existing.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpIncByTentGrpIdxKey newKeyTentGrpIdx = (CFSecBuffSecTentGrpIncByTentGrpIdxKey)schema.getFactorySecTentGrpInc().newByTentGrpIdxKey();
		newKeyTentGrpIdx.setRequiredSecTentGrpId( Buff.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpIncByNameIdxKey existingKeyNameIdx = (CFSecBuffSecTentGrpIncByNameIdxKey)schema.getFactorySecTentGrpInc().newByNameIdxKey();
		existingKeyNameIdx.setRequiredInclName( existing.getRequiredInclName() );

		CFSecBuffSecTentGrpIncByNameIdxKey newKeyNameIdx = (CFSecBuffSecTentGrpIncByNameIdxKey)schema.getFactorySecTentGrpInc().newByNameIdxKey();
		newKeyNameIdx.setRequiredInclName( Buff.getRequiredInclName() );

		// Check unique indexes

		// Validate foreign keys

		// Update is valid

		Map< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc > subdict;

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
			subdict = new HashMap< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc >();
			dictByTentGrpIdx.put( newKeyTentGrpIdx, subdict );
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
			subdict = new HashMap< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc >();
			dictByNameIdx.put( newKeyNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecTentGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpInc iBuff )
	{
		final String S_ProcName = "CFSecRamSecTentGrpIncTable.deleteSecTentGrpInc() ";
		CFSecBuffSecTentGrpInc Buff = (CFSecBuffSecTentGrpInc)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecTentGrpIncPKey pkey = (CFSecBuffSecTentGrpIncPKey)(Buff.getPKey());
		CFSecBuffSecTentGrpInc existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecTentGrpInc",
				pkey );
		}
		CFSecBuffSecTentGrpIncByTentGrpIdxKey keyTentGrpIdx = (CFSecBuffSecTentGrpIncByTentGrpIdxKey)schema.getFactorySecTentGrpInc().newByTentGrpIdxKey();
		keyTentGrpIdx.setRequiredSecTentGrpId( existing.getRequiredSecTentGrpId() );

		CFSecBuffSecTentGrpIncByNameIdxKey keyNameIdx = (CFSecBuffSecTentGrpIncByNameIdxKey)schema.getFactorySecTentGrpInc().newByNameIdxKey();
		keyNameIdx.setRequiredInclName( existing.getRequiredInclName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecTentGrpIncPKey, CFSecBuffSecTentGrpInc > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTentGrpIdx.get( keyTentGrpIdx );
		subdict.remove( pkey );

		subdict = dictByNameIdx.get( keyNameIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecTentGrpIncByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecTentGrpId,
		String InclName )
	{
		CFSecBuffSecTentGrpIncPKey key = (CFSecBuffSecTentGrpIncPKey)(schema.getFactorySecTentGrpInc().newPKey());
		key.setRequiredSecTentGrpId( SecTentGrpId );
		key.setRequiredInclName( InclName );
		deleteSecTentGrpIncByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpIncByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpIncPKey PKey )
	{
		CFSecBuffSecTentGrpIncPKey key = (CFSecBuffSecTentGrpIncPKey)(schema.getFactorySecTentGrpInc().newPKey());
		key.setRequiredSecTentGrpId( PKey.getRequiredSecTentGrpId() );
		key.setRequiredInclName( PKey.getRequiredInclName() );
		CFSecBuffSecTentGrpIncPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecTentGrpInc cur;
		LinkedList<CFSecBuffSecTentGrpInc> matchSet = new LinkedList<CFSecBuffSecTentGrpInc>();
		Iterator<CFSecBuffSecTentGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrpInc)(schema.getTableSecTentGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId(),
				cur.getRequiredInclName() ));
			deleteSecTentGrpInc( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentGrpIncByTentGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecTentGrpId )
	{
		CFSecBuffSecTentGrpIncByTentGrpIdxKey key = (CFSecBuffSecTentGrpIncByTentGrpIdxKey)schema.getFactorySecTentGrpInc().newByTentGrpIdxKey();
		key.setRequiredSecTentGrpId( argSecTentGrpId );
		deleteSecTentGrpIncByTentGrpIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpIncByTentGrpIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpIncByTentGrpIdxKey argKey )
	{
		CFSecBuffSecTentGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentGrpInc> matchSet = new LinkedList<CFSecBuffSecTentGrpInc>();
		Iterator<CFSecBuffSecTentGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrpInc)(schema.getTableSecTentGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId(),
				cur.getRequiredInclName() ));
			deleteSecTentGrpInc( Authorization, cur );
		}
	}

	@Override
	public void deleteSecTentGrpIncByNameIdx( ICFSecAuthorization Authorization,
		String argInclName )
	{
		CFSecBuffSecTentGrpIncByNameIdxKey key = (CFSecBuffSecTentGrpIncByNameIdxKey)schema.getFactorySecTentGrpInc().newByNameIdxKey();
		key.setRequiredInclName( argInclName );
		deleteSecTentGrpIncByNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecTentGrpIncByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecTentGrpIncByNameIdxKey argKey )
	{
		CFSecBuffSecTentGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecTentGrpInc> matchSet = new LinkedList<CFSecBuffSecTentGrpInc>();
		Iterator<CFSecBuffSecTentGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecTentGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecTentGrpInc)(schema.getTableSecTentGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecTentGrpId(),
				cur.getRequiredInclName() ));
			deleteSecTentGrpInc( Authorization, cur );
		}
	}
}
