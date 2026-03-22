
// Description: Java 25 in-memory RAM DbIO implementation for SecClusGrpInc.

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
 *	CFSecRamSecClusGrpIncTable in-memory RAM DbIO implementation
 *	for SecClusGrpInc.
 */
public class CFSecRamSecClusGrpIncTable
	implements ICFSecSecClusGrpIncTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecClusGrpIncPKey,
				CFSecBuffSecClusGrpInc > dictByPKey
		= new HashMap< ICFSecSecClusGrpIncPKey,
				CFSecBuffSecClusGrpInc >();
	private Map< CFSecBuffSecClusGrpIncByClusGrpIdxKey,
				Map< CFSecBuffSecClusGrpIncPKey,
					CFSecBuffSecClusGrpInc >> dictByClusGrpIdx
		= new HashMap< CFSecBuffSecClusGrpIncByClusGrpIdxKey,
				Map< CFSecBuffSecClusGrpIncPKey,
					CFSecBuffSecClusGrpInc >>();
	private Map< CFSecBuffSecClusGrpIncByNameIdxKey,
				Map< CFSecBuffSecClusGrpIncPKey,
					CFSecBuffSecClusGrpInc >> dictByNameIdx
		= new HashMap< CFSecBuffSecClusGrpIncByNameIdxKey,
				Map< CFSecBuffSecClusGrpIncPKey,
					CFSecBuffSecClusGrpInc >>();

	public CFSecRamSecClusGrpIncTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecClusGrpInc ensureRec(ICFSecSecClusGrpInc rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecClusGrpInc.CLASS_CODE) {
				return( ((CFSecBuffSecClusGrpIncDefaultFactory)(schema.getFactorySecClusGrpInc())).ensureRec((ICFSecSecClusGrpInc)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecClusGrpInc createSecClusGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpInc iBuff )
	{
		final String S_ProcName = "createSecClusGrpInc";
		
		CFSecBuffSecClusGrpInc Buff = (CFSecBuffSecClusGrpInc)ensureRec(iBuff);
		CFSecBuffSecClusGrpIncPKey pkey = (CFSecBuffSecClusGrpIncPKey)(schema.getFactorySecClusGrpInc().newPKey());
		pkey.setRequiredSecClusGrpId( Buff.getRequiredSecClusGrpId() );
		pkey.setRequiredIncName( Buff.getRequiredIncName() );
		Buff.setRequiredSecClusGrpId( pkey.getRequiredSecClusGrpId() );
		Buff.setRequiredIncName( pkey.getRequiredIncName() );
		CFSecBuffSecClusGrpIncByClusGrpIdxKey keyClusGrpIdx = (CFSecBuffSecClusGrpIncByClusGrpIdxKey)schema.getFactorySecClusGrpInc().newByClusGrpIdxKey();
		keyClusGrpIdx.setRequiredSecClusGrpId( Buff.getRequiredSecClusGrpId() );

		CFSecBuffSecClusGrpIncByNameIdxKey keyNameIdx = (CFSecBuffSecClusGrpIncByNameIdxKey)schema.getFactorySecClusGrpInc().newByNameIdxKey();
		keyNameIdx.setRequiredIncName( Buff.getRequiredIncName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc > subdictClusGrpIdx;
		if( dictByClusGrpIdx.containsKey( keyClusGrpIdx ) ) {
			subdictClusGrpIdx = dictByClusGrpIdx.get( keyClusGrpIdx );
		}
		else {
			subdictClusGrpIdx = new HashMap< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc >();
			dictByClusGrpIdx.put( keyClusGrpIdx, subdictClusGrpIdx );
		}
		subdictClusGrpIdx.put( pkey, Buff );

		Map< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc > subdictNameIdx;
		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			subdictNameIdx = dictByNameIdx.get( keyNameIdx );
		}
		else {
			subdictNameIdx = new HashMap< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc >();
			dictByNameIdx.put( keyNameIdx, subdictNameIdx );
		}
		subdictNameIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecClusGrpInc.CLASS_CODE) {
				CFSecBuffSecClusGrpInc retbuff = ((CFSecBuffSecClusGrpInc)(schema.getFactorySecClusGrpInc().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecClusGrpInc readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		String IncName )
	{
		{	CFLibDbKeyHash256 testSecClusGrpId = SecClusGrpId;
			if (testSecClusGrpId == null) {
				return( null );
			}
		}
		{	String testIncName = IncName;
			if (testIncName == null) {
				return( null );
			}
		}
		CFSecBuffSecClusGrpIncPKey key = (CFSecBuffSecClusGrpIncPKey)(schema.getFactorySecClusGrpInc().newPKey());
		key.setRequiredSecClusGrpId( SecClusGrpId );
		key.setRequiredIncName( IncName );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecClusGrpInc readDerived( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpIncPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecClusGrpInc.readDerived";
		CFSecBuffSecClusGrpIncPKey key = (CFSecBuffSecClusGrpIncPKey)(schema.getFactorySecClusGrpInc().newPKey());
		key.setRequiredSecClusGrpId( PKey.getRequiredSecClusGrpId() );
		key.setRequiredIncName( PKey.getRequiredIncName() );
		ICFSecSecClusGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrpInc lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpIncPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecClusGrpInc.lockDerived";
		CFSecBuffSecClusGrpIncPKey key = (CFSecBuffSecClusGrpIncPKey)(schema.getFactorySecClusGrpInc().newPKey());
		key.setRequiredSecClusGrpId( PKey.getRequiredSecClusGrpId() );
		key.setRequiredIncName( PKey.getRequiredIncName() );
		ICFSecSecClusGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrpInc[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecClusGrpInc.readAllDerived";
		ICFSecSecClusGrpInc[] retList = new ICFSecSecClusGrpInc[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecClusGrpInc > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecClusGrpInc[] readDerivedByClusGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId )
	{
		final String S_ProcName = "CFSecRamSecClusGrpInc.readDerivedByClusGrpIdx";
		CFSecBuffSecClusGrpIncByClusGrpIdxKey key = (CFSecBuffSecClusGrpIncByClusGrpIdxKey)schema.getFactorySecClusGrpInc().newByClusGrpIdxKey();

		key.setRequiredSecClusGrpId( SecClusGrpId );
		ICFSecSecClusGrpInc[] recArray;
		if( dictByClusGrpIdx.containsKey( key ) ) {
			Map< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc > subdictClusGrpIdx
				= dictByClusGrpIdx.get( key );
			recArray = new ICFSecSecClusGrpInc[ subdictClusGrpIdx.size() ];
			Iterator< CFSecBuffSecClusGrpInc > iter = subdictClusGrpIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc > subdictClusGrpIdx
				= new HashMap< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc >();
			dictByClusGrpIdx.put( key, subdictClusGrpIdx );
			recArray = new ICFSecSecClusGrpInc[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecClusGrpInc[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String IncName )
	{
		final String S_ProcName = "CFSecRamSecClusGrpInc.readDerivedByNameIdx";
		CFSecBuffSecClusGrpIncByNameIdxKey key = (CFSecBuffSecClusGrpIncByNameIdxKey)schema.getFactorySecClusGrpInc().newByNameIdxKey();

		key.setRequiredIncName( IncName );
		ICFSecSecClusGrpInc[] recArray;
		if( dictByNameIdx.containsKey( key ) ) {
			Map< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc > subdictNameIdx
				= dictByNameIdx.get( key );
			recArray = new ICFSecSecClusGrpInc[ subdictNameIdx.size() ];
			Iterator< CFSecBuffSecClusGrpInc > iter = subdictNameIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc > subdictNameIdx
				= new HashMap< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc >();
			dictByNameIdx.put( key, subdictNameIdx );
			recArray = new ICFSecSecClusGrpInc[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecClusGrpInc readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		String IncName )
	{
		final String S_ProcName = "CFSecRamSecClusGrpInc.readDerivedByIdIdx() ";
		CFSecBuffSecClusGrpIncPKey key = (CFSecBuffSecClusGrpIncPKey)(schema.getFactorySecClusGrpInc().newPKey());
		key.setRequiredSecClusGrpId( SecClusGrpId );
		key.setRequiredIncName( IncName );
		ICFSecSecClusGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrpInc readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		String IncName )
	{
		CFSecBuffSecClusGrpIncPKey key = (CFSecBuffSecClusGrpIncPKey)(schema.getFactorySecClusGrpInc().newPKey());
		key.setRequiredSecClusGrpId( SecClusGrpId );
		key.setRequiredIncName( IncName );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecClusGrpInc readRec( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpIncPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecClusGrpInc.readRec";
		ICFSecSecClusGrpInc buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecClusGrpInc.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrpInc lockRec( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpIncPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecClusGrpInc buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecClusGrpInc.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecClusGrpInc[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecClusGrpInc.readAllRec";
		ICFSecSecClusGrpInc buff;
		ArrayList<ICFSecSecClusGrpInc> filteredList = new ArrayList<ICFSecSecClusGrpInc>();
		ICFSecSecClusGrpInc[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrpInc.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusGrpInc[0] ) );
	}

	/**
	 *	Read a page of all the specific SecClusGrpInc buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecClusGrpInc instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecClusGrpInc[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecClusGrpId,
		String priorIncName )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecClusGrpInc readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		String IncName )
	{
		final String S_ProcName = "CFSecRamSecClusGrpInc.readRecByIdIdx() ";
		ICFSecSecClusGrpInc buff = readDerivedByIdIdx( Authorization,
			SecClusGrpId,
			IncName );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrpInc.CLASS_CODE ) ) {
			return( (ICFSecSecClusGrpInc)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecClusGrpInc[] readRecByClusGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId )
	{
		final String S_ProcName = "CFSecRamSecClusGrpInc.readRecByClusGrpIdx() ";
		ICFSecSecClusGrpInc buff;
		ArrayList<ICFSecSecClusGrpInc> filteredList = new ArrayList<ICFSecSecClusGrpInc>();
		ICFSecSecClusGrpInc[] buffList = readDerivedByClusGrpIdx( Authorization,
			SecClusGrpId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrpInc.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecClusGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusGrpInc[0] ) );
	}

	@Override
	public ICFSecSecClusGrpInc[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String IncName )
	{
		final String S_ProcName = "CFSecRamSecClusGrpInc.readRecByNameIdx() ";
		ICFSecSecClusGrpInc buff;
		ArrayList<ICFSecSecClusGrpInc> filteredList = new ArrayList<ICFSecSecClusGrpInc>();
		ICFSecSecClusGrpInc[] buffList = readDerivedByNameIdx( Authorization,
			IncName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecClusGrpInc.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecClusGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecClusGrpInc[0] ) );
	}

	/**
	 *	Read a page array of the specific SecClusGrpInc buffer instances identified by the duplicate key ClusGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusGrpId	The SecClusGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusGrpInc[] pageRecByClusGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		CFLibDbKeyHash256 priorSecClusGrpId,
		String priorIncName )
	{
		final String S_ProcName = "pageRecByClusGrpIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecClusGrpInc buffer instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	IncName	The SecClusGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusGrpInc[] pageRecByNameIdx( ICFSecAuthorization Authorization,
		String IncName,
		CFLibDbKeyHash256 priorSecClusGrpId,
		String priorIncName )
	{
		final String S_ProcName = "pageRecByNameIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecClusGrpInc updateSecClusGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpInc iBuff )
	{
		CFSecBuffSecClusGrpInc Buff = (CFSecBuffSecClusGrpInc)ensureRec(iBuff);
		CFSecBuffSecClusGrpIncPKey pkey = (CFSecBuffSecClusGrpIncPKey)(schema.getFactorySecClusGrpInc().newPKey());
		pkey.setRequiredSecClusGrpId( Buff.getRequiredSecClusGrpId() );
		pkey.setRequiredIncName( Buff.getRequiredIncName() );
		CFSecBuffSecClusGrpInc existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecClusGrpInc",
				"Existing record not found",
				"Existing record not found",
				"SecClusGrpInc",
				"SecClusGrpInc",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecClusGrpInc",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecClusGrpIncByClusGrpIdxKey existingKeyClusGrpIdx = (CFSecBuffSecClusGrpIncByClusGrpIdxKey)schema.getFactorySecClusGrpInc().newByClusGrpIdxKey();
		existingKeyClusGrpIdx.setRequiredSecClusGrpId( existing.getRequiredSecClusGrpId() );

		CFSecBuffSecClusGrpIncByClusGrpIdxKey newKeyClusGrpIdx = (CFSecBuffSecClusGrpIncByClusGrpIdxKey)schema.getFactorySecClusGrpInc().newByClusGrpIdxKey();
		newKeyClusGrpIdx.setRequiredSecClusGrpId( Buff.getRequiredSecClusGrpId() );

		CFSecBuffSecClusGrpIncByNameIdxKey existingKeyNameIdx = (CFSecBuffSecClusGrpIncByNameIdxKey)schema.getFactorySecClusGrpInc().newByNameIdxKey();
		existingKeyNameIdx.setRequiredIncName( existing.getRequiredIncName() );

		CFSecBuffSecClusGrpIncByNameIdxKey newKeyNameIdx = (CFSecBuffSecClusGrpIncByNameIdxKey)schema.getFactorySecClusGrpInc().newByNameIdxKey();
		newKeyNameIdx.setRequiredIncName( Buff.getRequiredIncName() );

		// Check unique indexes

		// Validate foreign keys

		// Update is valid

		Map< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc > subdict;

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
			subdict = new HashMap< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc >();
			dictByClusGrpIdx.put( newKeyClusGrpIdx, subdict );
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
			subdict = new HashMap< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc >();
			dictByNameIdx.put( newKeyNameIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecClusGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpInc iBuff )
	{
		final String S_ProcName = "CFSecRamSecClusGrpIncTable.deleteSecClusGrpInc() ";
		CFSecBuffSecClusGrpInc Buff = (CFSecBuffSecClusGrpInc)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecClusGrpIncPKey pkey = (CFSecBuffSecClusGrpIncPKey)(Buff.getPKey());
		CFSecBuffSecClusGrpInc existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecClusGrpInc",
				pkey );
		}
		CFSecBuffSecClusGrpIncByClusGrpIdxKey keyClusGrpIdx = (CFSecBuffSecClusGrpIncByClusGrpIdxKey)schema.getFactorySecClusGrpInc().newByClusGrpIdxKey();
		keyClusGrpIdx.setRequiredSecClusGrpId( existing.getRequiredSecClusGrpId() );

		CFSecBuffSecClusGrpIncByNameIdxKey keyNameIdx = (CFSecBuffSecClusGrpIncByNameIdxKey)schema.getFactorySecClusGrpInc().newByNameIdxKey();
		keyNameIdx.setRequiredIncName( existing.getRequiredIncName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecClusGrpIncPKey, CFSecBuffSecClusGrpInc > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusGrpIdx.get( keyClusGrpIdx );
		subdict.remove( pkey );

		subdict = dictByNameIdx.get( keyNameIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecClusGrpIncByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecClusGrpId,
		String IncName )
	{
		CFSecBuffSecClusGrpIncPKey key = (CFSecBuffSecClusGrpIncPKey)(schema.getFactorySecClusGrpInc().newPKey());
		key.setRequiredSecClusGrpId( SecClusGrpId );
		key.setRequiredIncName( IncName );
		deleteSecClusGrpIncByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusGrpIncByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpIncPKey PKey )
	{
		CFSecBuffSecClusGrpIncPKey key = (CFSecBuffSecClusGrpIncPKey)(schema.getFactorySecClusGrpInc().newPKey());
		key.setRequiredSecClusGrpId( PKey.getRequiredSecClusGrpId() );
		key.setRequiredIncName( PKey.getRequiredIncName() );
		CFSecBuffSecClusGrpIncPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecClusGrpInc cur;
		LinkedList<CFSecBuffSecClusGrpInc> matchSet = new LinkedList<CFSecBuffSecClusGrpInc>();
		Iterator<CFSecBuffSecClusGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusGrpInc)(schema.getTableSecClusGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusGrpId(),
				cur.getRequiredIncName() ));
			deleteSecClusGrpInc( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusGrpIncByClusGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusGrpId )
	{
		CFSecBuffSecClusGrpIncByClusGrpIdxKey key = (CFSecBuffSecClusGrpIncByClusGrpIdxKey)schema.getFactorySecClusGrpInc().newByClusGrpIdxKey();
		key.setRequiredSecClusGrpId( argSecClusGrpId );
		deleteSecClusGrpIncByClusGrpIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusGrpIncByClusGrpIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpIncByClusGrpIdxKey argKey )
	{
		CFSecBuffSecClusGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusGrpInc> matchSet = new LinkedList<CFSecBuffSecClusGrpInc>();
		Iterator<CFSecBuffSecClusGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusGrpInc)(schema.getTableSecClusGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusGrpId(),
				cur.getRequiredIncName() ));
			deleteSecClusGrpInc( Authorization, cur );
		}
	}

	@Override
	public void deleteSecClusGrpIncByNameIdx( ICFSecAuthorization Authorization,
		String argIncName )
	{
		CFSecBuffSecClusGrpIncByNameIdxKey key = (CFSecBuffSecClusGrpIncByNameIdxKey)schema.getFactorySecClusGrpInc().newByNameIdxKey();
		key.setRequiredIncName( argIncName );
		deleteSecClusGrpIncByNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecClusGrpIncByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusGrpIncByNameIdxKey argKey )
	{
		CFSecBuffSecClusGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecClusGrpInc> matchSet = new LinkedList<CFSecBuffSecClusGrpInc>();
		Iterator<CFSecBuffSecClusGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecClusGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecClusGrpInc)(schema.getTableSecClusGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecClusGrpId(),
				cur.getRequiredIncName() ));
			deleteSecClusGrpInc( Authorization, cur );
		}
	}
}
