package com.bja.bapps.tools.dao.dbUtils;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.dbutils.handlers.BeanListHandler;

import com.bja.bapps.tools.dao.exceptions.DaoException;


public abstract class  BaseDao<T extends Object> {
	
	protected Datasource ds ;
	private Properties infosBase;
	
	public BaseDao(Properties infosBase) throws DaoException  {		
		setInfosBase(infosBase);
		ds = Datasource.getInstance(infosBase);
	}

	public Properties getInfosBase() {
		return infosBase;
	}

	public void setInfosBase(Properties infosBase) {
		this.infosBase = infosBase;
	}
	
	

	public Connection getConnection() throws DaoException{
		
		Connection conn = null;
		try{
			 conn = ds.getConnection() ;
		}catch (Exception e) {
			throw new DaoException(e);
		}
		return conn;
	}
	
	
	

	
	///Executer les requetes d'update et d'insertion
	public int executeUpdate(String requete,Object[] params) throws DaoException{
		try{
			
			QueryRunner qRunner = new QueryRunner();
	    	int rows = qRunner.update(
	    						 getConnection(),
	        					 requete,
	        					 params);
	    	
	    	return rows;
		}catch (Exception e) {
			throw new DaoException(e);
		}
		finally{
			try{
				getConnection().close();
			}catch (Exception e) {}
		}
		
	}
	
	//@SuppressWarnings("unchecked")
	public  List<T> executeQuery(String requete,Class<T> classe) throws DaoException {
		return executeQuery(requete,null,classe);
	}
	
	@SuppressWarnings("unchecked")
	public  List<T> executeQuery(String requete,Object[] params,Class<T> classe) throws DaoException {
		 try{
			 List<T> beans = new ArrayList<T>();
			 QueryRunner qRunner = new QueryRunner();
	    	
			 if(params != null && params.length>0)	        		    	
			 	 beans = (List<T>) qRunner.query(getConnection(),requete, params, new BeanListHandler(classe));		
	    	 
	    	 else
	    		 beans = (List<T>) qRunner.query(
						 getConnection(),
						 requete,
						 new BeanListHandler(classe));
	    		 
			 
			 return beans;
	        } catch (SQLException e) {
	        	e.printStackTrace();
	        	throw new DaoException(e);
	        } finally {	     
	        	try{
	        		ds.closeConnection();
	        	}catch (Exception e) {}
	        }
	    }
	
	
	
	

	
}