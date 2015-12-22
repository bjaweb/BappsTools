package com.bja.bapps.tools.dao.core;


import java.io.Serializable;
import java.lang.reflect.TypeVariable;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
//
//import com.bja.spring.test3.beans.Role;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public  abstract class BappsDaoJpa<T> {
	
	 @PersistenceContext 
	  protected EntityManager entityManager; 
	 
	 
	 protected Logger logger = LoggerFactory.getLogger(this.getClass());
	 
	  protected List<T> findAll(Class<T> clazz){
			
			try { 
				logger.info("la classe "+clazz);
				return entityManager.createQuery("select rc from "+clazz.getSimpleName()+" rc").getResultList(); 
			} catch (Throwable th) { 
				th.printStackTrace();
				return null;
			} 
			
		}

	
	  
	 protected T findById(Serializable id,Class clazz){

		 return (T)entityManager.find(clazz, id);
	}
	 
	 public void save(T t){
		 entityManager.persist(t);	
	}

}
