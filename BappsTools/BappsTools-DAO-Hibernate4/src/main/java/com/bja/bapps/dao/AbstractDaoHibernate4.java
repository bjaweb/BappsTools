package com.bja.bapps.dao;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.bja.bapps.test.model.User;

public abstract class AbstractDaoHibernate4 {

	@Autowired
	private SessionFactory sessionFactory;
	
	
	 	protected Session getSession() {
	        return sessionFactory.getCurrentSession();
	    }
	 
	    public void persist(Object entity) {
	        getSession().persist(entity);
	    }
	 
	    public void delete(Object entity) {
	        getSession().delete(entity);	        
	    }
	    
	    
	    public List<?> listAlltable(Class clazz){
	    	return (List<?>)getSession().createCriteria(clazz).list();
	    }
	    
	    /*
	     * public List<User> list() {
		 @SuppressWarnings("unchecked")
	        List<User> listUser = (List<User>) getSession().createCriteria(User.class)
	                .setResultTransformer(Criteria.DISTINCT_ROOT_ENTITY).list();
	 
	        return listUser;
	}
	     */
	    
	
	
}
