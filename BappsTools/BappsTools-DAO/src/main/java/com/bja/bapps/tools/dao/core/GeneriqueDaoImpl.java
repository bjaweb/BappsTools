package com.bja.bapps.tools.dao.core;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.hibernate.Criteria;
import org.hibernate.HibernateException;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;

import com.bja.bapps.tools.dao.exceptions.DaoException;


/**
 * Implémentation du DAO générique {@link IGeneriqueDAO}.
 * 
 * @author isaqrani
 * @modif  bjanvion
 * 
 */
public class GeneriqueDaoImpl<T, U extends Serializable> implements IGeneriqueDAO<T, U> {
	
	private SessionFactory sessionFactory;

	public SessionFactory getSessionFactory() {
		
		return sessionFactory;
	}

	public void setSessionFactory(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;		
	}

	public Session getSession() throws HibernateException {
		Session session;
		try {
			session = sessionFactory.getCurrentSession();
		} catch (HibernateException e) {
			session = sessionFactory.openSession();
		}
		return session;
	}

	@SuppressWarnings("unchecked")
	public U save(T object) throws DaoException {
		//org.springframework.orm.hibernate3.support.HibernateDaoSupport h = null;
		//h.getHibernateTemplate();
		
		Session session = null;
		U result = null;
		if (object != null) {
			try {
				session = getSession();
				result = (U) session.save((U) object);
				session.flush();
			} catch (HibernateException e) {
				throw new DaoException(e);
			}
		}
		return result;
	}

	@SuppressWarnings("unchecked")
	public void update(T object) throws DaoException {
		Session session = null;
		if (object != null) {
			try {
				session = getSession();
				object = (T) session.merge((T) object);
				session.flush();
			} catch(HibernateException e) {
				throw new DaoException(e);
			}
		}
	}

	public void saveList(List<T> listObject) throws DaoException {

		try {												
			for (T object : listObject) {
				save(object);
			}
		} catch (HibernateException e) {
			throw new DaoException(e);
		}
	}

	public void updateList(List<T> listObject) throws DaoException {

		try {
			for (T object : listObject) {
				update(object);
			}
		} catch (HibernateException e) {
			throw new DaoException(e);
		}
	}
	

	public List<T> readTable(Class<T> clazz) throws DaoException {
		List<T> result = null;
		Session session = null;
		if (clazz != null) {
			try {
				session = getSession();

				Query query  = session.createQuery("from "+clazz.getSimpleName());
				
				result = (List<T>)query.list();
				
				session.flush();
			} catch(HibernateException e) {e.printStackTrace();
				throw new DaoException(e);
			}
		}
		return result;
	}
	
	//<String, Object>
	public List<T> findByFilter(Class<T> clazz, Map<String, Object> params ) throws DaoException {
		
		List<T> result = null;
		
		if((params != null && clazz!= null)&& params.size() > 0){
			
			try{
				
				Set<String> keys = params.keySet();
				Criteria crit = getSession().createCriteria(clazz);
				for(String key:keys){
					crit.add(Restrictions.eq(key, params.get(key)));	
					System.out.println("key "+key+"    value:"+params.get(key));
				}
								
				result = (List<T>)crit.list();
				System.out.println("result "+result);
				getSession().flush();
			}
			catch(HibernateException e) {	e.printStackTrace(); System.out.println("xwx");		
				throw new DaoException(e);
			}
			
			
		}
		else{
			return readTable(clazz);
		}
		
		
		return result;
	}
	
	
	public T getFromId(U id, Class<T> clazz) throws DaoException  {
		
		try{
			Session session = getSession(); 
			T res = (T)session.get(clazz, id);
			
			return res;
		}catch (HibernateException e) {
			throw new DaoException(e);
		}
	}
	
	
	

}
