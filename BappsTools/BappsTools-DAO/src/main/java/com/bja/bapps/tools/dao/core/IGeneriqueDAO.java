package com.bja.bapps.tools.dao.core;

import java.util.List;
import java.util.Map;

import org.hibernate.HibernateException;
import org.hibernate.Session;
import org.hibernate.SessionFactory;

import com.bja.bapps.tools.dao.exceptions.DaoException;


/**
 * DAO générique exposant toutes les méthodes génériques (CRUD) réutilisables
 * pour tous les objets metiers. Chaque DAO correspond à un et un seul objet
 * metier.
 * 
 * @author isaqrani
 */
public interface IGeneriqueDAO <T, U> {

	public SessionFactory getSessionFactory();

	public void setSessionFactory(SessionFactory sessionFactory);

	public Session getSession() throws HibernateException;
	
	/**
	 * Insertion d'un objet.
	 */
	public U save(T object) throws DaoException;

	/**
	 * Modification d'un objet.
	 */
	public void update(T object) throws DaoException;
	
	/**
	 * Insertion d'une collection d'objets.
	 */
	public void saveList(List<T> ListObject) throws DaoException;
	
	/**
	 * Modification d'une collection d'objets.
	 */
	public void updateList(List<T> ListObject) throws DaoException;
	

	/**
	 * Lecture d'une Table.
	 */
	public List<T> readTable(Class<T> clazz) throws DaoException ;

	/**
	 * Lecture d'une Table filtrée par paramètres.
	 *
	 * exemple
	 * List<T> liste = null;
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("id", id);
		liste = findByFilter(T, params);
	 */
	public List<T> findByFilter(Class<T> clazz, Map<String, Object> params ) throws DaoException ;
	
//	public T getFromId(U id) throws DaoException ;
	
	public T getFromId(U id, Class<T> clazz) throws DaoException  ;
	
}
