package com.bja.bapps.dao;

import java.util.List;

import org.hibernate.Criteria;
import org.springframework.stereotype.Repository;

import com.bja.bapps.test.model.User;

@Repository
public class UserDaoImpl extends AbstractDaoHibernate4 implements UserDao {
	
	
	@Override
	public List<User> list() {
		 @SuppressWarnings("unchecked")
	        List<User> listUser = (List<User>) getSession().createCriteria(User.class)
	                .setResultTransformer(Criteria.DISTINCT_ROOT_ENTITY).list();
	 
	        return listUser;
	}

	
	
	/* methode simple
	 * 
	 *  @SuppressWarnings("unchecked")
    public List<Employee> findAllEmployees() {
        Criteria criteria = getSession().createCriteria(Employee.class);
        return (List<Employee>) criteria.list();
    }
    
    
    
    public Client addClient(Client c) {
		em.persist(c);
		return c;
	}
	 */
	
	
	@Override
	public User addUser(User user) {
		persist(user);
		return user;
	}

}
