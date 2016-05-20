package com.bja.bapps.test.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.bja.bapps.dao.UserDao;
import com.bja.bapps.test.model.User;

@Service
@Transactional 
public class UserServiceImpl implements UserService{
	
	@Autowired
	private UserDao dao;
	
	public User sauvegarderUtilisateur(User user){
		return dao.addUser(user);
	}

	
	
	
}
