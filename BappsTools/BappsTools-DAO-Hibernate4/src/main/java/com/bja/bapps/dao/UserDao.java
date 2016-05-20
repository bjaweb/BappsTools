package com.bja.bapps.dao;

import java.util.List;

import com.bja.bapps.test.model.User;

public interface UserDao {
	
	 public List<User> list();
	 
	 public User addUser(User user);

}
