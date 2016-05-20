package com.bja.bapps.test.dao;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.bja.bapps.test.model.User;
import com.bja.bapps.test.service.UserService;


@RunWith(SpringJUnit4ClassRunner.class) 
//@ContextConfiguration(locations = {"classpath:/applicationContext.xml","classpath:/spring-config-bappsSocleDao.xml"})
@ContextConfiguration(locations = {"classpath:/bappsToolsDaoHibernate4Config.xml"})
public class DaoTests {
	

	@Autowired
	private UserService userService;
	
	
	@Test
	public void serviceCreerUser(){
		System.out.println("service "+userService);
		User user = new User();
		user.setUsername("ben");
		user.setPassword("password");
		user.setEmail("bja@test.com");
		
		userService.sauvegarderUtilisateur(user);
		
	}

	
//	@Autowired
//	private UserDao dao;
//	
//	
//	@Test
//	public void daoCreerUser(){
//		System.out.println("dao "+dao);
//		User user = new User();
//		user.setUsername("ben");
//		user.setPassword("password");
//		user.setEmail("bja@test.com");
//		
//		dao.addUser(user);
//		
//	}

}
