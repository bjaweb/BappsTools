package com.bja.bapps.tools.core.test.guava;

import static org.junit.Assert.*;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bja.bapps.tools.core.test.DaoBaseTest;
import com.google.common.base.CharMatcher;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;


/**
 * 
 * @author ben
 *
 * Test de du DAO DAOBanque
 *
 */
public class TestWrapperOptional extends DaoBaseTest{


//	@Autowired
//	private DAOBanque daoBanque;

	private static Logger logger = LoggerFactory.getLogger(TestWrapperOptional.class);
	
	
	@Test 
	public void testSimpleOptional() { 
	  // Arrange 
	  final Integer nb = 5; 
	 
	  // Act 
	  Optional<Integer> opt = Optional.of(nb); 
	 
	  // Assert 
	  assertTrue(opt.isPresent()); 
	  assertEquals(nb,opt.get()); 
	}
	
	
	
	@Test 
	public void testAbsent() { 
	  // Arrange 
	 
	  // Act 
	  Optional<String> opt = Optional.absent(); 
	 
	  // Assert 
	  assertFalse(opt.isPresent()); 
	}
	
	@Test(expected = IllegalStateException.class) 
	public void testAbsentISE() { 
	  // Arrange 
	 
	  // Act 
	  Optional<String> opt = Optional.absent(); 
	 
	  // Assert 
	  assertFalse(opt.isPresent()); 
	  opt.get(); // ISE 
	}
	
	
	/*
	 *on indique que le chien peut etre null
	 *si on mais of on a un npe 
	 */
	@Test 
	public void testFromNull() { 
	  // Arrange 
	  final SimpleDog dog = null; 
	 
	  // Act 
	  Optional<SimpleDog> opt = Optional.fromNullable(dog); 
	 
	  // Assert 
	  assertFalse(opt.isPresent()); 
	}
	
	
	
	/*
	 * wrap le dog meme si null 
	 * si null revoit le noname
	 */
	@Test 
	public void testFromNullAndGetOr() { 
	  // Arrange 
	  SimpleDog dog = new SimpleDog("fre"); 
	  final String nomane = "mery"; 
	 
	  // Act 
	  Optional<SimpleDog> opt = Optional.fromNullable(dog); 
	 
	  // Assert 
//	  assertFalse(opt.isPresent()); 
	  SimpleDog dog2 = opt.or(new SimpleDog(nomane)); 
	  logger.info(""+dog2);
	  assertNotNull(dog2);
	  
//	  assertTrue(nomane==dog2.getName()); 
	}
	
	
	
	private class SimpleDog{
		private String name;
		public SimpleDog(){}
		public SimpleDog(String s){this.name=s;}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}
		//public String toString(){return "SimpleDog : "+name;}
		@Override
		public String toString() {
			return "SimpleDog [name=" + name + "]";
		}
		
	}
	

}
