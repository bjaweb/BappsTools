package com.bja.bapps.tools.core.test.guava;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bja.bapps.tools.core.test.DaoBaseTest;
import com.google.common.base.CharMatcher;
import com.google.common.base.Preconditions;


/**
 * 
 * @author ben
 *
 * Test de du DAO DAOBanque
 *
 */
public class TestGuava1 extends DaoBaseTest{


//	@Autowired
//	private DAOBanque daoBanque;

	private static Logger logger = LoggerFactory.getLogger(TestGuava1.class);
	
	
	@Test
    public void testCharMatcherIsin() {
        String username = "Nicolas";
        String badUserName = "Nic ! olas,, @ et ?";
        assertTrue(validateUsername(username));
        assertFalse(validateUsername(badUserName));        

    }
	
	
	/**
     * Validates that the username does not contains one of !@?(,)
     * 
     * @param username is the username to validate.
     * 
     * @return true if none of the char in username is in the restricted list.
     */
    public static boolean validateUsername(String username) {
        Preconditions.checkNotNull(username);
        Preconditions.checkArgument(username.trim().length()>0, "trop court", username);
        // Je ne veux pas de caractères spéciaux dans les mots de passe ou les noms d'utilisateur
        CharMatcher noSpecialChars = CharMatcher.noneOf("!@?(,)").negate();
        if (noSpecialChars.matchesNoneOf(username)) {
            System.out.println(username + " is a valid username");
            return true;
        }
        logger.info("Please do not use one of !@?(,) in your username value.");
        return false;
    }
	

}
