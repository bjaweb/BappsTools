package com.bja.bapps.tools.core.test;

import org.junit.Test;
import static org.fest.assertions.Assertions.assertThat;

import com.bja.bapps.tools.core.test.bean.Utilisateur;

/**
 * 
 * @author ben
 * ceci est une class de test, à l'utilisation il faut etendre la classe YamlUtils
 */
public class YamlUtilsTest  {

	@Test
	public void getObjectFromYaml(){

		YamlUtils yamlUtils = new YamlUtils();

		Utilisateur utilisateur = yamlUtils.getObjectFromYaml("yaml/utilisateur.yml", "utilisateur"); 
		System.out.println("utilisateur "+utilisateur);

		assertThat(utilisateur).isNotNull().isInstanceOf(Utilisateur.class);
	}



}
