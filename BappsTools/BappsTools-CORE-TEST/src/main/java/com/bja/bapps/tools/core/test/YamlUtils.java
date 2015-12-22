package com.bja.bapps.tools.core.test;

import java.util.Map;

import org.yaml.snakeyaml.Yaml;

/**
 *  
 * @author bjanvion
 * 
 *
 */
public class YamlUtils {
	
	private Yaml yaml = new Yaml();	

	/**
	 * 
	 * @param fileName
	 * @param beanName
	 * @return
	 */
	public <T> T getObjectFromYaml(String fileName, String beanName) {
		@SuppressWarnings("unchecked")
		Map<String, Object> objets = (Map<String, Object>) yaml.load(Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName));
		@SuppressWarnings("unchecked")
		T demandeurAttendu = (T)objets.get(beanName);
		return demandeurAttendu;
	}

}
