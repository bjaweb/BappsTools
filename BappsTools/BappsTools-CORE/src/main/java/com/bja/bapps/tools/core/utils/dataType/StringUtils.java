package com.bja.bapps.tools.core.utils.dataType;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * Classe d'outils pour les objets de type String
 * @author smanley
 */
public class StringUtils {

	/**
	 * Defines if the passed string is empty or not
	 * @param s
	 * @return boolean
	 */
	public static boolean isEmpty(String s) {
		if(s == null || s.trim().equals(""))
			return true;
		return false;
	}
	
	public static String trimData(String dataToProcess, String postfix, Integer maxLength) {
		String result = dataToProcess;
		if (dataToProcess != null) {
			if (dataToProcess.length() > maxLength) {
				result = dataToProcess.substring(0, maxLength - postfix.length()) + postfix;
			}
		} else {
			result = "";
		}
		return result;
	}
	
	public static List<String> hashString (String ids, String delimiter){
		List<String> listId = new ArrayList<String>();
		
		try{
			StringTokenizer token = new StringTokenizer(ids,delimiter);
			
			while(token.hasMoreTokens()) listId.add(token.nextToken());
			
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		
		
		return listId;
	}
	
	public static String supprimeAccents(String s) {
		String temp = Normalizer.normalize(s, Normalizer.Form.NFD);
		return temp.replaceAll("[\u0300-\u036F]", "");
	}
	

}
