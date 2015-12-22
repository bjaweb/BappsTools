package com.bja.bapps.tools.core.testTools;

import java.math.BigDecimal;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.bja.bapps.tools.core.utils.Converter;



public class PojoGenerator {

	public static SimpleDateFormat dateFormater = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

	public static BigDecimal generateBigDecimal(String value) {
		BigDecimal result = null;
		try {
			result = Converter.convertStringToBigDecimal(value);
		} catch (Exception e) {
			result = null;
		}

		return result;

	}

	public static Integer generateInteger(String value) {
		Integer result = null;
		try {
			result = new Integer(value);
		} catch (Exception e) {
			result = null;
		}

		return result;

	}

	public static Long generateLong(String value) {
		Long result = null;
		try {
			result = new Long(value);
		} catch (Exception e) {
			result = new Long(0);
		}

		return result;

	}

	public static Date generateDate(String value) {
		Date result = null;
		try {
			result = dateFormater.parse(value);
		} catch (Exception e) {
			result = null;
		}

		return result;
	}

	public static char generateChar(String value) {
		char result = ' ';
		try {
			result = value.charAt(0);
		} catch (Exception e) {
			result = ' ';
		}

		return result;
	} 

	public static Character generateCharacter(String value) {

		Character result = ' ';
		try {
			result = new Character(value.charAt(0));
		} catch (Exception e) {
			result = ' ';
		}

		return result;
	}

	public static Boolean generateBoolean(String value) {
		Boolean result = null;
		try {
			if ("0".equals(value) || "false".equalsIgnoreCase(value)) {
				result = false;
			} else if ("1".equals(value) || "true".equalsIgnoreCase(value)) {
				result = true;
			}
		} catch (Exception e) {
			result = null;
		}

		return result;

	}

}
