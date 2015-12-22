package com.bja.bapps.tools.core.utils;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bja.bapps.tools.core.exceptions.DataFormatException;
import com.bja.bapps.tools.core.exceptions.TechnicalException;
import com.bja.bapps.tools.core.utils.dataType.enums.EDateFormat;

public class Converter {

	private static Logger logger = LoggerFactory.getLogger(Converter.class);
	
	public static SimpleDateFormat frenchTimeStampForEtat = new SimpleDateFormat("dd/MM/yyyy à HH'h'mm");
	public static SimpleDateFormat frenchDateFormat = new SimpleDateFormat("dd/MM/yyyy");

	public static Long convertStringToLong(String value) throws TechnicalException {

		Long result = new Long(0);

		try {
			if(value != null) {
				value = value.replace(" ", "");
				if (!"".equals(value)) {
					result = new Long(value);
				}
			} else {
				String [] errorParams = {value};
				throw new TechnicalException("errors.data.convert.string.to.long", errorParams);
			}

		} catch (NumberFormatException e) {
			logger.error("Cannot convert String to Long {" + value + "}", e);
			String [] errorParams = {value};
			throw new TechnicalException("errors.data.convert.string.to.long", errorParams);
		}

		return result;
	}

	public static BigDecimal getNotNullBigDecimal(BigDecimal value) {
		BigDecimal result = new BigDecimal(0);
		if (value != null) {
			result = value;
		}
		return result;
	}
	
	public static Integer getNonNullInteger(Integer value) {
		Integer result = new Integer(0);
		if (value != null) {
			result = value;
		}
		return result;
	}

	public static String convertLongToString(Long value) throws TechnicalException {
		String result = "";
		try {
			result = value.toString();
		} catch (NullPointerException e) {
			logger.error("Cannot convert Long to String {" + value + "}");
			String [] errorParams = {null};
			throw new TechnicalException("errors.data.convert.long.to.string", errorParams);
		}
		return result;
	}

	public static String convertIntegerToString(Integer value, String defaultValue) {
		String result = defaultValue;
		try {
			result = value.toString();
		} catch (NullPointerException e) {
		}
		return result;
	}

	public static String convertIntegerToString(Integer value) throws TechnicalException {
		String result = "";
		if (value != null) {
			result = convertIntegerToString(value, "0");
		} else {
			logger.error("Cannot convert Integer to String {" + value + "}");
			String [] errorParams = {"null"};
			throw new TechnicalException("errors.data.convert.integer.to.string", errorParams);
		}
		return result;
	}

	public static String convertCharToString(char value) {
		return Character.toString(value);
	}
	
	public static String convertBigDecimalToString(BigDecimal value, String pattern, char decimalSeparator) {
		DecimalFormat df = new DecimalFormat(pattern);
		DecimalFormatSymbols decimalFormatSymbols = new DecimalFormatSymbols();
		decimalFormatSymbols.setDecimalSeparator(decimalSeparator);
		decimalFormatSymbols.setGroupingSeparator(' ');
		df.setDecimalFormatSymbols(decimalFormatSymbols);
		return df.format(convertBigDecimalToDouble(value));
	}

	public static String convertBigDecimalToString(BigDecimal value, int scale) {
		return convertBigDecimalToString(value, scale, RoundingMode.HALF_UP);
	}

	public static BigDecimal convertStringToBigDecimal(String value) throws DataFormatException {

		BigDecimal result = null;

		if (value != null) {
			result = convertStringToBigDecimal(value, false, null);
		} else {
			throw new DataFormatException("errors.value.not.entered");
		}

		return result;
	}

	public static BigDecimal convertIntegerToBigDecimal(Integer value) throws TechnicalException {

		BigDecimal result = null;

		if(value != null) {
			result = new BigDecimal(value);
		} else {
			throw new TechnicalException("errors.value.not.entered");
		}

		return result;
	}

	public static int convertStringToInt(String value) throws TechnicalException {

		int result = 0;

		try {
			if(value != null) {
				value = value.replace(" ", "");
				if (!"".equals(value)) {
					result = Integer.parseInt(value);
				} else {
					throw new TechnicalException("errors.value.not.entered");
				}
			} else {
				throw new TechnicalException("errors.value.not.entered");
			}

		} catch (NumberFormatException e) {
			logger.error("Cannot convert String to int {" + value + "}");
			String [] errorParams = {value};
			throw new TechnicalException("errors.data.convert.string.to.int", errorParams);
		}

		return result;
	}


	public static String convertIntToString(int value) throws TechnicalException {

		return Integer.toString(value);
	}

	/**
	 * Affiche une date au format dd/MM/yyyy 
	 * @param date
	 * @return date formattée
	 */
	public static String convertDateToString(Date date) {

		String value = "";

		if(date != null) {
			final DateFormat df = new SimpleDateFormat("dd/MM/yyyy");
			value = df.format(date);
		} 

		return value;
	}

	/**
	 * Convertit une string au format date dd/MM/yyyy.
	 * @param value
	 * @return Date
	 * @throws TechnicalException
	 */
	public static Date convertStringToDate(String value) throws DataFormatException {
		return convertStringToDate(value, EDateFormat.FRENCH_DATE_FORMAT);
	}

	public static Date convertStringToDate(String value, EDateFormat dateFormat) throws DataFormatException {

		DateFormat format = new SimpleDateFormat(dateFormat.getPattern());

		Date date = null;

		try {
			if (value.length() == dateFormat.getPattern().length()) {
				date = format.parse(value);
			} else {
				throw new ParseException("cannot convert string to date", dateFormat.getPattern().length());
			}
		} catch (ParseException pe) {
			logger.error("Erreur sur la convertion de la date [" + value + "]");
			String [] errorParams = {value};
			throw new DataFormatException("errors.data.convert.string.to.date", errorParams);
		}

		return date;
	}

	public static Date convertNullableStringToDate(String value, EDateFormat dateFormat) throws DataFormatException {

		DateFormat format = new SimpleDateFormat(dateFormat.getPattern());

		Date date = null;

		if (value != null && value.trim().length() > 0) {
			try {
				if (value.length() == dateFormat.getPattern().length()) {
					date = format.parse(value);
				} else {
					throw new ParseException("cannot convert string to date", dateFormat.getPattern().length());
				}
			} catch (ParseException pe) {
				logger.error("Erreur sur la convertion de la date [" + value + "]");
				String [] errorParams = {value};
				throw new DataFormatException("errors.data.convert.string.to.date", errorParams);
			}
		}

		return date;
	}

	public static String convertToFrenchDate(Date value) throws TechnicalException {

		String result = null;
		try {
			if (value != null) {
				result = frenchDateFormat.format(value);
			} else {
				result = "";
			}
		} catch (Exception e) {
			throw new TechnicalException("errors.data.convert.date.to.string.frenchDateFormat");
		}

		return result;

	}

	public static String convertToFrenchTimeStampForEtat(Date value) throws TechnicalException {

		String result = null;
		try {
			if (value != null) {
				result = frenchTimeStampForEtat.format(value);
			} else {
				result = "";
			}
		} catch (Exception e) {
			throw new TechnicalException("errors.data.convert.date.to.string.frenchTimeStampForEtat");
		}

		return result;

	}

	public static Integer convertStringToInteger(String value) throws DataFormatException {
		return convertStringToInteger(value, 0);
	}

	public static String convertDateToString(Date date, EDateFormat dateFormat) {
		String result = "";
		if (date != null) {
			result = new SimpleDateFormat(dateFormat.getPattern()).format(date);
		}
		return result;
	}

	public static double convertBigDecimalToDouble(BigDecimal value) {
		return getNotNullBigDecimal(value).doubleValue();
	}

	public static Integer convertStringToInteger(String value, Integer defaultValue) throws DataFormatException {

		Integer result = defaultValue;

		try {
			if (value != null) {
				value = value.replace(" ", "");
				if (value != "") {
					result = new Integer(value);
				}
			}
		} catch (NumberFormatException e) {
			logger.error(e.getMessage(), e);
			String [] errorParams = {value};
			throw new DataFormatException("errors.data.convert.stringToInteger", errorParams);
		}

		return result;
	}

	public static BigDecimal convertStringToBigDecimal(String value, boolean withDelimiterReplacement, BigDecimal defaultValue) throws DataFormatException {

		BigDecimal result = defaultValue;

		if (value != null) {
			value = value.replaceAll(" ", "");
			if (!value.equals("")) {
				if (withDelimiterReplacement) {
					value = value.replace(".", "");
				}
				value = value.replaceAll(",", ".");
				try {
					result = new BigDecimal(value);
				} catch (NumberFormatException e) {
					logger.error(e.getMessage(), e);
					String [] errorParams = {value};
					throw new DataFormatException("errors.converter.invalidFormat", errorParams);
				}
			}
		} 

		return result;

	}

	public static String convertBigDecimalToString(BigDecimal value, Integer scale, RoundingMode roundingMode) {
		return new BigDecimal(getNotNullBigDecimal(value).setScale(10, roundingMode).toString()).setScale(scale, roundingMode).toString();
	}

	public static Boolean getNonNullBoolean(Boolean value) {
		Boolean result = false;
		if (value != null) {
			result = value;
		}
		return result;
	}

	public static Boolean convertIntegerToBoolean(Integer value) {
		Boolean result = false;

		if (value != null) {
			if (value != 0) {
				result = true;
			}
		}
		return result;
	}

	public static String getNonNullString(String value) {
		String result = "";
		if (value != null) {
			result = value;
		}
		return result;
	}

	public static String convertBigDecimalToString(BigDecimal value, Integer scale, RoundingMode roundingMode, String defaultValue) {
		String result = defaultValue;
		if (value != null) {
			result = convertBigDecimalToString(value, scale);
		}
		return result;
	}

	public static List<Integer> convertStringArrayToIntegerList(String [] stringArray) throws TechnicalException {

		List<Integer> result = new ArrayList<Integer>();

		for (String value : stringArray) {
			result.add(convertStringToInt(value));
		}

		return result;

	}
	
	public static List<Integer> convertStringToIntegerList(String value, String delimiter) throws TechnicalException {

		List<Integer> result = new ArrayList<Integer>();
		
		if (value != null && value.trim().length() != 0) {
			result = convertStringArrayToIntegerList(value.split(delimiter));
		}

		return result;

	}

	public static List<Long> convertStringArrayToLongList(String [] stringArray) throws TechnicalException {

		List<Long> result = new ArrayList<Long>();

		for (String value : stringArray) {
			result.add(convertStringToLong(value));
		}

		return result;

	}

	/**
	 * Convert a boolean value to an integer
	 * null = 0
	 * true = 1
	 * false = 0
	 * @param value
	 * @return
	 */
	public static Integer convertBooleanToInteger(Boolean value) {
		Integer result = 0;
		if (value != null) {
			if (value) {
				result = 1;
			}
		}
		return result;
	}

	/**
	 * Convert an array of String to a list of String
	 * @param stringArray
	 * @return
	 */
	public static List<String> convertStringArrayToStringList(String [] stringArray) {
		List<String> result = new ArrayList<String>();

		if (stringArray != null) {
			for (String value : stringArray) {
				result.add(value);
			}
		}

		return result;
	}

	public static String convertBigDecimalToString(BigDecimal inputData, String pattern, char decimalSeparator, String defaultValue) {
		String result = defaultValue;
		if (inputData != null) {
			result = convertBigDecimalToString(inputData, pattern, decimalSeparator);
		}
		return result;
	}

	public static Double getNonNullDouble(Double value) {
		Double result = 0d;
		if (value != null) {
			result = value;
		}
		return result;
	}
	
	public static Boolean convertStringToBoolean(String value) throws TechnicalException {
		
		Boolean result = null;
		
		if (value == null) {
			throw new TechnicalException("Cannot convert null value to Boolean");
		}
		
		if ("N".equalsIgnoreCase(value) || "NON".equalsIgnoreCase(value) || "NO".equalsIgnoreCase(value) || "FALSE".equalsIgnoreCase(value) || "0".equalsIgnoreCase(value)) {
			result = false;
		} else if ("O".equalsIgnoreCase(value) || "OUI".equalsIgnoreCase(value) || "Y".equalsIgnoreCase(value) || "YES".equalsIgnoreCase(value) || "TRUE".equalsIgnoreCase(value) || "1".equalsIgnoreCase(value)) {
			result = true;
		}
		
		return result;
		
	}

}
