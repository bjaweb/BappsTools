package com.bja.bapps.tools.core.utils.dataType;

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

import com.bja.bapps.tools.core.exceptions.DataException;
import com.bja.bapps.tools.core.exceptions.TechnicalException;
import com.bja.bapps.tools.core.utils.dataType.enums.EDateFormat;

public class DataConverter {

	
	private static Logger logger = LoggerFactory.getLogger(DataConverter.class);

	/**
	 * Convert a String value to Integer (return a default value if the input is null or is an empty string)
	 * @param value
	 * @param defaultValue
	 * @return
	 * @throws TechnicalException
	 */
	public static Integer convertStringToInteger(String value, Integer defaultValue) throws TechnicalException {

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
			throw new TechnicalException("errors.dataConversion.stringToInteger", errorParams);
		}

		return result;
	}

	/**
	 * Convert a String value to Integer (return 0 if the input is null or is an empty string)
	 * @param value
	 * @return
	 * @throws TechnicalException
	 */
	public static Integer convertStringToInteger(String value) throws TechnicalException {
		return convertStringToInteger(value, 0);
	}

	/**
	 * Convert a String value to BigDecimal (return a default value if the input is null or is an empty string)
	 * @param value
	 * @param withDelimiterReplacement (if setted to true remove all "." before conversion)
	 * @param defaultValue
	 * @return
	 * @throws TechnicalException
	 */
	public static BigDecimal convertStringToBigDecimal(String value, boolean withDelimiterReplacement, BigDecimal defaultValue) throws TechnicalException {

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
					logger.error("cannot convert string to bigDecimal {string=" + value + "}", e);
					String [] errorParams = {value};
					throw new TechnicalException("errors.dataConversion.invalidFormat", errorParams);
				}
			}
		} 

		return result;

	}

	/**
	 * Convert a String value to BigDecimal (return null if the input is null or is an empty string)
	 * @param value
	 * @param withDelimiterReplacement (if setted to true remove all "." before conversion)
	 * @return
	 * @throws TechnicalException
	 */
	public static BigDecimal convertStringToBigDecimal(String value, boolean withDelimiterReplacement) throws TechnicalException {

		BigDecimal result = null;

		if (value != null) {
			result = convertStringToBigDecimal(value, withDelimiterReplacement, null);
		} else {
			throw new TechnicalException("errors.dataConversion.valueNotEntered");
		}

		return result;
	}

	/**
	 * Convert a String value to BigDecimal (return null if the input is null or is an empty string).
	 * This conversion doesn't remove "." of the string before conversion
	 * @param value
	 * @return
	 * @throws TechnicalException
	 */
	public static BigDecimal convertStringToBigDecimal(String value) throws TechnicalException {
		return convertStringToBigDecimal(value, false);
	}

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
				throw new TechnicalException("errors.dataConversion.stringTooLong", errorParams);
			}

		} catch (NumberFormatException e) {
			logger.error("Cannot convert String to Long {" + value + "}", e);
			String [] errorParams = {value};
			throw new TechnicalException("errors.dataConversion.stringToLong", errorParams);
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
			throw new TechnicalException("errors.dataConversion.longToString", errorParams);
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
			throw new TechnicalException("errors.dataConversion.integerToString", errorParams);
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

	public static BigDecimal convertIntegerToBigDecimal(Integer value) throws TechnicalException {

		BigDecimal result = null;

		if(value != null) {
			result = new BigDecimal(value);
		} else {
			throw new TechnicalException("errors.dataConversion.valueNotEntered");
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
					throw new TechnicalException("errors.dataConversion.valueNotEntered");
				}
			} else {
				throw new TechnicalException("errors.dataConversion.valueNotEntered");
			}

		} catch (NumberFormatException e) {
			logger.error("Cannot convert String to int {" + value + "}");
			String [] errorParams = {value};
			throw new TechnicalException("errors.dataConversion.stringToInt", errorParams);
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
	 * Affiche une date en string au format voulu
	 * @param date date à convertir
	 * @param strDateFormat : format se basant sur DateFormat
	 * @return date formattée
	 * @throws TechnicalException
	 */
	public static String convertDateToString(Date date,String strDateFormat) throws TechnicalException {

		String value = "";
		try{
		if(date != null) {
			final DateFormat df = new SimpleDateFormat(strDateFormat);
			value = df.format(date);
		} 
		}catch (Exception e) {
			throw new TechnicalException("Erreur de conversion de date avec le format "+strDateFormat,e);
		}

		return value;
	}
	

	/**
	 * Convertit une string au format date dd/MM/yyyy.
	 * @param value
	 * @return Date
	 * @throws DataException
	 */
	public static Date convertStringToDate(String value) throws TechnicalException {
		return convertStringToDate(value, EDateFormat.FRENCH_DATE_FORMAT);
	}

	public static Date convertStringToDate(String value, EDateFormat dateFormat) throws TechnicalException {

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
			throw new TechnicalException("errors.dataConversion.stringToDate", errorParams);
		}

		return date;
	}

	public static Date convertNullableStringToDate(String value, EDateFormat dateFormat) throws TechnicalException {

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
				throw new TechnicalException("errors.dataConversion.stringToDate", errorParams);
			}
		}

		return date;
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

	/**
	 * Convert a bigDecimal value to string
	 * @param value
	 * @param scale
	 * @param roundingMode
	 * @param defaultValue
	 * @return
	 */
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

	/**
	 * Convert any string value to a boolean (value supported are : N, NO, NON, FALSE, 0, O, OUI, Y, YES, TRUE, 1)
	 * @param value
	 * @return
	 * @throws DataException
	 */
	public static Boolean convertStringToBoolean(String value) throws TechnicalException {

		Boolean result = null;

		if (value == null) {
			throw new TechnicalException("errors.dataConversion.cannotConvertNullToBoolean");
		}

		if ("N".equalsIgnoreCase(value) || "NON".equalsIgnoreCase(value) || "NO".equalsIgnoreCase(value) || "FALSE".equalsIgnoreCase(value) || "0".equalsIgnoreCase(value)) {
			result = false;
		} else if ("O".equalsIgnoreCase(value) || "OUI".equalsIgnoreCase(value) || "Y".equalsIgnoreCase(value) || "YES".equalsIgnoreCase(value) || "TRUE".equalsIgnoreCase(value) || "1".equalsIgnoreCase(value)) {
			result = true;
		}

		return result;

	}

}
