package com.bja.bapps.tools.core.utils.propertiesHandler;

import java.io.File;
import java.io.FileInputStream;
import java.math.BigDecimal;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bja.bapps.tools.core.exceptions.TechnicalException;
import com.bja.bapps.tools.core.utils.dataType.DataConverter;



public class PropertiesHandler {

	private static final long serialVersionUID = 4055395234617396062L;

	private static Logger logger = LoggerFactory.getLogger(PropertiesHandler.class);

	private Properties properties;

	public PropertiesHandler(String propertiesFilePath) throws TechnicalException {
		try {
			properties = new Properties();
			properties.load(new FileInputStream(new File(propertiesFilePath)));
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw new TechnicalException("errors.propertiesHandler.propertiesFileNotFound", e);
		}
	}

	/**
	 * Get an Integer property
	 * @param key
	 * @param defaultValue
	 * @param isMandatory
	 * @return
	 * @throws TechnicalException
	 */
	public Integer getIntProperty(String key, Integer defaultValue, Boolean isMandatory) throws TechnicalException {

		preProcessValidation();

		if (isMandatory) {
			if (properties.getProperty(key) == null) {
				throw new TechnicalException("errors.propertiesHandler.cannotGetMandatoryIntProperty");
			}
		}

		return DataConverter.convertStringToInteger(properties.getProperty(key), defaultValue);

	}

	/**
	 * Get an Integer property
	 * @param key
	 * @param isMandatory
	 * @return -1 if property not found and if property not mandatory
	 * @throws TechnicalException
	 */
	public Integer getIntProperty(String key, Boolean isMandatory) throws TechnicalException {
		return getIntProperty(key, -1, isMandatory);
	}

	/**
	 * Get a non mandatory Integer property 
	 * @param key
	 * @param defaultValue
	 * @return return a default value if property not found
	 * @throws TechnicalException
	 */
	public Integer getIntProperty(String key, Integer defaultValue) throws TechnicalException {
		return getIntProperty(key, defaultValue, false);
	}

	/**
	 * Get a mandatory Integer property 
	 * @param key
	 * @param defaultValue
	 * @return 
	 * @throws TechnicalException
	 */
	public Integer getIntProperty(String key) throws TechnicalException {
		return getIntProperty(key, null, true);
	}

	/**
	 * Get a BigDecimal property
	 * @param key
	 * @param defaultValue
	 * @param isMandatory
	 * @param withDelimiterReplacement (if setted to true remove all "." before conversion)
	 * @return
	 * @throws TechnicalException
	 */
	public BigDecimal getBigDecimalProperty(String key, BigDecimal defaultValue, Boolean isMandatory, Boolean withDelimiterReplacement) throws TechnicalException {

		preProcessValidation();

		if (isMandatory) {
			if (properties.getProperty(key) == null) {
				throw new TechnicalException("errors.propertiesHandler.cannotGetMandatoryBigDecimalProperty");
			}
		}

		return DataConverter.convertStringToBigDecimal(properties.getProperty(key), withDelimiterReplacement, defaultValue);

	}

	/**
	 * Get a BigDecimal property
	 * @param key
	 * @param isMandatory
	 * @param withDelimiterReplacement (if setted to true remove all "." before conversion)
	 * @return
	 * @throws TechnicalException
	 */
	public BigDecimal getBigDecimalProperty(String key, Boolean isMandatory, Boolean withDelimiterReplacement) throws TechnicalException {
		return getBigDecimalProperty(key, new BigDecimal("0"), isMandatory, withDelimiterReplacement);
	}

	/**
	 * Get a non mandatory BigDecimal property
	 * @param key
	 * @param defaultValue
	 * @param withDelimiterReplacement (if setted to true remove all "." before conversion)
	 * @return return a default value if property not found
	 * @throws TechnicalException
	 */
	public BigDecimal getBigDecimalProperty(String key, BigDecimal defaultValue, Boolean withDelimiterReplacement) throws TechnicalException {
		return getBigDecimalProperty(key, defaultValue, false, withDelimiterReplacement);
	}

	/**
	 * Get a mandatory BigDecimal property
	 * This conversion doesn't remove "." of the string before conversion
	 * @param key
	 * @return
	 * @throws TechnicalException
	 */
	public BigDecimal getBigDecimalProperty(String key) throws TechnicalException {
		return getBigDecimalProperty(key, null, true, false);
	}

	/**
	 * Get a String property
	 * @param key
	 * @param defaultValue
	 * @param isMandatory
	 * @return
	 * @throws TechnicalException
	 */
	public String getStringProperty(String key, String defaultValue, Boolean isMandatory) throws TechnicalException {

		String result = defaultValue;

		preProcessValidation();

		if (isMandatory) {
			if (properties.getProperty(key) == null) {
				throw new TechnicalException("errors.propertiesHandler.cannotGetMandatoryStringProperty");
			}
		}

		if (properties.getProperty(key) != null) {
			result = properties.getProperty(key);
		}

		return result;

	}

	/**
	 * Get a String property
	 * @param key
	 * @param isMandatory
	 * @return return null if property not found and if property not mandatory
	 * @throws TechnicalException
	 */
	public String getStringProperty(String key, Boolean isMandatory) throws TechnicalException {
		return getStringProperty(key, null, isMandatory);
	}

	/**
	 * Get a non mandatory String property
	 * @param key
	 * @param defaultValue
	 * @return return a default value if property not found
	 * @throws TechnicalException
	 */
	public String getStringProperty(String key, String defaultValue) throws TechnicalException {
		return getStringProperty(key, defaultValue, false);
	}

	/**
	 * Get a mandatory String property
	 * @param key
	 * @return
	 * @throws TechnicalException
	 */
	public String getStringProperty(String key) throws TechnicalException {
		return getStringProperty(key, null, true);
	}

	/**
	 * Check if the object properties is loaded before trying to get any property
	 * @throws TechnicalException
	 */
	protected void preProcessValidation() throws TechnicalException {
		if (properties == null) {
			throw new TechnicalException("errors.propertiesHandler.noPropertyLoaded");
		}
	}

}
