package com.bja.bapps.tools.core.utils.dataType.enums;

import com.bja.bapps.tools.core.exceptions.TechnicalException;

public enum EDateFormat {

	ENGLISH_DATE_FORMAT("ENGLISH_DATE_FORMAT", "yyyyMMdd"),
	FRENCH_DATE_FORMAT("FRENCH_DATE_FORMAT", "dd/MM/yyyy"),
	FRENCH_DATE_FORMAT_WITHOUT_DELIMITER("FRENCH_DATE_FORMAT_WITHOUT_DELIMITER", "ddMMyyyy"),
	FRENCH_TIMESTAMP_FOR_ETAT("FRENCH_TIMESTAMP_FOR_ETAT", "dd/MM/yyyy à HH'h'mm"),
	FRENCH_TIMESTAMP_WITH_DELIMITER("FRENCH_TIMESTAMP_WITH_DELIMITER", "dd/MM/yyyy HH:mm:ss"),
	FULL_TIMESTAMP("FULL_TIMESTAMP", "yyyyMMdd_HHmmssSSS"),
	TIMESTAMP_WITHOUT_DELIMITER("TIMESTAMP_WITHOUT_DELIMITER", "HHmmssSSS");

	// Array of centreCoutProperties
	private static EDateFormat []  enums = {
		ENGLISH_DATE_FORMAT,
		FRENCH_DATE_FORMAT,
		FRENCH_DATE_FORMAT_WITHOUT_DELIMITER,
		FRENCH_TIMESTAMP_FOR_ETAT,
		FRENCH_TIMESTAMP_WITH_DELIMITER,
		FULL_TIMESTAMP,
		TIMESTAMP_WITHOUT_DELIMITER
	};

	private String id;
	private String pattern;

	private EDateFormat(String id, String pattern) {
		this.id = id;
		this.pattern = pattern;
	}

	public String getId() {
		return id;
	}

	public String getPattern() {
		return pattern;
	}

	/**
	 * Get a dateFormat by his id
	 * @param id
	 * @return
	 * @throws TechnicalException
	 */
	public static EDateFormat parseById(String id) throws TechnicalException {
		for (EDateFormat dateFormat : enums) {
			if (dateFormat.id.equals(id)) {
				return dateFormat;
			}
		}
		throw new TechnicalException("Cannot match dateFormat enumeration {id=" + id + "}");
	}

	/**
	 * Get a dateFormat by his pattern
	 * @param pattern
	 * @return
	 * @throws TechnicalException
	 */
	public static EDateFormat parseByPattern(String pattern) throws TechnicalException {
		for (EDateFormat dateFormat : enums) {
			if (dateFormat.id.equals(pattern)) {
				return dateFormat;
			}
		}
		throw new TechnicalException("Cannot match dateFormat enumeration {pattern=" + pattern + "}");
	}


}
