//package com.bja.bapps.tools.core.utils.excelHandler;
//
//import java.io.File;
//import java.io.FileInputStream;
//import java.math.BigDecimal;
//import java.util.Calendar;
//import java.util.Date;
//import java.util.GregorianCalendar;
//
//import jxl.Cell;
//import jxl.CellType;
//import jxl.DateCell;
//import jxl.NumberCell;
//import jxl.Sheet;
//import jxl.Workbook;
//
//import com.bja.bapps.tools.core.exceptions.TechnicalException;
//import com.bja.bapps.tools.core.utils.dataType.DataConverter;
//import com.bja.bapps.tools.core.utils.dataType.enums.EDateFormat;
//import com.bja.bapps.tools.core.utils.excelHandler.enums.EExcelCellType;
//import com.bja.bapps.tools.core.utils.log.MyLogger;
//
//public class ExcelReader {
//	
//	private static MyLogger logger = MyLogger.getLogger(ExcelReader.class);
//	
//	/**
//	 * Get a workbook from his filePath
//	 * @param xlsFilePath
//	 * @return
//	 * @throws TechnicalException
//	 */
//	public static Workbook getWorkbook(String xlsFilePath) throws TechnicalException {
//		Workbook workbook = null;
//		try {
//			File file = new File(xlsFilePath);
//			new FileInputStream(new File(xlsFilePath));
//			workbook = Workbook.getWorkbook(new FileInputStream(new File(xlsFilePath)));
//		} catch (Exception e) {
//			logger.error(e.getMessage(), e);
//			throw new TechnicalException("errors.excelReader.cannotGetWorkbook", e);
//		}
//		return workbook;
//	}
//	
//	/**
//	 * Get a String from an Excel cell of a sheet according to his coordinate
//	 * @param sheet
//	 * @param rowIndex
//	 * @param columnIndex
//	 * @param mandatoryField
//	 * @param trimSpaces
//	 * @param maxSize
//	 * @return
//	 * @throws TechnicalException
//	 */
//	public static String getStringField(Sheet sheet, int rowIndex, int columnIndex, Boolean mandatoryField, Boolean trimSpaces, int maxSize) throws TechnicalException {
//		return getStringField(sheet.getCell(rowIndex, columnIndex), mandatoryField, trimSpaces, maxSize);
//	}
//
//	/**
//	 * Get a String from an Excel cell
//	 * @param cell
//	 * @param mandatoryField
//	 * @param trimSpaces
//	 * @param maxSize (if -1 doesn't check the length of the field)
//	 * @return
//	 * @throws TechnicalException 
//	 */
//	public static String getStringField(Cell cell, Boolean mandatoryField, Boolean trimSpaces, int maxSize) throws TechnicalException {
//
//		String cellContent = null;
//
//		if (
//				(mandatoryField && cell == null)
//				||
//				(mandatoryField && cell != null && cell.getContents().equals(""))
//				||
//				(mandatoryField && cell != null && trimSpaces && cell.getContents().trim().equals(""))
//		) {
//			throw new TechnicalException("errors.excelReader.mandatoryFieldNotFilled");
//		}
//
//		if (!EExcelCellType.STRING.getCellTypes().contains(cell.getType())) {
//			throw new TechnicalException("errors.excelReader.mismatchCellType");
//		}
//
//		cellContent = cell.getContents();
//
//		if (trimSpaces) {
//			cellContent = cellContent.trim();
//		} 
//
//		if (maxSize != -1 && cellContent.length() > maxSize) {
//			throw new TechnicalException("errors.excelReader.cellContentTooLong");
//		}
//
//		return cellContent;
//	}
//	
//	/**
//	 * Get a String from an Excel cell (without checking field size)
//	 * @param cell
//	 * @param mandatoryField
//	 * @param trimSpaces
//	 * @return
//	 * @throws TechnicalException
//	 */
//	public static String getStringField(Cell cell, Boolean mandatoryField, Boolean trimSpaces) throws TechnicalException {
//		return getStringField(cell, mandatoryField, trimSpaces, -1);
//	}
//
//	/**
//	 * Get a Date from an Excel cell
//	 * @param cell
//	 * @param dateFormat
//	 * @param mandatoryField
//	 * @param trimSpaces
//	 * @return
//	 * @throws TechnicalException
//	 */
//	public static Date getDateField(Cell cell, EDateFormat dateFormat, Boolean mandatoryField, Boolean trimSpaces) throws TechnicalException {
//
//		Date cellContent = null;
//
//		if (
//				(mandatoryField && cell == null)
//				||
//				(mandatoryField && cell != null && cell.getContents().equals(""))
//				||
//				(mandatoryField && cell != null && trimSpaces && cell.getContents().trim().equals(""))
//		) {
//			throw new TechnicalException("errors.excelReader.mandatoryFieldNotFilled");
//		}
//
//		if (!EExcelCellType.FRENCH_DATE_FORMAT.getCellTypes().contains(cell.getType())) {
//			throw new TechnicalException("errors.excelReader.mismatchCellType");
//		}
//
//		if (cell.getType().equals(CellType.DATE)) {
//			DateCell dateCell = (DateCell) cell;
//			if (dateCell.isTime()) {
//
//			} else {
//				GregorianCalendar cellDate = new GregorianCalendar();
//				cellDate.setTime(dateCell.getDate());
//
//				GregorianCalendar dateToConvert = new GregorianCalendar();
//				dateToConvert.set(cellDate.get(Calendar.YEAR), cellDate.get(Calendar.MONTH), cellDate.get(Calendar.DAY_OF_MONTH), 0, 0, 0);
//				dateToConvert.set(Calendar.MILLISECOND, 0);
//
//				cellContent = dateToConvert.getTime();
//			}
//		} else {
//			if (trimSpaces) {
//				if (!(!mandatoryField && (cell == null || cell.getContents().trim().equals("")))) {
//					cellContent = DataConverter.convertStringToDate(cell.getContents().trim(), dateFormat);
//				}
//			} else {
//				if (!(!mandatoryField && (cell == null || cell.getContents().trim().equals("")))) {
//					cellContent = DataConverter.convertStringToDate(cell.getContents(), dateFormat);
//				}
//			}
//		}
//
//		return cellContent;
//	}
//
//	/**
//	 * Get an Integer from an Excel cell
//	 * @param cell
//	 * @param mandatoryField
//	 * @param trimSpaces
//	 * @return
//	 * @throws TechnicalException
//	 */
//	public static Integer getIntegerField(Cell cell, Boolean mandatoryField, Boolean trimSpaces) throws TechnicalException {
//
//		Integer cellContent = null;
//
//		if (
//				(mandatoryField && cell == null)
//				||
//				(mandatoryField && cell != null && cell.getContents().equals(""))
//				||
//				(mandatoryField && cell != null && trimSpaces && cell.getContents().trim().equals(""))
//		) {
//			throw new TechnicalException("errors.excelReader.mandatoryFieldNotFilled");
//		}
//
//		if (!EExcelCellType.INTEGER.getCellTypes().contains(cell.getType())) {
//			throw new TechnicalException("errors.excelReader.mismatchCellType");
//		}
//
//		if (trimSpaces) {
//			if (!(!mandatoryField && (cell == null || cell.getContents().trim().equals("")))) {
//				cellContent = DataConverter.convertStringToInteger(cell.getContents().trim(), null);
//			}
//		} else {
//			cellContent = DataConverter.convertStringToInteger(cell.getContents(), null);
//		}
//
//		return cellContent;
//	}
//
//	/**
//	 * Get a BigDecimal from an Excel cell
//	 * @param cell
//	 * @param mandatoryField
//	 * @return
//	 * @throws TechnicalException
//	 */
//	public static BigDecimal getBigDecimalField(Cell cell, Boolean mandatoryField) throws TechnicalException {
//
//		BigDecimal cellContent = null;
//
//		if (
//				(mandatoryField && cell == null)
//				||
//				(mandatoryField && cell != null && cell.getContents().trim().equals(""))
//		) {
//			throw new TechnicalException("errors.excelReader.mandatoryFieldNotFilled");
//		}
//
//		if (!EExcelCellType.BIG_DECIMAL.getCellTypes().contains(cell.getType())) {
//			throw new TechnicalException("errors.excelReader.mismatchCellType");
//		}
//
//		if (cell.getType().equals(CellType.NUMBER)) {
//			NumberCell numberCell = (NumberCell) cell;
//			cellContent = new BigDecimal(numberCell.getValue() + "");
//		} else {
//			if (!(!mandatoryField && (cell == null || cell.getContents().trim().equals("")))) {
//				cellContent = DataConverter.convertStringToBigDecimal(cell.getContents().trim(), true, null);
//			} 
//		}
//
//		if (mandatoryField && cellContent == null) {
//			throw new TechnicalException("errors.excelReader.mandatoryFieldNotFilled");
//		}
//
//		return cellContent;
//	}
//
//	/**
//	 * Check if a line is empty
//	 * @param cells
//	 * @return
//	 */
//	public static Boolean isEmptyLine(Cell[] cells) {
//		String line = "";
//
//		if (cells != null) {
//			for (Cell cell : cells) {
//				line += cell.getContents();
//			}
//		}
//
//		return line.trim().equals("");
//	}
//
//}
