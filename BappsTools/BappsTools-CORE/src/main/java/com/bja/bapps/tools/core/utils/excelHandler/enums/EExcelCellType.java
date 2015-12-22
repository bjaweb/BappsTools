// TODO BJA à migrer en POI
//package com.bja.bapps.tools.core.utils.excelHandler.enums;
//
//import java.util.ArrayList;
//import java.util.List;
//
//import jxl.CellType;
//
//import com.bja.bapps.tools.core.exceptions.TechnicalException;
//
//public enum EExcelCellType {
//
//	INTEGER("INTEGER", CellType.NUMBER, CellType.NUMBER_FORMULA, CellType.LABEL, CellType.EMPTY),
//	STRING("STRING", CellType.LABEL, CellType.STRING_FORMULA, CellType.EMPTY),
//	FRENCH_DATE_FORMAT("FRENCH_DATE_FORMAT", CellType.DATE, CellType.DATE_FORMULA, CellType.LABEL, CellType.EMPTY),
//	BIG_DECIMAL("BIG_DECIMAL", CellType.NUMBER, CellType.NUMBER_FORMULA, CellType.LABEL, CellType.EMPTY);
//
//	// Array of excelCellType
//	private static EExcelCellType [] enums = {
//		INTEGER,
//		STRING,
//		FRENCH_DATE_FORMAT,
//		BIG_DECIMAL
//	};
//
//	private String id;
//	private List<CellType> cellTypes;
//
//	private EExcelCellType(String id, CellType... cellTypes) {
//		this.id = id;
//		setCellTypes(cellTypes);
//	}
//
//	private void setCellTypes(CellType... cellTypes) {
//		this.cellTypes = new ArrayList<CellType>();
//		for (int index = 0; index < cellTypes.length; index++) {
//			this.cellTypes.add(cellTypes[index]);
//		}
//	}
//
//	public String getId() {
//		return id;
//	}
//
//	public List<CellType> getCellTypes() {
//		return cellTypes;
//	}
//
//	/**
//	 * Get an excelCellType by his id
//	 * @param id
//	 * @return
//	 * @throws TechnicalException
//	 */
//	public static EExcelCellType parseById(String id) throws TechnicalException {
//		for (EExcelCellType excelCellType : enums) {
//			if (excelCellType.id.equals(id)) {
//				return excelCellType;
//			}
//		}
//		throw new TechnicalException("Cannot match ExcelCellType enumeration {id=" + id + "}");
//	}
//
//}
