package com.bja.bapps.tools.core.utils.xml;

public enum CharSetXML {
	UTF8("UTF8"),
	ISO885915("ISO-8859-15"),
	ISO88591("ISO-8859-1");
	
	/** L'attribut qui contient la valeur associé à l'enum */
	private final String value;
	 
	 private CharSetXML(String value) {
	   this.value = value;
	 }
	 
	 public String getValue() {
	   return value;
	 }
	 
	 
	 public static void main(String[] args) {
		 System.out.println(CharSetXML.ISO885915.getValue());
	}
}