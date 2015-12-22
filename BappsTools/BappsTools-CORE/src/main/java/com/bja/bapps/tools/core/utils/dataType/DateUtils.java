package com.bja.bapps.tools.core.utils.dataType;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public class DateUtils {

	public Date getCurrentDate() {

		return new Date();

	}


	public static Date addYear(Date date, int nbYear) throws Exception {

		GregorianCalendar gregorianCalendar = new GregorianCalendar();
		gregorianCalendar.setTime(date);

		gregorianCalendar.set(Calendar.YEAR,gregorianCalendar.get(Calendar.YEAR)+nbYear);
		
		return gregorianCalendar.getTime();

	}
	
	
	
	public static String getDateZulu(Date d){
		
		TimeZone timeZone1 = TimeZone.getTimeZone("Zulu");
        
		SimpleDateFormat sdf = new SimpleDateFormat("yyMMddHHmmss");
		
		sdf.setTimeZone(timeZone1);
		
		return sdf.format(d)+"Z";
	}
	

}
