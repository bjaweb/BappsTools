//package com.bja.bapps.tools.core.utils.log;
//
//import org.apache.log4j.Level;
//import org.apache.log4j.Logger;
//import org.apache.log4j.Priority;
//
//public class MyLogger {
//	
//	
//	private static MyLogger instance;
//	private Class clazz;
//	
//	
//	
//	private MyLogger(){}
//	
//	public static MyLogger getLogger(Class clazz){
//		
//		if (instance == null)
//			instance = new MyLogger();
//			
//			instance.setClazz(clazz);
//			return instance;
//	}
//	
//	public static MyLogger getLogger(){
//		
//		if (instance == null)
//			instance = new MyLogger();
//			return instance;
//	}
//	
//
//	private void log(Class classe,Object message, Priority priority, Throwable t){
//		Logger.getLogger(classe).log(priority, message,t);
//	}
//
//	private void log(Class classe,Object message, Priority priority){
//		log(clazz,message, priority,null);
//		//Logger.getLogger(classe).log(priority, message);
//	}
//	
//	public void log(Object message, Priority priority,Throwable t){
//		log(clazz,message, priority,t);
//	}
//	
//	public void log(Object message, Priority priority){
//		log(clazz,message, priority);
//	}
//	
//	
//	
//	
//	public void debug(Object message){
//		log( message,Level.DEBUG);
//	}
//	public void info(Object message){
//		log(message,Level.INFO);
//	}
//	public void error(Object message){
//		log(message,Level.ERROR);
//	}
//	
//	public void fatal(Object message){
//		log(message,Level.FATAL);
//	}
//
//
//	
//	
//	public void debug(Class classe,Object message){
//		log( classe,message,Level.DEBUG);
//	}
//	public void info(Class classe,Object message){
//		log(classe,message,Level.INFO);
//	}
//	public void error(Class classe,Object message){
//		log(classe,message,Level.ERROR);
//	}
//	
//	public void fatal(Class classe,Object message){
//		log(classe,message,Level.FATAL);
//	}
//
//	
//	//prise en compte des erreurs
//	
//	public void debug(Object message, Throwable t){
//		log( message,Level.DEBUG,t);
//	}
//	public void info(Object message, Throwable t){
//		log(message,Level.INFO,t);
//	}
//	public void error(Object message, Throwable t){
//		log(message,Level.ERROR,t);
//	}
//	
//	public void fatal(Object message, Throwable t){
//		log(message,Level.FATAL,t);
//	}
//
//
//	
//	
//	public void debug(Class classe,Object message, Throwable t){
//		log( classe,message,Level.DEBUG,t);
//	}
//	public void info(Class classe,Object message, Throwable t){
//		log(classe,message,Level.INFO,t);
//	}
//	public void error(Class classe,Object message, Throwable t){
//		log(classe,message,Level.ERROR,t);
//	}
//	
//	public void fatal(Class classe,Object message, Throwable t){
//		log(classe,message,Level.FATAL,t);
//	}
//	
//	public Class getClazz() {
//		return clazz;
//	}
//	public void setClazz(Class clazz) {
//		this.clazz = clazz;
//	}
//	
//
//}
