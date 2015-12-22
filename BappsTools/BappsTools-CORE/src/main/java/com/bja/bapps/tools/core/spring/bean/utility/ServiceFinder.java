//package com.bja.bapps.tools.core.e.spring.bean.utility;
//
//
//import javax.servlet.ServletContext;
//import javax.servlet.http.HttpServletRequest;
//
//import org.springframework.context.ApplicationContext;
//import org.springframework.web.context.support.WebApplicationContextUtils;
//
//
//public class ServiceFinder {
//	
//	public static ApplicationContext getContext(HttpServletRequest httpRequest) {
//		return WebApplicationContextUtils
//				.getRequiredWebApplicationContext(httpRequest.getSession()
//						.getServletContext());
//	}
//	
//	public static ApplicationContext getContext(ServletContext servletContext) {
//		return WebApplicationContextUtils
//				.getRequiredWebApplicationContext(servletContext);
//	}
//	
//	public static ApplicationContext getContext() {
//		return ApplicationContextProvider.getApplicationContext();
//	}
//}
//

