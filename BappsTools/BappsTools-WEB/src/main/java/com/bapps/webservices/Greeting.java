package com.bapps.webservices;


import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService
public interface Greeting {
	 @WebMethod String sayHello(String name);
}