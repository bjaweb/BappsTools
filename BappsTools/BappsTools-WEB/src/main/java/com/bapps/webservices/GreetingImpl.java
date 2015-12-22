package com.bapps.webservices;

import javax.jws.WebService;

@WebService(endpointInterface = "com.bapps.webservices.Greeting")
public class GreetingImpl implements Greeting {

	@Override
	public String sayHello(String name) {
		return "Hello, Welcom to jax-ws " + name;
	}

}