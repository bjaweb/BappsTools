package com.bja.bapps.tools.core.jaxws;


import javax.jws.WebService;

//Service Implementation
@WebService(endpointInterface = "com.bja.bapps.tools.core.jaxws.HelloWorld")
public class HelloWorldImpl implements HelloWorld{

	@Override
	public String getHelloWorldAsString(String name) {
		return "Hello World JAX-WS " + name;
	}

}