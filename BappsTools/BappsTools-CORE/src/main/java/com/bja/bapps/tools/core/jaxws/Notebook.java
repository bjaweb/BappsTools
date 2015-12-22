package com.bja.bapps.tools.core.jaxws;

import javax.jws.WebMethod;
import javax.jws.WebService;


@WebService (name = "Notebook")
public interface Notebook {

	@WebMethod 
	public String getHelloWorldAsString(String name);
}
