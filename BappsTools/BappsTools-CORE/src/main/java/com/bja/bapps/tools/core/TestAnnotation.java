package com.bja.bapps.tools.core;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

@MonAnnotation(arg1="valeur1", arg2="valeur2")
public class TestAnnotation {
	
	private String value1;
	
	
	private String value2;
	public TestAnnotation(){}
	
	@PostConstruct
	public void bjaTest(){
		System.out.println("avant construction");
	}
	
	@PreDestroy
	public void bjaTest2(){
		System.out.println("predestroy");
	}
	
	
	public String getValue1() {
		return value1;
	}
	public void setValue1(String value1) {
		this.value1 = value1;
	}
	public String getValue2() {
		return value2;
	}
	public void setValue2(String value2) {
		this.value2 = value2;
	}
	
	
	
	public static void main(String[] args) {
		TestAnnotation t = new TestAnnotation();
		t.setValue1("value1");
		System.out.println(t.getValue1());
	}
	

}
