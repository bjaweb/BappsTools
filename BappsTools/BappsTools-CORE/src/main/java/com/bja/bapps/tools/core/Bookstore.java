package com.bja.bapps.tools.core;

import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


//This statement means that class "Bookstore.java" is the root-element of our example
@XmlRootElement(namespace = "com.bja.bapps.tools.core")
//@XmlRootElement(name = "bookstore") dans ce cas c'est un sous noeud
@XmlType(propOrder = { "name", "location", "books", "bds" })
public class Bookstore {

	private List<Book> books;
	
	private List<BD> bds;

	private String name;
	private String location;


	// XmlElement sets the name of the entities
	@XmlElement(name = "nomBouquin")
	public String getName() {
		return name;
	}
	
	@XmlElement(name = "livre")
	public List<Book> getBooks() {
		return books;
	}
	
	public void setBooks(List<Book> books) {
		this.books = books;
	}
	
	@XmlElement(name = "bd")
	public List<BD> getBds() {
		return bds;
	}

	public void setBds(List<BD> bds) {
		this.bds = bds;
	}
	
	public void setName(String name) {
		this.name = name;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

} 