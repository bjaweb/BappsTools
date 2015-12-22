package com.bja.bapps.tools.core;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
 
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Todo {
 
  public enum Importance {
    MINEURE, IMPORTANT, MAJEUR, CRITIQUE
  };
  
  
 
  Importance importance() default Importance.MINEURE;
 
  String[] description();
 
  String assigneA();
 
  String dateAssignation();
  
  
}