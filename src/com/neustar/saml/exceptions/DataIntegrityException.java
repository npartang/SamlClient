package com.neustar.saml.exceptions;

public class DataIntegrityException extends Exception {
	private static String SYS_ERROR = "An data validation error occurred, please contact your systems administrator if this problem persists.";
	public DataIntegrityException() {
		super(SYS_ERROR);
	}

	public DataIntegrityException(String msg) {
		super(msg);
	}
}
