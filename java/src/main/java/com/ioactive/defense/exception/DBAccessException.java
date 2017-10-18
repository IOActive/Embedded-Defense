package com.ioactive.defense.exception;

public class DBAccessException
	extends DefenseRuntimeException {

	private static final long serialVersionUID = 1L;

	public DBAccessException() {
		super();
	}

	public DBAccessException(String msg) {
		super(msg);
	}

	public DBAccessException(Throwable cause) {
		super(cause);
	}

	public DBAccessException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
