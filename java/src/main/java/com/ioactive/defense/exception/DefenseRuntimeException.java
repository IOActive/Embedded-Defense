package com.ioactive.defense.exception;

public class DefenseRuntimeException
	extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public DefenseRuntimeException() {
		super();
	}

	public DefenseRuntimeException(String msg) {
		super(msg);
	}

	public DefenseRuntimeException(Throwable cause) {
		super(cause);
	}

	public DefenseRuntimeException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
