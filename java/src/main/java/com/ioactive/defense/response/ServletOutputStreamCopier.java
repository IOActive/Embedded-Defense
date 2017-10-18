package com.ioactive.defense.response;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;

public class ServletOutputStreamCopier
	extends ServletOutputStream {

	private final OutputStream outputStream;
	private final ByteArrayOutputStream copy;

	public ServletOutputStreamCopier(OutputStream outputStream) {
		this.outputStream = outputStream;
		this.copy = new ByteArrayOutputStream(1024);
	}

	@Override
	public void write(int b) throws IOException {
		outputStream.write(b);
		copy.write(b);
	}

	public byte[] getCopy() {
		return copy.toByteArray();
	}

	@Override
	public boolean isReady() {
		return true;
	}

	@Override
	public void setWriteListener(WriteListener writeListener) {
		// TODO Auto-generated method stub
	}

}