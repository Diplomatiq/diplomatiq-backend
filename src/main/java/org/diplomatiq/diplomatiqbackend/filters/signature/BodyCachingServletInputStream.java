package org.diplomatiq.diplomatiqbackend.filters.signature;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class BodyCachingServletInputStream extends ServletInputStream {
    private InputStream requestBodyInputStream;

    public BodyCachingServletInputStream(byte[] requestBody) {
        this.requestBodyInputStream = new ByteArrayInputStream(requestBody);
    }

    @Override
    public boolean isFinished() {
        try {
            return requestBodyInputStream.available() == 0;
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public boolean isReady() {
        return true;
    }

    @Override
    public void setReadListener(ReadListener readListener) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int read() throws IOException {
        return requestBodyInputStream.read();
    }
}
