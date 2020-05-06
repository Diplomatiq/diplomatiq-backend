package org.diplomatiq.diplomatiqbackend.filters.signature;

import org.springframework.util.StreamUtils;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;

public class BodyCachingHttpServletRequest extends HttpServletRequestWrapper {
    private byte[] body;

    public BodyCachingHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        ServletInputStream servletInputStream = request.getInputStream();
        this.body = StreamUtils.copyToByteArray(servletInputStream);
    }

    @Override
    public ServletInputStream getInputStream() {
        return new BodyCachingServletInputStream(this.body);
    }

    @Override
    public BufferedReader getReader() {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.body);
        InputStreamReader inputStreamReader = new InputStreamReader(byteArrayInputStream);
        return new BufferedReader(inputStreamReader);
    }

    public byte[] getBody() {
        return body;
    }
}
