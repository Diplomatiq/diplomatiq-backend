package org.diplomatiq.diplomatiqbackend.filters.signature;

import org.springframework.util.StreamUtils;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;

public class BodyCachingHttpServletRequest extends HttpServletRequestWrapper {
    private byte[] requestBody;

    public BodyCachingHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        InputStream requestInputStream = request.getInputStream();
        this.requestBody = StreamUtils.copyToByteArray(requestInputStream);
    }

    @Override
    public ServletInputStream getInputStream() {
        return new BodyCachingServletInputStream(this.requestBody);
    }

    @Override
    public BufferedReader getReader() {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.requestBody);
        return new BufferedReader(new InputStreamReader(byteArrayInputStream));
    }
}
