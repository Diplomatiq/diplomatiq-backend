package org.diplomatiq.diplomatiqbackend.filters.clockdiscrepancy;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.diplomatiq.diplomatiqbackend.exceptions.GlobalExceptionHandler;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.BadRequestException;
import org.diplomatiq.diplomatiqbackend.exceptions.internal.ClockDiscrepancyException;
import org.diplomatiq.diplomatiqbackend.filters.DiplomatiqHeaders;
import org.diplomatiq.diplomatiqbackend.filters.JsonResponseWritingFilter;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;

public class ClockDiscrepancyFilter extends JsonResponseWritingFilter {
    private static final Duration REQUEST_VALIDITY_DURATION = Duration.ofMinutes(1);

    private GlobalExceptionHandler globalExceptionHandler;

    public ClockDiscrepancyFilter(ObjectMapper objectMapper, GlobalExceptionHandler globalExceptionHandler) {
        super(objectMapper);
        this.globalExceptionHandler = globalExceptionHandler;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        String instantHeader = request.getHeader(DiplomatiqHeaders.KnownHeader.Instant.name());
        if (instantHeader == null || instantHeader.equals("")) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleBadRequestException(
                new BadRequestException("Instant header must not be null or empty."),
                new ServletWebRequest(request)
            );
            writeJsonResponse(response, responseEntity);
            return;
        }

        Instant requestInstant;
        try {
            requestInstant = Instant.parse(instantHeader);
        } catch (DateTimeParseException ex) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleBadRequestException(
                new BadRequestException("Instant header could not be parsed."),
                new ServletWebRequest(request)
            );
            writeJsonResponse(response, responseEntity);
            return;
        }

        Instant now = Instant.now();
        boolean tooLate = requestInstant.isBefore(now.minus(REQUEST_VALIDITY_DURATION));
        boolean tooEarly = requestInstant.isAfter(now.plus(REQUEST_VALIDITY_DURATION));
        if (tooLate || tooEarly) {
            ResponseEntity<Object> responseEntity = globalExceptionHandler.handleClockDiscrepancyException(
                new ClockDiscrepancyException("Request is too late or too early."),
                new ServletWebRequest(request)
            );
            writeJsonResponse(response, responseEntity);
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
