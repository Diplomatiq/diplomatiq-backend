package org.diplomatiq.diplomatiqbackend.filters.signature;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class DiplomatiqHeaders {
    private enum KnownHeader {
        AuthenticationSessionId,
        Authorization,
        ClientId,
        DeviceId,
        Instant,
        SessionId,
        SignedHeaders,
    }

    public static final Map<KnownHeader, String> headersWithDescriptions = new EnumMap<>(KnownHeader.class);

    static {
        headersWithDescriptions.put(
            KnownHeader.AuthenticationSessionId,
            "The ID of the current authentication session."
        );
        headersWithDescriptions.put(
            KnownHeader.Authorization,
            "The signature of the request in '${authenticationScheme} ${signature}' format."
        );
        headersWithDescriptions.put(
            KnownHeader.ClientId,
            "The ID of the connecting Diplomatiq client."
        );
        headersWithDescriptions.put(
            KnownHeader.DeviceId,
            "The ID of the connecting device."
        );
        headersWithDescriptions.put(
            KnownHeader.Instant,
            "The timestamp of the request in simplified extended ISO 8601 string format (YYYY-MM-DDTHH:mm:ss.sssZ)."
        );
        headersWithDescriptions.put(
            KnownHeader.SessionId,
            "The ID of the current session."
        );
        headersWithDescriptions.put(
            KnownHeader.SignedHeaders,
            "The list of those headers split by a ; character, which are part of the request signature."
        );
    }

    public static final Set<String> SignedHeadersBase = Collections.unmodifiableSet(
        Set.of(
            KnownHeader.ClientId.name(),
            KnownHeader.Instant.name(),
            KnownHeader.SignedHeaders.name()
        )
    );

    public static final Set<String> SignedSessionV1SignedHeaders;

    static {
        Set<String> signedSessionV1SignedHeaders = new HashSet<>(SignedHeadersBase);
        signedSessionV1SignedHeaders.add(KnownHeader.DeviceId.name());
        signedSessionV1SignedHeaders.add(KnownHeader.SessionId.name());
        SignedSessionV1SignedHeaders = Collections.unmodifiableSet(signedSessionV1SignedHeaders);
    }

    public static final Set<String> SignedSessionV1RequiredHeaders;

    static {
        Set<String> signedSessionV1RequiredHeaders = new HashSet<>(SignedSessionV1SignedHeaders);
        signedSessionV1RequiredHeaders.add(KnownHeader.Authorization.name());
        SignedSessionV1RequiredHeaders = Collections.unmodifiableSet(signedSessionV1RequiredHeaders);
    }

    public static final Set<String> SignedAuthenticationSessionV1SignedHeaders;

    static {
        Set<String> signedAuthenticationSessionV1SignedHeaders = new HashSet<>(SignedHeadersBase);
        signedAuthenticationSessionV1SignedHeaders.add(KnownHeader.AuthenticationSessionId.name());
        SignedAuthenticationSessionV1SignedHeaders =
            Collections.unmodifiableSet(signedAuthenticationSessionV1SignedHeaders);
    }

    public static final Set<String> SignedAuthenticationSessionV1RequiredHeaders;

    static {
        Set<String> signedAuthenticationSessionV1RequiredHeaders =
            new HashSet<>(SignedAuthenticationSessionV1SignedHeaders);
        signedAuthenticationSessionV1RequiredHeaders.add(KnownHeader.Authorization.name());
        SignedAuthenticationSessionV1RequiredHeaders =
            Collections.unmodifiableSet(signedAuthenticationSessionV1RequiredHeaders);
    }

    public static final Set<String> SignedRequestV1SignedHeaders;

    static {
        Set<String> signedRequestV1SignedHeaders = new HashSet<>(SignedHeadersBase);
        SignedRequestV1SignedHeaders = Collections.unmodifiableSet(signedRequestV1SignedHeaders);
    }

    public static final Set<String> SignedRequestV1RequiredHeaders;

    static {
        Set<String> signedRequestV1RequiredHeaders = new HashSet<>(SignedRequestV1SignedHeaders);
        signedRequestV1RequiredHeaders.add(KnownHeader.Authorization.name());
        SignedRequestV1RequiredHeaders = Collections.unmodifiableSet(signedRequestV1RequiredHeaders);
    }

    public static final Set<String> AllRequiredHeaders;

    static {
        Set<String> allRequiredHeaders = new HashSet<>();
        allRequiredHeaders.addAll(SignedSessionV1RequiredHeaders);
        allRequiredHeaders.addAll(SignedAuthenticationSessionV1RequiredHeaders);
        allRequiredHeaders.addAll(SignedRequestV1RequiredHeaders);
        AllRequiredHeaders = Collections.unmodifiableSet(allRequiredHeaders);
    }

    public static final Map<String, String> AllRequiredHeadersWithDescription = AllRequiredHeaders.stream().collect(
        Collectors.toUnmodifiableMap(
            Function.identity(),
            header -> headersWithDescriptions.get(KnownHeader.valueOf(header))
        )
    );

}
