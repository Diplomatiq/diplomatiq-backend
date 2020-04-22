package org.diplomatiq.diplomatiqbackend.filters;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class DiplomatiqHeaders {
    public enum KnownHeader {
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
            "The signature of the request in \"${authenticationScheme} ${signature}\" format."
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

    public static final Set<String> BaseHeaders = Collections.unmodifiableSet(
        Set.of(
            KnownHeader.ClientId.name(),
            KnownHeader.Instant.name()
        )
    );

    public static final Set<String> SignedBaseHeaders;

    static {
        Set<String> signedBaseHeaders = new HashSet<>(BaseHeaders);
        signedBaseHeaders.add(KnownHeader.SignedHeaders.name());
        SignedBaseHeaders = Collections.unmodifiableSet(signedBaseHeaders);
    }

    public static final Set<String> AuthenticationSessionSignatureV1SignedHeaders;

    static {
        Set<String> authenticationSessionSignatureV1SignedHeaders = new HashSet<>(SignedBaseHeaders);
        authenticationSessionSignatureV1SignedHeaders.add(KnownHeader.AuthenticationSessionId.name());
        AuthenticationSessionSignatureV1SignedHeaders =
            Collections.unmodifiableSet(authenticationSessionSignatureV1SignedHeaders);
    }

    public static final Set<String> AuthenticationSessionSignatureV1RequiredHeaders;

    static {
        Set<String> authenticationSessionSignatureV1RequiredHeaders =
            new HashSet<>(AuthenticationSessionSignatureV1SignedHeaders);
        authenticationSessionSignatureV1RequiredHeaders.add(KnownHeader.Authorization.name());
        AuthenticationSessionSignatureV1RequiredHeaders =
            Collections.unmodifiableSet(authenticationSessionSignatureV1RequiredHeaders);
    }

    public static final Set<String> DeviceSignatureV1SignedHeaders;

    static {
        Set<String> deviceSignatureV1SignedHeaders = new HashSet<>(SignedBaseHeaders);
        deviceSignatureV1SignedHeaders.add(KnownHeader.DeviceId.name());
        DeviceSignatureV1SignedHeaders = Collections.unmodifiableSet(deviceSignatureV1SignedHeaders);
    }

    public static final Set<String> DeviceSignatureV1RequiredHeaders;

    static {
        Set<String> deviceSignatureV1RequiredHeaders = new HashSet<>(DeviceSignatureV1SignedHeaders);
        deviceSignatureV1RequiredHeaders.add(KnownHeader.Authorization.name());
        DeviceSignatureV1RequiredHeaders = Collections.unmodifiableSet(deviceSignatureV1RequiredHeaders);
    }

    public static final Set<String> SessionSignatureV1SignedHeaders;

    static {
        Set<String> sessionSignatureV1SignedHeaders = new HashSet<>(SignedBaseHeaders);
        sessionSignatureV1SignedHeaders.add(KnownHeader.DeviceId.name());
        sessionSignatureV1SignedHeaders.add(KnownHeader.SessionId.name());
        SessionSignatureV1SignedHeaders = Collections.unmodifiableSet(sessionSignatureV1SignedHeaders);
    }

    public static final Set<String> SessionSignatureV1RequiredHeaders;

    static {
        Set<String> sessionSignatureV1RequiredHeaders = new HashSet<>(SessionSignatureV1SignedHeaders);
        sessionSignatureV1RequiredHeaders.add(KnownHeader.Authorization.name());
        SessionSignatureV1RequiredHeaders = Collections.unmodifiableSet(sessionSignatureV1RequiredHeaders);
    }

    public static final Set<String> AllRequiredHeaders;

    static {
        Set<String> allRequiredHeaders = new HashSet<>();
        allRequiredHeaders.addAll(AuthenticationSessionSignatureV1RequiredHeaders);
        allRequiredHeaders.addAll(DeviceSignatureV1RequiredHeaders);
        allRequiredHeaders.addAll(SessionSignatureV1RequiredHeaders);
        AllRequiredHeaders = Collections.unmodifiableSet(allRequiredHeaders);
    }

    public static final Set<String> AllKnownHeaders =
        Arrays.stream(KnownHeader.values()).map(KnownHeader::name).collect(Collectors.toUnmodifiableSet());

    public static final Map<String, String> AllRequiredHeadersWithDescription = AllRequiredHeaders.stream().collect(
        Collectors.toUnmodifiableMap(
            Function.identity(),
            header -> headersWithDescriptions.get(KnownHeader.valueOf(header))
        )
    );

}
