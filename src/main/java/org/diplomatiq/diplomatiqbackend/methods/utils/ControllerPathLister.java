package org.diplomatiq.diplomatiqbackend.methods.utils;

import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class ControllerPathLister {
    public static Set<String> getPaths(Class clazz) {
        return Arrays.stream(clazz.getDeclaredMethods()).flatMap(method ->
            Arrays.stream(method.getAnnotation(RequestMapping.class).path())
                .map(path -> !path.startsWith("/") ? "/" + path : path)
        ).collect(Collectors.toUnmodifiableSet());
    }
}
