package org.diplomatiq.diplomatiqbackend;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class DiplomatiqBackendApplication {
	public static void main(String[] args) {
	    configureBouncyCastle();
		SpringApplication.run(DiplomatiqBackendApplication.class, args);
	}

	private static void configureBouncyCastle() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
}
