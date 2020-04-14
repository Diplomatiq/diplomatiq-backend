package org.diplomatiq.diplomatiqbackend.utils.crypto.passwordstretching.impl.argon2;

import org.bouncycastle.util.encoders.Hex;
import org.diplomatiq.diplomatiqbackend.utils.crypto.passwordstretching.AbstractPasswordStretchingAlgorithmImpl;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public final class Argon2 extends AbstractPasswordStretchingAlgorithmImpl {

    private int version;
    private final Argon2Parameters parameters;

    private final Argon2PasswordEncoder argon2PasswordEncoder;
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

    private Argon2(int version, Argon2Parameters parameters) {
        this.version = version;
        this.parameters = parameters;

        argon2PasswordEncoder = new Argon2PasswordEncoder(this.parameters.getSaltLengthBytes(),
            this.parameters.getHashLengthBytes(), this.parameters.getParallelism(), this.parameters.getMemory(),
            this.parameters.getIterations());
    }

    public static Argon2 v1() {
        return new Argon2(1, new Argon2Parameters(16, 32, 2, 20480, 5));
    }

    @Override
    public final String getAlgorithmBaseName() {
        return "Argon2";
    }

    @Override
    public int getAlgorithmVersion() {
        return version;
    }

    @Override
    public int getDigestSize() {
        return parameters.getHashLengthBytes();
    }

    @Override
    public void update(byte b) {
        bytes.write(b);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        bytes.write(in, inOff, len);
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        byte[] bytes = this.bytes.toByteArray();
        String asHexString = Hex.toHexString(bytes);
        String argon2Result = argon2PasswordEncoder.encode(asHexString);
        byte[] argon2ResultBytes = argon2Result.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(argon2ResultBytes, 0, out, outOff, argon2ResultBytes.length);
        reset();
        return parameters.getHashLengthBytes();
    }

    @Override
    public void reset() {
        bytes.reset();
    }

}
