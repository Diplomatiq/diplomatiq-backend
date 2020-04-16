package org.diplomatiq.diplomatiqbackend.engines.crypto.passwordstretching.argon2;

public class Argon2Parameters {

    private final int saltLengthBytes;
    private final int hashLengthBytes;
    private final int parallelism;
    private final int memory;
    private final int iterations;

    public Argon2Parameters(int saltLengthBytes, int hashLengthBytes, int parallelism, int memory, int iterations) {
        this.saltLengthBytes = saltLengthBytes;
        this.hashLengthBytes = hashLengthBytes;
        this.parallelism = parallelism;
        this.memory = memory;
        this.iterations = iterations;
    }

    public int getSaltLengthBytes() {
        return saltLengthBytes;
    }

    public int getHashLengthBytes() {
        return hashLengthBytes;
    }

    public int getParallelism() {
        return parallelism;
    }

    public int getMemory() {
        return memory;
    }

    public int getIterations() {
        return iterations;
    }
}
