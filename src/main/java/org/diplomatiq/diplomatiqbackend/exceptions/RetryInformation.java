package org.diplomatiq.diplomatiqbackend.exceptions;

public class RetryInformation {
    enum BackoffStrategy {
        constant,
        linear,
        exponential,
        jittered
    }

    private Integer maxRetryCount;
    private BackoffStrategy backoffStrategy;
    private Integer delayMs;
    private boolean fastFirst;

    public RetryInformation(Integer maxRetryCount, BackoffStrategy backoffStrategy, Integer delayMs,
                            boolean fastFirst) {
        this.maxRetryCount = maxRetryCount;
        this.backoffStrategy = backoffStrategy;
        this.delayMs = delayMs;
        this.fastFirst = fastFirst;
    }

    public Integer getMaxRetryCount() {
        return maxRetryCount;
    }

    public BackoffStrategy getBackoffStrategy() {
        return backoffStrategy;
    }

    public Integer getDelayMs() {
        return delayMs;
    }

    public boolean isFastFirst() {
        return fastFirst;
    }
}
