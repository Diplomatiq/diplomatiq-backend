package org.diplomatiq.diplomatiqbackend.exceptions;

import io.swagger.v3.oas.annotations.media.Schema;

public class RetryInformation {
    private enum BackoffStrategy {
        constant,
        linear,
        exponential,
        jittered
    }

    @Schema(
        description = "The client should retry `maxRetryCount` times at most",
        example = "5"
    )
    private int maxRetryCount;

    @Schema(
        description = "The client should wait before each retry as specified by the `backoffStrategy` (see [https://github.com/Diplomatiq/resily#retrypolicy](https://github.com/Diplomatiq/resily#retrypolicy))"
    )
    private BackoffStrategy backoffStrategy;

    @Schema(
        description = "The basis delay of the backoff in ms",
        example = "1000"
    )
    private int delayMs;

    @Schema(
        description = "If `true`, the first retry can be immediate"
    )
    private boolean fastFirst;

    public RetryInformation(int maxRetryCount, BackoffStrategy backoffStrategy, int delayMs,
                            boolean fastFirst) {
        this.maxRetryCount = maxRetryCount;
        this.backoffStrategy = backoffStrategy;
        this.delayMs = delayMs;
        this.fastFirst = fastFirst;
    }

    public int getMaxRetryCount() {
        return maxRetryCount;
    }

    public BackoffStrategy getBackoffStrategy() {
        return backoffStrategy;
    }

    public int getDelayMs() {
        return delayMs;
    }

    public boolean isFastFirst() {
        return fastFirst;
    }
}
