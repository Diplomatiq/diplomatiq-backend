package org.diplomatiq.diplomatiqbackend.utils.crypto.convert;

import java.math.BigInteger;

public class BigIntegerToByteArray {
    public static byte[] convert(BigInteger bigInteger) {
        byte[] byteArray = bigInteger.toByteArray();

        if (byteArray[0] == 0) {
            byte[] output = new byte[byteArray.length - 1];
            System.arraycopy(byteArray, 1, output, 0, output.length);
            return output;
        }

        return byteArray;
    }
}
