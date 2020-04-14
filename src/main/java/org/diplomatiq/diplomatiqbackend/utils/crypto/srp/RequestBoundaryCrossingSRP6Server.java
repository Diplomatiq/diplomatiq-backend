package org.diplomatiq.diplomatiqbackend.utils.crypto.srp;

import org.bouncycastle.crypto.agreement.srp.SRP6Server;

import java.math.BigInteger;

public class RequestBoundaryCrossingSRP6Server extends SRP6Server {
    public void setB(BigInteger B) {
        this.B = B;
    }
}
