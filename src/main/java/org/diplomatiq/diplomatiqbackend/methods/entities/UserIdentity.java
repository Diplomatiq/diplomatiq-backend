package org.diplomatiq.diplomatiqbackend.methods.entities;

public class UserIdentity {
    private final String id;
    private final String emailAddress;

    public UserIdentity(String id, String emailAddress) {
        this.id = id;
        this.emailAddress = emailAddress;
    }

    public String getId() {
        return id;
    }

    public String getEmailAddress() {
        return emailAddress;
    }
}
