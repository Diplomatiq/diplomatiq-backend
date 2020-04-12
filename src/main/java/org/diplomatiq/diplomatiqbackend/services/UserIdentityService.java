package org.diplomatiq.diplomatiqbackend.services;

import org.diplomatiq.diplomatiqbackend.repositories.UserIdentityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class UserIdentityService {

    @Autowired
    private UserIdentityRepository userIdentityRepository;

}
