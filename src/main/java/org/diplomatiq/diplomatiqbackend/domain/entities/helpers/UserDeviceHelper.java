package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserDevice;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.DeviceContainerKeyGenerator;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.DeviceKeyGenerator;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.SessionTokenGenerator;
import org.springframework.stereotype.Component;

@Component
public class UserDeviceHelper {
    public UserDevice createUserDevice() {
        UserDevice userDevice = new UserDevice();

        userDevice.setDeviceKey(DeviceKeyGenerator.generate());
        userDevice.setDeviceContainerKey(DeviceContainerKeyGenerator.generate());
        userDevice.setSessionToken(SessionTokenGenerator.generate());

        return userDevice;
    }
}
