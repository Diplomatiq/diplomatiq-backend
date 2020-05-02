package org.diplomatiq.diplomatiqbackend.domain.entities.helpers;

import org.diplomatiq.diplomatiqbackend.domain.entities.concretes.UserDevice;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.DeviceContainerKeyGenerator;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.DeviceKeyGenerator;
import org.diplomatiq.diplomatiqbackend.utils.crypto.random.SessionTokenGenerator;

public class UserDeviceHelper {
    public static UserDevice create() {
        UserDevice userDevice = new UserDevice();

        userDevice.setDeviceKey(DeviceKeyGenerator.generate());
        userDevice.setDeviceContainerKey(DeviceContainerKeyGenerator.generate());
        userDevice.setSessionToken(SessionTokenGenerator.generate());

        return userDevice;
    }
}
