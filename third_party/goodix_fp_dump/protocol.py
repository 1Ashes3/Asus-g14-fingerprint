import abc
import struct
import time

import usb


class Protocol(abc.ABC):

    @abc.abstractmethod
    def __init__(self, vendor: int, product: int, timeout: float | None = 5):
        ...

    @abc.abstractmethod
    def write(self, data: bytes, timeout: float | None = 5):
        ...

    @abc.abstractmethod
    def read(self, size: int = 0x4000, timeout: float | None = 5) -> bytes:
        ...

    @abc.abstractmethod
    def disconnect(self, timeout: float | None = 5):
        ...


class USBProtocol(Protocol):

    def __init__(self, vendor, product, timeout=5):
        super().__init__(vendor, product, timeout)

        if timeout is not None:
            timeout += time.time()

        while True:
            device = usb.core.find(idVendor=vendor, idProduct=product)

            if device is not None:
                try:
                    usb.control.get_status(device)
                    break

                except usb.core.USBError as error:
                    if (error.backend_error_code != -1
                            and error.backend_error_code != -4):
                        raise error

            if timeout is not None and time.time() > timeout:
                if device is None:
                    raise TimeoutError("Device not found", -5, 19)

                raise TimeoutError("Invalid device state", -12, 131)

            time.sleep(0.01)

        self.device: usb.core.Device = device

        print(f"Found Goodix device: \"{self.device.product}\" "
              f"from \"{self.device.manufacturer}\" "
              f"on bus {self.device.bus} "
              f"address {self.device.address}.")

        interface_data = usb.util.find_descriptor(
            self.device.get_active_configuration(),
            custom_match=lambda interface: interface.bInterfaceClass == usb.
            legacy.CLASS_DATA or interface.bInterfaceClass == usb.legacy.
            CLASS_VENDOR_SPEC)

        if interface_data is None:
            raise ConnectionError("Interface data not found", -5, 6)

        print(f"Found interface data: {interface_data.bInterfaceNumber}")

        endpoint_in = usb.util.find_descriptor(
            interface_data,
            custom_match=lambda endpoint: usb.util.endpoint_direction(
                endpoint.bEndpointAddress) == usb.legacy.ENDPOINT_IN and usb.
            util.endpoint_type(endpoint.bmAttributes
                               ) == usb.legacy.ENDPOINT_TYPE_BULK)

        if endpoint_in is None:
            raise ConnectionError("Endpoint in not found", -5, 6)

        self.endpoint_in: int = endpoint_in.bEndpointAddress
        print(f"Found endpoint in: {hex(self.endpoint_in)}")

        endpoint_out = usb.util.find_descriptor(
            interface_data,
            custom_match=lambda endpoint: usb.util.endpoint_direction(
                endpoint.bEndpointAddress) == usb.legacy.ENDPOINT_OUT and usb.
            util.endpoint_type(endpoint.bmAttributes
                               ) == usb.legacy.ENDPOINT_TYPE_BULK)

        if endpoint_out is None:
            raise ConnectionError("Endpoint out not found", -5, 6)

        self.endpoint_out: int = endpoint_out.bEndpointAddress
        print(f"Found endpoint out: {hex(self.endpoint_out)}")

        if self.device.is_kernel_driver_active(
                interface_data.bInterfaceNumber):
            self.device.detach_kernel_driver(interface_data.bInterfaceNumber)

        self.device.set_configuration()

    def write(self, data, timeout=5):
        timeout = 0 if timeout is None else round(timeout * 1000)

        length = len(data)
        if length % 0x40:
            data += b"\x00" * (0x40 - length % 0x40)

        for i in range(0, length, 0x40):
            self.device.write(self.endpoint_out, data[i:i + 0x40], timeout)

    def read(self, size=0x10000, timeout=5):
        timeout = 0 if timeout is None else round(timeout * 1000)

        data: bytes = self.device.read(self.endpoint_in, size,
                                       timeout).tobytes()
        return data

    def disconnect(self, timeout=5):

        if timeout is not None:
            timeout += time.time()

        while True:
            try:
                usb.control.get_status(self.device)

            except usb.core.USBError as error:
                if (error.backend_error_code == -1
                        or error.backend_error_code == -4):
                    break

                raise error

            if timeout is not None and time.time() > timeout:
                raise TimeoutError("Device is still connected", -7, 110)

            time.sleep(0.01)
