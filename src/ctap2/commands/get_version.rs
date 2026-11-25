/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use super::{CommandError, CtapResponse, RequestCtap1, Retryable};
use crate::consts::U2F_VERSION;
use crate::transport::errors::{ApduErrorStatus, HIDError};
use crate::transport::{FidoDevice, VirtualFidoDevice};
use crate::u2ftypes::CTAP1RequestAPDU;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum U2FInfo {
    U2F_V2,
}

impl CtapResponse for U2FInfo {}

#[derive(Debug, Default)]
// TODO(baloo): if one does not issue U2F_VERSION before makecredentials or getassertion, token
//              will return error (ConditionsNotSatified), test this in unit tests
pub struct GetVersion {}

impl RequestCtap1 for GetVersion {
    type Output = U2FInfo;
    type AdditionalInfo = ();

    fn handle_response_ctap1<Dev: FidoDevice>(
        &self,
        _dev: &mut Dev,
        _status: Result<(), ApduErrorStatus>,
        input: &[u8],
        _add_info: &(),
    ) -> Result<Self::Output, Retryable<HIDError>> {
        if input.is_empty() {
            return Err(Retryable::Error(HIDError::Command(
                CommandError::InputTooSmall,
            )));
        }

        let expected = String::from("U2F_V2");
        let result = String::from_utf8_lossy(input);
        match result {
            ref data if data == &expected => Ok(U2FInfo::U2F_V2),
            _ => Err(Retryable::Error(HIDError::UnexpectedVersion)),
        }
    }

    fn ctap1_format(&self) -> Result<(Vec<u8>, ()), HIDError> {
        let flags = 0;

        let cmd = U2F_VERSION;
        let data = CTAP1RequestAPDU::serialize(cmd, flags, &[])?;
        Ok((data, ()))
    }

    fn send_to_virtual_device<Dev: VirtualFidoDevice>(
        &self,
        dev: &mut Dev,
    ) -> Result<Self::Output, HIDError> {
        dev.get_version(self)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::consts::{Capability, HIDCmd};
    use crate::transport::device_selector::Device;
    use crate::transport::{hid::HIDDevice, FidoDevice, FidoProtocol};
    use crate::CtapVersionSupport;

    /// Add a CTAP1 GetVersion request / response to the device.
    fn add_ctap1_getversion(device: &mut Device, cid: &[u8; 4]) {
        let mut msg = cid.to_vec();
        msg.extend([HIDCmd::Msg.into(), 0x00, 0x7]); // cmd + bcnt
        msg.extend([0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0]); // U2F_VERSION, extended
        device.add_write(&msg, 0);

        let mut msg = cid.to_vec();
        msg.extend(vec![HIDCmd::Msg.into(), 0x00, 0x8]); // cmd + bcnt
        msg.extend(b"U2F_V2");
        msg.extend([0x0, 0x0]); // success
        device.add_read(&msg, 0);
    }

    /// Add a CTAP1 GetVersion request / error response to the device.
    fn add_ctap1_getversion_error(device: &mut Device, cid: &[u8; 4]) {
        let mut msg = cid.to_vec();
        msg.extend([HIDCmd::Msg.into(), 0x00, 0x7]); // cmd + bcnt
        msg.extend([0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0]); // U2F_VERSION, extended
        device.add_write(&msg, 0);

        let mut msg = cid.to_vec();
        msg.extend([HIDCmd::Error.into(), 0x00, 0x1]); // cmd + bcnt
        msg.push(0x01); // ERR_INVALID_CMD
        device.add_read(&msg, 0);
    }

    /// Add a CTAP2 GetInfo request / error response to the device.
    fn add_ctap2_getinfo_error(device: &mut Device, cid: &[u8; 4]) {
        let mut msg = cid.to_vec();
        msg.extend([HIDCmd::Cbor.into(), 0x00, 0x1]); // cmd + bcnt
        msg.push(0x04); // authenticatorGetInfo
        device.add_write(&msg, 0);

        // Response based on MitID:
        // https://bugzilla.mozilla.org/show_bug.cgi?id=2093140#c20
        let mut msg = cid.to_vec();
        msg.extend([HIDCmd::Error.into(), 0x00, 0x3]); // cmd + bcnt
        msg.extend([0x7f, 0x6d, 0x0]); // ERR_UNKNOWN, ISO 7816-4: "Instruction code not supported or invalid"
        device.add_read(&msg, 0);
    }

    #[test]
    fn test_get_version_ctap1_only() {
        let mut device = Device::new_pre_inited("commands/get_version", Capability::WINK);
        let cid = *device.get_cid();
        add_ctap1_getversion(&mut device, &cid);

        device.init().expect("Failed to init device");

        device.downgrade_to_ctap1().expect("failed to downgrade");
        assert_eq!(device.get_protocol(), FidoProtocol::CTAP1);
        assert!(device.supports_ctap1());
        assert!(!device.supports_ctap2());
        assert!(
            !device.get_ctap2_failed(),
            "should not have attempted to use CTAP2"
        );

        let dev_info = device.get_device_info().expect("device info is set");
        assert_eq!(dev_info.cap_flags, Capability::WINK);

        let result = device.get_authenticator_info();
        assert!(result.is_none());
    }

    /// Test that we can fall back to using CTAP1 on authenticators that fail to respond to CTAP2
    /// commands, even when `CBOR | NMSG` is set.
    ///
    /// eg: MitID chip only supports CTAP1, but reports `capabilities: 0xf`:
    /// <https://bugzilla.mozilla.org/show_bug.cgi?id=2093140>.
    #[test]
    fn test_get_version_mitid_ctap1_fallback() {
        let mut device = Device::new_pre_inited_capabilities("commands/get_version", 0xf);
        let cid = *device.get_cid();

        // We should expect to make a CTAP2 GetInfo request, followed by a CTAP1 GetVersion request.
        add_ctap2_getinfo_error(&mut device, &cid);
        add_ctap1_getversion(&mut device, &cid);

        device.init().expect("Failed to init device");

        // We should now be operating in CTAP1 mode, even though the capabilities suggest otherwise.
        assert_eq!(device.get_protocol(), FidoProtocol::CTAP1);
        assert!(device.supports_ctap1());
        assert!(!device.supports_ctap2());
        assert!(device.get_ctap2_failed());

        let dev_info = device.get_device_info().expect("device info is set");
        // We should accurately retain the capabilities flags, even when they are lies.
        assert_eq!(
            dev_info.cap_flags,
            Capability::WINK | Capability::LOCK | Capability::CBOR | Capability::NMSG
        );

        let result = device.get_authenticator_info();
        assert!(result.is_none());
    }

    /// Test that we can fall back to using CTAP1 on authenticators that fail to respond to CTAP2
    /// commands, even when `CBOR` is set.
    #[test]
    fn test_get_version_cbor_ctap1_fallback() {
        let mut device = Device::new_pre_inited_capabilities("commands/get_version", 0x7);
        let cid = *device.get_cid();

        // We should expect to make a CTAP2 GetInfo request, followed by a CTAP1 GetVersion request.
        add_ctap2_getinfo_error(&mut device, &cid);
        add_ctap1_getversion(&mut device, &cid);

        device.init().expect("Failed to init device");

        // We should now be operating in CTAP1 mode, even though the capabilities suggest otherwise.
        assert_eq!(device.get_protocol(), FidoProtocol::CTAP1);
        assert!(device.supports_ctap1());
        assert!(!device.supports_ctap2());
        assert!(device.get_ctap2_failed());

        let dev_info = device.get_device_info().expect("device info is set");
        // We should accurately retain the capabilities flags, even when they are lies.
        assert_eq!(
            dev_info.cap_flags,
            Capability::WINK | Capability::LOCK | Capability::CBOR
        );

        let result = device.get_authenticator_info();
        assert!(result.is_none());
    }

    /// Test that we only use CTAP1 on authenticators that set `NMSG` without `CBOR`.
    #[test]
    fn test_get_version_nmsg_ctap1_fallback() {
        let mut device = Device::new_pre_inited_capabilities("commands/get_version", 0xb);
        let cid = *device.get_cid();

        // We should expect a CTAP1 GetVersion request, even though the device set NMSG.
        add_ctap1_getversion(&mut device, &cid);

        device.init().expect("Failed to init device");

        // We should now be operating in CTAP1 mode, even though the capabilities suggest otherwise.
        assert_eq!(device.get_protocol(), FidoProtocol::CTAP1);
        assert!(device.supports_ctap1());
        assert!(!device.supports_ctap2());
        assert!(
            !device.get_ctap2_failed(),
            "should not have attempted to use CTAP2"
        );

        let dev_info = device.get_device_info().expect("device info is set");
        // We should accurately retain the capabilities flags, even when they are lies.
        assert_eq!(
            dev_info.cap_flags,
            Capability::WINK | Capability::LOCK | Capability::NMSG
        );

        let result = device.get_authenticator_info();
        assert!(result.is_none());
    }

    /// `init` should try to use `GetVersion` and fail when when `CBOR` is set and the authenticator
    /// returns an error.
    #[test]
    fn test_error_ctap1() {
        for capabilities in [0x1, 0x3, 0xb] {
            let mut device =
                Device::new_pre_inited_capabilities("commands/get_version", capabilities);
            let cid = *device.get_cid();

            // We should expect a CTAP1 GetVersion request, but it should error out.
            add_ctap1_getversion_error(&mut device, &cid);

            device
                .init()
                .expect_err("Should have failed to init device");
            let dev_info = device.get_device_info().expect("device info is set");
            assert_eq!(dev_info.cap_flags.bits(), capabilities);

            let result = device.get_authenticator_info();
            assert!(result.is_none());
        }
    }

    /// `init` should try to use `GetInfo` and `GetVersion` and fail when `CBOR` is set and the
    /// authenticator returns errors.
    #[test]
    fn test_error_ctap2() {
        for capabilities in [0x5, 0x7, 0xd, 0xf] {
            let mut device =
                Device::new_pre_inited_capabilities("commands/get_version", capabilities);
            let cid = *device.get_cid();

            // We should expect a CTAP2 GetInfo and a CTAP1 GetVersion request, but it should error out.
            add_ctap2_getinfo_error(&mut device, &cid);
            add_ctap1_getversion_error(&mut device, &cid);

            device
                .init()
                .expect_err("Should have failed to init device");
            let dev_info = device.get_device_info().expect("device info is set");
            assert_eq!(dev_info.cap_flags.bits(), capabilities);

            let result = device.get_authenticator_info();
            assert!(result.is_none());
        }
    }
}
