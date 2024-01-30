pub mod tcap {
    use crate::{capabilities::tcap::{Capability, CapID}, object::tcap::object::MemoryObject};
    use bytemuck::*;
    use tokio::sync::Mutex;
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        str::FromStr, sync::Arc
    };
    use bitflags::bitflags;

    #[repr(C)]
    #[derive(Clone, Copy, Pod, Zeroable, Debug)]
    pub struct IpAddress {
        pub address: [u8; 4],
        pub netmask: [u8; 4],
        pub port: u16,
    }

    impl IpAddress {
        pub fn to_socket_addrs(&self) -> SocketAddrV4 {
            SocketAddrV4::new(self.address.into(), self.port)
        }
    }

    impl From<&str> for IpAddress {
        fn from(val: &str) -> Self {
            let netmask: Option<Ipv4Addr>;
            let address: Option<Ipv4Addr>;
            let port: Option<u16>;

            if val.contains(':') {
                //port provided
                let mut s = val.split(':');
                assert!(s.clone().count() == 2, "Ip address:port splitted at ':' must have two elements, address and port number {:?}", s);

                port = Some(
                    String::from(s.clone().last().unwrap())
                        .parse::<u16>()
                        .unwrap(),
                );
                let addr_mask = cidr::Ipv4Cidr::from_str(s.next().unwrap()).unwrap();
                netmask = Some(addr_mask.mask());
                address = Some(addr_mask.first_address());
            } else {
                port = Some(0);

                let addr_mask = cidr::Ipv4Cidr::from_str(val).unwrap();
                netmask = Some(addr_mask.mask());
                address = Some(addr_mask.first_address());
            }

            let netmask = netmask
                .unwrap_or(Ipv4Addr::new(0xff, 0xff, 0xff, 0xff))
                .octets();
            let address = address.unwrap().octets();
            let port = port.unwrap();

            Self {
                address,
                netmask,
                port,
            }
        }
    }

    impl From<std::net::SocketAddr> for IpAddress {
        fn from(val: std::net::SocketAddr) -> Self {
            if !val.is_ipv4() {
                panic!("only ipv4 addresses supported");
            }
            let address: IpAddress = val.ip().to_string().as_str().into();
            let address = address.address;
            let port = val.port();
            let netmask = [0xff, 0xff, 0xff, 0xff];

            Self {
                address,
                netmask,
                port,
            }
        }
    }

    impl IpAddress {
        pub fn equals(&self, b: std::net::SocketAddr) -> bool {
            if b.is_ipv6() {
                return false;
            }

            let ip_b = IpAddress::from(b);

            if ip_b.port == self.port && ip_b.address == self.address {
                return true;
            }

            return false;
        }
    }

    impl From<IpAddress> for String {
        fn from(value: IpAddress) -> Self {
            format!(
                "{}.{}.{}.{}:{}",
                value.address[0], value.address[1], value.address[2], value.address[3], value.port
            )
        }
    }

    #[repr(u32)]
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum CmdType {
        Nop = 0,
        CapGetInfo = 1,
        CapIsSame = 2,
        CapDiminish = 3,
        /* Gap in OPCode Numbers Caused by Packet Types Unsupported by this implementation */
        CapClose = 5,
        CapRevoke = 6,
        CapInvalid = 7,
        /* Gap in OPCode Numbers Caused by Packet Types Unsupported by this implementation */
        MemoryCopy = 10,
        MemoryCopyResponse = 11,
        /* Gap in OPCode Numbers Caused by Packet Types Unsupported by this implementation */
        RequestCreate = 13,
        RequestInvoke = 14,
        /* Gap in OPCode Numbers Caused by Packet Types Unsupported by this implementation */
        RequestReceive = 16,
        RequestResponse = 17,
        /* Gap in OPCode Numbers Caused by Packet Types Unsupported by this implementation */
        None = 32, // None is used as default value

        //nighP4 Implementation specific OP Codes
        InsertCap = 64,

        ControllerResetSwitch = 128,
        ControllerStop = 129,
        ControllerStartTimer = 130,
        ControllerStopTimer = 131
    }

    bitflags! {
        #[repr(C, packed)]
        #[derive(Copy, Clone, Debug, PartialEq)]    
        pub struct Flags: u8 {
            const REQUIRE_RESPONSE = 1;
        }
    }

    impl From<u32> for CmdType {
        fn from(value: u32) -> Self {
            match value {
                0 => CmdType::Nop,
                1 => CmdType::CapGetInfo,
                2 => CmdType::CapIsSame,
                3 => CmdType::CapDiminish,
                5 => CmdType::CapClose,
                6 => CmdType::CapRevoke,
                7 => CmdType::CapInvalid,
                10 => CmdType::MemoryCopy,
                11 => CmdType::MemoryCopyResponse,
                13 => CmdType::RequestCreate,
                14 => CmdType::RequestInvoke,
                16 => CmdType::RequestReceive,
                17 => CmdType::RequestResponse,
                32 => CmdType::None,
                64 => CmdType::InsertCap,

                128 => CmdType::ControllerResetSwitch,
                129 => CmdType::ControllerStop,
                130 => CmdType::ControllerStartTimer,
                131 => CmdType::ControllerStopTimer,
                _ => CmdType::None,
            }
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub(crate) struct CommonHeader {
        size: u64,
        pub(crate) stream_id: u32,
        cmd: u32,
        pub(crate) cap_id: CapID,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct RequestCreateHeader {
        common: CommonHeader,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub struct NOPRequestHeader {
        common: CommonHeader,
        info: u64,
    }

    impl NOPRequestHeader {
        pub fn _construct(cap: Capability, info: u64) -> NOPRequestHeader {
            let mut rng = rand::thread_rng();
            let stream_id = rand::Rng::gen::<u32>(&mut rng);
            NOPRequestHeader {
                common: CommonHeader {
                    size: 0,
                    cmd: CmdType::Nop as u32,
                    stream_id,
                    cap_id: cap.cap_id,
                },
                info,
            }
        }
    }

    impl Into<Box<[u8; std::mem::size_of::<NOPRequestHeader>()]>> for NOPRequestHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<NOPRequestHeader>()]> {
            let bytes: [u8; std::mem::size_of::<NOPRequestHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub struct RequestInvokeHeader {
        pub(crate) common: CommonHeader,
        pub(crate) number_of_conts: u8,
        pub(crate) continutaion_cap_ids: [CapID;4],
        pub(crate) flags: u8
    }

    impl Into<Box<[u8; std::mem::size_of::<RequestInvokeHeader>()]>> for RequestInvokeHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<RequestInvokeHeader>()]> {
            let bytes: [u8; std::mem::size_of::<RequestInvokeHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }

    impl RequestInvokeHeader {
        pub(crate) fn construct(cap: Capability, number_of_conts: u8, continutaion_cap_ids: [CapID; 4], flags: Flags) -> RequestInvokeHeader {
            let mut rng = rand::thread_rng();
            let stream_id = rand::Rng::gen::<u32>(&mut rng);

            RequestInvokeHeader {
                common: CommonHeader {
                    size: std::mem::size_of::<RequestInvokeHeader>()
                        .try_into()
                        .unwrap(),
                    stream_id,
                    cmd: CmdType::RequestInvoke as u32,
                    cap_id: cap.cap_id
                },
                number_of_conts,
                continutaion_cap_ids,
                flags: flags.bits()
            }
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub(crate) struct CapInvalidHeader {
        common: CommonHeader,
        address: [u8; 4],
        port: u16,
        cap_id: CapID
    }

    impl Into<Box<[u8; std::mem::size_of::<CapInvalidHeader>()]>> for CapInvalidHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<CapInvalidHeader>()]> {
            let bytes: [u8; std::mem::size_of::<CapInvalidHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }

    impl From<Vec<u8>> for CapInvalidHeader {
        fn from(value: Vec<u8>) -> Self {
            *bytemuck::from_bytes(&value)
        }
    }

    impl CapInvalidHeader {
        pub fn construct(cap_id: CapID, address: IpAddress, stream_id: u32) -> CapInvalidHeader {
            CapInvalidHeader {
                common: CommonHeader {
                    size: 0,
                    cmd: CmdType::CapInvalid as u32,
                    stream_id,
                    cap_id: cap_id,
                },
                address: address.address,
                port: address.port,
                cap_id
            }
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub(crate) struct RequestResponseHeader {
        pub(crate) common: CommonHeader,
        pub(crate) response_code: u64,
    }

    impl RequestResponseHeader {
        pub(crate) async fn construct(
            cap_id: CapID,
            stream_id: u32,
            response_code: u64,
        ) -> RequestResponseHeader {
            RequestResponseHeader {
                common: CommonHeader {
                    size: 0,
                    stream_id,
                    cmd: CmdType::RequestResponse as u32,
                    cap_id,
                },
                response_code,
            }
        }
    }

    impl Into<Box<[u8; std::mem::size_of::<RequestResponseHeader>()]>> for RequestResponseHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<RequestResponseHeader>()]> {
            let bytes: [u8; std::mem::size_of::<RequestResponseHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }

    impl From<Vec<u8>> for RequestResponseHeader {
        fn from(value: Vec<u8>) -> Self {
            assert!(
                value.len() >= std::mem::size_of::<Self>(),
                "Vector of len {:?} not large enough to unmarshal ResponseHeader req len {:?}",
                value.len(),
                std::mem::size_of::<Self>()
            );
            *bytemuck::from_bytes(&value)
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub struct InsertCapHeader {
        pub(crate) common: CommonHeader,
        pub(crate) cap_owner_ip: [u8;4],
        pub(crate) cap_owner_port: u16,
        pub(crate) cap_id: CapID,
        pub(crate) cap_type: u8,
        pub(crate) object_owner_ip_address: [u8; 4],
        pub(crate) object_owner_port: u16,
    }

    impl InsertCapHeader {
        pub fn construct(
            cap: &Capability,
            delegatee: IpAddress,
            owner: IpAddress,
        ) -> InsertCapHeader {
            let mut rng = rand::thread_rng();
            let stream_id = rand::Rng::gen::<u32>(&mut rng);
            InsertCapHeader {
                common: CommonHeader {
                    size: 0,
                    cmd: CmdType::InsertCap as u32,
                    stream_id,
                    cap_id: cap.cap_id,
                },
                cap_owner_ip: delegatee.address,
                cap_owner_port: delegatee.port,
                cap_id: cap.cap_id,
                cap_type: cap.cap_type.into(),
                object_owner_ip_address: owner.address,
                object_owner_port: owner.port
            }
        }
    }

    impl Into<Box<[u8; std::mem::size_of::<InsertCapHeader>()]>> for InsertCapHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<InsertCapHeader>()]> {
            let bytes: [u8; std::mem::size_of::<InsertCapHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }

    impl From<Vec<u8>> for InsertCapHeader {
        fn from(value: Vec<u8>) -> Self {
            *bytemuck::from_bytes(&value)
        }
    }

    impl From<Vec<u8>> for RevokeCapHeader {
        fn from(value: Vec<u8>) -> Self {
            *bytemuck::from_bytes(&value)
        }
    }

    impl From<Vec<u8>> for RequestInvokeHeader {
        fn from(value: Vec<u8>) -> Self {
            *bytemuck::from_bytes(&value)
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub(crate) struct RevokeCapHeader {
        common: CommonHeader,
        pub cap_owner_ip: IpAddress,
        pub cap_id: CapID,
    }

    impl RevokeCapHeader {
        pub fn construct(cap: &Capability, owner: IpAddress) -> RevokeCapHeader {
            let mut rng = rand::thread_rng();
            let stream_id = rand::Rng::gen::<u32>(&mut rng);

            RevokeCapHeader {
                common: CommonHeader {
                    size: 0,
                    cmd: CmdType::CapRevoke as u32,
                    stream_id,
                    cap_id: cap.cap_id,
                },
                cap_id: cap.cap_id,
                cap_owner_ip: owner,
            }
        }
    }

    impl Into<Box<[u8; std::mem::size_of::<RevokeCapHeader>()]>> for RevokeCapHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<RevokeCapHeader>()]> {
            let bytes: [u8; std::mem::size_of::<RevokeCapHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub(crate) struct ControllerStartTimerHeader {
        pub(crate) common: CommonHeader
    }

    impl Into<Box<[u8; std::mem::size_of::<ControllerStartTimerHeader>()]>> for ControllerStartTimerHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<ControllerStartTimerHeader>()]> {
            let bytes: [u8; std::mem::size_of::<ControllerStartTimerHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }

    impl ControllerStartTimerHeader {
        pub fn construct() -> ControllerStartTimerHeader {
            let mut rng = rand::thread_rng();
            let stream_id = rand::Rng::gen::<u32>(&mut rng);

            ControllerStartTimerHeader {
                common: CommonHeader {
                    size: 0,
                    cmd: CmdType::ControllerStartTimer as u32,
                    stream_id,
                    cap_id: 0,
                }
            }
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub(crate) struct ControllerStopTimerHeader {
        pub(crate) common: CommonHeader
    }

    impl Into<Box<[u8; std::mem::size_of::<ControllerStopTimerHeader>()]>> for ControllerStopTimerHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<ControllerStopTimerHeader>()]> {
            let bytes: [u8; std::mem::size_of::<ControllerStopTimerHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }

    impl ControllerStopTimerHeader {
        pub fn construct() -> ControllerStopTimerHeader {
            let mut rng = rand::thread_rng();
            let stream_id = rand::Rng::gen::<u32>(&mut rng);

            ControllerStopTimerHeader {
                common: CommonHeader {
                    size: 0,
                    cmd: CmdType::ControllerStopTimer as u32,
                    stream_id,
                    cap_id: 0,
                }
            }
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub(crate) struct ControllerResetSwitchHeader {
        pub(crate) common: CommonHeader
    }

    impl Into<Box<[u8; std::mem::size_of::<ControllerResetSwitchHeader>()]>> for ControllerResetSwitchHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<ControllerResetSwitchHeader>()]> {
            let bytes: [u8; std::mem::size_of::<ControllerResetSwitchHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }
    impl ControllerResetSwitchHeader {
        pub fn construct() -> ControllerResetSwitchHeader {
            let mut rng = rand::thread_rng();
            let stream_id = rand::Rng::gen::<u32>(&mut rng);

            ControllerResetSwitchHeader {
                common: CommonHeader {
                    size: 0,
                    cmd: CmdType::ControllerResetSwitch as u32,
                    stream_id,
                    cap_id: 0,
                }
            }
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub(crate) struct ControllerStopHeader {
        pub(crate) common: CommonHeader
    }

    impl From<Vec<u8>> for ControllerStopHeader {
        fn from(value: Vec<u8>) -> Self {
            *bytemuck::from_bytes(&value)
        }
    }

    impl Into<Box<[u8; std::mem::size_of::<ControllerStopHeader>()]>> for ControllerStopHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<ControllerStopHeader>()]> {
            let bytes: [u8; std::mem::size_of::<ControllerStopHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }
    impl ControllerStopHeader {
        pub fn construct() -> ControllerStopHeader {
            let mut rng = rand::thread_rng();
            let stream_id = rand::Rng::gen::<u32>(&mut rng);

            ControllerStopHeader {
                common: CommonHeader {
                    size: 0,
                    cmd: CmdType::ControllerStop as u32,
                    stream_id,
                    cap_id: 0,
                }
            }
        }
    }

    // Memory Copy

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub(crate) struct MemoryCopyRequestHeader {
        pub(crate) common: CommonHeader
    }


    impl From<Vec<u8>> for MemoryCopyRequestHeader {
        fn from(value: Vec<u8>) -> Self {
            *bytemuck::from_bytes(&value)
        }
    }

    
    impl Into<Box<[u8; std::mem::size_of::<MemoryCopyRequestHeader>()]>> for MemoryCopyRequestHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<MemoryCopyRequestHeader>()]> {
            let bytes: [u8; std::mem::size_of::<MemoryCopyRequestHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }
    impl MemoryCopyRequestHeader {
        pub fn construct(cap_id: CapID) -> MemoryCopyRequestHeader {
            let mut rng = rand::thread_rng();
            let stream_id = rand::Rng::gen::<u32>(&mut rng);

            MemoryCopyRequestHeader {
                common: CommonHeader {
                    size: 0,
                    cmd: CmdType::MemoryCopy as u32,
                    stream_id,
                    cap_id: cap_id,
                }
            }
        }
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub(crate) struct MemoryCopyResponseHeader {
        pub(crate) common: CommonHeader,
        pub(crate) size: u64,
        pub(crate) buffer: [u8;1024]
    }

    impl From<Vec<u8>> for MemoryCopyResponseHeader {
        fn from(value: Vec<u8>) -> Self {
            *bytemuck::from_bytes(&value)
        }
    }

    impl Into<Box<[u8; std::mem::size_of::<MemoryCopyResponseHeader>()]>> for MemoryCopyResponseHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<MemoryCopyResponseHeader>()]> {
            let bytes: [u8; std::mem::size_of::<MemoryCopyResponseHeader>()] =
                unsafe { std::mem::transmute_copy(&self) };
            Box::new(bytes)
        }
    }
    impl MemoryCopyResponseHeader {
        pub(crate) async fn construct(obj: Arc<Mutex<MemoryObject>>) -> MemoryCopyResponseHeader {
            let size = obj.lock().await.size.clone();
            let buffer = obj.lock().await.data.clone();

            let mut rng = rand::thread_rng();
            let stream_id = rand::Rng::gen::<u32>(&mut rng);

            MemoryCopyResponseHeader {
                common: CommonHeader {
                    size: 0,
                    cmd: CmdType::MemoryCopyResponse as u32,
                    stream_id,
                    cap_id: 0,
                },
               size, buffer
            }
        }
    }

    mod tests {
        #[allow(unused_imports)] // Not sure, why the import is detected as unused.
        use crate::packet_types::tcap::IpAddress;

        #[test]
        fn test_create_ip_addr_object_from_string() {
            let obj = IpAddress::from("10.0.0.1:1234");
            assert!(obj.port == 1234);
            assert!(obj.address == [10, 0, 0, 1]);
            assert!(obj.netmask == [255, 255, 255, 255]); // default value for netmask
        }

        #[test]
        fn test_create_ip_addr_object_with_netmask() {
            let obj = IpAddress::from("10.0.0.1/24:1012");
            assert!(obj.port == 0);
            assert!(obj.address == [10, 0, 0, 1]);
            assert!(obj.netmask == [255, 255, 255, 0]);
        }
    }
}
