pub mod tcap {
    use log::debug;
    use tokio::net::{ToSocketAddrs, unix::SocketAddr};
    use std::{net::{SocketAddrV4, Ipv4Addr}, str::FromStr};
    use crate::capabilities::tcap::Capability;
    use bytemuck::*;

    #[repr(C)]
    #[derive(Clone, Copy, Pod, Zeroable, Debug)]
    pub struct IpAddress {
        address: [u8; 4],
        netmask: [u8; 4],
        port: u16
    }

    impl IpAddress {
        pub fn to_socket_addrs(&self) -> SocketAddrV4 {
            SocketAddrV4::new(self.address.into(), self.port)
        }
    }

    impl From<&str> for IpAddress {
        fn from(val: &str) -> Self {
            let mut netmask: Option<Ipv4Addr> = None;
            let mut address: Option<Ipv4Addr> = None;
            let mut port: Option<u16> = None;

            if val.contains(':') {
                //port provided
                let mut s = val.split(':');
                assert!(s.clone().count() == 2, "Ip address:port splitted at ':' must have two elements, address and port number");

                port = Some(String::from(s.clone().last().unwrap()).parse::<u16>().unwrap());
                let addr_mask = cidr::Ipv4Cidr::from_str(s.next().unwrap()).unwrap();
                netmask = Some(addr_mask.mask());
                address = Some(addr_mask.first_address());
            } else {
                port = Some(0);

                let addr_mask = cidr::Ipv4Cidr::from_str(val).unwrap();
                netmask = Some(addr_mask.mask());
                address = Some(addr_mask.first_address());
            }

            let netmask = netmask.unwrap_or(Ipv4Addr::new(0xff, 0xff, 0xff, 0xff)).octets();
            let address = address.unwrap().octets();
            let port = port.unwrap();

            Self { address, netmask, port }
        }
    }

    impl From<std::net::SocketAddr> for IpAddress {
        fn from(val: std::net::SocketAddr) -> Self {
            if ! val.is_ipv4() {
                panic!("only ipv4 addresses supported");
            }
            let address: IpAddress = val.ip().to_string().as_str().into();
            let address = address.address;
            let port = val.port();
            let netmask = [0xff, 0xff, 0xff, 0xff];

            Self { address, netmask, port }
        }
    }

    #[repr(u32)]
    #[derive(Clone, Copy)]
    enum cmd_type {
        Nop= 0,
        CapGetInfo = 1,
        CapIsSame = 2,
        CapDiminish = 3,
        /* Gap in OPCode Numbers Caused by Packet Types Unsupported by this implementation */
        CapClose = 5,
        CapRevoke = 6,
        /* Gap in OPCode Numbers Caused by Packet Types Unsupported by this implementation */
        RequestCreate = 13,
        RequestInvoke = 14,
        /* Gap in OPCode Numbers Caused by Packet Types Unsupported by this implementation */
        RequestReceive = 16,
        /* Gap in OPCode Numbers Caused by Packet Types Unsupported by this implementation */
        None = 32, // None is used as default value
    
        //nighP4 Implementation specific OP Codes
        InsertCap = 64,
        CapDelegate = 65
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    struct CommonHeader {
        cmd: u32,
        cap_id: u64
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct RequestCreateHeader {
        common: CommonHeader,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct  NOPRequestHeader {
        common: CommonHeader,
        info: u64
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone, Pod, Zeroable, Debug)]
    pub struct InsertCapHeader {
        common: CommonHeader,
        cap_owner_ip: IpAddress,
        cap_id: u64,
        object_owner: IpAddress,
    }

    impl InsertCapHeader {
        pub fn construct(cap: &Capability, delegatee: IpAddress, owner: IpAddress) -> InsertCapHeader {
            InsertCapHeader {
                common: CommonHeader { cmd: cmd_type::CapDelegate as u32, cap_id: cap.cap_id },
                cap_owner_ip: delegatee,
                cap_id: cap.cap_id, 
                object_owner: owner
            }
        }
    }

    impl Into<Box<[u8; std::mem::size_of::<InsertCapHeader>()]>> for InsertCapHeader {
        fn into(self) -> Box<[u8; std::mem::size_of::<InsertCapHeader>()]> {
            debug!("transforming {:?} into [u8; {:?}]", self, std::mem::size_of::<InsertCapHeader>());
            let bytes: [u8; std::mem::size_of::<InsertCapHeader>()] = unsafe {
                std::mem::transmute_copy(&self)
            };
            debug!("result: {:?}", bytes);

            Box::new(bytes)
         }
    }

}