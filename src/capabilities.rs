pub mod tcap {
    use crate::{
        packet_types::tcap::{InsertCapHeader, IpAddress, RevokeCapHeader},
        service::tcap::{SendRequest, Service},
        Config,
    };
    use log::*;
    use rand::Rng;

    #[repr(u8)]
    #[derive(Clone, Copy, Debug)]
    pub enum CapType {
        None = 0,
        Request = 1,
        Memory = 2,
    }

    impl From<u8> for CapType {
        fn from(value: u8) -> Self {
            match value {
                0 => Self::None,
                1 => Self::Request,
                2 => Self::Memory,
                _ => Self::None,
            }
        }
    }
    impl Into<u8> for CapType {
        fn into(self) -> u8 {
            match self {
                CapType::None => 0,
                CapType::Request => 1,
                CapType::Memory => 2,
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Capability {
        pub cap_id: u64,
        pub cap_type: CapType,
    }

    impl From<InsertCapHeader> for Capability {
        fn from(value: InsertCapHeader) -> Self {
            Capability {
                cap_id: value.cap_id,
                cap_type: CapType::from(value.cap_type),
            }
        }
    }

    impl Capability {
        pub async fn create() -> Capability {
            let mut rng = rand::thread_rng();
            let cap_id = rng.gen::<u64>();
            Capability {
                cap_id,
                cap_type: CapType::None,
            }
        }

        pub(crate) async fn delegate(
            &self,
            s: Service,
            delegatee: IpAddress,
        ) -> Result<(), tokio::io::Error> {
            let address = s.config.address.clone();
            let packet: Box<[u8; std::mem::size_of::<InsertCapHeader>()]> =
                InsertCapHeader::construct(&self, delegatee, IpAddress::from(address.as_str()))
                    .into();
            debug!("packet to be send: {:?}", packet);

            let dest: String = delegatee.into();
            let _ = s.send(SendRequest::new(dest, packet), false).await;
            Ok(())
        }

        pub(crate) async fn revoke(&self, s: Service) -> tokio::io::Result<()> {
            let address = s.config.address.clone();
            let packet: Box<[u8; std::mem::size_of::<RevokeCapHeader>()]> =
                RevokeCapHeader::construct(self, address.as_str().into()).into();

            debug!("packet to be send: {:?}", packet);

            let resp = s
                .send(
                    SendRequest::new(s.config.switch_addr.clone(), packet),
                    false,
                )
                .await;

            Ok(())
        }
    }
}
