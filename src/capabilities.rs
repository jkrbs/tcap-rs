pub mod tcap {
    use std::string;

    use log::*;
    use rand::Rng;
    use tokio::net::UdpSocket;

    use crate::{
        packet_types::tcap::{InsertCapHeader, IpAddress, RevokeCapHeader},
        service::tcap::{SendRequest, Service},
        Config,
    };

    #[derive(Clone, Copy, Debug)]
    pub struct Capability {
        pub cap_id: u64,
    }

    impl Capability {
        pub async fn create() -> Capability {
            let mut rng = rand::thread_rng();
            let cap_id = rng.gen::<u64>();
            Capability { cap_id }
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
            s.send(SendRequest { dest, data: packet }).await;
            Ok(())
        }

        pub(crate) async fn revoke(&self, s: Service) -> tokio::io::Result<()> {
            /*   debug!("opening udp socket to {:?}", conf.switch_addr);
            debug!("socket addr pass to bind: {:?}", conf.switch_addr.as_str());
            let socket = match UdpSocket::bind(conf.address.clone()).await {
                Ok(socket) => socket,
                Err(e) => {
                    error!("Error while opening listener socket {:?}", e);
                    panic!("Exiting...")
                }
            }; */
            let address = s.config.address.clone();
            let packet: Box<[u8; std::mem::size_of::<RevokeCapHeader>()]> =
                RevokeCapHeader::construct(self, address.as_str().into()).into();

            debug!("packet to be send: {:?}", packet);

            s.send(SendRequest {
                dest: s.config.switch_addr.clone(),
                data: packet,
            })
            .await;
            Ok(())
        }
    }
}
