pub mod tcap {
    use rand::Rng;
    use tokio::net::UdpSocket;
    use log::*;

    use crate::packet_types::tcap::{IpAddress, InsertCapHeader};

    #[derive(Clone, Copy, Debug)]
    pub struct Capability {
        pub cap_id: u64
    }

    impl Capability {
        pub async fn create() -> Capability {
            let mut rng = rand::thread_rng();
            let cap_id = rng.gen::<u64>();
            Capability {
                cap_id
            }
        }

        pub async fn delegate(&self, delegatee: IpAddress) -> Result<(), tokio::io::Error> {
            debug!("opening udp socket to {:?}", delegatee);
            debug!("socket addr pass to bind: {:?}", delegatee.to_socket_addrs());
            let socket = UdpSocket::bind("0.0.0.0:1234").await.unwrap();
            socket.connect(delegatee.to_socket_addrs()).await?;
            debug!("connected");
            let packet: Box<[u8; std::mem::size_of::<InsertCapHeader>()]>= InsertCapHeader::construct(&self, delegatee, 
                IpAddress::from(socket.local_addr().unwrap())).into();

            debug!("packet to be send: {:?}", packet);

            let sent_bytes = socket.send(packet.as_ref()).await.unwrap();
            debug!("sent {:?} bytes over udp socket", sent_bytes);
            Ok(())
        }
    }
}