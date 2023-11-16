pub mod tcap {
    use std::sync::{Arc, Once};

    use crate::{
        object::tcap::object::RequestObject,
        packet_types::tcap::{
            InsertCapHeader, IpAddress, RequestInvokeHeader, RequestResponseHeader, RevokeCapHeader,
        },
        service::tcap::{SendRequest, Service},
    };
    use log::*;
    use rand::Rng;
    use tokio::sync::Mutex;

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

    #[derive(Clone, Debug)]
    pub struct Capability {
        pub cap_id: u64,
        pub cap_type: CapType,
        owner_address: IpAddress,
        delegatees: Arc<Mutex<Vec<IpAddress>>>,
        object: Option<Arc<Mutex<RequestObject>>>,
    }

    impl From<InsertCapHeader> for Capability {
        fn from(value: InsertCapHeader) -> Self {
            Capability {
                cap_id: value.cap_id,
                cap_type: CapType::from(value.cap_type),
                owner_address: value.object_owner,
                delegatees: Arc::new(Mutex::new(Vec::new())),
                object: None,
            }
        }
    }

    impl Capability {
        pub async fn create(owner_address: IpAddress) -> Capability {
            let mut rng = rand::thread_rng();
            let cap_id = rng.gen::<u64>();
            Capability {
                cap_id,
                cap_type: CapType::None,
                owner_address,
                delegatees: Arc::new(Mutex::new(Vec::new())),
                object: None,
            }
        }

        pub(crate) async fn bind(&mut self, obj: Arc<Mutex<RequestObject>>) {
            self.object = Some(obj);
            self.object
                .as_ref()
                .unwrap()
                .lock()
                .await
                .set_cap(self.clone());
            info!("Binding obj {:?} to cap {:?}", self.object, self.cap_id);
        }

        pub(crate) async fn delegate(
            &self,
            s: Service,
            delegatee: IpAddress,
        ) -> Result<(), tokio::io::Error> {
            self.delegatees.lock().await.push(delegatee);

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

            for delegatee in self.delegatees.lock().await.clone() {
                let _ = s
                    .send(SendRequest::new(delegatee.into(), packet.clone()), false)
                    .await;
            }

            Ok(())
        }

        pub(crate) async fn request_invoke(&self, s: Service) -> Result<(), ()> {
            let packet: Box<[u8; std::mem::size_of::<RequestInvokeHeader>()]> =
                RequestInvokeHeader::construct(self.clone()).into();

            let resp = s
                .send(SendRequest::new(self.owner_address.into(), packet), true)
                .await;

            let resp = RequestResponseHeader::from(resp.unwrap().data);
            if resp.response_code != 0 {
                return Err(());
            }
            Ok(())
        }

        pub(crate) async fn run(&self, s: Service) -> Result<(), ()> {
            match self.object.as_ref() {
                Some(o) => o.lock().await.invoke(s).await,
                None => {
                    error!(
                        "Cap {:?} has no Request object bound and cannot be run!",
                        self
                    );
                    Err(())
                }
            }
        }
    }
}
