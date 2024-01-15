pub mod tcap {
    use std::sync::Arc;

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
        pub service: Option<Arc<Mutex<Service>>>
    }

    impl From<InsertCapHeader> for Capability {
        fn from(value: InsertCapHeader) -> Self {
            Capability {
                cap_id: value.cap_id,
                cap_type: CapType::from(value.cap_type),
                owner_address: value.object_owner,
                delegatees: Arc::new(Mutex::new(Vec::new())),
                object: None,
                service: None
            }
        }
    }

    impl Capability {
        pub(crate) async fn create(s: Arc<Mutex<Service>>) -> Capability {
            let mut rng = rand::thread_rng();
            let cap_id = rng.gen::<u64>();

            let owner_address = IpAddress::from(s.lock().await.config.address.as_str());

            Capability {
                cap_id,
                cap_type: CapType::None,
                owner_address,
                delegatees: Arc::new(Mutex::new(Vec::new())),
                object: None,
                service: Some(s)
            }
        }

        pub(crate) async fn create_with_id(s: Arc<Mutex<Service>>, cap_id: u64) -> Capability {
            let owner_address = IpAddress::from(s.lock().await.config.address.as_str());
            Capability {
                cap_id,
                cap_type: CapType::None,
                owner_address,
                delegatees: Arc::new(Mutex::new(Vec::new())),
                object: None,
                service: Some(s)
            }
        }

        pub(crate) async fn create_remote_with_id(s: Arc<Mutex<Service>>, owner_address: IpAddress,cap_id: u64) -> Capability {
            Capability {
                cap_id,
                cap_type: CapType::None,
                owner_address,
                delegatees: Arc::new(Mutex::new(Vec::new())),
                object: None,
                service: Some(s)
            }
        }

        pub async fn bind(&mut self, obj: Arc<Mutex<RequestObject>>) {
            self.object = Some(obj);
            self.object
                .as_ref()
                .unwrap()
                .lock()
                .await
                .set_cap(self.clone());
            // TODO set correct cap type
            debug!("Binding obj {:?} to cap {:?}", self.object, self.cap_id);
        }

        pub async fn delegate(
            &self,
            delegatee: IpAddress,
        ) -> Result<(), tokio::io::Error> {
            self.delegatees.lock().await.push(delegatee);
            let address = self.service.as_ref().unwrap().lock().await.config.address.clone();
            let packet: Box<[u8; std::mem::size_of::<InsertCapHeader>()]> =
                InsertCapHeader::construct(&self, delegatee, IpAddress::from(address.as_str()))
                    .into();
            debug!("packet to be send: {:?}", packet);

            #[cfg(feature="directCPcommunication")]
            {
                let ctrl_plane = self.service.as_ref().unwrap().lock().await.config.switch_addr.clone();
                let _ = self.service.as_ref().unwrap().lock().await.send(SendRequest::new(ctrl_plane, packet.clone()), false).await;    
            }
            
            let dest: String = delegatee.into();
            let _ = self.service.as_ref().unwrap().lock().await.send(SendRequest::new(dest, packet), false).await;
            
            Ok(())
        }

        /**
         * Revoke all delegations of the capability
         */
        pub async fn revoke(&self, s: Service) -> tokio::io::Result<()> {
            let address = s.config.address.clone();
            let packet: Box<[u8; std::mem::size_of::<RevokeCapHeader>()]> =
                RevokeCapHeader::construct(self, address.as_str().into()).into();

            debug!("packet to be send: {:?}", packet);

            #[cfg(feature="directCPcommunication")]
            {
                let ctrl_plane = self.service.as_ref().unwrap().lock().await.config.switch_addr.clone();
                let _ = s
                    .send(SendRequest::new(ctrl_plane, packet.clone()), false)
                    .await;
            }

            for delegatee in self.delegatees.lock().await.clone() {
                let _ = s
                    .send(SendRequest::new(delegatee.into(), packet.clone()), false)
                    .await;
            }

            Ok(())
        }

        pub async fn revoke_on_node(&self, s: Service, node: IpAddress) -> tokio::io::Result<()> {
            let packet: Box<[u8; std::mem::size_of::<RevokeCapHeader>()]> =
                RevokeCapHeader::construct(self, node).into();

            debug!("packet to be send: {:?}", packet);

            #[cfg(feature="directCPcommunication")]
            {
                let ctrl_plane = self.service.as_ref().unwrap().lock().await.config.switch_addr.clone();
                let _ = s
                    .send(SendRequest::new(ctrl_plane, packet.clone()), false)
                    .await;
            }
            Ok(())
        }

        pub async fn request_invoke(&self) -> Result<(), ()> {
            self.request_invoke_with_continuation(None).await
        }

        pub async fn request_invoke_with_continuation(&self, continuation: Option<Arc<Mutex<Capability>>>) -> Result<(), ()> {
            let cont_id = match continuation{
                None => 0,
                Some(c) => c.lock().await.cap_id
            };

            let packet: Box<[u8; std::mem::size_of::<RequestInvokeHeader>()]> =
            RequestInvokeHeader::construct(self.clone(), cont_id).into();

            let resp = self.service.as_ref().unwrap().lock().await
                .send(SendRequest::new(self.owner_address.into(), packet), true)
                .await;

            let resp = RequestResponseHeader::from(resp.unwrap().data);
            if resp.response_code != 0 {
                return Err(());
            }
            Ok(())
        }

        pub(crate) async fn run(&self, continuation: Option<Arc<Mutex<Capability>>>) -> Result<(), ()> {
            match self.object.as_ref() {
                Some(o) => o.lock().await.invoke(continuation).await,
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
