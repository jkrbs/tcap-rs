pub mod tcap {
    use std::sync::Arc;

    use crate::{
        object::tcap::object::{RequestObject, MemoryObject},
        packet_types::tcap::{
            CmdType, Flags, InsertCapHeader, IpAddress, MemoryCopyRequestHeader, MemoryCopyResponseHeader, RequestInvokeHeader, RequestResponseHeader, RevokeCapHeader
        },
        service::tcap::{SendRequest, Service},
    };
    use log::*;
    use rand::Rng;
    use tokio::sync::Mutex;

    #[repr(u8)]
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum CapType {
        None = 0,
        Request = 1,
        Memory = 2,
    }

    pub type CapID = u128;

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
        pub cap_id: CapID,
        pub cap_type: CapType,
        owner_address: IpAddress,
        delegatees: Arc<Mutex<Vec<IpAddress>>>,
        request_object: Option<Arc<Mutex<RequestObject>>>,
        memory_object: Option<Arc<Mutex<MemoryObject>>>,
        pub service: Option<Arc<Service>>
    }

    impl From<InsertCapHeader> for Capability {
        fn from(value: InsertCapHeader) -> Self {
            Capability {
                cap_id: value.cap_id,
                cap_type: CapType::from(value.cap_type),
                owner_address: IpAddress{ address: value.object_owner_ip_address, netmask: [0,0,0,0], port: value.object_owner_port},
                delegatees: Arc::new(Mutex::new(Vec::new())),
                request_object: None,
                memory_object: None,
                service: None
            }
        }
    }

    impl PartialEq for Capability {
        fn eq(&self, other: &Self) -> bool {
            self.cap_id == other.cap_id
        }
    }

    impl Capability {
        pub(crate) async fn create(s: Arc<Service>) -> Capability {
            let mut rng = rand::thread_rng();
            let cap_id = rng.gen::<CapID>();

            let owner_address = IpAddress::from(s.config.address.as_str());

            Capability {
                cap_id,
                cap_type: CapType::None,
                owner_address,
                delegatees: Arc::new(Mutex::new(Vec::new())),
                request_object: None,
                memory_object: None,
                service: Some(s)
            }
        }

        pub(crate) async fn create_with_id(s: Arc<Service>, cap_id: CapID) -> Capability {
            let owner_address = IpAddress::from(s.config.address.as_str());
            Capability {
                cap_id,
                cap_type: CapType::None,
                owner_address,
                delegatees: Arc::new(Mutex::new(Vec::new())),
                request_object: None,
                memory_object: None,
                service: Some(s)
            }
        }

        pub(crate) async fn create_remote_with_id(s: Arc<Service>, owner_address: IpAddress,cap_id: CapID) -> Capability {
            Capability {
                cap_id,
                cap_type: CapType::None,
                owner_address,
                delegatees: Arc::new(Mutex::new(Vec::new())),
                request_object: None,
                memory_object: None,
                service: Some(s)
            }
        }

        #[deprecated = "Memory objects are supported, `bind_req` should now be used for request objects"]
        pub async fn bind(&mut self, obj: Arc<Mutex<RequestObject>>) {
            self.bind_req(obj).await;
        }

        pub async fn bind_req(&mut self, obj: Arc<Mutex<RequestObject>>) {
            self.request_object = Some(obj);
            self.request_object
                .as_ref()
                .unwrap()
                .lock()
                .await
                .set_cap(self.clone());
            self.cap_type = CapType::Request;
            debug!("Binding obj {:?} to cap {:?}", self.request_object, self.cap_id);
        }

        pub async fn bind_mem(&mut self, obj: Arc<Mutex<MemoryObject>>) {
            self.memory_object = Some(obj);
            self.memory_object
                .as_ref()
                .unwrap()
                .lock()
                .await
                .set_cap(self.clone());
            self.cap_type = CapType::Memory;
            debug!("Binding obj {:?} to cap {:?}", self.memory_object, self.cap_id);
        }

        pub async fn delegate(
            &self,
            delegatee: IpAddress,
        ) -> Result<(), tokio::io::Error> {
            self.delegatees.lock().await.push(delegatee);
            let address = self.service.as_ref().unwrap().config.address.clone();
            let packet: Box<[u8; std::mem::size_of::<InsertCapHeader>()]> =
                InsertCapHeader::construct(&self, delegatee, IpAddress::from(address.as_str()))
                    .into();
            debug!("packet to be send: {:?}", packet);

            #[cfg(feature="directCPcommunication")]
            {
                let ctrl_plane = self.service.as_ref().unwrap().config.switch_addr.clone();
                let _ = self.service.as_ref().unwrap().send(SendRequest::new(ctrl_plane, packet.clone()), false).await;    
            }
            
            let dest: String = delegatee.into();
            let _ = self.service.as_ref().unwrap().send(SendRequest::new(dest, packet), false).await;
            
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
                let ctrl_plane = self.service.as_ref().unwrap().config.switch_addr.clone();
                let _ = s
                    .send(SendRequest::new(ctrl_plane, packet.clone()), false)
                    .await;
            }

            for delegatee in self.delegatees.lock().await.clone() {
                let _ = s
                    .send(SendRequest::new(delegatee.into(), packet.clone()), false)
                    .await;
            }
            s.cap_table.remove(self.cap_id).await;
            Ok(())
        }

        pub async fn revoke_on_node(&self, s: Service, node: IpAddress) -> tokio::io::Result<()> {
            let packet: Box<[u8; std::mem::size_of::<RevokeCapHeader>()]> =
                RevokeCapHeader::construct(self, node).into();

            debug!("packet to be send: {:?}", packet);

            #[cfg(feature="directCPcommunication")]
            {
                let ctrl_plane = self.service.as_ref().unwrap().config.switch_addr.clone();
                let _ = s
                    .send(SendRequest::new(ctrl_plane, packet.clone()), false)
                    .await;
            }
            Ok(())
        }

        pub async fn request_invoke(&self) -> Result<(), ()> {
            self.request_invoke_with_continuation(vec!()).await
        }

        pub async fn request_invoke_no_wait(&self) -> Result<(), ()> {
            self.request_invoke_with_continuation_no_wait(vec!()).await
        }

        pub async fn request_invoke_with_continuation(&self, continuations: Vec<CapID>) -> Result<(), ()> {
            self.request_invoke_with_continuation_wait_param(continuations, true).await
        }

        pub async fn request_invoke_with_continuation_no_wait(&self, continuations: Vec<CapID>) -> Result<(), ()> {
            self.request_invoke_with_continuation_wait_param(continuations, false).await
        }

        async fn request_invoke_with_continuation_wait_param(&self, continuations: Vec<CapID>, wait: bool) -> Result<(), ()> {
            debug!("in request invocation with cont handler");

            let mut cont_ids: [CapID; 4] = [0;4];
            for i in 0..4.min(continuations.len()) {
                cont_ids[i] = continuations[i];
            }
            debug!("capids for continuations are: {:?}", cont_ids.clone());

            let mut flags = Flags::empty();
            flags.set(Flags::REQUIRE_RESPONSE, wait);

            let (stream_id, p) = RequestInvokeHeader::construct(self.clone(), continuations.len() as u8, cont_ids, flags);
            let packet: Box<[u8; std::mem::size_of::<RequestInvokeHeader>()]> = p.into();
            

            let notifier = self.service.as_ref().unwrap()
                .send(SendRequest::new(self.owner_address.into(), packet), wait)
                .await;
            if wait {
                debug!("Waiting for Response");
                let _ = notifier.unwrap().acquire().await.unwrap();
                debug!("Notified of response");
                let resp = self.service.as_ref().unwrap().get_response(stream_id).await;
                debug!("Packet type is {:?}", CmdType::from(* bytemuck::from_bytes::<u32>(&resp.as_ref().unwrap().data[12..16])));
                if CmdType::from(* bytemuck::from_bytes::<u32>(&resp.as_ref().unwrap().data[12..16])) != CmdType::RequestResponse {
                    return Err(());
                }

                let resp = RequestResponseHeader::from(resp.unwrap().data);
                if resp.response_code != 0 {
                    return Err(());
                }
            }
            Ok(())
        }

        pub(crate) async fn run(&self, continuations: Vec<Option<Arc<Mutex<Capability>>>>) -> Result<(), ()> {
            match self.request_object.as_ref() {
                Some(o) => o.lock().await.invoke(continuations).await,
                None => {
                    error!(
                        "Cap {:?} has no Request object bound and cannot be run!",
                        self
                    );
                    Err(())
                }
            }
        }

        pub async fn get_buffer(&mut self) -> Arc<Mutex<MemoryObject>> {
            if self.cap_type != CapType::Memory {
                panic!("get_buffer() can only be called on memory capabilities");
            }

            let local: bool = self.memory_object.is_some() && self.memory_object.as_ref().unwrap().lock().await.is_local().await;

            match local {
                true => {
                    self.memory_object.as_ref().unwrap().clone()
                }
                false => {
                    let (stream_id, data) = MemoryCopyRequestHeader::construct(self.cap_id);
                    let data: Box<[u8; std::mem::size_of::<MemoryCopyRequestHeader>()]> = data.into();

                    let req = SendRequest::new(self.owner_address.into(), data);

                    match self.service.as_ref().unwrap().send(req, true).await {
                        None => {
                            panic!("Response to MemoryCopy Request should not be None");
                        }
                        Some(notifier) => {
                            let _ = notifier.acquire().await.unwrap();

                            // first packet has sequence ID one
                            let mut sequence = 1;
                            debug!("get stream_id resp {:?}, currently avalable: {:?}", sequence+stream_id, self.service.as_ref().unwrap().responses.lock().await.keys());
                            while ! self.service.as_ref().unwrap().responses.lock().await.contains_key(&(stream_id + 1)) {
                               tokio::time::sleep(std::time::Duration::from_nanos(10)).await; 
                            }
                            let resp = self.service.as_ref().unwrap().get_response_no_delete(stream_id + sequence).await.unwrap();
                            let resp = MemoryCopyResponseHeader::from(resp.data);
                            self.memory_object = Some(Arc::new(Mutex::new(MemoryObject::from(resp))));
                            
                            // wait for all packets to be in response buffers
                            let num_packets = resp.buf_size.div_ceil(resp.size);
                            //first packet already arrived
                            if num_packets > 1 {
                                let _  = notifier.acquire_many((num_packets-1) as u32).await.unwrap();
                            }

                            let stream_id = stream_id - resp.sequence;
                            debug!("all notifiers triggered");
                            let buf_size =  resp.buf_size;
                            debug!("get stream_id resp {:?}, currently avalable: {:?}, buf_size {:?}", sequence+stream_id, self.service.as_ref().unwrap().responses.lock().await.keys(), buf_size);
                            //extract all packets from response buffers

                            while self.memory_object.as_ref().unwrap().lock().await.size < resp.buf_size {
                                sequence += 1;
                                if let Some(resp) = self.service.as_ref().unwrap().get_response(stream_id + sequence).await {
                                    let resp = MemoryCopyResponseHeader::from(resp.data);
                                    let seq =  resp.sequence;
                                    self.memory_object.as_ref().unwrap().lock().await.append(resp);
                                } else {
                                    debug!("packet missing in memcpy buffer constructor. Trying to access {:?}", stream_id + sequence)
                                }
                            }

                            self.memory_object.as_ref().unwrap().clone()
                        }
                    }
                }
            }
        }
    }
}
