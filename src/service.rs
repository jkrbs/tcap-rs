pub mod tcap {
    use std::collections::HashMap;
    use std::ops::{AddAssign, MulAssign};
    use std::sync::Arc;
    use std::io;

    use crate::cap_table::tcap::cap_table::CapTable;
    use crate::capabilities::tcap::{Capability, CapType, CapID};
    use crate::packet_types::tcap::*;
    use crate::config::Config;
    use log::{debug, error, info, warn};
    use tokio::net::UdpSocket;
    use tokio::sync::{mpsc, Mutex, Notify, Semaphore};
    use core::fmt;
    
    #[derive(Clone)]
    pub struct Service {
        send_channel: Arc<Mutex<mpsc::Sender<SendRequest>>>,
        receiver: Arc<Mutex<mpsc::Receiver<SendRequest>>>,
        pub(crate) config: Config,
        socket: Arc<UdpSocket>,
        pub(crate) responses: Arc<Mutex<HashMap<u32, Response>>>,
        response_notifiers: Arc<Mutex<HashMap<u32, Arc<Semaphore>>>>,
        pub(crate) cap_table: CapTable,
        termination_notifier: Arc<Notify>,
        #[cfg(feature="net-stats")]
        pub send_counter: Arc<Mutex<u128>>,
        #[cfg(feature="net-stats")]
        pub recv_counter: Arc<Mutex<u128>>
    }

    impl fmt::Debug for Service {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Service")
                .field("Config", &self.config)
                .finish()
        }
    }

    #[derive(Debug, Clone)]
    pub struct SendRequest {
        pub dest: String,
        pub data: Box<[u8]>,
        pub stream_id: u32,
        response_notification: Arc<Semaphore>
    }

    impl SendRequest {
        pub(crate) fn new(dest: String, data: Box<[u8]>) -> Self {
            assert!(
                data.len() >= std::mem::size_of::<CommonHeader>(),
                "Packet must at keast contain the common header"
            );
            let stream_id = CommonHeader::from(data[0..std::mem::size_of::<CommonHeader>()].to_vec()).stream_id;
            let response_notification = Arc::new(Semaphore::new(0));
            Self {
                dest,
                data,
                stream_id,
                response_notification,
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct Response {
        pub sender: String,
        pub data: Vec<u8>,
    }

    impl Service {
        pub async fn new(config: Config) -> Service {
            let (send_channel, receiver) = mpsc::channel::<SendRequest>(256);
            debug!("Binding UDP Socket to {:?}", config.address);
            let socket = Arc::new(UdpSocket::bind(config.address.clone())
                .await
                .unwrap());
            socket.bind_device(Some(config.interface.as_str().as_bytes())).unwrap();

            let send_channel = Arc::new(Mutex::new(send_channel));
            let receiver = Arc::new(Mutex::new(receiver));

            let responses = Arc::new(Mutex::new(HashMap::new()));
            let response_notifiers = Arc::new(Mutex::new(HashMap::new()));

            let cap_table = CapTable::new().await;
            
            let termination_notifier = Arc::new(Notify::new());
            Service {
                send_channel,
                receiver,
                config,
                socket,
                responses,
                response_notifiers,
                cap_table,
                termination_notifier,
                #[cfg(feature="net-stats")]
                send_counter: Arc::new(Mutex::new(0)),
                #[cfg(feature="net-stats")]
                recv_counter: Arc::new(Mutex::new(0))
            }
        }

        pub async fn reset(&self) {
            self.cap_table.reset().await;
            self.response_notifiers.lock().await.clear();
            self.responses.lock().await.clear();
            self.send_counter.lock().await.mul_assign(0);
            self.recv_counter.lock().await.mul_assign(0);
        }

        pub fn get_compilation_commit() -> String {
            env!("GIT_HASH").to_string()
        }

        pub async fn create_capability(&self) -> Arc<Mutex<Capability>> {
            let c = Arc::new(Mutex::new(
                Capability::create(Arc::new(self.clone())).await,
            ));

            self.cap_table.insert(c.clone()).await;

            c
        }

        pub async fn cap_exists(&self, cap_id: CapID) -> bool {
            self.cap_table.contains(cap_id).await
        }

        /*** This function create a capability with a predefined cap id
         * It is a work around, as there is no global name service or authentication broker
         * TODO (@jkrbs): Build name service or initial cap distribution system
         */
        pub async fn create_capability_with_id(&self, cap_id: CapID) -> Arc<Mutex<Capability>> {
            let c = Arc::new(Mutex::new(
                Capability::create_with_id(Arc::new(self.clone()), cap_id).await,
            ));

            self.cap_table.insert(c.clone()).await;

            c
        }

        pub async fn create_remote_capability_with_id(&self, owner: String, cap_id: CapID) -> Arc<Mutex<Capability>> {
            let owner_address = IpAddress::from(owner.as_str());
            let c = Arc::new(Mutex::new(
                Capability::create_remote_with_id(Arc::new(self.clone()), owner_address, cap_id).await,
            ));

            self.cap_table.insert(c.clone()).await;

            c
        }

        pub async fn delete_capability(&self, cap: Arc<Mutex<Capability>>) {
            self.cap_table.remove(cap.lock().await.cap_id).await;
        }

        pub async fn terminate(&self) {
            info!("Terminating Service");

            for cap_id in self.cap_table.get_capids().await {
                let cap =  self.cap_table.get(cap_id).await;
                if let Some(cap) = cap {
                    cap.lock().await.revoke(self.clone()).await.unwrap();
                }
            }
            self.termination_notifier.clone().notify_waiters();
            info!("refcount of socket should now be 1, is {:?}", Arc::strong_count(&self.socket));
            
            #[cfg(feature="net-stats")]
            info!("Send Counter: {:?}, Receive Counter: {:?}", self.send_counter.lock().await, self.recv_counter.lock().await, )
        }

        pub async fn run(&self) -> io::Result<()> {
            let s = self.clone();
            let sender_handle = tokio::spawn(async move {
                debug!("started sender thread");
                loop {
                    debug!("receive next packet from send queue");
                    let packet = s.receiver.clone().lock().await.recv().await;
                    if let Some(packet) = packet {
                        s.response_notifiers
                            .lock()
                            .await
                            .insert(packet.stream_id, packet.response_notification.clone());

                        match s.socket.send_to(&packet.data, packet.dest.clone()).await {
                            Ok(b) => debug!("sent stream id {:?}, size: {:?}", packet.stream_id, b),
                            Err(_) => panic!("failed to send network packet to {:?}", packet.dest),
                        };
                        #[cfg(feature="net-stats")]
                        s.send_counter.lock().await.add_assign(1);
                    } else {
                        info!("Received None Type from Udp Sender queue. This is probably a bug.");
                    }
                }
            });

            //receive loop
            let s = self.clone();
            let receiver_handle = tokio::spawn(async move {
                debug!("Start receiver Thread");
                loop {
                    let mut buf = Vec::with_capacity(10000);

                    match s.socket.recv_buf_from(&mut buf).await {
                        Ok((received_bytes, sender)) => {
                            #[cfg(feature="net-stats")]
                            s.clone().recv_counter.lock().await.add_assign(1);

                            let ss = s.clone();
                            tokio::spawn(async move {
                            let common = CommonHeader::from(buf[0..std::mem::size_of::<CommonHeader>()].to_vec());
                            let cmd = common.cmd;
                            debug!(
                                "Service at {:?} Received packet from {:?} size {:?}, cmdtype {:?}",
                                ss.config.address, sender, received_bytes, cmd
                            );
                            if IpAddress::from(ss.config.address.as_str()).equals(sender) {
                                debug!("ignoring packet");
                                return;
                            }

                            assert!(
                                received_bytes >= std::mem::size_of::<CommonHeader>(),
                                "Received packets must include the common header"
                            );
                            let stream_id = common.stream_id;
                            debug!("Received packet with stream id {:?}", stream_id);

                            match ss.response_notifiers.lock().await.get(&stream_id) {
                                Some(notifier) => {
                                    if CmdType::from(common.cmd) == CmdType::MemoryCopyResponse{
                                        let hdr = MemoryCopyResponseHeader::from(buf.clone());
                                        ss.responses.lock().await.insert(
                                            stream_id + hdr.sequence,
                                            Response {
                                                sender: sender.to_string(),
                                                data: buf,
                                            },
                                        );
                                    } else {
                                    ss.responses.lock().await.insert(
                                        stream_id,
                                        Response {
                                            sender: sender.to_string(),
                                            data: buf,
                                        },
                                    );
                                }
                                    notifier.add_permits(1);
                                    debug!("notified stream id {:?}", stream_id);
                                }
                                None => {
                                    debug!("stream {:?} is not waited for. Trying to parse unsolicited packet", stream_id);

                                    ss.parse(sender.to_string(), buf, common).await;
                                }
                            };
                        });
                        }
                        Err(e) => {
                            debug!("Error branch of receiver loop: {:?}", e);
                        }
                    };
                }
            });
            
            self.termination_notifier.clone().notified().await;
            
            let  _ = sender_handle.abort();
            let  _ = receiver_handle.abort();

            info!("aborted all service threads");
            Ok(())
        }

        pub(crate) async fn send(&self, r: SendRequest, wait_for_response: bool) -> Option<Arc<Semaphore>> {
            let notification = r.response_notification.clone();
            debug!(
                "sending Request: {:?} via mpsc",
                r.stream_id,
            );
            let _ = self.send_channel.clone().lock().await.send(r).await;

            if wait_for_response {
                return Some(notification.clone());
            }
            None
        }


        pub(crate) async fn get_response(&self, stream_id: u32) -> Option<Response> {
            self.responses.lock().await.remove(&stream_id)
        }

        pub(crate) async fn get_response_no_delete(&self, stream_id: u32) -> Option<Response> {
            self.responses.lock().await.get(&stream_id).cloned()
        }

        async fn parse(&self, source: String, packet: Vec<u8>, common: CommonHeader) {
            assert!(
                packet.len() >= std::mem::size_of::<CommonHeader>(),
                "Received packets must include the common header"
            );
            let command = common.cmd;
            match CmdType::from(command) {
                CmdType::Nop => todo!(),
                CmdType::CapGetInfo => todo!(),
                CmdType::CapIsSame => todo!(),
                CmdType::CapDiminish => todo!(),
                CmdType::CapClose => todo!(),
                CmdType::CapInvalid => {
                    error!("Received CapInvalid packet, but not as response to outgoing stream");
                }
                CmdType::CapRevoke => {
                    let hdr = RevokeCapHeader::from(packet);
                    debug!("Received CapRevoke: {:?}", hdr);
                    self.cap_table.get(hdr.cap_id).await.unwrap().lock().await.revoke(self.clone()).await.unwrap();
                }
                CmdType::RequestCreate => todo!(),
                CmdType::RequestInvoke => {
                    let hdr = RequestInvokeHeader::from(packet);
                    debug!("Received RequestInvoke: {:?}", hdr);

                    if !self.cap_table.contains(hdr.common.cap_id).await {
                        let packet: Box<[u8; std::mem::size_of::<CapInvalidHeader>()]> =
                            CapInvalidHeader::construct(hdr.common.cap_id, source.clone().as_str().into(), hdr.common.stream_id)
                                .into();
                        #[cfg(feature="directCPcommunication")]
                        self.send(SendRequest::new(self.config.switch_addr.clone(), packet.clone()), false)
                            .await;
                        
                        self.send(SendRequest::new(source, packet), false)
                            .await;
                        return;
                    }

                    let cap = self.cap_table.get(hdr.common.cap_id).await.unwrap();
                    let mut continuations = vec!();
                    for i in 0..hdr.number_of_conts.min(4) {
                        let c = match hdr.continutaion_cap_ids[i as usize] {
                            0 => None,
                            // TODO (@jkrbs): do not require a previous delegation for the invocation
                            s => match self.cap_table.get(s).await {
                                Some(cap) => Some(cap),
                                None => {
                                    error!("Received Request Invoke with parameters, which are not in the cap table");
                                    None
                                } 
                            },
                        };
                        continuations.push(c);
                    }
                    let capid = cap.lock().await.cap_id;

                    let result = cap
                    .lock()
                    .await
                    .run(continuations)
                    .await;
                    debug!("Flags: {:?}", hdr.flags);
                    if ! Flags::from_bits(hdr.flags)
                            .expect("Invalid Bits set in RequestInvoke Flag")
                            .contains(Flags::REQUIRE_RESPONSE) {
                        debug!("Not sending response packet");
                        return;
                    }

                    let packet: Box<[u8; std::mem::size_of::<RequestResponseHeader>()]> = match result
                    {
                        Ok(_) => {
                            debug!("result ok: constructing reponse header with code 0");
                            RequestResponseHeader::construct(capid, hdr.common.stream_id, 0)
                                .await
                                .into()
                        }
                        Err(_) => {
                            debug!("result ok: constructing reponse header with code 100");
                            RequestResponseHeader::construct(capid, hdr.common.stream_id, 100)
                                .await
                                .into()
                        }
                    };
                    debug!("Sent Response packet to {:?}", source);
                    let _ = self
                        .send(SendRequest::new(source, packet), false)
                        .await;
                }
                CmdType::RequestReceive => todo!(),
                CmdType::None => todo!(),
                CmdType::InsertCap => {
                    debug!("received insert cap packet with len {:?}", packet.len());

                    let hdr = InsertCapHeader::from(packet);
                    debug!("Received CapInsert: {:?}", hdr);
                    let cap = Arc::new(Mutex::new(Capability::from(hdr)));
                    cap.lock().await.service = Some(Arc::new(self.clone()));
                    let _ = self    
                        .cap_table
                        .insert(cap)
                        .await;
                }
                CmdType::RequestResponse => {
                    debug!("Received Request Response");
                    let hdr = RequestResponseHeader::from(packet.clone());
                    let streamid = hdr.common.stream_id;
                    self.responses.lock().await.insert(streamid, Response { sender: source, data: packet });
                    self.response_notifiers.lock().await.get(&streamid).unwrap().add_permits(1);
                },
                CmdType::MemoryCopy => {
                    debug!("Received MemoryCopy");
                    let hdr = MemoryCopyRequestHeader::from(packet.clone());
                    if !self.cap_table.contains(hdr.common.cap_id).await {
                        let packet: Box<[u8; std::mem::size_of::<CapInvalidHeader>()]> =
                            CapInvalidHeader::construct(hdr.common.cap_id, source.clone().as_str().into(), hdr.common.stream_id)
                                .into();

                        #[cfg(feature="directCPcommunication")]
                        self.send(SendRequest::new(self.config.switch_addr.clone(), packet.clone()), false)
                            .await;

                        self.send(SendRequest::new(source, packet), false)
                            .await;
                        return;
                    }

                    let cap = self.cap_table.get(hdr.common.cap_id).await.unwrap();

                    if cap.lock().await.cap_type != CapType::Memory {
                        panic!("someone ties to capy memory from a non-memory type capability");
                    }

                    let packets = MemoryCopyResponseHeader::construct(cap.lock().await.get_buffer().await, hdr.common.cap_id, hdr.common.stream_id).await;
                    for packet in packets {
                        let resp: Box<[u8; std::mem::size_of::<MemoryCopyResponseHeader>()]> = packet.into();

                        debug!("Sent Response packet to {:?}", source.clone());
                        let _ = self
                            .send(SendRequest::new(source.clone(), resp), false)
                            .await;
                    }
                },
                CmdType::MemoryCopyResponse => {
                    debug!("Received MemoryCopyResponse");
                    let hdr = MemoryCopyResponseHeader::from(packet.clone());
                    let streamid = hdr.common.stream_id;

                    // TODO (@jkrbs): fix sequence and stream id mangling. This is an ungly hack
                    self.responses.lock().await.insert(streamid+hdr.sequence, Response { sender: source.clone(), data: packet });
                    self.response_notifiers.lock().await.get(&streamid).unwrap().add_permits(1);
                },
                _ => {
                    warn!("Unrecognized CMDType received");
                }
            };
        }
    
        pub async fn controller_timer_start(&self) {
            let data:Box<[u8; std::mem::size_of::<ControllerStartTimerHeader>()]> = ControllerStartTimerHeader::construct().into();
            let req = SendRequest::new(self.config.switch_addr.clone(), data);
            
            self.send(req, false).await;
        }

        pub async fn controller_timer_stop(&self) {
            let data:Box<[u8; std::mem::size_of::<ControllerStopTimerHeader>()]> = ControllerStopTimerHeader::construct().into();
            let req = SendRequest::new(self.config.switch_addr.clone(), data);
            
            self.send(req, false).await;
        }

        pub async fn controller_reset_switch(&self) {
            let data:Box<[u8; std::mem::size_of::<ControllerResetSwitchHeader>()]> = ControllerResetSwitchHeader::construct().into();
            let req = SendRequest::new(self.config.switch_addr.clone(), data);
            
            self.send(req, false).await;
        }

        pub async fn controller_stop(&self) {
            let data:Box<[u8; std::mem::size_of::<ControllerStopHeader>()]> = ControllerStopHeader::construct().into();
            let req = SendRequest::new(self.config.switch_addr.clone(), data);
            
            self.send(req, false).await;
        }
    }
}
