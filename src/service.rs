pub mod tcap {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::io;

    use crate::cap_table::tcap::cap_table::CapTable;
    use crate::capabilities::tcap::Capability;
    use crate::packet_types::tcap::{
        CapInvalidHeader, CmdType, CommonHeader, InsertCapHeader, IpAddress, RequestInvokeHeader,
        RequestResponseHeader, RevokeCapHeader,
    };
    use crate::config::Config;
    use log::{debug, info};
    use tokio::net::UdpSocket;
    use tokio::sync::{mpsc, Mutex, Notify};

    #[derive(Clone, Debug)]
    pub struct Service {
        send_channel: Arc<Mutex<mpsc::Sender<SendRequest>>>,
        receiver: Arc<Mutex<mpsc::Receiver<SendRequest>>>,
        pub(crate) config: Config,
        socket: Arc<UdpSocket>,
        responses: Arc<Mutex<HashMap<u32, Response>>>,
        response_notifiers: Arc<Mutex<HashMap<u32, Arc<Notify>>>>,
        pub(crate) cap_table: CapTable,
        termination_notifier: Arc<Notify>
    }

    #[derive(Debug, Clone)]
    pub struct SendRequest {
        pub dest: String,
        pub data: Box<[u8]>,
        pub stream_id: u32,
        response_notification: Arc<Notify>
    }

    impl SendRequest {
        pub(crate) fn new(dest: String, data: Box<[u8]>) -> Self {
            assert!(
                data.len() >= std::mem::size_of::<CommonHeader>(),
                "Packet must at keast contain the common header"
            );
            debug!(
                "Extracting stream ID from data of len: {:?}, raw: {:?}",
                data.len(),
                data
            );
            let stream_id = u32::from_be_bytes(*bytemuck::from_bytes(&data[8..12]));
            let response_notification = Arc::new(Notify::new());
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
            }
        }

        pub fn get_compilation_commit() -> String {
            env!("GIT_HASH").to_string()
        }

        pub async fn create_capability(&self) -> Arc<Mutex<Capability>> {
            let c = Arc::new(Mutex::new(
                Capability::create(Arc::new(Mutex::new(self.clone()))).await,
            ));

            self.cap_table.insert(c.clone()).await;

            c
        }

        /*** This function create a capability with a predefined cap id
         * It is a work around, as there is no global name service or authentication broker
         * TODO (@jkrbs): Build name service or initial cap distribution system
         */
        pub async fn create_capability_with_id(&self, cap_id: u64) -> Arc<Mutex<Capability>> {
            let c = Arc::new(Mutex::new(
                Capability::create_with_id(Arc::new(Mutex::new(self.clone())), cap_id).await,
            ));

            self.cap_table.insert(c.clone()).await;

            c
        }

        pub async fn create_remote_capability_with_id(&self, owner: String, cap_id: u64) -> Arc<Mutex<Capability>> {
            let owner_address = IpAddress::from(owner.as_str());
            let c = Arc::new(Mutex::new(
                Capability::create_remote_with_id(Arc::new(Mutex::new(self.clone())), owner_address, cap_id).await,
            ));

            self.cap_table.insert(c.clone()).await;

            c
        }

        pub async fn terminate(&self) {
            for cap_id in self.cap_table.get_capids().await {
                let cap =  self.cap_table.get(cap_id).await;
                if let Some(cap) = cap {
                    cap.lock().await.revoke(self.clone()).await.unwrap();
                }
            }
            self.termination_notifier.clone().notify_waiters();
        }

        pub async fn run(&self) -> io::Result<()> {
            let s = self.clone();
            let sender_handle = tokio::spawn(async move {
                debug!("started sender thread");
                loop {
                    let packet = s.receiver.clone().lock().await.recv().await;
                    if let Some(packet) = packet {
                        debug!("Received packet via send mpsc: {:?}", packet);

                        s.response_notifiers
                            .lock()
                            .await
                            .insert(packet.stream_id, packet.response_notification.clone());

                        match s.socket.send_to(&packet.data, packet.dest).await {
                            Ok(b) => debug!("sent {:?} bytes", b),
                            Err(_) => panic!("failed to send network packet"),
                        };
                    } else {
                        info!("Received None Type from Udp Sender queue. This is probably a bug.");
                    }
                }
            });

            //receive loop
            let s = self.clone();
            let receiver_handle = tokio::spawn(async move {
                loop {
                    let mut buf = vec![];

                    match s.socket.recv_buf_from(&mut buf).await {
                        Ok((received_bytes, sender)) => {
                            debug!(
                                "Service at {:?} Received packet from {:?}",
                                s.config.address, sender
                            );
                            if IpAddress::from(s.config.address.as_str()).equals(sender) {
                                debug!("ignoring packet");
                                continue;
                            }
                            debug!("received {:?} bytes: {:?}", received_bytes, buf);

                            assert!(
                                received_bytes >= std::mem::size_of::<CommonHeader>(),
                                "Received packets must includethe common header"
                            );
                            debug!(
                                "[8..12]: {:?}, [9..13]: {:?}",
                                u32::from_be_bytes(*bytemuck::from_bytes(&buf[8..12])),
                                u32::from_be_bytes(*bytemuck::from_bytes(&buf[9..13]))
                            );
                            let stream_id = u32::from_be_bytes(*bytemuck::from_bytes(&buf[8..12]));
                            debug!("Received packet with stream id {:?}", stream_id);

                            match s.response_notifiers.lock().await.get(&stream_id) {
                                Some(notifier) => {
                                    s.responses.lock().await.insert(
                                        stream_id,
                                        Response {
                                            sender: String::from(""),
                                            data: buf,
                                        },
                                    );
                                    notifier.notify_one();
                                    debug!("notified stream id {:?}", stream_id);
                                }
                                None => {
                                    debug!("stream {:?} is not waited for. Trying to parse unsolicited packet", stream_id);

                                    s.parse(sender.to_string(), buf).await;
                                }
                            };
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

            Ok(())
        }

        pub async fn send(&self, r: SendRequest, wait_for_response: bool) -> Option<Response> {
            let stream_id = r.stream_id;
            let notification = r.response_notification.clone();
            debug!(
                "sending Request: {:?}, stream_id: {:?} via mpsc",
                r, stream_id
            );
            let _ = self.send_channel.clone().lock().await.send(r).await;

            if wait_for_response {
                debug!("Waiting for Response");
                notification.clone().notified().await;
                return self.responses.lock().await.remove(&stream_id);
            }
            None
        }

        async fn parse(&self, source: String, packet: Vec<u8>) {
            assert!(
                packet.len() >= std::mem::size_of::<CommonHeader>(),
                "Received packets must include the common header"
            );
            let command: u32 = *bytemuck::from_bytes(&packet[12..16]);
            match CmdType::from(command) {
                CmdType::Nop => todo!(),
                CmdType::CapGetInfo => todo!(),
                CmdType::CapIsSame => todo!(),
                CmdType::CapDiminish => todo!(),
                CmdType::CapClose => todo!(),
                CmdType::CapInvalid => {}
                CmdType::CapRevoke => {
                    let hdr = RevokeCapHeader::from(packet);
                    debug!("Received CapRevoke: {:?}", hdr);
                    let _ = self.cap_table.remove(hdr.cap_id).await;
                }
                CmdType::RequestCreate => todo!(),
                CmdType::RequestInvoke => {
                    let hdr = RequestInvokeHeader::from(packet);
                    debug!("Received RequestInvoke: {:?}", hdr);

                    if !self.cap_table.contains(hdr.common.cap_id).await {
                        let packet: Box<[u8; std::mem::size_of::<CapInvalidHeader>()]> =
                            CapInvalidHeader::construct(hdr.common.cap_id, hdr.common.stream_id)
                                .into();

                        self.send(SendRequest::new("".to_string(), packet), false)
                            .await;
                    }

                    let cap = self.cap_table.get(hdr.common.cap_id).await.unwrap();
                    let continuation = match hdr.continutaion_cap_id {
                        0 => None,
                        // TODO (@jkrbs): do not require a previous delegation for the invocation
                        s => Some(self.cap_table.get(s).await.unwrap())
                    };
                    let capid = cap.lock().await.cap_id;
                    let packet: Box<[u8; std::mem::size_of::<RequestResponseHeader>()]> = match cap
                        .lock()
                        .await
                        .run(continuation)
                        .await
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
                    debug!("Sent Response packet {:?} to {:?}", packet, source);
                    let _ = self
                        .send(SendRequest::new(source, packet), false)
                        .await;
                }
                CmdType::RequestReceive => todo!(),
                CmdType::None => todo!(),
                CmdType::InsertCap => {
                    let hdr = InsertCapHeader::from(packet);
                    debug!("Received CapInsert: {:?}", hdr);
                    let cap = Arc::new(Mutex::new(Capability::from(hdr)));
                    cap.lock().await.service = Some(Arc::new(Mutex::new(self.clone())));
                    let _ = self    
                        .cap_table
                        .insert(cap)
                        .await;
                }
                CmdType::RequestResponse => {
                    debug!("Received Request Response");
                    let hdr = RequestResponseHeader::from(packet.clone());
                    let streamid = hdr.common.stream_id;
                    self.responses.lock().await.insert(streamid, Response { sender: "".to_string(), data: packet });
                    self.response_notifiers.lock().await.get(&streamid).unwrap().notify_waiters();
                },
            };
        }
    }
}
