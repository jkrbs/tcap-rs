pub mod tcap {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::{io, usize};

    use crate::{Config, cap_table};
    use crate::cap_table::tcap::cap_table::CapTable;
    use crate::capabilities::tcap::Capability;
    use crate::packet_types::tcap::{CommonHeader, CmdType, RevokeCapHeader, InsertCapHeader};
    use log::{debug, info};
    use tokio::net::UdpSocket;
    use tokio::sync::{mpsc, Mutex, Notify};
    

    #[derive(Clone, Debug)]
    pub struct Service {
        send_channel: Arc<Mutex<mpsc::Sender<SendRequest>>>,
        receiver: Arc<Mutex<mpsc::Receiver<SendRequest>>>,
        pub config: Config,
        socket: Arc<UdpSocket>,
        responses: Arc<Mutex<HashMap<u32, Response>>>,
        response_notifiers: Arc<Mutex<HashMap<u32, Arc<Notify>>>>,
        cap_table: CapTable
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
            assert!(data.len() >= std::mem::size_of::<CommonHeader>(), "Packet must at keast contain the common header");
            debug!("Extracting stream ID from data of len: {:?}, raw: {:?}", data.len(), data);
            let stream_id = u32::from_be_bytes(*bytemuck::from_bytes(&data[4..8]));
            let response_notification = Arc::new(Notify::new());
            Self {
                dest, data, stream_id, response_notification
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct Response {
        pub sender: String,
        pub data: Box<Vec<u8>>
    }

    impl Service {
        pub async fn new(config: Config) -> Service {
            let (send_channel, receiver) = mpsc::channel::<SendRequest>(256);
            info!("Binding UDP Socket to {:?}", config.address);
            let socket = Arc::new(
                UdpSocket::bind(config.address.clone()).await.unwrap(),
            );

            let send_channel = Arc::new(Mutex::new(send_channel));
            let receiver = Arc::new(Mutex::new(receiver));

            let responses = Arc::new(Mutex::new(HashMap::new()));
            let response_notifiers = Arc::new(Mutex::new(HashMap::new()));

            let cap_table = CapTable::new().await;

            Service {
                send_channel,
                receiver,
                config,
                socket,
                responses,
                response_notifiers,
                cap_table
            }
        }

        pub async fn run(&self) -> io::Result<()> {
            let s = self.clone();
            let sender_handle = tokio::spawn(async move {
                debug!("started sender thread");
                loop {
                    let packet = s.receiver.clone().lock().await.recv().await;
                    if let Some(packet) = packet {
                        debug!("Received packet via send mpsc: {:?}", packet);

                        // s.response_notifiers.lock().await.insert(packet.stream_id, packet.response_notification.clone());

                        debug!("Connecting to {:?}", packet.dest);
                        s.socket.connect(packet.dest).await.unwrap();
                        match s.socket.send(&packet.data).await {
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

                match s.socket.recv_buf(&mut buf).await {
                    Ok(received_bytes) => {
                        debug!("received {:?} bytes: {:?}", received_bytes, buf);
                        
                        assert!(received_bytes >= std::mem::size_of::<CommonHeader>(), "Received packets must includethe common header");

                        let stream_id = u32::from_be_bytes(*bytemuck::from_bytes(&buf[4..8]));
                        debug!("Received packet with stream id {:?}", stream_id);   

                        match s.response_notifiers.lock().await.get(&stream_id) {
                            Some(notifier) => {
                                s.responses.lock().await.insert(stream_id, Response { sender: String::from(""), data: Box::new(buf) });
                                notifier.notify_one();
                                debug!("notified stream id {:?}", stream_id);
                            },
                            None => {
                                info!("stream {:?} is not waited for. Trying to parse unsolicited packet", stream_id);

                                s.parse(buf);
                            },
                        };
                        
                    },
                    Err(e) => {
                        debug!("Error branch of receiver loop: {:?}", e);
                    },
                };
            }});

            let _ = sender_handle.await;
            let _ = receiver_handle.await;
            Ok(())
        }

        pub async fn send(&self, r: SendRequest, wait_for_response: bool) -> Option<Response> {
            let stream_id = r.stream_id;
            let notification = r.response_notification.clone();
            debug!("sending Request: {:?}, stream_id: {:?} via mpsc", r, stream_id);
            let _ = self.send_channel.clone().lock().await.send(r).await;

            if wait_for_response {
                debug!("Waiting for Response");
                notification.clone().notified().await;
                return self.responses.lock().await.remove(&stream_id)
            }
            None 
        }

        async fn parse(&self, packet: Vec<u8>) {
            assert!(packet.len() >= std::mem::size_of::<CommonHeader>(), "Received packets must includethe common header");
            let command: u32 = *bytemuck::from_bytes(&packet[8..12]);
            match CmdType::from(command) {
                CmdType::Nop => todo!(),
                CmdType::CapGetInfo => todo!(),
                CmdType::CapIsSame => todo!(),
                CmdType::CapDiminish => todo!(),
                CmdType::CapClose => todo!(),
                CmdType::CapRevoke => {
                    let hdr = RevokeCapHeader::from(packet);
                    let _ = self.cap_table.remove(hdr.cap_id).await;
                },
                CmdType::RequestCreate => todo!(),
                CmdType::RequestInvoke => todo!(),
                CmdType::RequestReceive => todo!(),
                CmdType::None => todo!(),
                CmdType::InsertCap => {
                    let hdr = InsertCapHeader::from(packet);
                    let _ = self.cap_table.insert(Capability::from(hdr)).await;
                },
                CmdType::CapDelegate => {
                    todo!()
                }
            }

        }
    }
}
