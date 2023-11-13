pub mod tcap {
    use std::{io, usize};
    use std::sync::Arc;

    use tokio::net::UdpSocket;
    use tokio::sync::{mpsc, Mutex};
    use log::{info, debug};
    use crate::Config;

    #[derive(Clone, Debug)]
    pub struct Service {
        send_channel: Arc<Mutex<mpsc::Sender<SendRequest>>>,
        receiver: Arc<Mutex<mpsc::Receiver<SendRequest>>>,
        pub config: Config,
        socket: Arc<Mutex<UdpSocket>>
    }

    #[derive(Debug, Clone)]
    pub struct SendRequest {
        pub dest: String,
        pub data: Box<[u8]>,
    }

    impl Service {
        pub async fn new(config: Config) -> Service {
            let (send_channel, receiver) = mpsc::channel::<SendRequest>(256);
            let socket = Arc::new(Mutex::new(UdpSocket::bind(config.address.clone()).await.unwrap()));

            let send_channel = Arc::new(Mutex::new(send_channel));
            let receiver = Arc::new(Mutex::new(receiver));
            Service {
                send_channel,
                receiver,
                config,
                socket
            }
        }


        pub async fn run(&self) -> io::Result<()> {
            let s = self.clone();
            let handle = tokio::spawn(async move {
                debug!("started sender thread");
                loop {
                    let packet = s.receiver.clone().lock().await.recv().await;
                    if let Some(packet) = packet {
                        debug!("Received packet via send mpsc: {:?}", packet);

                        let mut buf : Box<[u8]> = Box::new([0; 1024]);
                        let s = s.socket.lock().await;

                        s.connect(packet.dest).await.unwrap();
                        match s.send(&packet.data).await {
                            Ok(b) => debug!("sent {:?} bytes", b),
                            Err(_) => panic!("failed to send network packet"),
                        };          
                        s.recv(&mut buf);
                        debug!("Response: {:?}", buf);
                

                    } else {
                        info!("Received None Type from Udp Sender queue. This is probably a bug.");
                    }
                }
            });


            let _ = handle.await;
            Ok(())
        }
 
        pub async fn send(&self, r: SendRequest) {
            debug!(" sending Request: {:?} via mpsc", r);
            let _ = self.send_channel.clone().lock().await.send(r).await;
        }

    }

}