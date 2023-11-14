pub mod capabilities;
pub mod packet_types;
pub mod service;

use log::*;
use simple_logger::SimpleLogger;

use clap::Parser;

use crate::capabilities::tcap::*;
use crate::packet_types::tcap::*;
use crate::service::tcap::*;

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    /// The Network Interface to bind
    #[arg(short, long)]
    interface: String,

    /// Address to bind to (including port number)
    #[arg(short, long)]
    address: String,

    /// Address of the switch control plane (including port number)
    #[arg(short, long)]
    switch_addr: String,
}

impl Config {
    fn clone(&self) -> Self {
        Self {
            interface: self.interface.clone(),
            address: self.address.clone(),
            switch_addr: self.switch_addr.clone(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    SimpleLogger::new().init().unwrap();

    let conf: Config = Config::parse();
    let service = Service::new(conf.clone()).await;
    let s = service.clone();
    let service_handle = tokio::spawn(async move {
        debug!("starting service thread");
        let _ = s.run().await.unwrap();
    });

    debug!("starting tcap-rs main");
    service_handle.await.unwrap();
    Ok(())
}

mod tests {
    use log::debug;
    use simple_logger::SimpleLogger;

    use crate::{Config, service::tcap::Service, capabilities::tcap::Capability, packet_types::tcap::IpAddress};

    #[tokio::test]
    async fn test_delegate() {
        SimpleLogger::new().init().unwrap();

        let conf: Config = Config { interface: "veth250".to_string(), address:"10.0.0.9:2234".to_string(), switch_addr: "10.0.0.1".to_string() };
        let service = Service::new(conf.clone()).await;
        let s = service.clone();
        let service_handle = tokio::spawn(async move {
            debug!("starting service thread");
            let _ = s.run().await.unwrap();
        });
    
        debug!("starting tcap-rs main");
        let c1 = Capability::create().await;
        debug!("created cap c1: {:?}", c1);
    
        let _ = c1.delegate(service, IpAddress::from("10.0.0.9:1234")).await;
    
        debug!("delegation of c1 finished");
    
        service_handle.await.unwrap();
        ()
    }
}