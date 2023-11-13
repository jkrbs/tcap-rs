pub mod packet_types;
pub mod service;
pub mod capabilities;

use log::*;
use simple_logger::SimpleLogger;

use clap::Parser;

use crate::service::tcap::*;
use crate::capabilities::tcap::*;
use crate::packet_types::tcap::*;

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    /// The Network Interface to bind 
    #[arg(short, long)]
    interface: String,

    /// Address to bind to (including port number)
    #[arg(short, long)]
    address: String,
}

impl Config {
    fn clone(&self) -> Self {
        Self { interface: self.interface.clone(), address: self.address.clone()}
    }
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    SimpleLogger::new().init().unwrap();

    let conf: Config = Config::parse();
    let service= Service::new(conf.clone()).await;
    let s = service.clone();
    let service_handle = tokio::spawn(async move {
        s.run().await.unwrap();
    });

    debug!("starting tcap-rs main");
    let c1 = Capability::create().await;
    debug!("created cap c1: {:?}", c1);

    let _ = c1.delegate(conf, IpAddress::from("10.0.0.9:1002")).await;

    debug!("delegation of c1 finished");

    service_handle.await.unwrap();
    Ok(())
}
