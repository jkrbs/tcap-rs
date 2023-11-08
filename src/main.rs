pub mod packet_types;
pub mod capabilities;

use log::*;
use simple_logger::SimpleLogger;


use crate::capabilities::tcap::*;
use crate::packet_types::tcap::*;

#[tokio::main]
async fn main() -> Result<(), ()> {
    SimpleLogger::new().init().unwrap();

    debug!("starting tcap-rs main");
    let c1 = Capability::create().await;
    debug!("created cap c1: {:?}", c1);
    let _ = c1.delegate(IpAddress::from("192.168.122.217:1002")).await;
    debug!("delegation of c1 finished");
    Ok(())
}
