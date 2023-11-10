pub mod packet_types;
pub mod capabilities;

use log::*;
use simple_logger::SimpleLogger;

use clap::Parser;

use crate::capabilities::tcap::*;
use crate::packet_types::tcap::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Config {
    /// The Network Interface to bind 
    #[arg(short, long)]
    interface: String,

    /// Address to bind to (including port number)
    #[arg(short, long)]
    address: String,
}


#[tokio::main]
async fn main() -> Result<(), ()> {
    SimpleLogger::new().init().unwrap();

    let conf: Config = Config::parse();

    debug!("starting tcap-rs main");
    let c1 = Capability::create().await;
    debug!("created cap c1: {:?}", c1);
    let _ = c1.delegate(conf, IpAddress::from("192.168.122.217:1002")).await;
    debug!("delegation of c1 finished");
    Ok(())
}
