use clap::Parser;

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// The Network Interface to bind
    #[arg(short, long)]
    pub interface: String,

    /// Address to bind to (including port number)
    #[arg(short, long)]
    pub address: String,

    /// Address of the switch control plane (including port number)
    #[arg(short, long)]
    pub switch_addr: String,
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