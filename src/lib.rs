pub(crate) mod cap_table;
pub(crate) mod packet_types;

pub mod capabilities;
pub mod object;
pub mod service;
pub mod config;

pub(crate) const MEMCOPY_BUFFER_SIZE: usize = 4096;

// export objects in crate base mod
#[allow(unused_imports)]
use config::Config;
#[allow(unused_imports)]
use object::tcap::object::RequestObject;
#[allow(unused_imports)]
use capabilities::tcap::Capability;

pub mod tcap {
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use crate::capabilities::tcap::Capability;
    
    #[allow(unused)]
    pub type HandlerParameters = Vec<Option<Arc<Mutex<Capability>>>>;
}
