pub mod tcap {
    pub mod object {
        use core::fmt;
        use log::debug;
        use tokio::sync::Mutex;
        use std::sync::Arc;

        //TODO (@jkrbs): Refactor into Object Trait and multiple object types for Memory and Requests at least
        use crate::{capabilities::tcap::Capability, packet_types::tcap::MemoryCopyResponseHeader};

        pub struct RequestObject {
            is_local: bool,
            pub(crate) cap: Option<Capability>,
            function: Box<dyn Fn(Vec<Option<Arc<Mutex<Capability>>>>) -> Result<(), ()> + Send + Sync>,
        }

        impl fmt::Debug for RequestObject {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("RequestObject")
                    .field("is_local", &self.is_local)
                    .field("cap", &self.cap)
                    .finish()
            }
        }

        impl RequestObject {
            pub async fn new(
                function: Box<dyn Fn(Vec<Option<Arc<Mutex<Capability>>>>) -> Result<(), ()> + Send + Sync>,
            ) -> RequestObject {
                RequestObject {
                    is_local: true,
                    cap: None,
                    function,
                }
            }

            pub async fn is_local(&self) -> bool {
                self.is_local
            }

            pub fn set_cap(&mut self, c: Capability) {
                self.cap = Some(c);
            }

            pub async fn invoke(&self, continuations: Vec<Option<Arc<Mutex<Capability>>>>) -> Result<(), ()> {
                debug!("invoking Request Object");
                if self.is_local {
                    debug!("Calling RequestObject Function");
                    return self.function.as_ref()(continuations);
                } else {
                    return self.cap.as_ref().unwrap().request_invoke_with_continuation(continuations.iter().map(|c| {
                        match c {
                            Some(c) => c.blocking_lock().cap_id,
                            None => 0,
                        }
                    }).collect()).await;
                }
            }
        }

        pub struct MemoryObject {
            is_local: bool,
            pub(crate) cap: Option<Capability>,
            pub(crate) size: u64,
            pub(crate) data: [u8;1024]
        }
        
        impl From<MemoryCopyResponseHeader> for MemoryObject {
            fn from(value: MemoryCopyResponseHeader) -> Self {
                MemoryObject {
                    is_local: true,
                    size: value.size,
                    data: value.buffer,
                    cap: None
                }
            }
        }

        impl fmt::Debug for MemoryObject {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("MemoryObject")
                    .field("is_local", &self.is_local)
                    .field("cap", &self.cap)
                    .finish()
            }
        }

        impl MemoryObject {
            pub async fn new(
                buf: &[u8],
            ) -> MemoryObject {
                if buf.len() > 1024 {
                    panic!("Currently only 1KiB Memory Regions are supported")
                }

                let mut data: [u8; 1024] = [0;1024];
                let size = 1024.min(buf.len());
                data[0..size].clone_from_slice(buf);

                MemoryObject {
                    is_local: true,
                    cap: None,
                    size: size as u64,
                    data
                }
            }

            pub async fn is_local(&self) -> bool {
                self.is_local
            }

            pub fn set_cap(&mut self, c: Capability) {
                self.cap = Some(c);
            }
        }
    }
}
