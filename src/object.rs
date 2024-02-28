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
            pub(crate) data: Vec<u8>
        }
        
        impl From<MemoryCopyResponseHeader> for MemoryObject {
            fn from(value: MemoryCopyResponseHeader) -> Self {
                MemoryObject {
                    is_local: true,
                    size: value.size,
                    data: value.buffer.to_vec(),
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
                data: Vec<u8>,
            ) -> MemoryObject {
                let size: u64 = data.len() as u64;

                MemoryObject {
                    is_local: true,
                    cap: None,
                    size: size,
                    data
                }
            }

            pub async fn is_local(&self) -> bool {
                self.is_local
            }

            pub(crate) fn set_cap(&mut self, c: Capability) {
                self.cap = Some(c);
            }

            pub fn data(&self) -> Vec<u8> {
                self.data.clone()
            }

            pub(crate) fn append(&mut self, value: MemoryCopyResponseHeader) {
                //TODO (@jkrbs): Check if cap is correct and all other field match
                let extend = &value.buffer[..value.size as usize];
                self.data.extend(extend);
                self.size += value.size;
            }
        }
    }
}
