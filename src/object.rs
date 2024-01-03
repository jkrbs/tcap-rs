pub mod tcap {
    pub mod object {
        use core::fmt;
        use std::collections::HashMap;

        use log::{debug, info};
        use tokio::sync::mpsc;
        use tokio::sync::Mutex;
        use std::sync::Arc;

        //TODO (@jkrbs): Refactor into Object Trait and multiple object types for Memory and Requests at least
        use crate::{capabilities::tcap::Capability, service::tcap::Service};

        pub struct RequestObject {
            is_local: bool,
            pub(crate) cap: Option<Capability>,
            function: Box<dyn Fn(Option<Arc<Mutex<Capability>>>) -> Result<(), ()> + Send + Sync>,
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
                function: Box<dyn Fn(Option<Arc<Mutex<Capability>>>) -> Result<(), ()> + Send + Sync>,
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

            pub async fn invoke(&self, continuation: Option<Arc<Mutex<Capability>>>) -> Result<(), ()> {
                debug!("invoking Request Object");
                if self.is_local {
                    debug!("Calling RequestObject Function");
                    return self.function.as_ref()(continuation);
                } else {
                    return self.cap.as_ref().unwrap().request_invoke().await;
                }
            }
        }

        struct ObjectTable {
            objects: HashMap<u64, RequestObject>,
            pipeline: mpsc::Receiver<u64>,
        }

        impl ObjectTable {
            pub(crate) async fn run(&self) {}
        }
    }
}
