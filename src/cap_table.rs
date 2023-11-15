pub mod tcap {
    pub(crate) mod cap_table {
        use std::{collections::HashMap, sync::Arc};

        use log::debug;
        use tokio::sync::Mutex;

        use crate::capabilities::tcap::Capability;

        type CapID = u64;

        #[derive(Debug, Clone)]
        pub(crate) struct CapTable {
            caps: Arc<Mutex<HashMap<CapID, Capability>>>,
        }

        impl CapTable {
            pub(crate) async fn new() -> Self {
                let caps = Arc::new(Mutex::new(HashMap::new()));

                Self { caps }
            }

            pub(crate) async fn insert(&self, cap: Capability) {
                self.caps.lock().await.insert(cap.cap_id, cap);
                debug!("Inserted capID {:?} into table", cap.cap_id);
            }

            pub(crate) async fn remove(&self, cap_id: CapID) {
                self.caps.lock().await.remove(&cap_id);
                debug!("Removed capID {:?} from table", cap_id);
            }

            pub(crate) async fn get_capids(&self) -> Vec<CapID> {
                self.caps.lock().await.keys().cloned().collect()
            }
        }
    }
}
