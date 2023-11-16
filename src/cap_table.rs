pub mod tcap {
    pub(crate) mod cap_table {
        use std::{collections::HashMap, sync::Arc};

        use log::debug;
        use tokio::sync::Mutex;

        use crate::capabilities::tcap::Capability;

        type CapID = u64;

        #[derive(Debug, Clone)]
        pub(crate) struct CapTable {
            caps: Arc<Mutex<HashMap<CapID, Arc<Mutex<Capability>>>>>,
        }

        impl CapTable {
            pub(crate) async fn new() -> Self {
                let caps = Arc::new(Mutex::new(HashMap::new()));

                Self { caps }
            }

            pub(crate) async fn insert(&self, cap: Arc<Mutex<Capability>>) {
                let id = cap.lock().await.cap_id;
                self.caps.lock().await.insert(id, cap);
                debug!("Inserted capID {:?} into table", id);
            }

            pub(crate) async fn remove(&self, cap_id: CapID) {
                self.caps.lock().await.remove(&cap_id);
                debug!("Removed capID {:?} from table", cap_id);
            }

            pub(crate) async fn get_capids(&self) -> Vec<CapID> {
                self.caps.lock().await.keys().cloned().collect()
            }

            pub(crate) async fn contains(&self, cap_id: CapID) -> bool {
                self.caps.lock().await.contains_key(&cap_id)
            }

            pub(crate) async fn get(&self, id: CapID) -> Option<Arc<Mutex<Capability>>> {
                match self.caps.lock().await.get(&id) {
                    Some(cap) => Some(cap.clone()),
                    None => None,
                }
            }
        }
    }
}
