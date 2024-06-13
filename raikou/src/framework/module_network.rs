use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleId(usize);

impl ModuleId {
    pub fn next(&self) -> Self {
        ModuleId(self.0 + 1)
    }

    /// Returns the first dynamic module ID.
    /// This and higher module IDs are reserved for
    pub fn first_dynamic() -> Self {
        ModuleId(1_000_000_000)
    }
}

pub type ModuleEvent = Box<dyn Send + std::any::Any + 'static>;

pub struct ModuleNetwork {
    send: Arc<RwLock<BTreeMap<ModuleId, mpsc::Sender<(ModuleId, ModuleEvent)>>>>,
    next_id: ModuleId,
}

impl ModuleNetwork {
    pub fn new() -> Self {
        ModuleNetwork {
            send: Arc::new(tokio::sync::RwLock::new(BTreeMap::new())),
            next_id: ModuleId::first_dynamic(),
        }
    }

    pub async fn register(&mut self) -> ModuleNetworkService {
        let module = self.next_id;
        self.next_id = ModuleId(module.0 + 1);
        self.register_with_id(module).await
    }

    pub async fn register_with_id(&mut self, module: ModuleId) -> ModuleNetworkService {
        match self.send.write().await.entry(module) {
            Entry::Occupied(_) => panic!("Module id {:?} already registered", module),
            Entry::Vacant(entry) => {
                let (send, recv) = tokio::sync::mpsc::channel(100);
                entry.insert(send);

                ModuleNetworkService {
                    module_id: module,
                    send: self.send.clone(),
                    receive: recv,
                }
            }
        }
    }
}

pub struct ModuleNetworkService {
    module_id: ModuleId,
    send: Arc<RwLock<BTreeMap<ModuleId, mpsc::Sender<(ModuleId, ModuleEvent)>>>>,
    receive: mpsc::Receiver<(ModuleId, ModuleEvent)>,
}

impl ModuleNetworkService {
    pub fn module_id(&self) -> ModuleId {
        self.module_id
    }

    pub async fn send(&self, module: ModuleId, event: ModuleEvent) {
        self.send.read().await[&module].send((self.module_id, event)).await.unwrap();
    }

    pub async fn recv(&mut self) -> (ModuleId, ModuleEvent) {
        self.receive.recv().await.unwrap()
    }
}
