use std::future::Future;

use tokio::select;

use crate::framework::{network::NetworkService, NodeId, timer::TimerService};
use crate::framework::module_network::{ModuleEvent, ModuleId, ModuleNetworkService};

pub enum Event<M, TE> {
    Message(NodeId, M),
    Timer(TE),
    ModuleEvent(ModuleId, ModuleEvent),
}

pub trait Context: Send + Sync {
    type Message: Clone + Send + Sync;
    type TimerEvent;

    fn node_id(&self) -> NodeId;

    fn n_nodes(&self) -> usize;

    // Unicast sends the message to a single node.
    fn unicast(&self, message: Self::Message, target: NodeId) -> impl Future<Output = ()> + Send;

    /// Multicast sends the same message to all nodes in the network.
    fn multicast(&self, message: Self::Message) -> impl Future<Output = ()> + Send {
        async move {
            for target in 0..self.n_nodes() {
                self.unicast(message.clone(), target).await;
            }
        }
    }

    fn notify<E>(&self, module: ModuleId, event: E) -> impl Future<Output = ()> + Send
    where
        E: Send + 'static,
    {
        self.notify_boxed(module, Box::new(event))
    }

    fn notify_boxed(&self, module: ModuleId, event: ModuleEvent) -> impl Future<Output = ()> + Send;

    fn set_timer(&mut self, duration: std::time::Duration, event: Self::TimerEvent);

    fn halt(&mut self);

    fn halted(&self) -> bool;

    fn next_event(&mut self)
        -> impl Future<Output = Event<Self::Message, Self::TimerEvent>> + Send;
}

// impl<'a, Ctx: Context> Context for &'a mut Ctx {
//     type Message = Ctx::Message;
//     type TimerEvent = Ctx::TimerEvent;
//
//     fn node_id(&self) -> NodeId {
//         (**self).node_id()
//     }
//
//     fn n_nodes(&self) -> usize {
//         (**self).n_nodes()
//     }
//
//     async fn unicast(&self, message: Self::Message, target: NodeId) {
//         (**self).unicast(message, target).await;
//     }
//
//     async fn multicast(&self, message: Self::Message) {
//         (**self).multicast(message).await;
//     }
//
//     async fn next_event(&mut self) -> Event<Self::Message, Self::TimerEvent> {
//         (**self).next_event().await
//     }
// }


pub struct SimpleContext<NS, TS> {
    id: NodeId,
    network: NS,
    module_network: ModuleNetworkService,
    timer: TS,
    halted: bool,
}

impl<NS: NetworkService, TS: TimerService> SimpleContext<NS, TS> {
    pub fn new(id: NodeId, network: NS, module_network: ModuleNetworkService, timer: TS) -> Self {
        SimpleContext {
            id,
            network,
            module_network,
            timer,
            halted: false,
        }
    }
}

impl<NS: NetworkService, TS: TimerService> Context for SimpleContext<NS, TS> {
    type Message = <NS as NetworkService>::Message;
    type TimerEvent = <TS as TimerService>::Event;

    fn node_id(&self) -> NodeId {
        self.id
    }

    fn n_nodes(&self) -> usize {
        self.network.n_nodes()
    }

    async fn unicast(&self, message: Self::Message, target: NodeId) {
        self.network.send(target, message).await;
    }

    async fn notify_boxed(&self, module: ModuleId, event: ModuleEvent) {
        self.module_network.send(module, event).await;
    }

    fn set_timer(&mut self, duration: std::time::Duration, event: Self::TimerEvent) {
        self.timer.schedule(duration, event);
    }

    fn halt(&mut self) {
        self.halted = true;
    }

    fn halted(&self) -> bool {
        self.halted
    }

    async fn next_event(&mut self) -> Event<Self::Message, Self::TimerEvent> {
        select! {
            (from, message) = self.network.recv() => {
                Event::Message(from, message)
            },
            timer_event = self.timer.tick() => {
                Event::Timer(timer_event)
            },
            (module, notification) = self.module_network.recv() => {
                Event::ModuleEvent(module, notification)
            }
        }
    }
}
