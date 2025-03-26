// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    framework::{
        context::{Context, Event, SimpleContext},
        module_network::{ModuleEvent, ModuleNetworkService},
    },
    monitor,
    raikou::counters::OP_COUNTERS,
};
use std::{any::Any, future::Future, sync::Arc};

pub mod context;
pub mod crypto;
pub mod injection;
pub mod module_network;
pub mod network;
pub mod tcp_network;
pub mod timer;

pub type NodeId = usize;

// Trait alias.
pub trait ContextFor<P: Protocol + ?Sized>:
    Context<Message = P::Message, TimerEvent = P::TimerEvent>
{
}

impl<P, Ctx> ContextFor<P> for Ctx
where
    P: Protocol + ?Sized,
    Ctx: Context<Message = P::Message, TimerEvent = P::TimerEvent>,
{
}

pub trait Protocol: Send + Sync {
    type Message: Clone + Send + Sync;
    type TimerEvent: Send + Sync;

    fn name(&self) -> &str;

    fn start_handler<Ctx>(&mut self, ctx: &mut Ctx) -> impl Future<Output = ()> + Send
    where
        Ctx: ContextFor<Self>;

    fn message_handler<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        from: NodeId,
        message: Self::Message,
    ) -> impl Future<Output = ()> + Send
    where
        Ctx: ContextFor<Self>;

    fn module_event_handler<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        module: module_network::ModuleId,
        event: ModuleEvent,
    ) -> impl Future<Output = ()> + Send
    where
        Ctx: ContextFor<Self>;

    fn timer_event_handler<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        event: Self::TimerEvent,
    ) -> impl Future<Output = ()> + Send
    where
        Ctx: ContextFor<Self>;

    fn condition_handler<Ctx>(&mut self, ctx: &mut Ctx) -> impl Future<Output = ()> + Send
    where
        Ctx: ContextFor<Self>;

    fn run_ctx<Ctx>(
        protocol: Arc<tokio::sync::Mutex<Self>>,
        ctx: &mut Ctx,
    ) -> impl Future<Output = ()> + Send
    where
        Ctx: ContextFor<Self>,
    {
        async move {
            let protocol_name = protocol.lock().await.name().to_string();
            let protocol_main_loop_name = protocol_name.clone() + "_main_loop";
            let protocol_lock_name = protocol_name.clone() + "_lock";
            let protocol_msg_handle_name = protocol_name.clone() + "_msg_handle";
            let protocol_tmr_handle_name = protocol_name.clone() + "_tmr_handle";
            let protocol_evt_handle_name = protocol_name.clone() + "_evt_handle";
            let protocol_cnd_handle_name = protocol_name.clone() + "_cnd_handle";

            {
                // Run the start handler and then the condition handlers
                // under the same lock so that nothing can happen in between.
                let mut lock = protocol.lock().await;
                lock.start_handler(ctx).await;
                lock.condition_handler(ctx).await;
            }

            while !ctx.halted() {
                // Listen for incoming events.
                // While waiting for an event, the lock is not held.
                let next_event = ctx.next_event().await;

                let _main_timer = OP_COUNTERS.timer(&protocol_main_loop_name);
                let mut lock = {
                    let _lock_timer = OP_COUNTERS.timer(&protocol_lock_name);
                    protocol.lock().await
                };

                match next_event {
                    Event::Message(from, message) => {
                        let _msg_timer = OP_COUNTERS.timer(&protocol_msg_handle_name);
                        lock.message_handler(ctx, from, message).await;
                    },
                    Event::Timer(event) => {
                        let _tmr_timer = OP_COUNTERS.timer(&protocol_tmr_handle_name);
                        lock.timer_event_handler(ctx, event).await;
                    },
                    Event::ModuleEvent(module, event) => {
                        let _evt_timer = OP_COUNTERS.timer(&protocol_evt_handle_name);
                        lock.module_event_handler(ctx, module, event).await;
                    },
                };

                // Run the event handler and then the condition handlers
                // under the same lock so that nothing can happen in between.
                {
                    let _cnd_timer = OP_COUNTERS.timer(&protocol_cnd_handle_name);
                    lock.condition_handler(ctx).await;
                }
            }
        }
    }

    fn run<NS, TS>(
        protocol: Arc<tokio::sync::Mutex<Self>>,
        node_id: NodeId,
        network_service: NS,
        module_network: ModuleNetworkService,
        timer: TS,
    ) -> impl Future<Output = ()> + Send
    where
        NS: network::NetworkService<Message = Self::Message>,
        TS: timer::TimerService<Event = Self::TimerEvent>,
    {
        async move {
            let mut context = SimpleContext::new(node_id, network_service, module_network, timer);
            Protocol::run_ctx(protocol, &mut context).await;
        }
    }
}

/// Should be used as follows:
/// ```ignore
/// use raikou::framework::Protocol;
/// use raikou::protocol;
///
/// impl Protocol for MyProtocol {
///     type Message = MyMessageType;
///     type TimerEvent = MyTimerEventType;
///
///     protocol! {
///         // These lines need to be written as below at the beginning.
///         self: self;
///         ctx: ctx;
///
///         // Handlers (see syntax below)
///         // Note that each handler must be followed by a semicolon.
///
///         // Start handler executes once, upon starting the node.
///         upon start {
///             ...
///         };
///
///         // Handlers for messages received from other nodes.
///         upon receive [MESSAGE_PATTERN] from [SENDER_PATTERN] {
///            ...
///         };
///
///         // Handlers for timer events.
///         upon timer [TIMER_PATTERN] {
///             ...
///         };
///
///         // Conditional handlers are executed in a loop until the condition is false
///         // each time after receiving a message or a timer event.
///         upon [CONDITION] {
///             ...
///         };
///
///         // You can specify a variable number of conditional handlers at once.
///         for [VAR in RANGE]
///         upon [CONDITION] {
///             ...
///         };
///     }
/// }
/// ```
#[macro_export]
macro_rules! protocol {
    (
        /// $self must be "self" and nothing else.
        /// $ctx is the name for the context variable passed to the handlers.
        self: $self:ident;
        ctx: $ctx:ident;

        $(
            // Start handler executes once, upon starting the node.
            $(upon start $($start_label:lifetime:)? $start_handler:block)?
            // Handlers for messages received from other nodes.
            $(upon receive [$msg_pat:pat] from $(node)? [$from_pat:pat] $(if [$msg_cond:expr])? $($msg_label:lifetime:)? $msg_handler:block)?
            // Handlers for events received from other modules on the same node.
            $(upon $(module)? event of type [$module_event_type:ty] from $(module)? [$module_pat:pat] {
                $(upon [$module_event_pat:pat]  $(if [$module_event_cond:expr])? $($module_event_label:lifetime:)? $module_event_handler:block;)*
            })?
            // Handlers for timer events.
            $(upon timer $(event)? [$timer_pat:pat] $(if [$timer_cond:expr])?  $($timer_label:lifetime:)? $timer_handler:block)?
            // Conditional handlers are executed in a loop until the condition is false
            // each time after a receiving a message or a timer event.
            $(upon [$cond:expr] $(if [$cond_cond:expr])? $($cond_label:lifetime:)? $cond_handler:block)?
            $(for [$cond_loop_var:ident in $cond_loop_range:expr] upon [$cond_loop_cond:expr] $($cond_loop_label:lifetime:)? $cond_loop_handler:block)?
            // Due to some limitations of the declarative macro system,
            // every handler must be followed by a semicolon.
            ;
        )*
    ) => {
        async fn start_handler<Ctx>(&mut $self, $ctx: &mut Ctx)
        where
            Ctx: crate::framework::ContextFor<Self>,
        {
            let _ = $ctx;  // suppress unused variable warning
            $(
                $(
                    $($start_label:)? {
                        $start_handler;
                    }
                )?
            )*
        }

        async fn message_handler<Ctx>(&mut $self, $ctx: &mut Ctx, from: NodeId, message: Self::Message)
        where
            Ctx: crate::framework::ContextFor<Self>
        {
            let _ = $ctx;  // suppress unused variable warning
            match (from, message) {
                $(
                    $(
                        ($from_pat, $msg_pat) $(if $msg_cond)? => $($msg_label:)? {
                            $msg_handler;
                        },
                    )?
                )*
            }
        }

        async fn module_event_handler<Ctx>(
            &mut $self,
            $ctx: &mut Ctx,
            module: crate::framework::module_network::ModuleId,
            event: crate::framework::module_network::ModuleEvent,
        )
        where
            Ctx: crate::framework::ContextFor<Self>
        {
            let _ = $ctx;  // suppress unused variable warning
            let _ = &module;  // suppress unused variable warning

            match module {
                $(
                    $(
                        $module_pat if crate::framework::module_network::match_event_type::<$module_event_type>(
                            &event
                        ) => {

                            let event = event.as_any().downcast::<$module_event_type>().ok().unwrap();

                            match *event {
                                $(
                                    $module_event_pat $(if $module_event_cond)? => $($module_event_label:)? {
                                        $module_event_handler;
                                    },
                                )*
                            }
                        },
                    )?
                )*
                _ => {
                    panic!("Unhandled module event: {}", event.debug_string());
                }
            }
        }

        async fn timer_event_handler<Ctx>(&mut $self, $ctx: &mut Ctx, event: Self::TimerEvent)
        where
            Ctx: crate::framework::ContextFor<Self>
        {
            let _ = $ctx;  // suppress unused variable warning

            match event {
                $(
                    $(
                        $timer_pat $(if $timer_cond)? => $($timer_label:)? {
                            $timer_handler;
                        },
                    )?
                )*
            }
        }

        async fn condition_handler<Ctx>(&mut $self, $ctx: &mut Ctx)
        where
            Ctx: crate::framework::ContextFor<Self>
        {
            let _ = $ctx;  // suppress unused variable warning

            let mut n_hits: u64 = 0;
            let mut was_hit = true;

            while was_hit && !$ctx.halted() {
                was_hit = false;
                let mut hit = || {
                    was_hit = true;
                    n_hits += 1;
                    if n_hits % 100_000 == 0 {
                        aptos_logger::warn!("Condition handler looped {} times. \
                        Possible infinite loop.", n_hits);
                    }
                };
                let _ = &mut hit;  // suppress unused variable warning

                $(
                    $(
                        while !$ctx.halted() && $cond $(&& $cond_cond)? {
                            hit();
                            $($cond_label:)? {
                                $cond_handler;
                            }
                        }
                    )?
                )*
                $(
                    $(
                        for $cond_loop_var in $cond_loop_range {
                            while !$ctx.halted() && $cond_loop_cond {
                                hit();
                                $($cond_loop_label:)? {
                                    $cond_loop_handler;
                                }
                            }
                        }
                    )?
                )*
            }
        }
    }
}
