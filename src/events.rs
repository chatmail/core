//! # Events specification.

use anyhow::Result;
use tokio::sync::Mutex;

pub(crate) mod chatlist_events;
mod payload;

pub use self::payload::EventType;

/// Event channel.
#[derive(Debug, Clone)]
pub struct Events {
    /// Unused receiver to prevent the channel from closing.
    _receiver: async_broadcast::InactiveReceiver<Event>,

    /// Sender side of the event channel.
    sender: async_broadcast::Sender<Event>,
}

impl Default for Events {
    fn default() -> Self {
        Self::new()
    }
}

impl Events {
    /// Creates a new event channel.
    pub fn new() -> Self {
        let (mut sender, _receiver) = async_broadcast::broadcast(10_000);

        // We only keep this receiver around
        // to prevent the channel from closing.
        // Deactivating it to prevent it from consuming memory
        // holding events that are not going to be received.
        let _receiver = _receiver.deactivate();

        // Remove oldest event on overflow.
        sender.set_overflow(true);

        Self { _receiver, sender }
    }

    /// Emits an event into event channel.
    ///
    /// If the channel is full, deletes the oldest event first.
    pub fn emit(&self, event: Event) {
        self.sender.try_broadcast(event).ok();
    }

    /// Creates an event emitter.
    pub fn get_emitter(&self) -> EventEmitter {
        EventEmitter(Mutex::new(self.sender.new_receiver()))
    }
}

/// A receiver of events from a [`Context`].
///
/// See [`Context::get_event_emitter`] to create an instance.  If multiple instances are
/// created events emitted by the [`Context`] will only be delivered to one of the
/// `EventEmitter`s.
///
/// [`Context`]: crate::context::Context
/// [`Context::get_event_emitter`]: crate::context::Context::get_event_emitter
#[derive(Debug)]
pub struct EventEmitter(Mutex<async_broadcast::Receiver<Event>>);

impl EventEmitter {
    /// Async recv of an event. Return `None` if the `Sender` has been dropped.
    ///
    /// [`try_recv`]: Self::try_recv
    pub async fn recv(&self) -> Option<Event> {
        let mut lock = self.0.lock().await;
        match lock.recv().await {
            Err(async_broadcast::RecvError::Overflowed(n)) => Some(Event {
                id: 0,
                typ: EventType::EventChannelOverflow { n },
            }),
            Err(async_broadcast::RecvError::Closed) => None,
            Ok(event) => Some(event),
        }
    }

    /// Tries to receive an event without blocking.
    ///
    /// Returns error if no events are available for reception
    /// or if receiver mutex is locked by a concurrent call to [`recv`]
    /// or `try_recv`.
    ///
    /// [`recv`]: Self::recv
    pub fn try_recv(&self) -> Result<Event> {
        // Using `try_lock` instead of `lock`
        // to avoid blocking
        // in case there is a concurrent call to `recv`.
        let mut lock = self.0.try_lock()?;
        match lock.try_recv() {
            Err(async_broadcast::TryRecvError::Overflowed(n)) => {
                // Some events have been lost,
                // but the channel is not closed.
                Ok(Event {
                    id: 0,
                    typ: EventType::EventChannelOverflow { n },
                })
            }
            res @ (Err(async_broadcast::TryRecvError::Empty)
            | Err(async_broadcast::TryRecvError::Closed)
            | Ok(_)) => Ok(res?),
        }
    }
}

/// The event emitted by a [`Context`] from an [`EventEmitter`].
///
/// Events are documented on the C/FFI API in `deltachat.h` as `DC_EVENT_*` constants.  The
/// context emits them in relation to various operations happening, a lot of these are again
/// documented in `deltachat.h`.
///
/// [`Context`]: crate::context::Context
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The ID of the [`Context`] which emitted this event.
    ///
    /// This allows using multiple [`Context`]s in a single process as they are identified
    /// by this ID.
    ///
    /// [`Context`]: crate::context::Context
    pub id: u32,
    /// The event payload.
    ///
    /// These are documented in `deltachat.h` as the `DC_EVENT_*` constants.
    pub typ: EventType,
}
