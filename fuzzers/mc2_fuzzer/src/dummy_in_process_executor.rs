use core::fmt;
use core::marker::PhantomData;

use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    inputs::Input,
    observers::ObserversTuple,
    prelude::{EventFirer, EventRestarter, UsesInput, UsesState},
    Error, HasObjective,
};

/// The inmem executor simply calls a target function, then returns afterwards.
pub struct DummyInProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    S: UsesInput,
    OT: ObserversTuple<S>,
{
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: &'a mut H,
    /// The observers, observing each run
    observers: OT,
    phantom: PhantomData<(I, S)>,
}

impl<'a, H, OT, S, I> UsesState for DummyInProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    type State = S;
}

impl<'a, EM, H, I, OT, S, Z> Executor<EM, Z> for DummyInProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<S>,
{
    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        (self.harness_fn)(input)
    }
}

impl<'a, H, I, OT, S> HasObservers for DummyInProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<S>,
{
    #[inline]
    fn observers(&self) -> &OT {
        &self.observers
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<'a, H, I, OT, S> DummyInProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<S>,
{
    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `harness_fn` - the harness, executiong the function
    /// * `observers` - the observers observing the target during execution
    /// This may return an error on unix, if signal handler setup fails
    pub fn new<EM, OC, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer + EventRestarter,
        OF: Feedback<S>,
        Z: HasObjective,
    {
        Ok(Self {
            harness_fn,
            observers,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> &H {
        self.harness_fn
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness_fn
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DummyInProcessExecutor")
            .field("harness_fn", &"<fn>")
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}
