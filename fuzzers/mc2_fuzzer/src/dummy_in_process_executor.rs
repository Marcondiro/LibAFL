use core::{
    borrow::BorrowMut,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::{ObserversTuple, UsesObservers},
    state::{HasClientPerfMonitor, UsesState},
    Error,
};

/// The inmem executor simply calls a target function, then returns afterwards.
pub struct DummyInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: HB,
    /// The observers, observing each run
    observers: OT,
    // Crash and timeout hah
    phantom: PhantomData<(S, *const H)>,
}

impl<H, HB, OT, S> Debug for DummyInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DummyInProcessExecutor")
            .field("harness_fn", &"<fn>")
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}

impl<H, HB, OT, S> UsesState for DummyInProcessExecutor<H, HB, OT, S>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    type State = S;
}

impl<H, HB, OT, S> UsesObservers for DummyInProcessExecutor<H, HB, OT, S>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    type Observers = OT;
}

impl<EM, H, HB, OT, S, Z> Executor<EM, Z> for DummyInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    EM: UsesState<State = S>,
    OT: ObserversTuple<S>,
    S: UsesInput,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        Ok((self.harness_fn.borrow_mut())(input))
    }
}

impl<H, HB, OT, S> HasObservers for DummyInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: UsesInput,
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

impl<H, HB, OT, S> DummyInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&<S as UsesInput>::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: HasClientPerfMonitor + UsesInput,
{
    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `harness_fn` - the harness, executing the function
    /// * `observers` - the observers observing the target during execution
    /// This may return an error on unix, if signal handler setup fails
    pub fn new<EM, OF, Z>(
        harness_fn: HB,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        Z: HasObjective<Objective = OF, State = S>, // TODO : should we keep it?
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
        self.harness_fn.borrow()
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness_fn.borrow_mut()
    }
}
