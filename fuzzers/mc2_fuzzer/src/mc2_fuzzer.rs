use crate::dummy_in_process_executor;
use crate::mc2_state::{Hyperrectangle, Mc2State};
use crate::BranchCmp;
use crate::Predicate;
use crate::BRANCH_CMP;

use core::marker::PhantomData;
use core::time::Duration;

use libafl::{
    bolts::rands::Rand,
    events::ProgressReporter,
    executors::{Executor, ExitKind},
    inputs::BytesInput,
    prelude::{current_time, Monitor, SimpleEventManager, UsesInput, UsesState},
    Error,
};

const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

// Number of execution of the harness for each fuzz_loop
const EXECUTION_NUMBER: usize = 5;

pub struct Mc2Fuzzer<R> {
    is_left: bool,
    p: f64,
    phantom: PhantomData<R>,
}

impl<R> UsesState for Mc2Fuzzer<R>
where
    R: Rand,
{
    type State = Mc2State<R>;
}

impl<R> Mc2Fuzzer<R> {
    pub fn new(p: f64) -> Self {
        Self {
            is_left: false,
            p,
            phantom: PhantomData,
        }
    }

    /**
     * It is the actual core of the MC2 fuzzer
     */
    pub fn fuzz_loop<H, OT: libafl::observers::ObserversTuple<Mc2State<R>>, MT>(
        &mut self,
        executor: &mut dummy_in_process_executor::DummyInProcessExecutor<H, OT, Mc2State<R>>,
        state: &mut Mc2State<R>,
        manager: &mut SimpleEventManager<MT, Mc2State<R>>,
    ) -> Result<(), Error>
    where
        R: Rand,
        H: FnMut(&<Mc2State<R> as UsesInput>::Input) -> ExitKind + ?Sized,
        MT: Monitor,
    {
        let mut last = current_time();
        let monitor_timeout = STATS_TIMEOUT_DEFAULT;

        while !state.terminate_search() {
            // find a group to split
            let (group_index, w_l) = state.find_group();

            // split the group in two group of the same dimension
            state.split_group(group_index);

            // Execute the harness
            self.noisy_counting_oracle(
                &state.get_hyperrectangles(group_index).clone(),
                &state.get_hyperrectangles(group_index + 1).clone(),
                executor,
                state,
                manager,
            )?;

            let z = if self.is_left {
                (w_l + state.get_weight(group_index)) * (1.0 - self.p) + (1.0 - w_l) * self.p
            } else {
                (w_l + state.get_weight(group_index)) * self.p + (1.0 - w_l) * (1.0 - self.p)
            };

            // update the weight of the groups
            state.update_weights(group_index, self.p, z, self.is_left);

            last = manager.maybe_report_progress(state, last, monitor_timeout)?;
        }

        Ok(())
    }

    /**
     * This function executes the harness for two given hyperrecangle.
     * After the counting_helper is called for each hyperrectangle, it
     * computes the probability for each hyperrectangle.
     */
    fn noisy_counting_oracle<H, OT, MT>(
        &mut self,
        i_l: &Hyperrectangle,
        i_r: &Hyperrectangle,
        executor: &mut dummy_in_process_executor::DummyInProcessExecutor<H, OT, Mc2State<R>>,
        state: &mut Mc2State<R>,
        manager: &mut SimpleEventManager<MT, Mc2State<R>>,
    ) -> Result<(), Error>
    where
        H: FnMut(&<Mc2State<R> as UsesInput>::Input) -> ExitKind + ?Sized,
        OT: libafl::observers::ObserversTuple<Mc2State<R>>,
        R: Rand,
    {
        self.counting_helper(i_l, executor, state, manager)?;
        let mut i_l_count = 1.0;
        for val in BRANCH_CMP.lock().unwrap().values() {
            let tmp_count = Mc2Fuzzer::<R>::compute_prob(val);
            if i_l_count > tmp_count {
                i_l_count = tmp_count;
            }
        }

        self.counting_helper(i_r, executor, state, manager)?;
        let mut i_r_count = 1.0;
        for val in BRANCH_CMP.lock().unwrap().values() {
            let tmp_count = Mc2Fuzzer::<R>::compute_prob(val);
            if i_r_count > tmp_count {
                i_r_count = tmp_count;
            }
        }

        self.is_left = i_l_count >= i_r_count;
        Ok(())
    }

    /**
     * This function executes the haress for the given hyperrectangel.
     * The harness is executed EXECUTION_NUMBER times in order to reduce
     * the error of the sample mean an variance.
     * For each execution, a random input sample is selected within the
     * given hyperrectangle.
     */
    fn counting_helper<H, OT: libafl::observers::ObserversTuple<Mc2State<R>>, MT>(
        &mut self,
        h: &Hyperrectangle,
        executor: &mut dummy_in_process_executor::DummyInProcessExecutor<H, OT, Mc2State<R>>,
        state: &mut Mc2State<R>,
        manager: &mut SimpleEventManager<MT, Mc2State<R>>,
    ) -> Result<(), Error>
    where
        H: FnMut(&<Mc2State<R> as UsesInput>::Input) -> ExitKind + ?Sized,
        R: Rand,
    {

        // Clear the global data structure to store the statistics
        // for the current execution
        BRANCH_CMP.lock().unwrap().clear();

        for _ in 0..EXECUTION_NUMBER {
            // Generate the input for the current execution
            // picking a value within the given hyperrectangle
            let mut tmp_input = Vec::new();
            for i in 0..h.intervals.len() {
                #[allow(clippy::cast_possible_truncation)]
                tmp_input.push(
                    (state.get_rand_byte() as u16
                        % (h.intervals[i].high as u16 - h.intervals[i].low as u16 + 1)
                        + h.intervals[i].low as u16) as u8,
                );
            }

            let input = BytesInput::new(tmp_input);
            // execute the target
            executor.run_target(self, state, manager, &input)?;
        }

        Ok(())
    }

    /**
     * After the harness is executed EXECUTION_NUMBER times (updating the BranchCmp data
     * structure), this function is called to compute the probability that the current
     * hypperrectanle contains the target.
     */
    fn compute_prob(branch_compare: &BranchCmp) -> f64 {
        if branch_compare.sat > 0 {
            // if the branch is satisfied
            return branch_compare.sat as f64 / branch_compare.count as f64;
        }

        let m = branch_compare.mean;
        let variance = if branch_compare.count == 1 {
            0.0
        } else {
            branch_compare.m2 / branch_compare.count as f64
        };

        // integer only for now
        let shift = 1.0; //if true { 1.0 } else { f64::MIN_POSITIVE };

        // was present in the prototype, but it's never used (?)
        // let epsilon = 0.001; // 10^-3

        let ratio = match branch_compare.typ {
            Predicate::FcmpOeq
            | Predicate::FcmpUeq
            | Predicate::IcmpEq
            | Predicate::FcmpOge
            | Predicate::FcmpUge
            | Predicate::IcmpSge
            | Predicate::IcmpUge => {
                /* equal, unsigned greater or equal */
                variance / (variance + m * m)
            }
            Predicate::FcmpOne | Predicate::FcmpUne | Predicate::IcmpNe => {
                /* not equal */
                let ratio1 = variance / (variance + (m - shift) * (m - shift));
                let ratio2 = variance / (variance + (m + shift) * (m + shift));
                ratio1 + ratio2
            }
            Predicate::FcmpOgt | Predicate::FcmpUgt | Predicate::IcmpSgt | Predicate::IcmpUgt => {
                /* unsigned greater than */
                variance / (variance + (m - shift) * (m - shift))
            }
            Predicate::FcmpOlt
            | Predicate::FcmpUlt
            | Predicate::IcmpSlt
            | Predicate::IcmpUlt
            | Predicate::FcmpOle
            | Predicate::FcmpUle
            | Predicate::IcmpSle
            | Predicate::IcmpUle => {
                /* unsigned less or equal, unsigned less than */
                variance / (variance + (m + shift) * (m + shift))
            }
            _ => 0.0,
        };
        assert!(ratio >= 0.0);
        assert!(ratio <= 1.0);
        ratio
    }
}
