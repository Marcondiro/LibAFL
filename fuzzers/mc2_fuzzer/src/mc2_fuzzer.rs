use crate::dummy_in_process_executor;
use crate::mc2_state::*;
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
     * After the counting_helper is called for each hyperrectangle, the 
     * probability is computed for that branch.
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
            let tmp_count = self.compute_prob(val);
            if i_l_count > tmp_count {
                i_l_count = tmp_count;
            }
        }

        self.counting_helper(i_r, executor, state, manager)?;
        let mut i_r_count = 1.0;
        for val in BRANCH_CMP.lock().unwrap().values() {
            let tmp_count = self.compute_prob(val);
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
        BRANCH_CMP.lock().unwrap().clear();

        for _ in 0..EXECUTION_NUMBER {
            let mut tmp_input = Vec::new();
            for i in 0..h.intervals.len() {
                tmp_input.push(
                    (state.get_rand_byte() as u16
                        % (h.intervals[i].high as u16 - h.intervals[i].low as u16 + 1)
                        + h.intervals[i].low as u16) as u8,
                );
            }

            let input = BytesInput::new(tmp_input);
            executor.run_target(self, state, manager, &input)?;
        }

        Ok(())
    }

    /**
     * After the harness is executed several times (updating the BranchCmp data
     * structure), this function is called to compute the probability that the current 
     * hypperrectanle contains the target 
     */
    fn compute_prob(&mut self, val: &BranchCmp) -> f64 {
        if val.sat > 0 {
            return val.sat as f64 / val.count as f64;
        }

        let m = val.mean;
        let var = if val.count == 1 {
            0.0
        } else {
            val.m2 / val.count as f64
        };

        // integer only for now
        let shift = if true { 1.0 } else { f64::MIN_POSITIVE };

        // was present in the prototype, but it's never used (?)
        // let epsilon = 0.001; // 10^-3

        let ratio = match val.typ {
            Predicate::FcmpOeq | Predicate::FcmpUeq | Predicate::IcmpEq => {
                /* equal */
                var / (var + m * m)
            }
            Predicate::FcmpOne | Predicate::FcmpUne | Predicate::IcmpNe => {
                /* not equal */
                let ratio1 = var / (var + (m - shift) * (m - shift));
                let ratio2 = var / (var + (m + shift) * (m + shift));
                ratio1 + ratio2
            }
            Predicate::FcmpOgt | Predicate::FcmpUgt | Predicate::IcmpSgt | Predicate::IcmpUgt => {
                /* unsigned greater than */
                var / (var + (m - shift) * (m - shift))
            }
            Predicate::FcmpOge | Predicate::FcmpUge | Predicate::IcmpSge | Predicate::IcmpUge => {
                /* unsigned greater or equal */
                var / (var + m * m)
            }
            Predicate::FcmpOlt | Predicate::FcmpUlt | Predicate::IcmpSlt | Predicate::IcmpUlt => {
                /* unsigned less than */
                var / (var + (m + shift) * (m + shift))
            }
            Predicate::FcmpOle | Predicate::FcmpUle | Predicate::IcmpSle | Predicate::IcmpUle => {
                /* unsigned less or equal */
                var / (var + (m + shift) * (m + shift))
            }
            _ => 0.0,
        };
        assert!(ratio >= 0.0);
        assert!(ratio <= 1.0);
        return ratio;
    }
}
