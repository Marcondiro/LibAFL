use lazy_static::lazy_static;
use num_enum::TryFromPrimitive;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Mutex;

use core::{fmt::Debug, time::Duration};

use libafl::{
    bolts::rands::{Rand, StdRand},
    executors::{inprocess::InProcessExecutor, ExitKind},
    fuzzer::Fuzzer,
    inputs::{BytesInput, HasBytesVec},
    prelude::{current_time, SimpleEventManager, SimpleMonitor, UsesInput},
};

mod mc2_state;

use crate::mc2_state::{Hyperrectangle, Mc2State};

const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);
const EXECUTION_NUMBER: usize = 5;

// TODO find a better solution for global stuff
lazy_static! {
    static ref BRANCH_CMP: Mutex<HashMap<u32, BranchCmp>> = Mutex::new(HashMap::new());
    static ref BRANCH_POLICY: Mutex<HashMap<u32, BranchSequence>> = Mutex::new(HashMap::new());
}

extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> isize;
}

struct Mc2Fuzzer {
    is_left: bool,
    branch_policy: HashMap<u32, BranchSequence>,
    p: f64,
}

impl Mc2Fuzzer {
    pub fn new(p: f64, branch_policy: HashMap<u32, BranchSequence>) -> Self {
        Self {
            is_left: false,
            p,
            branch_policy,
        }
    }

    fn fuzz_loop<H, OT: libafl::observers::ObserversTuple<mc2_state::Mc2State<R>>, R, MT>(
        &mut self,
        executor: &mut InProcessExecutor<H, OT, Mc2State<R>>,
        state: &mut Mc2State<R>,
        manager: &mut SimpleEventManager<MT, Mc2State<R>>,
    ) where
        R: Rand,
        H: FnMut(&<Mc2State<R> as UsesInput>::Input) -> ExitKind + ?Sized,
    {
        // noisy binary search

        let mut last = current_time();
        let monitor_timeout = STATS_TIMEOUT_DEFAULT;

        let promising_hyperrectangle;
        loop {
            match state.terminate_search() {
                None => {
                    let (group_index, w_l) = state.find_group();

                    state.split_group(group_index);

                    self.noisy_counting_oracle(
                        state.get_hyperrectangles(group_index),
                        state.get_hyperrectangles(group_index + 1),
                        executor,
                        state,
                        manager,
                    );

                    let z = if self.is_left {
                        (w_l + state.get_weight(group_index)) * (1.0 - self.p)
                            + (1.0 - w_l) * self.p
                    } else {
                        (w_l + state.get_weight(group_index)) * self.p
                            + (1.0 - w_l) * (1.0 - self.p)
                    };

                    state.update_weights(group_index, self.p, z, self.is_left);
                }
                Some(ph) => {
                    promising_hyperrectangle = ph;
                    break;
                }
            }
            // last = manager.maybe_report_progress(state, last, monitor_timeout)?;
        }

        // TODO return promising instead of printing
        println!("--- Most Promising Input Region ----");
        println!("{:?}", promising_hyperrectangle);
        // println!("--- Obtained groups at the end of execution ----");
        // for wg in groups {
        //     println!("{:?}", wg.h);
        // }
    }

    fn noisy_counting_oracle<H, OT, R, MT>(
        &mut self,
        i_l: &Hyperrectangle,
        i_r: &Hyperrectangle,
        executor: &mut InProcessExecutor<H, OT, Mc2State<R>>,
        state: &mut mc2_state::Mc2State<R>,
        manager: &mut SimpleEventManager<MT, Mc2State<R>>,
    ) where
        H: FnMut(&<Mc2State<R> as UsesInput>::Input) -> ExitKind + ?Sized,
        OT: libafl::observers::ObserversTuple<mc2_state::Mc2State<R>>,
    {
        self.counting_helper(i_l, executor, state, manager);
        let mut i_l_count = 1.0;
        for val in BRANCH_CMP.lock().unwrap().values() {
            let tmp_count = compute_prob(val);
            if i_l_count > tmp_count {
                i_l_count = tmp_count;
            }
        }

        self.counting_helper(i_r, executor, state, manager);
        let mut i_r_count = 1.0;
        for val in BRANCH_CMP.lock().unwrap().values() {
            let tmp_count = compute_prob(val);
            if i_r_count > tmp_count {
                i_r_count = tmp_count;
            }
        }

        self.is_left = i_l_count >= i_r_count;
    }

    fn counting_helper<H, OT: libafl::observers::ObserversTuple<mc2_state::Mc2State<R>>, R, MT>(
        &mut self,
        h: &Hyperrectangle,
        executor: &mut InProcessExecutor<H, OT, Mc2State<R>>,
        state: &mut mc2_state::Mc2State<R>,
        manager: &mut SimpleEventManager<MT, Mc2State<R>>,
    ) where
        H: FnMut(&<Mc2State<R> as UsesInput>::Input) -> ExitKind + ?Sized,
    {
        BRANCH_CMP.lock().unwrap().clear();

        for _ in 0..EXECUTION_NUMBER {
            let mut tmp_input = Vec::new();
            for i in 0..h.interval.len() {
                tmp_input.push(
                    // TODO use libafl rand
                    rand::random::<u8>() % (h.interval[i].high - h.interval[i].low + 1)
                        + h.interval[i].low,
                );
            }

            let input = BytesInput::new(tmp_input);
            executor.run_target(&mut self, state, manager, input);
        }
    }
}

#[derive(Debug)]
struct BranchCmp {
    mean: f64,
    m2: f64,
    sat: u64,
    count: u64,
    typ: Predicate,
}

struct BranchSequence {
    direction: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, TryFromPrimitive)]
#[repr(u8)]
enum Predicate {
    /// 0 0 0 0    Always false (always folded)
    FcmpFalse = 0u8,
    /// 0 0 0 1    True if ordered and equal
    FcmpOeq = 1u8,
    /// 0 0 1 0    True if ordered and greater than
    FcmpOgt = 2u8,
    /// 0 0 1 1    True if ordered and greater than or equal
    FcmpOge = 3u8,
    /// 0 1 0 0    True if ordered and less than
    FcmpOlt = 4u8,
    /// 0 1 0 1    True if ordered and less than or equal
    FcmpOle = 5u8,
    /// 0 1 1 0    True if ordered and operands are unequal
    FcmpOne = 6u8,
    /// 0 1 1 1    True if ordered (no nans)
    FcmpOrd = 7u8,
    /// 1 0 0 0    True if unordered: isnan(X) | isnan(Y)
    FcmpUno = 8u8,
    /// 1 0 0 1    True if unordered or equal
    FcmpUeq = 9u8,
    /// 1 0 1 0    True if unordered or greater than
    FcmpUgt = 10u8,
    /// 1 0 1 1    True if unordered, greater than, or equal
    FcmpUge = 11u8,
    /// 1 1 0 0    True if unordered or less than
    FcmpUlt = 12u8,
    /// 1 1 0 1    True if unordered, less than, or equal
    FcmpUle = 13u8,
    /// 1 1 1 0    True if unordered or not equal
    FcmpUne = 14u8,
    /// 1 1 1 1    Always true (always folded)
    FcmpTrue = 15u8,
    /// equal
    IcmpEq = 32u8,
    /// not equal
    IcmpNe = 33u8,
    /// unsigned greater than
    IcmpUgt = 34u8,
    /// unsigned greater or equal
    IcmpUge = 35u8,
    /// unsigned less than
    IcmpUlt = 36u8,
    /// unsigned less or equal
    IcmpUle = 37u8,
    /// signed greater than
    IcmpSgt = 38u8,
    /// signed greater or equal
    IcmpSge = 39u8,
    /// signed less than
    IcmpSlt = 40u8,
    /// signed less or equal
    IcmpSle = 41u8,
}

fn compute_prob(val: &BranchCmp) -> f64 {
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

#[no_mangle]
pub extern "C" fn log_func8(
    br_id: u32,
    old_cond: bool,
    arg1: u8,
    arg2: u8,
    is_signed: u8,
    cond_type: u8,
) -> bool {
    if is_signed != 0 {
        log_funchelper(br_id, old_cond, arg1 as i8, arg2 as i8, cond_type)
    } else {
        log_funchelper(br_id, old_cond, arg1, arg2, cond_type)
    }
}

#[no_mangle]
pub extern "C" fn log_func16(
    br_id: u32,
    old_cond: bool,
    arg1: u16,
    arg2: u16,
    is_signed: u8,
    cond_type: u8,
) -> bool {
    if is_signed != 0 {
        log_funchelper(br_id, old_cond, arg1 as i16, arg2 as i16, cond_type)
    } else {
        log_funchelper(br_id, old_cond, arg1, arg2, cond_type)
    }
}

#[no_mangle]
pub extern "C" fn log_func32(
    br_id: u32,
    old_cond: bool,
    arg1: u32,
    arg2: u32,
    is_signed: u8,
    cond_type: u8,
) -> bool {
    if is_signed != 0 {
        log_funchelper(br_id, old_cond, arg1 as i32, arg2 as i32, cond_type)
    } else {
        log_funchelper(br_id, old_cond, arg1, arg2, cond_type)
    }
}

#[no_mangle]
pub extern "C" fn log_func64(
    br_id: u32,
    old_cond: bool,
    arg1: u64,
    arg2: u64,
    is_signed: u8,
    cond_type: u8,
) -> bool {
    if is_signed != 0 {
        log_funchelper(br_id, old_cond, arg1 as i64, arg2 as i64, cond_type)
    } else {
        log_funchelper(br_id, old_cond, arg1, arg2, cond_type)
    }
}

fn log_funchelper<T>(br_id: u32, old_cond: bool, args0: T, args1: T, cond_type: u8) -> bool
where
    i128: From<T>,
{
    let mut ret_cond = old_cond;

    if let Some(bseq) = BRANCH_POLICY.lock().unwrap().get(&br_id) {
        ret_cond = bseq.direction;
    }

    update_branch(
        br_id,
        ret_cond,
        ret_cond == old_cond,
        args0,
        args1,
        cond_type,
    );

    ret_cond
}

fn update_branch<T>(br_id: u32, ret_cond: bool, is_sat: bool, args0: T, args1: T, cond_type: u8)
where
    i128: From<T>,
{
    assert!(cond_type > 0);
    let ret_cond_u32: u32 = ret_cond.into();
    let is_sat_u64: u64 = is_sat.into();

    let args0_i = i128::from(args0);
    let args1_i = i128::from(args1);

    BRANCH_CMP
        .lock()
        .unwrap()
        .entry(2 * br_id + ret_cond_u32)
        .and_modify(|bcmp| {
            bcmp.count += 1;
            bcmp.sat += is_sat_u64;
            let delta = (args0_i - args1_i) as f64 - bcmp.mean;
            bcmp.mean += delta / bcmp.count as f64;
            let delta2 = (args0_i - args1_i) as f64 - bcmp.mean;
            bcmp.m2 += delta * delta2;
        })
        .or_insert(BranchCmp {
            mean: (args0_i - args1_i) as f64,
            count: 1,
            sat: is_sat_u64,
            typ: cond_type.try_into()
                .expect("Condition type has an invalid u8 value, no discriminant in enum `Predicate` matches"),
            m2: 0.0,
        });
}

fn main() {
    let mut harness = |input: &BytesInput| {
        unsafe {
            LLVMFuzzerTestOneInput(input.bytes().as_ptr(), input.bytes().len());
        }
        ExitKind::Ok
    };

    let mut state = mc2_state::Mc2State::new(StdRand::with_seed(42), 1);

    // TODO support tui as in BabyFuzzer ?
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(mon);

    // TODO fuzzer
    let fuzzer = Mc2Fuzzer::new();

    let mut executor = InProcessExecutor::new(&mut harness, (), &mut fuzzer, &mut state, &mut mgr)
        .expect("Failed to create the Executor");

    // BRANCH_POLICY
    //     .lock()
    //     .unwrap()
    //     .entry(0)
    //     .or_insert(BranchSequence { direction: false });
    //
    // noisy_binary_search(0.01);
}