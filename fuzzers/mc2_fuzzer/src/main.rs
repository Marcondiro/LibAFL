use lazy_static::lazy_static;
use num_enum::TryFromPrimitive;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Mutex;

use core::fmt::Debug;

use libafl::{
    bolts::rands::StdRand,
    executors::ExitKind,
    inputs::{BytesInput, HasBytesVec},
    prelude::{SimpleEventManager, SimpleMonitor},
};

mod dummy_in_process_executor;
mod mc2_fuzzer;
mod mc2_state;

use crate::dummy_in_process_executor::DummyInProcessExecutor;
use crate::mc2_fuzzer::Mc2Fuzzer;

lazy_static! {
    static ref BRANCH_CMP: Mutex<HashMap<u32, BranchCmp>> = Mutex::new(HashMap::new());
    static ref BRANCH_POLICY: Mutex<HashMap<u32, BranchSequence>> = Mutex::new(HashMap::new());
}

extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> isize;
}

#[derive(Debug, Clone)]
struct BranchCmp {
    mean: f64,
    m2: f64,
    sat: u64,
    count: u64,
    typ: Predicate,
}

#[derive(Clone)]
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
    //TODO move to file (?)
    BRANCH_POLICY
        .lock()
        .unwrap()
        .insert(0, BranchSequence { direction: true });

    BRANCH_POLICY
        .lock()
        .unwrap()
        .insert(1, BranchSequence { direction: true });

    BRANCH_POLICY
        .lock()
        .unwrap()
        .insert(2, BranchSequence { direction: true });

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

    let mut fuzzer: Mc2Fuzzer<StdRand> = Mc2Fuzzer::new(0.01);

    let mut executor =
        DummyInProcessExecutor::new(&mut harness, (), &mut fuzzer, &mut state, &mut mgr)
            .expect("Failed to create the Executor");

    fuzzer.fuzz_loop(&mut executor, &mut state, &mut mgr);
}
