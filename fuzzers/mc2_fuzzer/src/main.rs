use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

const EXECUTION_NUMBER: usize = 5;

// TODO find a better solution for global stuff
static MONTECARLO_EXECING: AtomicBool = AtomicBool::new(true);
static TRACING: AtomicBool = AtomicBool::new(true);
static IS_LEFT: AtomicBool = AtomicBool::new(false);

lazy_static! {
    static ref BRANCH_CMP: Mutex<HashMap<u32, BranchCmp>> = Mutex::new(HashMap::new());
    static ref BRANCH_POLICY: Mutex<HashMap<u32, BranchSequence>> = Mutex::new(HashMap::new());
}

extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> isize;
}

#[derive(Debug)]
struct BranchCmp {
    mean: f64,
    m2: f64,
    sat: u64,
    count: u64,
    typ: Predicate,
}

#[derive(Copy, Clone, Debug)]
struct Interval {
    low: u8,
    high: u8,
}

#[derive(Clone, Debug)]
struct Hyperrectangle {
    size: usize,
    interval: Vec<Interval>,
}

struct BranchSequence {
    direction: bool,
}

#[derive(Debug)]
struct WeightGroup {
    h: Hyperrectangle,
    weight: f64,
}

#[derive(Copy, Clone, Debug)]
enum Predicate {
    /// 0 0 0 0    Always false (always folded)
    FcmpFalse = 0,
    /// 0 0 0 1    True if ordered and equal
    FcmpOeq = 1,
    /// 0 0 1 0    True if ordered and greater than
    FcmpOgt = 2,
    /// 0 0 1 1    True if ordered and greater than or equal
    FcmpOge = 3,
    /// 0 1 0 0    True if ordered and less than
    FcmpOlt = 4,
    /// 0 1 0 1    True if ordered and less than or equal
    FcmpOle = 5,
    /// 0 1 1 0    True if ordered and operands are unequal
    FcmpOne = 6,
    /// 0 1 1 1    True if ordered (no nans)
    FcmpOrd = 7,
    /// 1 0 0 0    True if unordered: isnan(X) | isnan(Y)
    FcmpUno = 8,
    /// 1 0 0 1    True if unordered or equal
    FcmpUeq = 9,
    /// 1 0 1 0    True if unordered or greater than
    FcmpUgt = 10,
    /// 1 0 1 1    True if unordered, greater than, or equal
    FcmpUge = 11,
    /// 1 1 0 0    True if unordered or less than
    FcmpUlt = 12,
    /// 1 1 0 1    True if unordered, less than, or equal
    FcmpUle = 13,
    /// 1 1 1 0    True if unordered or not equal
    FcmpUne = 14,
    /// 1 1 1 1    Always true (always folded)
    FcmpTrue = 15,
    /// equal
    IcmpEq = 32,
    /// not equal
    IcmpNe = 33,
    /// unsigned greater than
    IcmpUgt = 34,
    /// unsigned greater or equal
    IcmpUge = 35,
    /// unsigned less than
    IcmpUlt = 36,
    /// unsigned less or equal
    IcmpUle = 37,
    /// signed greater than
    IcmpSgt = 38,
    /// signed greater or equal
    IcmpSge = 39,
    /// signed less than
    IcmpSlt = 40,
    /// signed less or equal
    IcmpSle = 41,
}

// TODO try to remove error prone duplication (enum -> u8 / u8 -> enum)
impl From<u8> for Predicate {
    fn from(val: u8) -> Self {
        match val {
            0 => Predicate::FcmpFalse,
            1 => Predicate::FcmpOeq,
            2 => Predicate::FcmpOgt,
            3 => Predicate::FcmpOge,
            4 => Predicate::FcmpOlt,
            5 => Predicate::FcmpOle,
            6 => Predicate::FcmpOne,
            7 => Predicate::FcmpOrd,
            8 => Predicate::FcmpUno,
            9 => Predicate::FcmpUeq,
            10 => Predicate::FcmpUgt,
            11 => Predicate::FcmpUge,
            12 => Predicate::FcmpUlt,
            13 => Predicate::FcmpUle,
            14 => Predicate::FcmpUne,
            15 => Predicate::FcmpTrue,
            32 => Predicate::IcmpEq,
            33 => Predicate::IcmpNe,
            34 => Predicate::IcmpUgt,
            35 => Predicate::IcmpUge,
            36 => Predicate::IcmpUlt,
            37 => Predicate::IcmpUle,
            38 => Predicate::IcmpSgt,
            39 => Predicate::IcmpSge,
            40 => Predicate::IcmpSlt,
            41 => Predicate::IcmpSle,
            _ => panic!("Invalid Predicate value: {}", val),
        }
    }
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
    if MONTECARLO_EXECING.load(Ordering::Relaxed) {
        if let Some(bseq) = BRANCH_POLICY.lock().unwrap().get(&br_id) {
            ret_cond = bseq.direction;
        }
    }

    if TRACING.load(Ordering::Relaxed) {
        update_branch(
            br_id,
            ret_cond,
            ret_cond == old_cond,
            args0,
            args1,
            cond_type,
        )
    }

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
            typ: cond_type.into(),
            m2: 0.0,
        });
}

fn counting_helper(h: &Hyperrectangle) {
    BRANCH_CMP.lock().unwrap().clear();

    for _ in 0..EXECUTION_NUMBER {
        let mut input = Vec::new();
        for i in 0..h.size {
            input.push(
                rand::random::<u8>() % (h.interval[i].high - h.interval[i].low + 1)
                    + h.interval[i].low,
            );
        }

        unsafe {
            LLVMFuzzerTestOneInput(input.as_ptr(), h.size); //TODO try to use libafl wrapper
        }
    }
}

fn find_group(groups: &Vec<WeightGroup>, w_l: &mut f64) -> usize {
    let mut cumulative_weight: f64 = 0.0;
    let mut group_index: usize = 0;

    for (i, group) in groups.iter().enumerate() {
        cumulative_weight += group.weight;
        if cumulative_weight > 0.5 {
            group_index = i;
            break;
        }
    }

    *w_l = cumulative_weight - groups[group_index].weight;
    group_index
}

fn terminate_search(groups: &[WeightGroup]) -> Option<Hyperrectangle> {
    let threshold = 1.0 / f64::sqrt(groups[0].h.size as f64 * 8.0);

    for group in groups {
        let mut cardinality: u64 = 1;
        for j in 0..group.h.size {
            let interval = group.h.interval[j];
            cardinality *= (interval.high - interval.low) as u64 + 1;
        }

        if threshold < (group.weight / cardinality as f64) {
            return Some(group.h.clone());
        }
    }

    None
}

fn create_new_weight_groups(groups: &mut Vec<WeightGroup>, group_index: usize) {
    let hyperrectangle = Hyperrectangle {
        size: groups[group_index].h.size,
        interval: groups[group_index].h.interval.clone(),
    };

    let mut dim = 0;
    // TODO fix this to avoid dim == size
    while dim < groups[group_index].h.size
        && groups[group_index].h.interval[dim].high == groups[group_index].h.interval[dim].low
    {
        dim += 1;
    }

    groups.insert(
        group_index,
        WeightGroup {
            h: hyperrectangle,
            weight: groups[group_index].weight,
        },
    );

    let m = ((groups[group_index].h.interval[dim].high as u16
        + groups[group_index].h.interval[dim].low as u16)
        / 2) as u8;
    groups[group_index].h.interval[dim].high = m;
    groups[group_index + 1].h.interval[dim].low = m + 1;
}

fn noisy_counting_oracle(i_l: &Hyperrectangle, i_r: &Hyperrectangle) {
    counting_helper(i_l);
    let mut i_l_count = 1.0;
    for val in BRANCH_CMP.lock().unwrap().values() {
        let tmp_count = compute_prob(val);
        if i_l_count > tmp_count {
            i_l_count = tmp_count;
        }
    }

    counting_helper(i_r);
    let mut i_r_count = 1.0;
    for val in BRANCH_CMP.lock().unwrap().values() {
        let tmp_count = compute_prob(val);
        if i_r_count > tmp_count {
            i_r_count = tmp_count;
        }
    }

    IS_LEFT.store(i_l_count >= i_r_count, Ordering::Relaxed);
}

fn update_weight_groups(
    groups: &mut [WeightGroup],
    group_index: usize,
    p: f64,
    z: f64,
    is_left: bool,
) {
    for i in 0..(group_index + 1) {
        if is_left {
            groups[i].weight *= (1.0 - p) / z;
        } else {
            groups[i].weight *= p / z;
        }
    }

    for i in (group_index + 1)..groups.len() {
        if is_left {
            groups[i].weight *= p / z;
        } else {
            groups[i].weight *= (1.0 - p) / z;
        }
    }
}

fn noisy_binary_search(p: f64) {
    let mut groups = Vec::new();

    let size = 1; // let's start from 1 byte size!
    let hyperrectangle = Hyperrectangle {
        size,
        interval: vec![Interval { low: 0, high: 255 }; size as usize],
    };

    groups.push(WeightGroup {
        h: hyperrectangle,
        weight: 1.0,
    });

    let promising_hyperrectangle;
    loop {
        match terminate_search(&groups) {
            None => {
                let mut w_l = 0.0;
                let group_index = find_group(&groups, &mut w_l);

                create_new_weight_groups(&mut groups, group_index);

                noisy_counting_oracle(&groups[group_index].h, &groups[group_index + 1].h);

                let z = if IS_LEFT.load(Ordering::Relaxed) {
                    (w_l + groups[group_index].weight) * (1.0 - p) + (1.0 - w_l) * p
                } else {
                    (w_l + groups[group_index].weight) * p + (1.0 - w_l) * (1.0 - p)
                };

                update_weight_groups(
                    &mut groups,
                    group_index,
                    p,
                    z,
                    IS_LEFT.load(Ordering::Relaxed),
                )
            }
            Some(ph) => {
                promising_hyperrectangle = ph;
                break;
            }
        }
    }

    println!("--- Most Promising Input Region ----");
    println!("{:?}", promising_hyperrectangle);
    println!("--- Obtained groups at the end of execution ----");
    for wg in groups {
        println!("{:?}", wg.h);
    }
}

fn main() {
    BRANCH_POLICY
        .lock()
        .unwrap()
        .entry(0)
        .or_insert(BranchSequence { direction: false });

    noisy_binary_search(0.01);
}
