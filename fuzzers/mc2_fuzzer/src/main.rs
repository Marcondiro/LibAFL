const MAXPOSSIBLE_BBS: u32 = 4000;

extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> isize;
}

struct BranchCmp {
    mean: f64,
    m2: f64,
    sat: u64,
    count: u64,
    time: u64,
    typ: Predicate,
}

struct Interval {
    low: u8,
    high: u8,
}

struct Hyperrectangle {
    size: u64,
    interval: Interval,
}

struct BranchSequence {
    direction: u8,
}

struct WeightGroup {
    h: Hyperrectangle,
    weight: f64,
}

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

fn main() {
    let input = b"a";
    unsafe {
        LLVMFuzzerTestOneInput(input.as_ptr(), 1);
    }
}

fn compute_prob(br_id: u32, val: BranchCmp) -> f64 {
    if val.sat > 0 {
        return val.sat as f64 / val.count as f64;
    }

    let m = val.mean;
    let var = if val.count == 1 { 0.0 } else { val.m2 / val.count as f64 };

    // integer only for now
    let shift = if true { 1.0 } else { DBL_MIN }; // TODO dbl_min is defined in clang float.h
    let epsilon = 0.001; // 10^-3

    let ratio = match val.typ {
        Predicate::FcmpOeq |
        Predicate::FcmpUeq |
        Predicate::IcmpEq => {
            /* equal */
            var / (var + m * m)
        }
        Predicate::FcmpOne |
        Predicate::FcmpUne |
        Predicate::IcmpNe => {
            /* not equal */
            let ratio1 = var / (var + (m - shift) * (m - shift));
            let ratio2 = var / (var + (m + shift) * (m + shift));
            ratio1 + ratio2
        }
        Predicate::FcmpOgt |
        Predicate::FcmpUgt |
        Predicate::IcmpSgt |
        Predicate::IcmpUgt => {
            /* unsigned greater than */
            var / (var + (m - shift) * (m - shift));
        }
        Predicate::FcmpOge |
        Predicate::FcmpUge |
        Predicate::IcmpSge |
        Predicate::IcmpUge => {
            /* unsigned greater or equal */
            var / (var + m * m)
        }
        Predicate::FcmpOlt |
        Predicate::FcmpUlt |
        Predicate::IcmpSlt |
        Predicate::IcmpUlt => {
            /* unsigned less than */
            var / (var + (m + shift) * (m + shift))
        }
        Predicate::FcmpOle |
        Predicate::FcmpUle |
        Predicate::IcmpSle |
        Predicate::IcmpUle => {
            /* unsigned less or equal */
            var / (var + (m + shift) * (m + shift))
        }
        _ => 0.0
    };
    assert!(ratio >= 0.0);
    assert!(ratio <= 1.0);
    return ratio;
}

// TODO these fns are just placeholders

#[no_mangle]
pub extern "C" fn log_func8(
    br_id: u32,
    old_cond: bool,
    arg1: u8,
    arg2: u8,
    is_signed: u8,
    cond_type: u8,
) -> bool {
    log_funchelper(
        br_id,
        old_cond,
        arg1.into(),
        arg2.into(),
        8,
        is_signed,
        cond_type,
    )
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
    log_funchelper(
        br_id,
        old_cond,
        arg1.into(),
        arg2.into(),
        16,
        is_signed,
        cond_type,
    )
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
    log_funchelper(
        br_id,
        old_cond,
        arg1.into(),
        arg2.into(),
        32,
        is_signed,
        cond_type,
    )
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
    log_funchelper(br_id, old_cond, arg1, arg2, 64, is_signed, cond_type)
}

fn log_funchelper(
    br_id: u32,
    old_cond: bool,
    args0: u64,
    args1: u64,
    bitsize: u8,
    is_signed: u8,
    cond_type: u8,
) -> bool {
    assert!(br_id < MAXPOSSIBLE_BBS);

    false
}
