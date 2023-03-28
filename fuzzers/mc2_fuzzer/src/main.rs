const maxpossibleBBs: u32 = 4000;

extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> isize;
}

struct BranchCmp {
    mean: f64,
    m2: f64,
    sat: u64,
    count: u64,
    time: u64,
    typ: u8,
}

enum Predicate {
    /// 0 0 0 0    Always false (always folded)
    FCMP_FALSE = 0,
    /// 0 0 0 1    True if ordered and equal
    FCMP_OEQ = 1,
    /// 0 0 1 0    True if ordered and greater than
    FCMP_OGT = 2,
    /// 0 0 1 1    True if ordered and greater than or equal
    FCMP_OGE = 3,
    /// 0 1 0 0    True if ordered and less than
    FCMP_OLT = 4,
    /// 0 1 0 1    True if ordered and less than or equal
    FCMP_OLE = 5,
    /// 0 1 1 0    True if ordered and operands are unequal
    FCMP_ONE = 6,
    /// 0 1 1 1    True if ordered (no nans)
    FCMP_ORD = 7,
    /// 1 0 0 0    True if unordered: isnan(X) | isnan(Y)
    FCMP_UNO = 8,
    /// 1 0 0 1    True if unordered or equal
    FCMP_UEQ = 9,
    /// 1 0 1 0    True if unordered or greater than
    FCMP_UGT = 10,
    /// 1 0 1 1    True if unordered, greater than, or equal
    FCMP_UGE = 11,
    /// 1 1 0 0    True if unordered or less than
    FCMP_ULT = 12,
    /// 1 1 0 1    True if unordered, less than, or equal
    FCMP_ULE = 13,
    /// 1 1 1 0    True if unordered or not equal
    FCMP_UNE = 14,
    /// 1 1 1 1    Always true (always folded)
    FCMP_TRUE = 15, //< equal
    ICMP_EQ = 32,
    /// not equal
    ICMP_NE = 33,
    /// unsigned greater than
    ICMP_UGT = 34,
    /// unsigned greater or equal
    ICMP_UGE = 35,
    /// unsigned less than
    ICMP_ULT = 36,
    /// unsigned less or equal
    ICMP_ULE = 37,
    /// signed greater than
    ICMP_SGT = 38,
    /// signed greater or equal
    ICMP_SGE = 39,
    /// signed less than
    ICMP_SLT = 40,
    /// signed less or equal
    ICMP_SLE = 41,
}

fn main() {
    let input = b"a";
    unsafe {
        LLVMFuzzerTestOneInput(input.as_ptr(), 1);
    }
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
    assert!(br_id < maxpossibleBBs);

    false
}
