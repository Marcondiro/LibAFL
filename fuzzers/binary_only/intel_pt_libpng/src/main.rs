#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::{path::PathBuf, process, slice, time::Duration};

#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{
        hooks::intel_pt::{IntelPT, IntelPTHook, PtImage},
        inprocess::GenericInProcessExecutor,
        ExitKind,
    },
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, HasLen};
use proc_maps::get_process_maps;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Coverage map
const MAP_SIZE: usize = 64 * 1024;
static mut MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];
#[allow(static_mut_refs)]
static mut MAP_PTR: *mut u8 = unsafe { MAP.as_mut_ptr() };

pub fn main() {
    // Enable logging
    env_logger::init();

    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        unsafe { LLVMFuzzerTestOneInput(input.target_bytes().as_ptr(), input.len()) };
        ExitKind::Ok
    };

    // Create an observation channel using the map
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", MAP_PTR, MAP_SIZE) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    #[cfg(not(feature = "tui"))]
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    #[cfg(feature = "tui")]
    let mon = TuiMonitor::builder()
        .title("Baby Fuzzer Intel PT")
        .enhanced_graphics(false)
        .build();

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    unsafe {
        LLVMFuzzerTestOneInput([0u8].as_ptr(), 1);
    }

    // Get the memory map of the current process
    let my_pid = i32::try_from(process::id()).unwrap();
    let process_maps = get_process_maps(my_pid).unwrap();
    // filter out all the dynamic libs
    let (images, filters) = process_maps
        .iter()
        .filter(|pm| pm.is_exec())
        .filter(|pm| pm.inode != 0)
        .filter(|pm| {
            pm.filename()
                .is_some_and(|path| !path.to_string_lossy().contains("/usr/lib/"))
        })
        .map(|pm| {
            let data = unsafe { slice::from_raw_parts(pm.start() as *const u8, pm.size()) };
            (
                PtImage::new(data, pm.start() as u64),
                pm.start() as u64..=(pm.start() + pm.size()) as u64,
            )
        })
        .collect::<(Vec<_>, Vec<_>)>();

    let pt = IntelPT::builder()
        .ip_filters(filters)
        .pid(Some(my_pid))
        .images(&images)
        .build()
        .unwrap();
    // Intel PT hook that will handle the setup of Intel PT for each execution and fill the map
    let pt_hook = unsafe {
        IntelPTHook::builder()
            .intel_pt(pt)
            .map_ptr(MAP_PTR)
            .map_len(MAP_SIZE)
    }
    .build();

    type PTInProcessExecutor<'a, 'b, EM, H, I, OT, S, T, Z> =
        GenericInProcessExecutor<EM, H, &'a mut H, (IntelPTHook<'b, T>, ()), I, OT, S, Z>;
    // Create the executor for an in-process function with just one observer
    let mut executor = PTInProcessExecutor::with_timeout_generic(
        tuple_list!(pt_hook),
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_millis(5000),
    )
    .expect("Failed to create the Executor");

    let seeds = PathBuf::from("./seeds");
    state
        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seeds])
        .expect("Failed to generate the initial corpus");

    // Set up a mutational stage with a basic bytes mutator
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
