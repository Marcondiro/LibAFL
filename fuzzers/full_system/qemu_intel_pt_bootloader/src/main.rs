//! A fuzzer using qemu in systemmode for binary-only coverage of bootloaders

use core::time::Duration;
use std::{env, path::PathBuf, process};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    executors::ExitKind,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::{StdMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    config, config::Accelerator, executor::QemuExecutor, modules::intel_pt::IntelPTModule,
    Emulator, Qemu, QemuExitReason, QemuShutdownCause,
};
// Coverage map
const MAP_SIZE: usize = 4096;
static mut MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];
const MAX_INPUT_SIZE: usize = 50;

#[cfg(target_os = "linux")]
fn main() {
    env_logger::init();

    // Hardcoded parameters
    let timeout = Duration::from_secs(3);
    let broker_port = 1337;
    let cores = Cores::from_cmdline("0").unwrap();
    let corpus_dirs = [PathBuf::from("./corpus")];
    let objective_dir = PathBuf::from("./crashes");

    let mut run_client = |state: Option<_>, mut mgr, _core_id| -> Result<(), Error> {
        let target_dir = env::var("TARGET_DIR").expect("TARGET_DIR env not set");
        println!("run client");
        // Initialize QEMU
        let qemu = Qemu::builder()
            .no_graphic(true)
            .drives([config::Drive::builder()
                .format(config::DiskImageFileFormat::Raw)
                .file(format!("{target_dir}/boot.bin"))
                .build()])
            .accelerator(Accelerator::Kvm)
            .bios(format!(
                "{target_dir}/qemu-libafl-bridge/build/qemu-bundle/usr/local/share/qemu"
            ))
            .start_cpu(false)
            .build()
            .expect("Failed to initialize QEMU");

        let emulator_modules =
            tuple_list!(IntelPTModule::new(unsafe { MAP.as_mut_ptr() }, MAP_SIZE));

        let emulator = Emulator::empty()
            .qemu(qemu)
            .modules(emulator_modules)
            .build()?;

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |emulator: &mut Emulator<_, _, _, StdState<BytesInput, _, _, _>, _>,
                           _: &mut StdState<BytesInput, _, _, _>,
                           _: &BytesInput| unsafe {
            match emulator.qemu().run() {
                Ok(QemuExitReason::End(QemuShutdownCause::GuestShutdown)) => {
                    println!("VM shut down!")
                }
                _ => panic!("Unexpected QEMU exit."),
            }
            ExitKind::Ok
        };

        // Create an observation channel using the map
        let observer =
            unsafe { StdMapObserver::from_mut_ptr("signals", MAP.as_mut_ptr(), MAP_SIZE) };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&observer),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // A queue policy to get testcases from the corpus
        let scheduler = QueueScheduler::new();

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Create a QEMU in-process executor
        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness,
            tuple_list!(observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");

        // Instead of calling the timeout handler and restart the process, trigger a breakpoint ASAP
        // executor.break_on_timeout();

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                    process::exit(0);
                });
            println!("Imported {} inputs from disk.", state.corpus().count());
        }

        // Setup an havoc mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .unwrap();
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .build()
        .launch()
    {
        Ok(()) => println!("OK"),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}