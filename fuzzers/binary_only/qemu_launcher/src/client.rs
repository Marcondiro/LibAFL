use std::env;

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{
        ClientDescription, EventFirer, EventReceiver, EventRestarter, ProgressReporter, SendExiting,
    },
    inputs::BytesInput,
    state::StdState,
    Error,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use libafl_qemu::modules::{
    asan_guest::AsanGuestModule, asan_host::AsanHostModule, cmplog::CmpLogModule,
    utils::filters::StdAddressFilter, DrCovModule, InjectionModule,
};

use crate::{harness::Harness, instance::Instance, options::FuzzerOptions};

pub type ClientState =
    StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

pub struct Client<'a> {
    options: &'a FuzzerOptions,
}

impl Client<'_> {
    pub fn new(options: &FuzzerOptions) -> Client {
        Client { options }
    }

    pub fn args(&self) -> Result<Vec<String>, Error> {
        let program = env::args()
            .next()
            .ok_or_else(|| Error::empty_optional("Failed to read program name"))?;

        let mut args = self.options.args.clone();
        args.insert(0, program);
        Ok(args)
    }

    #[expect(clippy::unused_self)] // Api should look the same as args above
    pub fn env(&self) -> Vec<(String, String)> {
        env::vars()
            .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
            .collect::<Vec<(String, String)>>()
    }

    #[expect(clippy::too_many_lines)]
    pub fn run<EM>(
        &self,
        state: Option<ClientState>,
        mgr: EM,
        client_description: ClientDescription,
    ) -> Result<(), Error>
    where
        EM: EventFirer<BytesInput, ClientState>
            + EventRestarter<ClientState>
            + ProgressReporter<ClientState>
            + SendExiting
            + EventReceiver<BytesInput, ClientState>,
    {
        let core_id = client_description.core_id();
        let mut args = self.args()?;
        Harness::edit_args(&mut args);
        log::info!("ARGS: {:#?}", args);

        let mut env = self.env();
        Harness::edit_env(&mut env);
        log::info!("ENV: {:#?}", env);

        let is_asan_host = self.options.is_asan_host_core(core_id);
        let is_asan_guest = self.options.is_asan_guest_core(core_id);

        if is_asan_host && is_asan_guest {
            Err(Error::empty_optional("Multiple ASAN modes configured"))?;
        }

        #[cfg(not(feature = "injections"))]
        let injection_module = Option::<InjectionModule>::None;

        #[cfg(feature = "injections")]
        let injection_module = self
            .options
            .injections
            .as_ref()
            .and_then(|injections_file| {
                let lower = injections_file.to_lowercase();
                if lower.ends_with("yaml") || lower.ends_with("yml") {
                    Some(InjectionModule::from_yaml(injections_file).unwrap())
                } else if lower.ends_with("toml") {
                    Some(InjectionModule::from_toml(injections_file).unwrap())
                } else {
                    None
                }
            });

        let is_cmplog = self.options.is_cmplog_core(core_id);

        let is_drcov = self.options.drcov.is_some();

        let extra_tokens = if cfg!(feature = "injections") {
            injection_module
                .as_ref()
                .map(|h| h.tokens.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let instance_builder = Instance::builder()
            .options(self.options)
            .mgr(mgr)
            .client_description(client_description)
            .extra_tokens(extra_tokens);

        let asan_filter = if let Some(include_asan) = &self.options.include_asan {
            log::info!("ASAN includes: {include_asan:#x?}");
            StdAddressFilter::allow_list(include_asan.to_vec())
        } else if let Some(exclude_asan) = &self.options.exclude_asan {
            log::info!("ASAN excludes: {exclude_asan:#x?}");
            StdAddressFilter::deny_list(exclude_asan.to_vec())
        } else {
            log::info!("ASAN no additional filter");
            StdAddressFilter::default()
        };

        if self.options.rerun_input.is_some() {
            if is_drcov {
                // Special code path for re-running inputs with DrCov and Asan.
                // TODO: Add injection support
                let drcov = self.options.drcov.as_ref().unwrap();

                if is_asan_host {
                    let modules = tuple_list!(
                        DrCovModule::builder()
                            .filename(drcov.clone())
                            .full_trace(true)
                            .build(),
                        unsafe {
                            AsanHostModule::builder()
                                .env(&env)
                                .filter(asan_filter)
                                .asan_report()
                                .build()
                        }
                    );

                    instance_builder.build().run(args, modules, state)
                } else if is_asan_guest {
                    let modules = tuple_list!(
                        DrCovModule::builder()
                            .filename(drcov.clone())
                            .full_trace(true)
                            .build(),
                        AsanGuestModule::new(&env, asan_filter),
                    );

                    instance_builder.build().run(args, modules, state)
                } else {
                    let modules = tuple_list!(DrCovModule::builder()
                        .filename(drcov.clone())
                        .full_trace(true)
                        .build(),);

                    instance_builder.build().run(args, modules, state)
                }
            } else if is_asan_host {
                let modules = tuple_list!(unsafe {
                    AsanHostModule::builder()
                        .env(&env)
                        .filter(asan_filter)
                        .asan_report()
                        .build()
                });

                instance_builder.build().run(args, modules, state)
            } else if is_asan_guest {
                let modules = tuple_list!(AsanGuestModule::new(&env, asan_filter));

                instance_builder.build().run(args, modules, state)
            } else {
                let modules = tuple_list!();

                instance_builder.build().run(args, modules, state)
            }
        } else if is_asan_host && is_cmplog {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    args,
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanHostModule::builder()
                            .env(&env)
                            .filter(asan_filter)
                            .build(),
                        injection_module,
                    ),
                    state,
                )
            } else {
                instance_builder.build().run(
                    args,
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanHostModule::builder()
                            .env(&env)
                            .filter(asan_filter)
                            .build()
                    ),
                    state,
                )
            }
        } else if is_asan_guest && is_cmplog {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    args,
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanGuestModule::new(&env, asan_filter),
                        injection_module
                    ),
                    state,
                )
            } else {
                instance_builder.build().run(
                    args,
                    tuple_list!(
                        CmpLogModule::default(),
                        AsanGuestModule::new(&env, asan_filter),
                    ),
                    state,
                )
            }
        } else if is_asan_host {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    args,
                    tuple_list!(
                        AsanHostModule::builder()
                            .env(&env)
                            .filter(asan_filter)
                            .build(),
                        injection_module
                    ),
                    state,
                )
            } else {
                instance_builder.build().run(
                    args,
                    tuple_list!(AsanHostModule::builder()
                        .env(&env)
                        .filter(asan_filter)
                        .build()),
                    state,
                )
            }
        } else if is_asan_guest {
            instance_builder.build().run(
                args,
                tuple_list!(AsanGuestModule::new(&env, asan_filter)),
                state,
            )
        } else if is_cmplog {
            if let Some(injection_module) = injection_module {
                instance_builder.build().run(
                    args,
                    tuple_list!(CmpLogModule::default(), injection_module),
                    state,
                )
            } else {
                instance_builder
                    .build()
                    .run(args, tuple_list!(CmpLogModule::default()), state)
            }
        } else if let Some(injection_module) = injection_module {
            instance_builder
                .build()
                .run(args, tuple_list!(injection_module), state)
        } else {
            instance_builder.build().run(args, tuple_list!(), state)
        }
    }
}
