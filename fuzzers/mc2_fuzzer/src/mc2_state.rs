use serde::{Deserialize, Serialize};
use core::{
    fmt::Debug,
    
    time::Duration,
};

use libafl::{
    bolts::rands::Rand,
    prelude::{UsesInput, State},
};



#[derive(Serialize, Deserialize, Clone, Debug, Copy)]
struct Interval {
    low: u8,
    high: u8,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
struct Hyperrectangle {
    interval: Vec<Interval>,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
struct WeightGroup {
    h: Hyperrectangle,
    weight: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "
        R: serde::Serialize + for<'a> serde::Deserialize<'a>
    ")]
pub struct Mc2State<R> {
    /// RNG instance
    rand: R,
    /// How many times the executor ran the harness/target
    executions: usize,
    /// At what time the fuzzing started
    start_time: Duration,
    // Groups
    weighted_groups : Vec<WeightGroup>,
}


impl<R> State for Mc2State<R>
where
    R: Rand,
    Self: UsesInput,
{
}


impl <R> Mc2State<R> 
where
    R : Rand,
{
    pub fn new(
        rand: R,
        input_size : usize,

    ) -> Self
    {
        let mut groups = Vec::new();

        let hyperrectangle = Hyperrectangle {
            interval: vec![Interval { low: 0, high: 255 }; input_size ],
        };
    
        groups.push(WeightGroup {
            h: hyperrectangle,
            weight: 1.0,
        });

        Self {
            rand,
            executions: 0,
            start_time: Duration::from_millis(0),
            weighted_groups : groups,
        }
    }
}   
