use core::{fmt::Debug, time::Duration};
use serde::{Deserialize, Serialize};

use libafl::{
    bolts::rands::Rand,
    inputs::BytesInput,
    prelude::{State, UsesInput},
};

#[derive(Serialize, Deserialize, Clone, Debug, Copy)]
pub struct Interval {
    pub low: u8,
    pub high: u8,
}

// TODO replace this struct with vec of intervals in WeightGroup
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Hyperrectangle {
    pub interval: Vec<Interval>,
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
    weighted_groups: Vec<WeightGroup>,
    // Number of bytes of the input
    input_size: usize,
}

impl<R> State for Mc2State<R>
where
    R: Rand,
    Self: UsesInput,
{
}

impl<R> UsesInput for Mc2State<R> {
    type Input = BytesInput;
}

impl<R> Mc2State<R>
where
    R: Rand,
{
    pub fn new(rand: R, input_size: usize) -> Self {
        let mut groups = Vec::new();

        let hyperrectangle = Hyperrectangle {
            interval: vec![Interval { low: 0, high: 255 }; input_size],
        };

        groups.push(WeightGroup {
            h: hyperrectangle,
            weight: 1.0,
        });

        Self {
            rand,
            executions: 0,
            start_time: Duration::from_millis(0),
            weighted_groups: groups,
            input_size,
        }
    }

    pub fn terminate_search(&self) -> Option<Hyperrectangle> {
        let threshold = 1.0 / f64::sqrt((self.input_size * 8) as f64);

        for group in self.weighted_groups {
            let mut cardinality = 1;
            for j in 0..self.input_size {
                let interval = group.h.interval[j];
                cardinality *= (interval.high - interval.low) as u128 + 1;
            }

            if threshold < (group.weight / cardinality as f64) {
                return Some(group.h.clone());
            }
        }
        None
    }

    pub fn find_group(&self) -> (usize, f64) {
        let mut cumulative_weight: f64 = 0.0;
        let mut group_index: usize = 0;

        for (i, group) in self.weighted_groups.iter().enumerate() {
            cumulative_weight += group.weight;
            if cumulative_weight > 0.5 {
                group_index = i;
                break;
            }
        }

        let w_l = cumulative_weight - self.weighted_groups[group_index].weight;
        (group_index, w_l)
    }

    pub fn split_group(&mut self, group_index: usize) {
        let target_group = &self.weighted_groups[group_index];

        let hyperrectangle = Hyperrectangle {
            interval: target_group.h.interval.clone(),
        };

        let mut dim = 0;
        // TODO fix this to avoid dim == size
        while dim < target_group.h.interval.len()
            && target_group.h.interval[dim].high == target_group.h.interval[dim].low
        {
            dim += 1;
        }

        self.weighted_groups.insert(
            group_index,
            WeightGroup {
                h: hyperrectangle,
                weight: target_group.weight,
            },
        );

        let m = ((target_group.h.interval[dim].high as u16
            + target_group.h.interval[dim].low as u16)
            / 2) as u8;
        target_group.h.interval[dim].high = m;
        self.weighted_groups[group_index + 1].h.interval[dim].low = m + 1;
    }

    pub fn get_hyperrectangles(&self, group_index: usize) -> &Hyperrectangle {
        assert!(group_index < self.weighted_groups.len());

        &self.weighted_groups[group_index].h
    }

    pub fn get_weight(&self, group_index: usize) -> f64 {
        assert!(group_index < self.weighted_groups.len());

        self.weighted_groups[group_index].weight
    }

    pub fn update_weights(&mut self, group_index: usize, p: f64, z: f64, is_left: bool) {
        assert!(group_index < self.weighted_groups.len());

        for i in 0..(group_index + 1) {
            if is_left {
                self.weighted_groups[i].weight *= (1.0 - p) / z;
            } else {
                self.weighted_groups[i].weight *= p / z;
            }
        }

        for i in (group_index + 1)..self.weighted_groups.len() {
            if is_left {
                self.weighted_groups[i].weight *= p / z;
            } else {
                self.weighted_groups[i].weight *= (1.0 - p) / z;
            }
        }
    }
}