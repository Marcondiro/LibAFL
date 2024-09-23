use alloc::borrow::Cow;
use std::{
    sync::{Arc, Mutex},
    vec::Vec,
};

use libafl_bolts::{Error, Named};
use similar::{capture_diff_slices, Algorithm, DiffOp};

use crate::{
    events::EventFirer, executors::ExitKind, feedbacks::Feedback, observers::ObserversTuple,
    state::State,
};

#[derive(Debug, Default)]
struct Bucket {
    traces: Vec<Vec<u8>>,
    avg_score: f64,
}

#[derive(Debug)]
pub struct IntelPTFeedback {
    trace: Arc<Mutex<Vec<u8>>>,
    past_traces_buckets: Vec<Bucket>,
}

impl IntelPTFeedback {
    pub fn new(trace: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            trace,
            past_traces_buckets: vec![],
        }
    }
}

impl Named for IntelPTFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("IntelPTFeedback")
    }
}

impl<S> Feedback<S> for IntelPTFeedback
where
    S: State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let trace = self.trace.lock().unwrap();
        if !self.past_traces_buckets.is_empty() {
            for mut bucket in &mut self.past_traces_buckets {
                let mut tot_score = 0;
                let mut count = 0;
                // limit the compared traces
                let step = bucket.traces.len().div_ceil(200);

                for pt in bucket.traces.iter().step_by(step) {
                    let diff = capture_diff_slices(Algorithm::Myers, &trace, &pt);
                    let score = diff
                        .iter()
                        .map(|e| match e {
                            DiffOp::Equal { .. } => 0,
                            DiffOp::Delete { .. } => 0,
                            DiffOp::Insert { new_len, .. } => *new_len,
                            DiffOp::Replace { new_len, .. } => *new_len,
                        })
                        .sum::<usize>();
                    tot_score += score;
                    count += 1;
                }
                let weighted_score = tot_score as f64 / count as f64;

                if bucket.avg_score == 0.0 || weighted_score < bucket.avg_score * 2.0 {
                    bucket.traces.push(trace.clone());
                    let n = bucket.traces.len() as f64;
                    bucket.avg_score = (bucket.avg_score * (n - 1.0) + weighted_score) / n;
                    return Ok(false);
                }
            }
        }

        self.past_traces_buckets.push(Bucket {
            traces: vec![trace.clone()],
            avg_score: 0.0,
        });
        println!("number of buckets: {}", self.past_traces_buckets.len());
        println!("{}", serde_json::to_string_pretty(&state).unwrap());
        Ok(true)
    }
}
