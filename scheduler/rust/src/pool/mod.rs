// SPDX-License-Identifier: GPL-2.0-only

//! Three task pools backed by one shared EEVDF implementation.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use crate::eevdf::{place_vruntime, rebase_vruntime};
use crate::identity::{TaskClass, TaskKey};

/// Immutable runnable token stored in EEVDF and oldest-wait indexes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PoolNode {
    pub task: TaskKey,
    pub enqueue_sequence: u64,
    pub class_generation: u64,
    pub class: TaskClass,
    pub enqueue_time_ns: u64,
    /// Lag-preserving virtual start time.
    pub vruntime_ns: u64,
    /// Requested service used for both deadline and dispatch slice.
    pub request_ns: u64,
    /// Virtual finish deadline (`vruntime_ns + request_ns`).
    pub deadline_ns: u64,
}

impl PoolNode {
    fn deadline_tuple(&self) -> (u64, u64, u64, u64, u32, u64) {
        (
            self.deadline_ns,
            self.vruntime_ns,
            self.enqueue_time_ns,
            self.enqueue_sequence,
            self.task.tid,
            self.task.task_cookie,
        )
    }

    fn future_tuple(&self) -> (u64, u64, u64, u64, u32, u64) {
        (
            self.vruntime_ns,
            self.deadline_ns,
            self.enqueue_time_ns,
            self.enqueue_sequence,
            self.task.tid,
            self.task.task_cookie,
        )
    }

    fn wait_tuple(&self) -> (u64, u64, u32, u64) {
        (
            self.enqueue_time_ns,
            self.enqueue_sequence,
            self.task.tid,
            self.task.task_cookie,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DeadlineEntry {
    order: (u64, u64, u64, u64, u32, u64),
    node: PoolNode,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FutureEntry {
    order: (u64, u64, u64, u64, u32, u64),
    node: PoolNode,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct WaitEntry {
    order: (u64, u64, u32, u64),
    node: PoolNode,
}

/// Eligible-deadline and future-vruntime indexes for one workload class.
#[derive(Clone, Debug, Default)]
struct EevdfPool {
    virtual_time_ns: u64,
    eligible: BinaryHeap<Reverse<DeadlineEntry>>,
    future: BinaryHeap<Reverse<FutureEntry>>,
    waiting: BinaryHeap<Reverse<WaitEntry>>,
}

impl EevdfPool {
    fn push(&mut self, node: PoolNode) {
        self.requeue_primary(node);
        self.waiting.push(Reverse(WaitEntry {
            order: node.wait_tuple(),
            node,
        }));
    }

    fn requeue_primary(&mut self, node: PoolNode) {
        if node.vruntime_ns <= self.virtual_time_ns {
            self.eligible.push(Reverse(DeadlineEntry {
                order: node.deadline_tuple(),
                node,
            }));
        } else {
            self.future.push(Reverse(FutureEntry {
                order: node.future_tuple(),
                node,
            }));
        }
    }

    fn pop(&mut self) -> Option<PoolNode> {
        self.promote_eligible();
        if self.eligible.is_empty() {
            self.virtual_time_ns = self
                .future
                .peek()
                .map(|entry| self.virtual_time_ns.max(entry.0.node.vruntime_ns))?;
            self.promote_eligible();
        }
        self.eligible.pop().map(|entry| entry.0.node)
    }

    fn promote_eligible(&mut self) {
        while self
            .future
            .peek()
            .is_some_and(|entry| entry.0.node.vruntime_ns <= self.virtual_time_ns)
        {
            let node = self.future.pop().expect("peeked future node").0.node;
            self.eligible.push(Reverse(DeadlineEntry {
                order: node.deadline_tuple(),
                node,
            }));
        }
    }

    fn is_empty(&self) -> bool {
        self.eligible.is_empty() && self.future.is_empty()
    }

    fn peek_oldest(&self) -> Option<PoolNode> {
        self.waiting.peek().map(|entry| entry.0.node)
    }

    fn pop_oldest(&mut self) -> Option<PoolNode> {
        self.waiting.pop().map(|entry| entry.0.node)
    }

    fn restore_oldest(&mut self, node: PoolNode) {
        self.waiting.push(Reverse(WaitEntry {
            order: node.wait_tuple(),
            node,
        }));
    }

    fn node_count(&self) -> usize {
        self.eligible
            .len()
            .saturating_add(self.future.len())
            .saturating_add(self.waiting.len())
    }
}

/// Dense class-indexed collection of identical EEVDF pools.
#[derive(Clone, Debug, Default)]
pub struct TaskPools {
    pools: [EevdfPool; 3],
}

impl TaskPools {
    pub fn push(&mut self, node: PoolNode) {
        self.pools[node.class.index()].push(node);
    }

    pub fn pop(&mut self, class: TaskClass) -> Option<PoolNode> {
        self.pools[class.index()].pop()
    }

    pub fn is_empty(&self, class: TaskClass) -> bool {
        self.pools[class.index()].is_empty()
    }

    pub fn peek_oldest(&self, class: TaskClass) -> Option<PoolNode> {
        self.pools[class.index()].peek_oldest()
    }

    pub fn pop_oldest(&mut self, class: TaskClass) -> Option<PoolNode> {
        self.pools[class.index()].pop_oldest()
    }

    pub fn requeue_primary(&mut self, node: PoolNode) {
        self.pools[node.class.index()].requeue_primary(node);
    }

    pub fn restore_oldest(&mut self, node: PoolNode) {
        self.pools[node.class.index()].restore_oldest(node);
    }

    /// Places a waking task with no more than one request of positive lag.
    pub fn place_vruntime(&self, class: TaskClass, vruntime_ns: u64, request_ns: u64) -> u64 {
        place_vruntime(
            self.pools[class.index()].virtual_time_ns,
            vruntime_ns,
            request_ns,
        )
    }

    /// Translates bounded lag instead of resetting service on a class change.
    pub fn rebase_vruntime(
        &self,
        source: TaskClass,
        target: TaskClass,
        vruntime_ns: u64,
        source_request_ns: u64,
        target_request_ns: u64,
    ) -> u64 {
        rebase_vruntime(
            self.pools[source.index()].virtual_time_ns,
            self.pools[target.index()].virtual_time_ns,
            vruntime_ns,
            source_request_ns,
            target_request_ns,
        )
    }

    pub fn node_count(&self) -> usize {
        self.pools.iter().map(EevdfPool::node_count).sum()
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::{PoolNode, TaskPools};
    use crate::identity::{TaskClass, TaskKey};

    fn node(tid: u32, vruntime_ns: u64, request_ns: u64) -> PoolNode {
        PoolNode {
            task: TaskKey::new(tid, tid as u64).unwrap(),
            enqueue_sequence: 1,
            class_generation: 0,
            class: TaskClass::Balanced,
            enqueue_time_ns: tid as u64,
            vruntime_ns,
            request_ns,
            deadline_ns: vruntime_ns.saturating_add(request_ns),
        }
    }

    #[test]
    fn earliest_deadline_wins_among_eligible_tasks() {
        let mut pools = TaskPools::default();
        pools.push(node(1, 0, 4));
        pools.push(node(2, 0, 1));
        assert_eq!(pools.pop(TaskClass::Balanced).unwrap().task.tid, 2);
    }

    #[test]
    fn virtual_time_advances_only_when_no_entity_is_eligible() {
        let mut pools = TaskPools::default();
        pools.push(node(1, 10, 4));
        pools.push(node(2, 20, 1));
        assert_eq!(pools.pop(TaskClass::Balanced).unwrap().task.tid, 1);
        assert_eq!(pools.pop(TaskClass::Balanced).unwrap().task.tid, 2);
    }
}
