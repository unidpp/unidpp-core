//! Provenance DAG navigation: trace-up (composition of C), trace-down
//! (where did A's remainder go), recall sets, and downstream taint
//! propagation.

use std::collections::{BTreeMap, BTreeSet};

use unidpp_model::PassportId;

use crate::taint::TaintSet;

/// The provenance graph over passports (nodes) formed by splits and
/// combines. Edges point input -> output.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceGraph {
    inputs_of: BTreeMap<PassportId, BTreeSet<PassportId>>,
    outputs_of: BTreeMap<PassportId, BTreeSet<PassportId>>,
}

impl ProvenanceGraph {
    pub fn new() -> ProvenanceGraph {
        ProvenanceGraph::default()
    }

    /// Record a split: parent -> children.
    pub fn record_split(&mut self, parent: PassportId, children: &[PassportId]) {
        for child in children {
            self.inputs_of
                .entry(child.clone())
                .or_default()
                .insert(parent.clone());
            self.outputs_of
                .entry(parent.clone())
                .or_default()
                .insert(child.clone());
        }
    }

    /// Record a combine: inputs -> output.
    pub fn record_combine(&mut self, output: PassportId, inputs: &[PassportId]) {
        for input in inputs {
            self.inputs_of
                .entry(output.clone())
                .or_default()
                .insert(input.clone());
            self.outputs_of
                .entry(input.clone())
                .or_default()
                .insert(output.clone());
        }
    }

    fn walk(&self, start: &PassportId, forward: bool) -> BTreeSet<PassportId> {
        let adjacency = if forward {
            &self.outputs_of
        } else {
            &self.inputs_of
        };
        let mut seen: BTreeSet<PassportId> = BTreeSet::new();
        let mut queue: Vec<PassportId> = vec![start.clone()];
        while let Some(node) = queue.pop() {
            if let Some(next) = adjacency.get(&node) {
                for n in next {
                    if seen.insert(n.clone()) {
                        queue.push(n.clone());
                    }
                }
            }
        }
        seen
    }

    /// Ancestors: everything `id` derives from (trace-up).
    pub fn ancestors(&self, id: &PassportId) -> BTreeSet<PassportId> {
        self.walk(id, false)
    }

    /// Descendants: everything derived from `id` (trace-down; where did
    /// the remainder go).
    pub fn descendants(&self, id: &PassportId) -> BTreeSet<PassportId> {
        self.walk(id, true)
    }

    /// Recall set for a root: the root plus all descendants (the
    /// predicate itself is evaluated locally by each custodian; this is
    /// the routing set after a match).
    pub fn recall_set(&self, root: &PassportId) -> BTreeSet<PassportId> {
        let mut set = self.descendants(root);
        set.insert(root.clone());
        set
    }

    /// Taints effective on `id`: its own plus all ancestors' taints
    /// (taint propagates downstream through the graph).
    pub fn taints_of(
        &self,
        id: &PassportId,
        taint_index: &BTreeMap<PassportId, TaintSet>,
    ) -> TaintSet {
        let mut out = TaintSet::new();
        let mut sources: BTreeSet<PassportId> = self.ancestors(id);
        sources.insert(id.clone());
        for s in &sources {
            if let Some(t) = taint_index.get(s) {
                out.merge(t);
            }
        }
        out
    }

    pub fn edge_count(&self) -> usize {
        self.inputs_of.values().map(|s| s.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint::{KnownTaint, Taint, TaintKind};

    fn pid(n: &str) -> PassportId {
        PassportId::new(&format!("urn:unidpp:passport:{n}")).unwrap()
    }

    fn graph() -> ProvenanceGraph {
        let mut g = ProvenanceGraph::new();
        // cell-1, cell-2 -> pack; pack -> car? No: pack -> (split) -> module-a, module-b
        g.record_combine(pid("pack"), &[pid("cell-1"), pid("cell-2")]);
        g.record_split(pid("pack"), &[pid("mod-a"), pid("mod-b")]);
        g.record_combine(pid("battery-2"), &[pid("mod-b"), pid("cell-3")]);
        g
    }

    #[test]
    fn trace_up_and_down() {
        let g = graph();
        assert_eq!(
            g.ancestors(&pid("battery-2")),
            BTreeSet::from([
                pid("cell-2"),
                pid("cell-3"),
                pid("pack"),
                pid("mod-b"),
                pid("cell-1")
            ])
        );
        let mut down = g.descendants(&pid("cell-1"));
        assert!(down.contains(&pid("pack")));
        assert!(down.contains(&pid("mod-a")));
        assert!(down.contains(&pid("mod-b")));
        assert!(down.contains(&pid("battery-2")));
        assert!(!down.contains(&pid("cell-3")));
        down = g.descendants(&pid("cell-3"));
        assert_eq!(down, BTreeSet::from([pid("battery-2")]));
    }

    #[test]
    fn taint_propagates_downstream() {
        let g = graph();
        let mut index = BTreeMap::new();
        let mut ts = TaintSet::new();
        ts.add(Taint {
            source: pid("cell-1"),
            kind: TaintKind::Known(KnownTaint::Fraud),
            reason: "stolen cells".into(),
            at: unidpp_model::Timestamp::from_secs(1),
            window: None,
        });
        index.insert(pid("cell-1"), ts);
        // Direct child tainted
        assert!(g.taints_of(&pid("pack"), &index).voids_ab_initio());
        // Transitive descendant tainted
        assert!(g.taints_of(&pid("mod-b"), &index).voids_ab_initio());
        // Unrelated branch clean
        assert!(!g.taints_of(&pid("cell-3"), &index).voids_ab_initio());
    }

    #[test]
    fn recall_set_includes_root() {
        let g = graph();
        let set = g.recall_set(&pid("cell-2"));
        assert!(set.contains(&pid("cell-2")));
        assert!(set.contains(&pid("battery-2")));
        assert!(!set.contains(&pid("cell-1")));
    }
}
