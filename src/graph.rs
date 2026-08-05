//this is a graph libarary i am working on
//it is moved from project to project when needed (inspired by rustc data structures)

use crate::index::{Idx, IndexVec};
use std::ops::Range;

pub trait DirectedGraph {
    type Node: Idx;

    fn num_nodes(&self) -> usize;
    fn iter_nodes(&self) -> impl DoubleEndedIterator<Item = Self::Node> + ExactSizeIterator {
        (0..self.num_nodes()).map(<Self::Node as Idx>::new)
    }

    fn edges(&self, node: Self::Node) -> impl Iterator<Item = Self::Node>;
}

#[derive(Debug, Clone)]
pub struct BasicGraph<Node: Idx> {
    pub edges: IndexVec<Node, Vec<Node>>,
}

impl<N: Idx> DirectedGraph for BasicGraph<N> {
    type Node = N;
    fn num_nodes(&self) -> usize {
        self.edges.len()
    }
    fn edges(&self, i: Self::Node) -> impl Iterator<Item = Self::Node> {
        self.edges[i].iter().copied()
    }
}

#[derive(Debug, Clone)]
pub struct VecGraph<Node: Idx> {
    nodes: IndexVec<Node, Range<usize>>,
    edges: Vec<Node>,
}

impl<Node: Idx> VecGraph<Node> {
    pub fn new_empty() -> Self {
        Self {
            nodes: IndexVec::new(),
            edges: Vec::new(),
        }
    }

    /// Copies a graph into a contiguous adjacency-list representation.
    pub fn from_graph<G: DirectedGraph<Node = Node>>(graph: &G) -> Self {
        let mut nodes = IndexVec::with_capacity(graph.num_nodes());
        let mut edges = Vec::new();

        for node in graph.iter_nodes() {
            let start = edges.len();
            edges.extend(graph.edges(node));
            nodes.push(start..edges.len());
        }

        Self { nodes, edges }
    }

    pub(crate) fn from_raw(nodes: IndexVec<Node, Range<usize>>, edges: Vec<Node>) -> Self {
        Self { nodes, edges }
    }
    pub fn num_edges(&self) -> usize {
        self.edges.len()
    }
}

impl<N: Idx> DirectedGraph for VecGraph<N> {
    type Node = N;
    fn num_nodes(&self) -> usize {
        self.nodes.len()
    }
    fn edges(&self, i: Self::Node) -> impl Iterator<Item = Self::Node> {
        let r = self.nodes[i].clone();
        self.edges[r.start..r.end].iter().copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitState<Node: Idx> {
    NotSeen,
    Working {
        index: Node,
        min_val: Node,
    },
    Done {
        index: Node,
        min_val: Node,
        scc_id: CompId<Node>,
    },
}

impl<Node: Idx> VisitState<Node> {
    fn get_min(&self) -> Node {
        match self {
            VisitState::NotSeen => unreachable!("bad call"),
            VisitState::Working { min_val, .. } | VisitState::Done { min_val, .. } => *min_val,
        }
    }
    fn update_min(&mut self, other: Node) {
        match self {
            VisitState::NotSeen => unreachable!("bad call"),
            VisitState::Working { min_val, .. } | VisitState::Done { min_val, .. } => {
                if min_val.index() > other.index() {
                    *min_val = other;
                }
            }
        }
    }

    fn mark_done(&mut self, cid: CompId<Node>) {
        let VisitState::Working { index, min_val, .. } = *self else {
            return;
        };
        *self = VisitState::Done {
            index,
            min_val,
            scc_id: cid,
        };
    }
}

struct WorkFrame<Node: Idx, I: Iterator<Item = Node>> {
    node: Node,
    edges: I,
    successor_len: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CompId<Node: Idx>(Node);

impl<Node: Idx> Idx for CompId<Node> {
    fn new(idx: usize) -> Self {
        CompId(Node::new(idx))
    }

    fn index(self) -> usize {
        self.0.index()
    }
}

pub struct SCCS<Node: Idx> {
    pub map: IndexVec<Node, CompId<Node>>,
    pub comps: IndexVec<CompId<Node>, Vec<Node>>,
    ///a DAG ordered in reverse topologiacl order
    pub o_dag: VecGraph<CompId<Node>>,
}

pub fn tarjan<G: DirectedGraph>(graph: &G) -> SCCS<G::Node> {
    let mut scc_stack = Vec::new();
    let mut successor_stack = Vec::new();
    let mut successor_dedup = foldhash::HashSet::default();

    let mut call_stack = Vec::new();
    let mut states: IndexVec<G::Node, _> =
        graph.iter_nodes().map(|_| VisitState::NotSeen).collect();

    let mut map: IndexVec<G::Node, CompId<G::Node>> =
        graph.iter_nodes().map(|_| CompId::new(0)).collect();
    let mut comps: IndexVec<CompId<G::Node>, Vec<G::Node>> = IndexVec::new();
    let mut o_dag = VecGraph::new_empty();

    let mut index = G::Node::new(0);

    for node in graph.iter_nodes() {
        let VisitState::NotSeen = states[node] else {
            debug_assert!(matches!(states[node], VisitState::Done { .. }));
            continue;
        };

        call_stack.push(WorkFrame {
            node,
            edges: graph.edges(node),
            successor_len: successor_stack.len(),
        });
        states[node] = VisitState::Working {
            index,
            min_val: index,
        };
        index.increment_by(1);
        scc_stack.push(node);

        'recurse: while let Some(frame) = call_stack.last_mut() {
            #[allow(clippy::while_let_on_iterator)]
            while let Some(next) = frame.edges.next() {
                match states[next] {
                    VisitState::NotSeen => {
                        call_stack.push(WorkFrame {
                            node: next,
                            edges: graph.edges(next),
                            successor_len: successor_stack.len(),
                        });
                        states[next] = VisitState::Working {
                            index,
                            min_val: index,
                        };
                        index.increment_by(1);
                        scc_stack.push(next);

                        continue 'recurse;
                    }
                    VisitState::Working { index, .. } => {
                        states[frame.node].update_min(index);
                    }
                    VisitState::Done { scc_id, .. } => {
                        successor_stack.push(scc_id);
                    }
                }
            }

            let frame = call_stack.pop().unwrap();

            if let VisitState::Working {
                index: i, min_val, ..
            } = states[frame.node]
                && i == min_val
            {
                let cid = CompId::new(comps.len());

                //first gather members
                let mut members = Vec::new();
                loop {
                    let c = scc_stack
                        .pop()
                        .expect("SCC root must be present on SCC stack");

                    states[c].mark_done(cid);
                    map[c] = cid;
                    members.push(c);

                    if c == frame.node {
                        break;
                    }
                }
                comps.push(members);

                //now gather the o_dag edges
                successor_dedup.clear();

                let start = o_dag.num_edges();
                o_dag.edges.extend(
                    successor_stack
                        .drain(frame.successor_len..)
                        .filter(|s| successor_dedup.insert(*s)),
                );
                let end = o_dag.num_edges();

                o_dag.nodes.push(start..end);

                //we are done but a calling parent needs to have us as a successor
                if call_stack.last().is_some() {
                    successor_stack.push(cid);
                }
            };

            if let Some(pf) = call_stack.last() {
                let m = states[frame.node].get_min();
                states[pf.node].update_min(m);
            }
        }
    }
    SCCS { comps, map, o_dag }
}

///similar to a classic union find but with A >= B style edges as well
#[derive(Debug)]
pub struct BasicOrder<I: Idx, T = ()> {
    edges: IndexVec<I, foldhash::HashMap<I, T>>,
}

impl<I: Idx, T> BasicOrder<I, T> {
    pub fn new() -> Self {
        BasicOrder {
            edges: IndexVec::new(),
        }
    }

    pub fn add_node(&mut self) -> I {
        self.edges.push(foldhash::HashMap::default())
    }

    pub fn add_edge(&mut self, from: I, to: I, label: T) {
        self.edges[from].insert(to, label);
    }

    pub fn unify(&mut self, a: I, b: I, label: T)
    where
        T: Clone,
    {
        self.add_edge(a, b, label.clone());
        self.add_edge(b, a, label);
    }
}

impl<I: Idx> Default for BasicOrder<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Idx, T> DirectedGraph for BasicOrder<I, T> {
    type Node = I;
    fn num_nodes(&self) -> usize {
        self.edges.len()
    }
    fn edges(&self, idx: I) -> impl Iterator<Item = I> {
        self.edges[idx].keys().copied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphCycle<Node: Idx> {
    /// Closed path: the first and last nodes are identical.
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone)]
pub struct TopologicalOrder<Node: Idx> {
    /// Every edge points from an earlier node to a later node.
    pub order: Vec<Node>,

    /// `map[node]` is the node's index in `order`.
    pub map: IndexVec<Node, Node>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DagVisitState {
    NotSeen,
    Working,
    Done,
}

struct DagWorkFrame<Node: Idx, I: Iterator<Item = Node>> {
    node: Node,
    edges: I,
}

/// Returns a topological ordering, or the first cycle encountered by DFS.
pub fn topological_order<G: DirectedGraph>(
    graph: &G,
) -> Result<TopologicalOrder<G::Node>, GraphCycle<G::Node>> {
    let mut states: IndexVec<G::Node, DagVisitState> = graph
        .iter_nodes()
        .map(|_| DagVisitState::NotSeen)
        .collect();

    let mut stack_pos: IndexVec<G::Node, usize> =
        graph.iter_nodes().map(|_| usize::MAX).collect();

    let mut call_stack = Vec::new();
    let mut reverse_order = Vec::with_capacity(graph.num_nodes());

    for root in graph.iter_nodes() {
        if states[root] != DagVisitState::NotSeen {
            continue;
        }

        states[root] = DagVisitState::Working;
        stack_pos[root] = call_stack.len();

        call_stack.push(DagWorkFrame {
            node: root,
            edges: graph.edges(root),
        });

        'recurse: while let Some(frame) = call_stack.last_mut() {
            while let Some(next) = frame.edges.next() {
                match states[next] {
                    DagVisitState::NotSeen => {
                        states[next] = DagVisitState::Working;
                        stack_pos[next] = call_stack.len();

                        call_stack.push(DagWorkFrame {
                            node: next,
                            edges: graph.edges(next),
                        });

                        continue 'recurse;
                    }

                    DagVisitState::Working => {
                        let start = stack_pos[next];

                        let mut cycle: Vec<_> = call_stack[start..]
                            .iter()
                            .map(|frame| frame.node)
                            .collect();

                        cycle.push(next);
                        return Err(GraphCycle { nodes: cycle });
                    }

                    DagVisitState::Done => {}
                }
            }

            let frame = call_stack.pop().unwrap();

            states[frame.node] = DagVisitState::Done;
            stack_pos[frame.node] = usize::MAX;
            reverse_order.push(frame.node);
        }
    }

    reverse_order.reverse();

    let mut map: IndexVec<G::Node, G::Node> = graph.iter_nodes().collect();

    for (index, &node) in reverse_order.iter().enumerate() {
        map[node] = G::Node::new(index);
    }

    Ok(TopologicalOrder {
        order: reverse_order,
        map,
    })
}

/// Returns a new graph with transitively redundant edges removed.
pub fn transitive_reduction<G: DirectedGraph>(
    graph: &G,
) -> Result<(BasicGraph<G::Node>, TopologicalOrder<G::Node>), GraphCycle<G::Node>> {
    let topo = topological_order(graph)?;
    let node_count = graph.num_nodes();

    let mut reachable: IndexVec<G::Node, Vec<bool>> = graph
        .iter_nodes()
        .map(|_| vec![false; node_count])
        .collect();

    let mut reduced = BasicGraph {
        edges: graph.iter_nodes().map(|_| Vec::new()).collect(),
    };

    for &from in topo.order.iter().rev() {
        let mut successors: Vec<_> = graph.edges(from).collect();

        successors.sort_unstable_by_key(|&to| topo.map[to].index());
        successors.dedup();

        let mut covered = vec![false; node_count];

        for to in successors {
            if covered[to.index()] {
                continue;
            }

            reduced.edges[from].push(to);
            covered[to.index()] = true;

            for (index, &value) in reachable[to].iter().enumerate() {
                covered[index] |= value;
            }
        }

        reachable[from] = covered;
    }

    Ok((reduced, topo))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    type Set = BTreeSet<usize>;
    type Edge = (Set, Set);

    fn graph(num_nodes: usize, edges: &[(usize, usize)]) -> BasicGraph<usize> {
        let mut g = BasicGraph {
            edges: (0..num_nodes).map(|_| Vec::new()).collect(),
        };

        for &(from, to) in edges {
            g.edges[from].push(to);
        }

        g
    }

    #[test]
    fn vec_graph_from_graph_preserves_adjacency_lists() {
        let source = graph(5, &[(0, 1), (0, 3), (0, 1), (2, 2), (4, 0)]);
        let compact = VecGraph::from_graph(&source);

        assert_eq!(compact.num_nodes(), 5);
        assert_eq!(compact.num_edges(), 5);

        for node in source.iter_nodes() {
            assert_eq!(
                compact.edges(node).collect::<Vec<_>>(),
                source.edges(node).collect::<Vec<_>>()
            );
        }
    }

    fn set(nodes: &[usize]) -> Set {
        nodes.iter().copied().collect()
    }

    fn sets(comps: &[&[usize]]) -> BTreeSet<Set> {
        comps.iter().map(|comp| set(comp)).collect()
    }

    fn actual_comps(sccs: &SCCS<usize>) -> BTreeSet<Set> {
        sccs.comps.iter().map(|comp| set(comp)).collect()
    }

    fn actual_dag_edges(sccs: &SCCS<usize>) -> BTreeSet<Edge> {
        let mut edges = BTreeSet::new();

        for raw_from in 0..sccs.comps.len() {
            let from = CompId::new(raw_from);
            let from_set = set(&sccs.comps[from]);
            let range = sccs.o_dag.nodes[from].clone();

            for &to in &sccs.o_dag.edges[range] {
                edges.insert((from_set.clone(), set(&sccs.comps[to])));
            }
        }

        edges
    }

    fn expected_dag_edges(edges: &[(&[usize], &[usize])]) -> BTreeSet<Edge> {
        edges
            .iter()
            .map(|(from, to)| (set(from), set(to)))
            .collect()
    }

    fn assert_invariants(graph: &BasicGraph<usize>, sccs: &SCCS<usize>) {
        let mut seen = BTreeMap::new();

        for (raw_cid, comp) in sccs.comps.iter().enumerate() {
            let cid = CompId::new(raw_cid);

            for &node in comp {
                assert_eq!(sccs.map[node], cid, "map[{node:?}] points to wrong SCC");

                let old = seen.insert(node, cid);
                assert!(
                    old.is_none(),
                    "node {node:?} appeared in multiple SCCs: {old:?} and {cid:?}"
                );
            }
        }

        for node in graph.iter_nodes() {
            assert!(
                seen.contains_key(&node),
                "node {node:?} did not appear in any SCC"
            );
        }

        assert_eq!(
            sccs.o_dag.nodes.len(),
            sccs.comps.len(),
            "DAG should have exactly one node per SCC"
        );

        for raw_from in 0..sccs.comps.len() {
            let from = CompId::new(raw_from);
            let range = sccs.o_dag.nodes[from].clone();

            for &to in &sccs.o_dag.edges[range] {
                assert_ne!(
                    from, to,
                    "SCC DAG should not contain self-edge {from:?} -> {to:?}"
                );
            }
        }
    }

    fn assert_sccs(
        graph: &BasicGraph<usize>,
        expected_comps: &[&[usize]],
        expected_edges: &[(&[usize], &[usize])],
    ) {
        let sccs = tarjan(graph);

        assert_eq!(
            actual_comps(&sccs),
            sets(expected_comps),
            "wrong SCC partition"
        );

        assert_invariants(graph, &sccs);

        assert_eq!(
            actual_dag_edges(&sccs),
            expected_dag_edges(expected_edges),
            "wrong SCC DAG edges"
        );
    }

    #[test]
    fn empty_graph() {
        let g = graph(0, &[]);
        assert_sccs(&g, &[], &[]);
    }

    #[test]
    fn found_hard_graph() {
        let g = graph(3, &[(1, 2)]);

        let dag = tarjan(&g).o_dag;
        eprintln!("{dag:?}");
        for node in dag.iter_nodes() {
            println!("in node {node:?}");
            for edge in dag.edges(node) {
                println!("has edge ({node:?},{edge:?})");
            }
        }

        assert_sccs(&g, &[&[0], &[1], &[2]], &[(&[1], &[2])]);
    }

    #[test]
    fn isolated_nodes() {
        let g = graph(4, &[]);
        assert_sccs(&g, &[&[0], &[1], &[2], &[3]], &[]);
    }

    #[test]
    fn simple_chain() {
        let g = graph(4, &[(0, 1), (1, 2), (2, 3)]);

        assert_sccs(
            &g,
            &[&[0], &[1], &[2], &[3]],
            &[(&[0], &[1]), (&[1], &[2]), (&[2], &[3])],
        );
    }

    #[test]
    fn simple_cycle() {
        let g = graph(3, &[(0, 1), (1, 2), (2, 0)]);
        assert_sccs(&g, &[&[0, 1, 2]], &[]);
    }

    #[test]
    fn self_loop() {
        let g = graph(1, &[(0, 0)]);
        assert_sccs(&g, &[&[0]], &[]);
    }

    #[test]
    fn disconnected_cycles() {
        let g = graph(5, &[(0, 1), (1, 0), (2, 3), (3, 4), (4, 2)]);

        assert_sccs(&g, &[&[0, 1], &[2, 3, 4]], &[]);
    }

    #[test]
    fn edge_between_sccs_does_not_merge_them() {
        let g = graph(4, &[(0, 1), (1, 0), (1, 2), (2, 3), (3, 2)]);

        assert_sccs(&g, &[&[0, 1], &[2, 3]], &[(&[0, 1], &[2, 3])]);
    }

    #[test]
    fn diamond_without_back_edges() {
        let g = graph(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);

        assert_sccs(
            &g,
            &[&[0], &[1], &[2], &[3]],
            &[(&[0], &[1]), (&[0], &[2]), (&[1], &[3]), (&[2], &[3])],
        );
    }

    #[test]
    fn diamond_with_back_edge() {
        let g = graph(4, &[(0, 1), (0, 2), (1, 3), (2, 3), (3, 0)]);

        assert_sccs(&g, &[&[0, 1, 2, 3]], &[]);
    }

    #[test]
    fn cycle_reaching_tail() {
        let g = graph(5, &[(0, 1), (1, 2), (2, 0), (2, 3), (3, 4)]);

        assert_sccs(
            &g,
            &[&[0, 1, 2], &[3], &[4]],
            &[(&[0, 1, 2], &[3]), (&[3], &[4])],
        );
    }

    #[test]
    fn tail_reaching_cycle() {
        let g = graph(4, &[(0, 1), (1, 2), (2, 3), (3, 1)]);

        assert_sccs(&g, &[&[0], &[1, 2, 3]], &[(&[0], &[1, 2, 3])]);
    }

    #[test]
    fn cross_edge_to_done_scc_does_not_corrupt_lowlink() {
        let g = graph(4, &[(0, 1), (1, 0), (2, 3), (3, 2), (2, 0)]);

        assert_sccs(&g, &[&[0, 1], &[2, 3]], &[(&[2, 3], &[0, 1])]);
    }

    #[test]
    fn dag_deduplicates_many_edges_between_same_sccs() {
        let g = graph(
            4,
            &[
                (0, 1),
                (1, 0),
                (2, 3),
                (3, 2),
                (0, 2),
                (0, 3),
                (1, 2),
                (1, 3),
            ],
        );

        assert_sccs(&g, &[&[0, 1], &[2, 3]], &[(&[0, 1], &[2, 3])]);
    }

    #[test]
    fn branching_scc_dag() {
        let g = graph(
            6,
            &[
                (0, 1),
                (1, 0),
                (0, 2),
                (1, 3),
                (2, 4),
                (3, 5),
                (4, 5),
                (5, 4),
            ],
        );

        assert_sccs(
            &g,
            &[&[0, 1], &[2], &[3], &[4, 5]],
            &[
                (&[0, 1], &[2]),
                (&[0, 1], &[3]),
                (&[2], &[4, 5]),
                (&[3], &[4, 5]),
            ],
        );
    }

    #[test]
    fn child_scc_edge_is_recorded_after_child_finishes() {
        let g = graph(2, &[(0, 1)]);

        assert_sccs(&g, &[&[0], &[1]], &[(&[0], &[1])]);
    }

    #[test]
    fn finds_cycle() {
        let g = graph(4, &[
            (0, 1),
            (1, 2),
            (2, 3),
            (3, 1),
        ]);

        let cycle = topological_order(&g).unwrap_err();

        assert_eq!(cycle.nodes, vec![1, 2, 3, 1]);
    }

    #[test]
    fn removes_transitive_edges() {
        let g = graph(4, &[
            (0, 1),
            (1, 2),
            (2, 3),

            (0, 2),
            (0, 3),
            (1, 3),
        ]);

        let (reduced, topo) = transitive_reduction(&g).unwrap();

        assert_eq!(reduced.edges[0], vec![1]);
        assert_eq!(reduced.edges[1], vec![2]);
        assert_eq!(reduced.edges[2], vec![3]);
        assert!(reduced.edges[3].is_empty());

        for from in g.iter_nodes() {
            for to in g.edges(from) {
                assert!(topo.map[from] < topo.map[to]);
            }
        }
    }
}
