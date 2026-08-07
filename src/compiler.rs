use crate::graph::{
    DirectedGraph, GraphCycle, TopologicalOrder, VecGraph, topological_order,
    transitive_solved_reduction,
};
use crate::index::Idx;
use crate::model::{Atom, CompiledSetup, Task, TaskInfo};
use foldhash::HashSet;
use foldhash::HashSetExt;

impl TaskInfo {
    pub fn compile(&self) -> Result<CompiledSetup, GraphCycle<u32>> {
        #[derive(Clone, Default)]
        struct Boundary {
            entries: Vec<u32>,
            exits: Vec<u32>,
        }

        #[derive(Clone, Copy)]
        enum State {
            NotSeen,
            OnStack,
            Done,
        }

        struct BoundaryBuild<'a> {
            boundaries: &'a mut [Option<Boundary>],
            states: &'a mut [State],
            stack: &'a mut Vec<u32>,
            stack_positions: &'a mut [usize],
            atom_edges: &'a mut [HashSet<u32>],
        }

        /// Adds every edge from `exits` to every node in `entries`.
        fn connect(edges: &mut [HashSet<u32>], exits: &[u32], entries: &[u32]) {
            for &from in exits {
                for &to in entries {
                    edges[from as usize].insert(to);
                }
            }
        }

        fn deduplicate(values: &mut Vec<u32>) {
            values.sort_unstable();
            values.dedup();
        }

        /// Computes the intrinsic atom boundary of a task.
        ///
        /// `entries` are the atoms that may execute first.
        /// `exits` are the atoms that may execute last.
        ///
        /// This also emits atom edges implied by nested `Ordered` tasks.
        /// Empty children inherit the surrounding ordering, so
        /// `A, empty, B` emits the same atom edge as `A, B`.
        ///
        /// The result is intrinsic to the task. Ordering inherited from
        /// external predecessors is handled later by the task-graph pass.
        ///
        /// `states` and `stack` detect recursive task containment. Any
        /// returned cycle is expressed using task IDs.
        fn build_boundary(
            task_idx: u32,
            tasks: &[Task],
            atoms_map: &[u32],
            build: &mut BoundaryBuild<'_>,
        ) -> Result<Boundary, GraphCycle<u32>> {
            let idx = task_idx as usize;

            match build.states[idx] {
                State::OnStack => {
                    let start = build.stack_positions[idx];
                    let mut nodes = build.stack[start..].to_vec();
                    nodes.push(task_idx);

                    return Err(GraphCycle { nodes });
                }

                State::Done => {
                    return Ok(build.boundaries[idx].as_ref().unwrap().clone());
                }

                State::NotSeen => {}
            }

            build.states[idx] = State::OnStack;
            build.stack_positions[idx] = build.stack.len();
            build.stack.push(task_idx);

            let boundary = match &tasks[idx] {
                Task::Atom(_) => {
                    let atom = atoms_map[idx];

                    Boundary {
                        entries: vec![atom],
                        exits: vec![atom],
                    }
                }

                Task::Unordered(children) => {
                    let mut entries = Vec::new();
                    let mut exits = Vec::new();

                    for &child_idx in children {
                        let child = build_boundary(child_idx, tasks, atoms_map, build)?;

                        entries.extend(child.entries);
                        exits.extend(child.exits);
                    }

                    deduplicate(&mut entries);
                    deduplicate(&mut exits);

                    Boundary { entries, exits }
                }

                Task::Ordered(children) => {
                    let mut entries = Vec::new();
                    let mut previous_exits: Option<Vec<u32>> = None;

                    for &child_idx in children {
                        let child = build_boundary(child_idx, tasks, atoms_map, build)?;

                        // Empty tasks inherit the surrounding ordering.
                        if child.entries.is_empty() {
                            continue;
                        }

                        if entries.is_empty() {
                            entries = child.entries.clone();
                        }

                        if let Some(previous) = &previous_exits {
                            connect(build.atom_edges, previous, &child.entries);
                        }

                        previous_exits = Some(child.exits);
                    }

                    Boundary {
                        entries,
                        exits: previous_exits.unwrap_or_default(),
                    }
                }
            };

            build.stack.pop();
            build.states[idx] = State::Done;
            build.boundaries[idx] = Some(boundary.clone());

            Ok(boundary)
        }

        /*
         * Atom tasks are initially packed in task-index order. They are
         * remapped to the task graph's topological order before returning.
         *
         * For composite tasks, the corresponding atoms_map value is unused.
         */
        let mut count = 0;
        let mut atoms_map: Vec<u32> = Vec::with_capacity(self.tasks.len());

        let atoms: Vec<Atom> = self
            .tasks
            .iter()
            .filter_map(|task| match task {
                Task::Atom(atom) => {
                    atoms_map.push(count);
                    count += 1;
                    Some(*atom)
                }

                _ => {
                    atoms_map.push(0);
                    None
                }
            })
            .collect();

        /*
         * First compute intrinsic boundaries and nested atom ordering.
         */
        let mut atom_edges: Vec<HashSet<u32>> = (0..atoms.len()).map(|_| HashSet::new()).collect();

        let mut boundaries = vec![None; self.tasks.len()];
        let mut states = vec![State::NotSeen; self.tasks.len()];
        let mut stack = Vec::new();
        let mut stack_positions = vec![0; self.tasks.len()];
        {
            let mut boundary_build = BoundaryBuild {
                boundaries: &mut boundaries,
                states: &mut states,
                stack: &mut stack,
                stack_positions: &mut stack_positions,
                atom_edges: &mut atom_edges,
            };

            for task_idx in 0..self.tasks.len() {
                build_boundary(
                    task_idx as u32,
                    &self.tasks,
                    &atoms_map,
                    &mut boundary_build,
                )?;
            }
        }

        /*
         * Build the task-level ordering graph.
         *
         * It contains:
         * - explicit happens_before constraints;
         * - consecutive child constraints from Ordered tasks.
         *
         * Keeping these as task edges allows ordering to pass through tasks
         * that contain no atoms.
         */
        let mut task_edges: Vec<HashSet<u32>> =
            (0..self.tasks.len()).map(|_| HashSet::new()).collect();

        for (&from, destinations) in &self.happens_before {
            task_edges[from as usize].extend(destinations.iter().copied());
        }

        for task in &self.tasks {
            if let Task::Ordered(children) = task {
                for pair in children.windows(2) {
                    task_edges[pair[0] as usize].insert(pair[1]);
                }
            }
        }

        /*
         * Follow each task edge through empty tasks to the next nonempty
         * boundary. This contracts empty paths without requiring an order.
         */
        for from in 0..self.tasks.len() as u32 {
            let source = boundaries[from.index()].as_ref().unwrap();
            if source.entries.is_empty() {
                continue;
            }

            let mut seen = vec![false; self.tasks.len()];
            let mut stack: Vec<_> = task_edges[from.index()].iter().copied().collect();
            while let Some(to) = stack.pop() {
                if seen[to.index()] {
                    continue;
                }
                seen[to.index()] = true;

                let destination = boundaries[to.index()].as_ref().unwrap();
                if destination.entries.is_empty() {
                    stack.extend(task_edges[to.index()].iter().copied());
                } else {
                    connect(&mut atom_edges, &source.exits, &destination.entries);
                }
            }
        }

        let atom_tasks: Vec<u32> = self
            .tasks
            .iter()
            .enumerate()
            .filter_map(|(task, value)| matches!(value, Task::Atom(_)).then_some(task as u32))
            .collect();
        for (from, destinations) in atom_edges.iter().enumerate() {
            let from_task = atom_tasks[from];
            task_edges[from_task.index()].extend(destinations.iter().filter_map(|&to| {
                let to_task = atom_tasks[to as usize];
                (from_task != to_task).then_some(to_task)
            }));
        }

        let task_graph =
            VecGraph::from_adjacency_lists(task_edges.into_iter().map(|destinations| {
                let mut destinations: Vec<_> = destinations.into_iter().collect();
                destinations.sort_unstable();
                destinations
            }));

        // Atom tasks are now a subgraph, so their subsequence is already a
        // valid topological order for transitive reduction.
        let task_order = topological_order(&task_graph)?;

        /*
         * The atom tasks retain the topological order already computed for
         * the full task graph, so reduction does not need another DFS.
         */
        let atom_graph =
            VecGraph::from_adjacency_lists(atom_edges.into_iter().map(|destinations| {
                let mut destinations: Vec<_> = destinations.into_iter().collect();
                destinations.sort_unstable();
                destinations
            }));

        let atom_order: Vec<u32> = task_order
            .order
            .iter()
            .filter_map(|&task| {
                matches!(self.tasks[task.index()], Task::Atom(_)).then_some(atoms_map[task.index()])
            })
            .collect();
        let mut atom_map: Vec<u32> = (0..atoms.len() as u32).collect();
        for (index, &atom) in atom_order.iter().enumerate() {
            atom_map[atom as usize] = index as u32;
        }
        let atom_order = TopologicalOrder {
            order: atom_order,
            map: atom_map.into_iter().collect(),
        };
        let reduced = transitive_solved_reduction(&atom_graph, &atom_order);

        let ordered_atoms: Vec<Atom> = atom_order
            .order
            .iter()
            .map(|&atom| atoms[atom as usize])
            .collect();
        let after_graph = VecGraph::from_adjacency_lists(
            atom_order
                .order
                .iter()
                .map(|&from| reduced.edges(from).map(|to| atom_order.map[to])),
        );
        let mut before_edges = vec![Vec::new(); after_graph.num_nodes()];
        for from in after_graph.iter_nodes() {
            for to in after_graph.edges(from) {
                before_edges[to.index()].push(from);
            }
        }
        let before_graph = VecGraph::from_adjacency_lists(before_edges);

        Ok(CompiledSetup {
            atoms: ordered_atoms,
            file_count: self.file_count as usize,
            after_graph,
            before_graph,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AtomData, Text};
    use foldhash::{HashMap, HashMapExt};

    fn atom(name: Text) -> Task {
        Task::Atom(Atom {
            data: AtomData::DebugName(name),
            error: None,
        })
    }

    fn edges(work: &CompiledSetup, from_name: Text) -> Vec<Text> {
        let from = work
            .atoms
            .iter()
            .position(|atom| matches!(atom.data, AtomData::DebugName(name) if name == from_name))
            .unwrap() as u32;
        let mut edges: Vec<_> = work
            .after_graph
            .edges(from)
            .map(|to| match work.atoms[to as usize].data {
                AtomData::DebugName(name) => name,
                _ => unreachable!(),
            })
            .collect();
        edges.sort_unstable();
        edges
    }

    #[test]
    fn ordered_tasks_are_flattened_to_atom_edges() {
        let info = TaskInfo {
            tasks: vec![
                atom("a"),
                atom("b"),
                atom("c"),
                Task::Ordered(vec![0, 1, 2]),
            ],
            happens_before: HashMap::new(),
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(work.atoms.len(), 3);
        assert_eq!(edges(&work, "a"), vec!["b"]);
        assert_eq!(edges(&work, "b"), vec!["c"]);
        assert!(edges(&work, "c").is_empty());
    }

    #[test]
    fn dependencies_use_group_boundaries() {
        let mut happens_before = HashMap::new();
        happens_before.insert(4, vec![5]);
        let info = TaskInfo {
            tasks: vec![
                atom("a"),
                atom("b"),
                atom("c"),
                atom("d"),
                Task::Unordered(vec![0, 1]),
                Task::Ordered(vec![2, 3]),
            ],
            happens_before,
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["c"]);
        assert_eq!(edges(&work, "b"), vec!["c"]);
        assert_eq!(edges(&work, "c"), vec!["d"]);
    }

    #[test]
    fn nested_ordering_connects_only_terminal_and_initial_atoms() {
        let info = TaskInfo {
            tasks: vec![
                atom("a"),
                atom("b"),
                atom("c"),
                atom("d"),
                Task::Ordered(vec![0, 1]),
                Task::Unordered(vec![2, 3]),
                Task::Ordered(vec![4, 5]),
            ],
            happens_before: HashMap::new(),
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["b"]);
        assert_eq!(edges(&work, "b"), vec!["c", "d"]);
        assert!(edges(&work, "c").is_empty());
        assert!(edges(&work, "d").is_empty());
    }

    #[test]
    fn empty_groups_do_not_break_ordering() {
        let info = TaskInfo {
            tasks: vec![
                atom("a"),
                atom("b"),
                Task::Unordered(vec![]),
                Task::Ordered(vec![0, 2, 1]),
            ],
            happens_before: HashMap::new(),
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["b"]);
    }

    #[test]
    fn compile_remaps_edges_with_topologically_ordered_atoms() {
        let mut happens_before = HashMap::new();
        happens_before.insert(1, vec![0]);
        let info = TaskInfo {
            tasks: vec![atom("a"), atom("b")],
            happens_before,
            file_count: 0,
        };

        let compiled = info.compile().unwrap();

        assert!(matches!(compiled.atoms[0].data, AtomData::DebugName("b")));
        assert!(matches!(compiled.atoms[1].data, AtomData::DebugName("a")));
        assert_eq!(compiled.after_graph.edges(0).collect::<Vec<_>>(), vec![1]);
        assert!(compiled.after_graph.edges(1).next().is_none());
        assert!(compiled.before_graph.edges(0).next().is_none());
        assert_eq!(compiled.before_graph.edges(1).collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn explicit_dependencies_pass_through_empty_task() {
        // a < empty < b  =>  a < b
        let mut happens_before = HashMap::new();
        happens_before.insert(0, vec![2]);
        happens_before.insert(2, vec![1]);

        let info = TaskInfo {
            tasks: vec![atom("a"), atom("b"), Task::Unordered(vec![])],
            happens_before,
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["b"]);
        assert!(edges(&work, "b").is_empty());
    }

    #[test]
    fn explicit_dependencies_pass_through_chain_of_empty_tasks() {
        // a < empty_1 < empty_2 < empty_3 < b  =>  a < b
        let mut happens_before = HashMap::new();
        happens_before.insert(0, vec![2]);
        happens_before.insert(2, vec![3]);
        happens_before.insert(3, vec![4]);
        happens_before.insert(4, vec![1]);

        let info = TaskInfo {
            tasks: vec![
                atom("a"),
                atom("b"),
                Task::Unordered(vec![]),
                Task::Ordered(vec![]),
                Task::Unordered(vec![2, 3]),
            ],
            happens_before,
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["b"]);
    }

    #[test]
    fn dependency_into_empty_ordered_child_reaches_later_atom() {
        // Ordered(a, empty, b), with d < empty.
        //
        // d < empty < b, so d < b.
        let mut happens_before = HashMap::new();
        happens_before.insert(3, vec![2]);

        let info = TaskInfo {
            tasks: vec![
                atom("a"),
                atom("b"),
                Task::Unordered(vec![]),
                atom("d"),
                Task::Ordered(vec![0, 2, 1]),
            ],
            happens_before,
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["b"]);
        assert_eq!(edges(&work, "d"), vec!["b"]);
    }

    #[test]
    fn dependency_out_of_empty_ordered_child_inherits_previous_atom() {
        // Ordered(a, empty, b), with empty < d.
        //
        // a < empty < d, so a < d.
        let mut happens_before = HashMap::new();
        happens_before.insert(2, vec![3]);

        let info = TaskInfo {
            tasks: vec![
                atom("a"),
                atom("b"),
                Task::Unordered(vec![]),
                atom("d"),
                Task::Ordered(vec![0, 2, 1]),
            ],
            happens_before,
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["b", "d"]);
        assert!(edges(&work, "b").is_empty());
        assert!(edges(&work, "d").is_empty());
    }

    #[test]
    fn empty_task_between_unordered_groups_preserves_cartesian_ordering() {
        // unordered(a, b) < empty < unordered(c, d)
        //
        // Every exit on the left must precede every entry on the right.
        let mut happens_before = HashMap::new();
        happens_before.insert(4, vec![5]);
        happens_before.insert(5, vec![6]);

        let info = TaskInfo {
            tasks: vec![
                atom("a"),
                atom("b"),
                atom("c"),
                atom("d"),
                Task::Unordered(vec![0, 1]),
                Task::Ordered(vec![]),
                Task::Unordered(vec![2, 3]),
            ],
            happens_before,
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["c", "d"]);
        assert_eq!(edges(&work, "b"), vec!["c", "d"]);
        assert!(edges(&work, "c").is_empty());
        assert!(edges(&work, "d").is_empty());
    }

    #[test]
    fn nested_all_empty_group_passes_external_ordering_through() {
        // a < outer_empty < b
        //
        // outer_empty is structurally nontrivial but contains no atoms.
        let mut happens_before = HashMap::new();
        happens_before.insert(0, vec![5]);
        happens_before.insert(5, vec![1]);

        let info = TaskInfo {
            tasks: vec![
                atom("a"),
                atom("b"),
                Task::Unordered(vec![]),
                Task::Ordered(vec![]),
                Task::Ordered(vec![2, 3]),
                Task::Unordered(vec![4]),
            ],
            happens_before,
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["b"]);
    }

    #[test]
    fn empty_prefix_and_suffix_do_not_change_group_boundary() {
        // Ordered(empty, a, b, empty) has entry a and exit b.
        //
        // d < group < e must become d < a and b < e.
        let mut happens_before = HashMap::new();
        happens_before.insert(5, vec![4]);
        happens_before.insert(4, vec![6]);

        let info = TaskInfo {
            tasks: vec![
                atom("a"),
                atom("b"),
                Task::Unordered(vec![]),
                Task::Ordered(vec![]),
                Task::Ordered(vec![2, 0, 1, 3]),
                atom("d"),
                atom("e"),
            ],
            happens_before,
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["b"]);
        assert_eq!(edges(&work, "b"), vec!["e"]);
        assert_eq!(edges(&work, "d"), vec!["a"]);
        assert!(edges(&work, "e").is_empty());
    }

    #[test]
    fn multiple_predecessors_merge_through_empty_task() {
        // a ─┐
        //    ├─> empty ─> c
        // b ─┘
        let mut happens_before = HashMap::new();
        happens_before.insert(0, vec![3]);
        happens_before.insert(1, vec![3]);
        happens_before.insert(3, vec![2]);

        let info = TaskInfo {
            tasks: vec![atom("a"), atom("b"), atom("c"), Task::Unordered(vec![])],
            happens_before,
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["c"]);
        assert_eq!(edges(&work, "b"), vec!["c"]);
    }

    #[test]
    fn multiple_successors_fan_out_through_empty_task() {
        // a -> empty -> b
        //            \-> c
        let mut happens_before = HashMap::new();
        happens_before.insert(0, vec![3]);
        happens_before.insert(3, vec![1, 2]);

        let info = TaskInfo {
            tasks: vec![atom("a"), atom("b"), atom("c"), Task::Ordered(vec![])],
            happens_before,
            file_count: 0,
        };

        let work = info.compile().unwrap();

        assert_eq!(edges(&work, "a"), vec!["b", "c"]);
    }

    #[test]
    fn cycle_through_empty_task_is_not_erased() {
        // a < empty < a
        //
        // After empty-task contraction this is an atom self-cycle.
        let mut happens_before = HashMap::new();
        happens_before.insert(0, vec![1]);
        happens_before.insert(1, vec![0]);

        let info = TaskInfo {
            tasks: vec![atom("a"), Task::Unordered(vec![])],
            happens_before,
            file_count: 0,
        };

        let cycle = info.compile().unwrap_err();

        assert_eq!(cycle.nodes, vec![0, 1, 0]);
    }
}
