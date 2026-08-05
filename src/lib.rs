use crate::graph::VecGraph;
use crate::graph::transitive_reduction;
use crate::index::Idx;
pub mod index;
pub mod graph;

use crate::graph::topological_order;
use crate::graph::GraphCycle;
use crate::graph::DirectedGraph;
use crate::index::IndexSpan;
use index::UnionFind;
use foldhash::HashMap;
use foldhash::HashMapExt;
use std::num::NonZero;

pub type Text = &'static  str;
pub type ErrCode = Option<NonZero<u32>>;

#[derive(Debug,Clone,Copy)]
pub enum AtomData {
    Open(Text),
    Read(Text,usize),
    Write(Text,usize),
    Close(Text),

    ///this is used as a way to give collections of atoms names 
    ///Atom::DebugName("Task Start")
    ///Atom::DebugName("Task End")
    ///which can give nicer debug prints at times
    DebugName(Text),
}


#[derive(Debug,Clone,Copy)]
pub struct Atom {
    pub data:AtomData,
    pub error:ErrCode,
}

pub enum Task {
    Atom(Atom),
    Ordered(Vec<u32>),
    UnOredred(Vec<u32>),
}

pub struct TaskInfo {
    tasks:Vec<Task>,
    happens_before:HashMap<u32,Vec<u32>>,
}

impl TaskInfo {
    fn to_work(&self)->WorkInfo {
        
    }
}

struct WorkInfo {
    atoms:Vec<Atom>,
    happens_before:HashMap<u32,Vec<u32>>,
}

pub struct CompiledSetup {
    atoms:Vec<Atom>,
    graph:VecGraph<u32>,
}

impl DirectedGraph for WorkInfo {
type Node = u32;
fn num_nodes(&self) -> usize { self.atoms.len().into() }
fn edges(&self, idx:u32) -> impl Iterator<Item = u32> {
    match self.happens_before.get(&idx) {
        None => (&[]).iter(),
        Some(v) => v.as_slice().iter()
    }.copied()
}
}


impl WorkInfo {
    fn compile(&self)-> Result<CompiledSetup, GraphCycle<u32>>{
        let (reduced,ord) = transitive_reduction(self)?;

        let atoms = ord.order.iter().map(|i| self.atoms[i.index()]).collect();
        
       
        let graph = VecGraph::from_graph(&reduced);
        Ok(CompiledSetup{atoms,graph})
    }
}