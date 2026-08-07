use crate::graph::VecGraph;
use foldhash::HashMap;
use std::num::NonZero;

pub type Text = &'static str;
pub type ErrCode = Option<NonZero<u32>>;

#[derive(Debug, Clone, Copy)]
pub enum AtomData {
    Open(Text),
    Read(u32, Text, usize),  // text.len() <= size
    Write(u32, Text, usize), // size <= text.len()
    Close(u32),

    /// Gives a collection of atoms a name for clearer debug output.
    DebugName(Text),
}

#[derive(Debug, Clone, Copy)]
pub struct Atom {
    pub data: AtomData,
    pub error: ErrCode,
}

#[derive(Debug)]
pub enum Task {
    Atom(Atom),
    Ordered(Vec<u32>),
    Unordered(Vec<u32>),
}

#[derive(Debug)]
pub struct TaskInfo {
    pub(crate) tasks: Vec<Task>,
    pub(crate) happens_before: HashMap<u32, Vec<u32>>,
}

#[derive(Debug)]
pub struct CompiledSetup {
    pub(crate) atoms: Vec<Atom>,
    /// Edges lead to atoms that execute after the source atom.
    pub(crate) after_graph: VecGraph<u32>,
    /// Edges lead to atoms that execute before the source atom.
    pub(crate) before_graph: VecGraph<u32>,
}
