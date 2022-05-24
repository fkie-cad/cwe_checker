use super::*;

impl<'a, T: AbstractDomain + DomainInsertion + HasTop + Eq + From<String>> Context<'a, T> {
    pub fn mock(
        project: &'a Project,
        string_symbols: HashMap<Tid, &'a ExternSymbol>,
        format_string_index: HashMap<String, usize>,
        pointer_inference_results: &'a PointerInferenceComputation<'a>,
    ) -> Self {
        let mut extern_symbol_map = HashMap::new();
        for (tid, symbol) in project.program.term.extern_symbols.iter() {
            extern_symbol_map.insert(tid.clone(), symbol);
        }

        let mut block_start_node_map = HashMap::new();
        let mut block_first_def_set = HashSet::new();
        let mut jmp_to_blk_end_node_map = HashMap::new();
        for (node_id, node) in pointer_inference_results.get_graph().node_references() {
            match node {
                Node::BlkStart(block, sub) => {
                    if let Some(def) = block.term.defs.get(0) {
                        block_start_node_map.insert((def.tid.clone(), sub.tid.clone()), node_id);
                        block_first_def_set.insert((def.tid.clone(), sub.tid.clone()));
                    }
                }
                Node::BlkEnd(block, sub) => {
                    for jmp in block.term.jmps.iter() {
                        jmp_to_blk_end_node_map.insert((jmp.tid.clone(), sub.tid.clone()), node_id);
                    }
                }
                _ => (),
            }
        }

        Context {
            project,
            pointer_inference_results,
            string_symbol_map: string_symbols,
            extern_symbol_map,
            format_string_index_map: format_string_index,
            block_start_node_map,
            block_first_def_set,
            jmp_to_blk_end_node_map: jmp_to_blk_end_node_map,
            _phantom_string_domain: PhantomData,
        }
    }
}
