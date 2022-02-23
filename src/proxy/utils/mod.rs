use crate::config::ToChainableStreamBuilder;
use crate::proxy::{ChainableStreamBuilder, ProtocolType};
use gentian::gentian;

pub(super) struct ChainStreamBuilderProtocolTypeIter<'a> {
    builders: &'a Vec<Box<dyn ChainableStreamBuilder>>,
    ty: Option<ProtocolType>,
    pos: usize,
    state: u32,
}
impl<'a> ChainStreamBuilderProtocolTypeIter<'a> {
    pub(super) fn new(
        builders: &'a Vec<Box<dyn ChainableStreamBuilder>>,
        last_builder: &'a Option<Box<dyn ToChainableStreamBuilder>>,
    ) -> Self {
        let mut ty = None;
        if let Some(b) = last_builder {
            ty = Some(b.get_protocol_type());
        }
        Self {
            builders,
            ty,
            pos: builders.len(),
            state: 0,
        }
    }
}

impl<'a> Iterator for ChainStreamBuilderProtocolTypeIter<'a> {
    type Item = ProtocolType;

    #[gentian]
    #[gentian_attr(ret_val=None)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.ty.is_some() {
            co_yield(self.ty);
        }
        if self.pos == 0 {
            return None;
        }
        while self.pos != 0 {
            self.pos -= 1;
            co_yield(Some(self.builders[self.pos].protocol_type()));
        }
        return None;
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.ty.is_some() {
            return (0, Some(self.pos + 1));
        }
        (0, Some(self.pos))
    }
}
