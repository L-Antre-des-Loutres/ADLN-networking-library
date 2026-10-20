/// A 64-datagram duplicate window. Reordered packets inside the window are
/// delivered, not silently treated as superseded application state.
#[derive(Default)]
pub(crate) struct ReplayWindow {
    latest: Option<u32>,
    seen: u64,
}

impl ReplayWindow {
    pub fn accept(&mut self, sequence: u32) -> bool {
        let Some(latest) = self.latest else {
            self.latest = Some(sequence);
            self.seen = 1;
            return true;
        };
        let advance = sequence.wrapping_sub(latest);
        if advance != 0 && advance < 0x8000_0000 {
            self.seen = if advance >= 64 {
                1
            } else {
                (self.seen << advance) | 1
            };
            self.latest = Some(sequence);
            return true;
        }
        let behind = latest.wrapping_sub(sequence);
        if behind >= 64 || self.seen & (1u64 << behind) != 0 {
            return false;
        }
        self.seen |= 1u64 << behind;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permits_reordering_and_wrap_but_rejects_duplicates_old_and_ambiguous_packets() {
        let mut window = ReplayWindow::default();
        for sequence in [u32::MAX - 1, 0, u32::MAX, 2, 1] {
            assert!(window.accept(sequence));
            assert!(!window.accept(sequence));
        }
        assert!(!window.accept(2 + 0x8000_0000));
        assert!(window.accept(100));
        assert!(!window.accept(36));
        assert!(window.accept(37));
        assert!(!window.accept(37));
    }
}
