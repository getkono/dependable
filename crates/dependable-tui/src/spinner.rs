//! The spinner shown while something is being fetched.
//!
//! A static `loading…` is indistinguishable from a hung one: the reader has no
//! way to tell a slow registry from a UI that has stopped. A turning spinner
//! says "still working" without claiming to know how much longer.
//!
//! Pure over elapsed time rather than driven by a counter, so every spinner on
//! screen turns in phase from one clock and no caller has to remember to tick
//! anything. [`crate::app::App`] holds that clock; the event loop shortens its
//! poll to [`PERIOD`] while one is turning.

use std::time::Duration;

/// The frames, in order.
///
/// Braille, because each is exactly one column wide: the tree's status column
/// is a fixed width, and a variable-width spinner would shove the badge beside
/// it back and forth on every frame.
const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// How long each frame is held.
///
/// Slow enough to read as a rotation rather than a flicker, and fast enough
/// that the UI plainly has not stopped.
pub const PERIOD: Duration = Duration::from_millis(80);

/// The frame to show for a spinner that has been turning for `elapsed`.
#[must_use]
pub fn frame(elapsed: Duration) -> &'static str {
    let step = (elapsed.as_millis() / PERIOD.as_millis()) as usize;
    FRAMES[step % FRAMES.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frame_advances_once_per_period() {
        assert_eq!(frame(Duration::ZERO), FRAMES[0]);
        assert_eq!(frame(PERIOD - Duration::from_millis(1)), FRAMES[0]);
        assert_eq!(frame(PERIOD), FRAMES[1]);
        assert_eq!(frame(PERIOD * 2), FRAMES[2]);
    }

    #[test]
    fn the_frames_wrap_rather_than_running_out() {
        // A spinner outlives its frame list; a slow lookup must not panic.
        let cycle = PERIOD * FRAMES.len() as u32;
        assert_eq!(frame(cycle), FRAMES[0]);
        assert_eq!(frame(cycle + PERIOD), FRAMES[1]);
        assert_eq!(
            frame(Duration::from_secs(3600)),
            FRAMES[(3_600_000 / 80) % 10]
        );
    }

    #[test]
    fn every_frame_is_one_column_wide() {
        // The tree's status column is a fixed width; a frame wider than one cell
        // would move the badge beside it on every tick.
        use ratatui::buffer::CellWidth;
        for frame in FRAMES {
            assert_eq!(frame.cell_width(), 1, "{frame:?}");
        }
    }
}
