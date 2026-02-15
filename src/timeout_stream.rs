use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{Future, Stream};
use pin_project_lite::pin_project;
use tokio::time::{Sleep, Instant, sleep_until};

pin_project! {
	pub struct TimeoutStream<S> {
		#[pin]
		stream: S,
		#[pin]
		sleep: Sleep,
		extend_on_recv: bool,
		timeout: Duration,
	}
}

impl<S> TimeoutStream<S> where S: Stream {
	pub fn new_persistent(stream: S, timeout: Duration) -> Self {
		let sleep = sleep_until(Instant::now() + timeout);
		Self {
			stream,
			sleep,
			extend_on_recv: true,
			timeout,
		}
	}

	pub fn new_timeout(stream: S, timeout: Instant) -> Self {
		let sleep = sleep_until(timeout);
		Self {
			stream,
			sleep,
			extend_on_recv: false,
			timeout: Duration::from_secs(0),
		}
	}
}

impl<S, T> Stream for TimeoutStream<S> where S: Stream<Item = T> {
	type Item = T;
	
	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let mut this = self.project();
		
		// Check if timeout elapsed
		if this.sleep.as_mut().poll(cx).is_ready() {
			return Poll::Ready(None);
		}
		
		// Poll the underlying stream
		match this.stream.poll_next(cx) {
			Poll::Ready(Some(v)) => {
				if *this.extend_on_recv {
					this.sleep.as_mut().reset(Instant::now() + *this.timeout);
				}
				Poll::Ready(Some(v))
			},
			Poll::Ready(None) => Poll::Ready(None),
			Poll::Pending => Poll::Pending,
		}
	}
}
