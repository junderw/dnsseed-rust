use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::time::{Duration, Instant};
use std::marker::PhantomData;
use std::sync::RwLock;

// Constants for roughly 1 in 250k fp with 20m entries
/// Number of entries in the filter (each 4 bits). 256MiB in total.
const FILTER_SIZE: usize = 64 * 1024 * 1024 * 8;
const HASHES: usize = 18;
const ROLL_COUNT: usize = 1_370_000;
#[cfg(test)]
const GENERATION_BITS: usize = 2;
#[cfg(not(test))]
const GENERATION_BITS: usize = 4;
pub const GENERATION_COUNT: usize = (1 << GENERATION_BITS) - 1;
const ELEMENTS_PER_VAR: usize = 64 / GENERATION_BITS;

struct FilterState {
	last_roll: Instant,
	inserted_in_last_generations: [usize; GENERATION_COUNT - 1],
	inserted_since_last_roll: usize,
	current_generation: u8,
	bits: Vec<u64>,
}

pub struct RollingBloomFilter<T: Hash> {
	state: RwLock<FilterState>,
	hash_keys: [RandomState; HASHES],
	_entry_type: PhantomData<T>,
}

impl<T: Hash> RollingBloomFilter<T> {
	pub fn new() -> Self {
		let mut bits = Vec::new();
		bits.resize(FILTER_SIZE * GENERATION_BITS / 64, 0);
		Self {
			state: RwLock::new(FilterState {
				last_roll: Instant::now(),
				inserted_since_last_roll: 0,
				inserted_in_last_generations: [0; GENERATION_COUNT - 1],
				current_generation: 1,
				bits,
			}),
			hash_keys: [RandomState::new(), RandomState::new(), RandomState::new(), RandomState::new(), RandomState::new(),
			            RandomState::new(), RandomState::new(), RandomState::new(), RandomState::new(), RandomState::new(),
			            RandomState::new(), RandomState::new(), RandomState::new(), RandomState::new(), RandomState::new(),
			            RandomState::new(), RandomState::new(), RandomState::new()],
			_entry_type: PhantomData,
		}
	}

	pub fn contains(&self, item: &T) -> bool {
		let mut hashes = [None; HASHES];
		for (idx, state) in self.hash_keys.iter().enumerate() {
			let mut hasher = state.build_hasher();
			item.hash(&mut hasher);
			hashes[idx] = Some(hasher.finish() as usize);
		}

		let state = self.state.read().unwrap();
		for idx_opt in hashes.iter() {
			let idx = idx_opt.unwrap();

			let byte = state.bits[(idx / ELEMENTS_PER_VAR) % (FILTER_SIZE / 64)];
			let bits_shift = (idx % ELEMENTS_PER_VAR) * GENERATION_BITS;
			let bits = (byte & ((GENERATION_COUNT as u64) << bits_shift)) >> bits_shift;
			if bits == 0 { return false; }
		}
		true
	}

	pub fn get_element_count(&self) -> [usize; GENERATION_COUNT] {
		let mut res = [0; GENERATION_COUNT];
		let state = self.state.read().unwrap();
		res[0..(GENERATION_COUNT-1)].copy_from_slice(&state.inserted_in_last_generations);
		*res.last_mut().unwrap() = state.inserted_since_last_roll;
		res
	}

	pub fn insert(&self, item: &T, roll_duration: Duration) {
		let mut hashes = [None; HASHES];
		for (idx, state) in self.hash_keys.iter().enumerate() {
			let mut hasher = state.build_hasher();
			item.hash(&mut hasher);
			hashes[idx] = Some(hasher.finish() as usize);
		}

		let mut state = self.state.write().unwrap();
		if Instant::now() - state.last_roll > roll_duration / GENERATION_COUNT as u32 ||
		   state.inserted_since_last_roll > ROLL_COUNT {
			state.current_generation += 1;
			if state.current_generation == GENERATION_COUNT as u8 + 1 { state.current_generation = 1; }
			let remove_generation = state.current_generation;

			for idx in 0..(FILTER_SIZE / ELEMENTS_PER_VAR) {
				let mut var = state.bits[idx];
				for i in 0..ELEMENTS_PER_VAR {
					let bits_shift = i * GENERATION_BITS;
					let bits = (var & ((GENERATION_COUNT as u64) << bits_shift)) >> bits_shift;

					if bits == remove_generation as u64 {
						var &= !((GENERATION_COUNT as u64) << bits_shift);
					}
				}
				state.bits[idx] = var;
			}
			state.last_roll = Instant::now();
			let mut new_generations = [0; GENERATION_COUNT - 1];
			new_generations[0..GENERATION_COUNT - 2].copy_from_slice(&state.inserted_in_last_generations[1..]);
			new_generations[GENERATION_COUNT - 2] = state.inserted_since_last_roll;
			state.inserted_in_last_generations = new_generations;
			state.inserted_since_last_roll = 0;
		}

		let generation = state.current_generation;
		for idx_opt in hashes.iter() {
			let idx = idx_opt.unwrap();

			let byte = &mut state.bits[(idx / ELEMENTS_PER_VAR) % (FILTER_SIZE / 64)];
			let bits_shift = (idx % ELEMENTS_PER_VAR) * GENERATION_BITS;
			*byte &= !((GENERATION_COUNT as u64) << bits_shift);
			*byte |= (generation as u64) << bits_shift;
		}
		state.inserted_since_last_roll += 1;
	}
}

#[test]
fn test_bloom() {
	let filter = RollingBloomFilter::new();
	for i in 0..1000 {
		filter.insert(&i, Duration::from_secs(60 * 60 * 24));
	}
	for i in 0..1000 {
		assert!(filter.contains(&i));
	}
	for i in 1000..2000 {
		assert!(!filter.contains(&i));
	}
	assert_eq!(filter.get_element_count(), [0, 0, 1000]);
	filter.state.write().unwrap().inserted_since_last_roll = ROLL_COUNT + 1;
	filter.insert(&1000, Duration::from_secs(60 * 60 * 24));
	assert_eq!(filter.get_element_count(), [0, ROLL_COUNT + 1, 1]);
	for i in 0..1001 {
		assert!(filter.contains(&i));
	}
	filter.state.write().unwrap().inserted_since_last_roll = ROLL_COUNT + 1;
	for i in 1001..2000 {
		filter.insert(&i, Duration::from_secs(60 * 60 * 24));
	}
	assert_eq!(filter.get_element_count(), [ROLL_COUNT + 1, ROLL_COUNT + 1, 999]);
	for i in 0..2000 {
		assert!(filter.contains(&i));
	}
	filter.state.write().unwrap().inserted_since_last_roll = ROLL_COUNT + 1;
	filter.insert(&2000, Duration::from_secs(60 * 60 * 24));
	assert_eq!(filter.get_element_count(), [ROLL_COUNT + 1, ROLL_COUNT + 1, 1]);
	for i in 0..1000 {
		assert!(!filter.contains(&i));
	}
	for i in 1000..2001 {
		assert!(filter.contains(&i));
	}
}
