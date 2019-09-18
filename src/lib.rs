fn getblock64(p: *const u64, i: u32) -> u64 {
  return unsafe { *p.offset(i as isize) };
}

fn rotl64(x: u64, r: i8) -> u64 {
  return (x << r) | (x >> (64 - r));
}

fn optionsfn(
  len: u32,
  k1: &mut u64,
  k2: &mut u64,
  tail: *const u8,
  c1: u64,
  c2: u64,
  h2: &mut u64,
  h1: &mut u64,
) {
  match len {
    15 => *k2 ^= unsafe { (*tail.offset(14) as u64) << 48 },
    14 => *k2 ^= unsafe { (*tail.offset(13) as u64) << 40 },
    13 => *k2 ^= unsafe { (*tail.offset(12) as u64) << 32 },
    12 => *k2 ^= unsafe { (*tail.offset(11) as u64) << 24 },
    11 => *k2 ^= unsafe { (*tail.offset(10) as u64) << 16 },
    10 => *k2 ^= unsafe { (*tail.offset(9) as u64) << 8 },
    9 => {
      *k2 ^= unsafe { (*tail.offset(8) as u64) << 0 };
      *k2 = (*k2).wrapping_mul(c2);
      *k2 = rotl64(*k2, 33);
      *k2 = (*k2).wrapping_mul(c1);
      *h2 = *h2 ^ *k2;
    }

    8 => *k1 ^= unsafe { (*tail.offset(7) as u64) << 56 },
    7 => *k1 ^= unsafe { (*tail.offset(6) as u64) << 48 },
    6 => *k1 ^= unsafe { (*tail.offset(5) as u64) << 40 },
    5 => *k1 ^= unsafe { (*tail.offset(4) as u64) << 32 },
    4 => *k1 ^= unsafe { (*tail.offset(3) as u64) << 24 },
    3 => *k1 ^= unsafe { (*tail.offset(2) as u64) << 16 },
    2 => *k1 ^= unsafe { (*tail.offset(1) as u64) << 8 },
    1 => {
      *k1 ^= unsafe { (*tail.offset(0) as u64) << 0 };
      *k1 = (*k1).wrapping_mul(c1);
      *k1 = rotl64(*k1, 31);
      *k1 = (*k1).wrapping_mul(c2);
      *h1 = *h1 ^ *k1;
    }

    _ => {}
  }
}

fn fmix64(k: u64) -> u64 {
  let mut tmp = k;
  tmp ^= tmp >> 33;
  tmp = tmp.wrapping_mul(0xff51afd7ed558ccdu64);
  tmp ^= tmp >> 33;
  tmp = tmp.wrapping_mul(0xc4ceb9fe1a85ec53u64);
  tmp ^= tmp >> 33;

  return tmp;
}

// murmurhash3 x64 128
pub fn murmurhash3(data: *const u8, len: u32, seed: u32, out: *mut u64) {
  let nblocks = len / 16;
  let mut h1: u64 = seed.into();
  let mut h2: u64 = seed.into();

  let c1: u64 = 0x87c37b91114253d5u64;
  let c2: u64 = 0x4cf5ad432745937fu64;

  let blocks = data as *const u64;

  for i in 0..nblocks {
    let mut k1: u64 = getblock64(blocks, i * 2 + 0);
    let mut k2: u64 = getblock64(blocks, i * 2 + 1);

    k1 = k1.wrapping_mul(c1);
    k1 = rotl64(k1, 31);
    k1 = k1.wrapping_mul(c2);
    h1 ^= k1;

    h1 = rotl64(h1, 27);
    h1 = h1.wrapping_add(h2);
    h1 = h1.wrapping_mul(5).wrapping_add(0x52dce729u64);

    k2 = k2.wrapping_mul(c2);
    k2 = rotl64(k2, 33);
    k2 = k2.wrapping_mul(c1);
    h2 ^= k2;

    h2 = rotl64(h2, 31);
    h2 = h2.wrapping_add(h1);
    h2 = h2.wrapping_mul(5).wrapping_add(0x38495ab5);
  }

  let tail: *const u8 = unsafe { data.offset((nblocks * 16) as isize) as *const u8 };

  let mut k1: u64 = 0;
  let mut k2: u64 = 0;

  let mut l = len & 15;
  for _ in 0..(len & 15) {
    optionsfn(l, &mut k1, &mut k2, tail, c1, c2, &mut h2, &mut h1);
    l = l - 1;
  }

  h1 ^= len as u64;
  h2 ^= len as u64;

  h1 = h1.wrapping_add(h2);
  h2 = h2.wrapping_add(h1);

  h1 = fmix64(h1);
  h2 = fmix64(h2);

  h1 = h1.wrapping_add(h2);
  h2 = h2.wrapping_add(h1);

  unsafe {
    *out.offset(0) = h1;
    *out.offset(1) = h2;
  }
}

#[cfg(test)]
mod tests {
  use super::murmurhash3;

  #[test]
  fn basic_murmurhash3_test() {
    let mut data = String::from("Hello World!");
    let mut out: [u64; 2] = [0, 0];

    unsafe {
      murmurhash3(
        data.as_ptr(),
        data.len() as u32,
        0x12345678u32,
        out.as_mut_ptr(),
      );
    }

    assert_eq!(out[0], 0xdfecbed61eb206f6u64);
    assert_eq!(out[1], 0x3a830a857525309fu64);

    data = String::from(
      "Lorem ipsum \
       dolor sit amet, consectetur adipiscing elit, sed do \
       eiusmod tempor incididunt ut labore et dolore magna \
       aliqua. Ut enim ad minim veniam, quis nostrud exercitation \
       ullamco laboris nisi ut aliquip ex ea commodo consequat. \
       Duis aute irure dolor in reprehenderit in voluptate velit \
       esse cillum dolore eu fugiat nulla pariatur. Excepteur sint \
       occaecat cupidatat non proident, sunt in culpa qui officia \
       deserunt mollit anim id est laborum.",
    );

    unsafe {
      murmurhash3(
        data.as_ptr(),
        data.len() as u32,
        0x12345678u32,
        out.as_mut_ptr(),
      );
    }

    assert_eq!(out[0], 0xc97cd9afb57c14f3u64);
    assert_eq!(out[1], 0xd54289078d15076fu64);
  }
}
