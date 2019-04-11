#[macro_export]
macro_rules! new_wrapper {
    ($name:ident; $length:expr)  =>  (
        #[derive(Clone, Copy)]
        pub struct $name([u8; $length]);

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
              &self.0[..]
            }
        }

        impl $name {
            fn from_slice(data: &[u8]) -> Option<Self> {
              let to = [0; $length];
              if item.len() != $length {
                  return None;
              }
              for (to, &from) in to.iter_mut().zip(data.iter()) {
                  *to = from;
              }
              Some($name(to))
            }
        }
    )
}