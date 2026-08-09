pub mod domain {
    pub mod campaign;
}

pub mod storage {
    pub mod artifacts;
    pub mod s3;
}

pub(crate) mod recovery {
    pub(crate) mod reconcile;
}

pub mod sync;
