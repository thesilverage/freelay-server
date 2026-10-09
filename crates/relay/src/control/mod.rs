//! Freelay's local control plane. Data synchronization stays in the upstream server.
pub mod http;
pub mod identity;
pub mod maintenance;
pub mod metadata;
pub mod safety;
pub mod tokens;

#[cfg(test)]
mod tests;
