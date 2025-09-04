pub mod query;
pub mod mutation;
pub mod subscription;

use async_graphql::{EmptySubscription, Schema};
use query::QueryRoot;
use mutation::MutationRoot;
use subscription::SubscriptionRoot;

pub type AppSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;