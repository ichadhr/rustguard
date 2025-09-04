use axum::{routing::get, Router};
use crate::handler::graphql_handler;
use crate::state::graphql_state::GraphQLState;

pub fn routes() -> Router<GraphQLState> {
    Router::<GraphQLState>::new()
        .route("/graphql", get(graphql_handler::playground).post(graphql_handler::graphql))
}