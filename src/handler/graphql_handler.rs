use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{extract::State, response::Html};
use crate::graphql::context::GraphQLContext;
use crate::entity::user::User;
use crate::state::graphql_state::GraphQLState;

pub async fn graphql(
    State(state): State<GraphQLState>,
    axum::Extension(user): axum::Extension<Option<User>>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    // Create GraphQL context with user and services from state
    let context = GraphQLContext {
        user,
        user_service: state.user_service,
    };

    state.schema.execute(req.into_inner().data(context)).await.into()
}

pub async fn playground() -> Html<String> {
    Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/api/graphql")
            .title("Rust Framework GraphQL Playground")
    ))
}