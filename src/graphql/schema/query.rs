use async_graphql::{Context, Object, Result};
use crate::graphql::context::GraphQLContext;
use crate::graphql::resolvers::user_resolver::UserResolver;
use crate::graphql::types::common::{PaginationInput, SortInput, GlobalFilter};
use crate::graphql::types::user::{User, UserConnection};

#[derive(Default)]
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Get current authenticated user
    async fn me(&self, ctx: &Context<'_>) -> Result<User> {
        let context = ctx.data::<GraphQLContext>()?;
        UserResolver.get_current_user(ctx).await
    }

    /// Get a user by ID (returns null if not found)
    async fn user(&self, ctx: &Context<'_>, id: String) -> Result<Option<User>> {
        let context = ctx.data::<GraphQLContext>()?;
        UserResolver.get_user_by_id(ctx, id).await
    }

    /// Get paginated list of users
    async fn users(
        &self,
        ctx: &Context<'_>,
        pagination: PaginationInput,
        sorting: Vec<SortInput>,
        global_filter: Option<GlobalFilter>,
    ) -> Result<UserConnection> {
        let context = ctx.data::<GraphQLContext>()?;
        UserResolver.get_users_paginated(ctx, pagination, sorting, global_filter).await
    }
}