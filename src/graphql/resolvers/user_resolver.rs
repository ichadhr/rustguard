use async_graphql::{Context, Result};
use crate::error::AppError;
use crate::error::user_error::UserError;
use crate::graphql::context::GraphQLContext;
use crate::graphql::types::common::{Connection, PaginationInput, SortDirection, SortInput, GlobalFilter, PageInfo};
use crate::graphql::types::user::{User, UserConnection};

pub struct UserResolver;

impl UserResolver {
    pub async fn get_user_by_id(
        &self,
        ctx: &Context<'_>,
        id: String,
    ) -> Result<Option<User>> {
        let context = ctx.data::<GraphQLContext>()?;
        let user_id = uuid::Uuid::parse_str(&id).map_err(|_| {
            async_graphql::Error::new("Invalid user ID format")
        })?;

        // Use existing service method
        match context.user_service.find_by_id(user_id).await {
            Ok(user) => Ok(Some(user.into())),
            Err(AppError::User(UserError::UserNotFound)) => Ok(None), // Return null for not found
            Err(e) => Err(async_graphql::Error::new(format!("Database error: {:?}", e))),
        }
    }

    pub async fn get_users_paginated(
        &self,
        ctx: &Context<'_>,
        pagination: PaginationInput,
        sorting: Vec<SortInput>,
        global_filter: Option<GlobalFilter>,
    ) -> Result<UserConnection> {
        let context = ctx.data::<GraphQLContext>()?;

        // Convert sorting to service parameters
        let sort_field = sorting.first().map(|s| s.field.clone());
        let sort_direction = sorting.first().map(|s| match s.direction {
            SortDirection::ASC => "ASC".to_string(),
            SortDirection::DESC => "DESC".to_string(),
        });
        let global_filter_value = global_filter.map(|f| f.value);

        // Call service method
        let (users, total_count) = context.map_error(
            context.user_service.get_users_paginated(
                pagination.page_index,
                pagination.page_size,
                sort_field,
                sort_direction,
                global_filter_value,
            ).await,
            "users"
        )?;

        // Calculate pagination info
        let total_pages = (total_count as f64 / pagination.page_size as f64).ceil() as i32;
        let has_next_page = pagination.page_index + 1 < total_pages;
        let has_previous_page = pagination.page_index > 0;

        let page_info = PageInfo {
            has_next_page,
            has_previous_page,
            total_pages,
        };

        let items = users.into_iter().map(Into::into).collect();

        Ok(Connection {
            items,
            records_filtered: total_count,
            records_total: total_count,
            page_info,
        })
    }

    pub async fn get_current_user(&self, ctx: &Context<'_>) -> Result<User> {
        let context = ctx.data::<GraphQLContext>()?;
        let user = context.require_auth()?;
        Ok((*user).clone().into())
    }
}