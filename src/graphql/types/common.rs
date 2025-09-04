use async_graphql::*;

// ===== PAGINATION =====
#[derive(InputObject)]
pub struct PaginationInput {
    #[graphql(name = "pageIndex")]
    pub page_index: i32,
    #[graphql(name = "pageSize")]
    pub page_size: i32,
}

#[derive(SimpleObject)]
pub struct PageInfo {
    #[graphql(name = "hasNextPage")]
    pub has_next_page: bool,
    #[graphql(name = "hasPreviousPage")]
    pub has_previous_page: bool,
    #[graphql(name = "totalPages")]
    pub total_pages: i32,
}

// ===== SORTING =====
#[derive(InputObject)]
pub struct SortInput {
    pub field: String,
    pub direction: SortDirection,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum SortDirection {
    ASC,
    DESC,
}

// ===== FILTERING =====
#[derive(InputObject)]
pub struct GlobalFilter {
    pub value: String,
}

// ===== GENERIC RESPONSE =====
#[derive(SimpleObject)]
pub struct Connection<T: OutputType> {
    pub items: Vec<T>,
    pub records_filtered: i32,
    pub records_total: i32,
    pub page_info: PageInfo,
}