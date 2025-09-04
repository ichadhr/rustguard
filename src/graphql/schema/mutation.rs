use async_graphql::{Context, Object, Result};

#[derive(Default)]
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    // Mutations will be added here
    // For now, this is a placeholder
    async fn placeholder(&self) -> Result<String> {
        Ok("Mutations not yet implemented".to_string())
    }
}