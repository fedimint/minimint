use super::{Database, DatabaseError, Transaction};
use async_trait::async_trait;
use futures::future::LocalBoxFuture;
use futures::stream::{self, LocalBoxStream};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default, Clone)]
pub struct MemDatabase {
    data: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DummyError;

impl MemDatabase {
    pub fn new() -> MemDatabase {
        Default::default()
    }

    pub fn dump_db(&self) {
        for (key, value) in self.data.lock().unwrap().iter() {
            eprintln!("{}: {}", hex::encode(key), hex::encode(value));
        }
    }
}

#[async_trait(?Send)]
impl Database for MemDatabase {
    async fn raw_insert_entry(
        &self,
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self.data.lock().unwrap().insert(key.to_vec(), value))
    }

    async fn raw_get_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self.data.lock().unwrap().get(key).cloned())
    }

    async fn raw_remove_entry(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self.data.lock().unwrap().remove(key))
    }

    fn raw_find_by_prefix(
        &self,
        key_prefix: &[u8],
    ) -> LocalBoxStream<'_, Result<(Vec<u8>, Vec<u8>), DatabaseError>> {
        let mut data = self
            .data
            .lock()
            .unwrap()
            .range::<Vec<u8>, _>((key_prefix.to_vec())..)
            .take_while(|(key, _)| key.starts_with(key_prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        data.reverse();

        Box::pin(stream::iter(data.into_iter().map(Ok)))
    }

    fn raw_transaction<'a>(
        &'a self,
        f: &mut (dyn FnMut(&'a mut dyn Transaction) -> Pin<Box<dyn Future<Output = ()> + 'a>> + 'a),
    ) -> LocalBoxFuture<'a, Result<(), DatabaseError>> {
        todo!()
    }
}

struct MemDbIter {
    data: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Iterator for MemDbIter {
    type Item = Result<(Vec<u8>, Vec<u8>), DatabaseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.data.pop().map(Result::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::MemDatabase;
    use std::sync::Arc;

    #[test_log::test]
    fn test_basic_rw() {
        let mem_db = MemDatabase::new();
        crate::db::tests::test_db_impl(Arc::new(mem_db));
    }
}
