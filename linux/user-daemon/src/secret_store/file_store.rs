use alloc::vec::IntoIter;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use u2f_core::{AppId, ApplicationKey, Counter};

use crate::secret_store::Secret;

#[derive(Serialize, Deserialize)]
struct Data {
    application_keys: HashMap<AppId, ApplicationKey>,
    counters: HashMap<AppId, Counter>,
}

pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: PathBuf) -> io::Result<FileStore> {
        Ok(FileStore { path })
    }

    pub fn default_path<H>(home_dir: H) -> PathBuf
    where
        H: AsRef<Path>,
    {
        home_dir.as_ref().join(".softu2f-secrets.json")
    }

    pub fn delete(self) -> io::Result<()> {
        fs::remove_file(self.path)
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn iter(&self) -> io::Result<IntoIter<Secret>> {
        let data = self.load()?;
        Ok(data
            .application_keys
            .values()
            .map(|application_key| {
                let counter = data
                    .counters
                    .get(&application_key.application)
                    .unwrap_or(&0);
                Secret {
                    application_key: application_key.clone(),
                    counter: *counter,
                }
            })
            .collect::<Vec<Secret>>()
            .into_iter())
    }

    fn load(&self) -> io::Result<Data> {
        match File::open(&self.path) {
            Ok(file) => serde_json::from_reader(file).map_err(|e| e.into()),
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(Data {
                application_keys: HashMap::new(),
                counters: HashMap::new(),
            }),
            Err(err) => Err(err),
        }
    }
}
