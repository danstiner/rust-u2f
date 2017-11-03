use std::fs;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::collections::HashMap;

use serde_json;

use u2f_core::{ApplicationKey, ApplicationParameter, Counter, KeyHandle, SecretStore};

#[derive(Serialize, Deserialize)]
struct Store {
    application_keys: HashMap<ApplicationParameter, ApplicationKey>,
    counters: HashMap<ApplicationParameter, Counter>,
}

pub struct FileStorage {
    path: PathBuf,
    store: Store,
}

impl FileStorage {
    pub fn new(path: PathBuf) -> io::Result<FileStorage> {
        let store = Self::load_store(&path)?;
        Ok(FileStorage {
            path: path,
            store: store,
        })
    }

    fn save(&self) -> io::Result<()> {
        overwrite_file_atomic(&self.path, |writer| {
            serde_json::to_writer_pretty(writer, &self.store).unwrap();
            Ok(())
        })
    }

    fn load_store(path: &Path) -> io::Result<Store> {
        match File::open(path) {
            Ok(file) => Ok(serde_json::from_reader(file).unwrap()),
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(Store {
                application_keys: HashMap::new(),
                counters: HashMap::new(),
            }),
            Err(err) => Err(err),
        }
    }
}

impl SecretStore for FileStorage {
    fn add_application_key(&mut self, key: &ApplicationKey) -> io::Result<()> {
        self.store.application_keys.insert(
            key.application,
            key.clone(),
        );
        self.save()?;
        Ok(())
    }

    fn get_then_increment_counter(
        &mut self,
        application: &ApplicationParameter,
    ) -> io::Result<Counter> {
        if !self.store.counters.contains_key(application) {
            self.store.counters.insert(*application, 0);
        }
        let value = match self.store.counters.get_mut(application) {
            Some(counter) => {
                let value = *counter;
                *counter = value + 1;
                value
            },
            None => unreachable!(),
        };

        self.save()?;
        Ok(value)
    }

    fn retrieve_application_key(
        &self,
        application: &ApplicationParameter,
        handle: &KeyHandle,
    ) -> io::Result<Option<&ApplicationKey>> {
        match self.store.application_keys.get(application) {
            Some(key) => {
                if key.handle.eq_consttime(handle) {
                    Ok(Some(key))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}

fn overwrite_file_atomic<W>(path: &Path, writer_fn: W) -> io::Result<()>
where
    W: FnOnce(Box<Write>) -> io::Result<()>,
{
    let mut tmp_path = PathBuf::from(path);
    let mut new_ext = match tmp_path.extension() {
        Some(ext) => ext.to_os_string(),
        None => return Err(io::Error::new(io::ErrorKind::Other, "Invalid file path")),
    };
    new_ext.push(".tmp");
    tmp_path.set_extension(new_ext);

    {
        let file = OpenOptions::new().write(true).create_new(true).open(
            &tmp_path,
        )?;
        writer_fn(Box::new(file.try_clone()?))?;
        file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;
    Ok(())
}
