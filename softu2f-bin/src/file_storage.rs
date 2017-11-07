use futures::{Future, IntoFuture};
use futures::future;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use serde_json;

use u2f_core::{ApplicationKey, ApplicationParameter, Counter, KeyHandle, SecretStore};

#[derive(Serialize, Deserialize)]
struct Store {
    application_keys: HashMap<ApplicationParameter, ApplicationKey>,
    counters: HashMap<ApplicationParameter, Counter>,
}

pub struct FileStorage {
    path: PathBuf,
    store: RefCell<Store>,
}

impl FileStorage {
    pub fn new(path: PathBuf) -> io::Result<FileStorage> {
        let store = Self::load_store(&path)?;
        Ok(FileStorage {
            path: path,
            store: RefCell::new(store),
        })
    }

    fn save(&self) -> io::Result<()> {
        overwrite_file_atomic(&self.path, |writer| {
            serde_json::to_writer_pretty(writer, &*self.store.borrow()).unwrap();
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
    fn add_application_key(&self, key: &ApplicationKey) -> Box<Future<Item=(), Error=io::Error>> {
        self.store.borrow_mut().application_keys.insert(
            key.application,
            key.clone(),
        );

        Box::new(self.save().into_future())
    }

    fn get_and_increment_counter(
        &self,
        application: &ApplicationParameter,
    ) -> Box<Future<Item=Counter, Error=io::Error>> {
        let value = {
            let mut store = self.store.borrow_mut();

            if !store.counters.contains_key(application) {
                store.counters.insert(*application, 0);
            }

            match store.counters.get_mut(application) {
                Some(counter) => {
                    let value = *counter;
                    *counter = value + 1;
                    value
                },
                None => unreachable!(),
            }
        };

        Box::new(self.save().into_future().map(move |_| value))
    }

    fn retrieve_application_key(
        &self,
        application: &ApplicationParameter,
        handle: &KeyHandle,
    ) -> Box<Future<Item=Option<ApplicationKey>, Error=io::Error>> {
        let res = match self.store.borrow().application_keys.get(application) {
            Some(key) => {
                if key.handle.eq_consttime(handle) {
                    Some(key.clone())
                } else {
                    None
                }
            }
            None => None,
        };
        Box::new(future::ok(res))
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
