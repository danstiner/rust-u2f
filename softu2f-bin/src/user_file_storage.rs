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
use slog::Logger;
use users::switch::switch_user_group;

use super::SecurityIds;
use u2f_core::{ApplicationKey, ApplicationParameter, Counter, KeyHandle, SecretStore};

#[derive(Serialize, Deserialize)]
struct Store {
    application_keys: HashMap<ApplicationParameter, ApplicationKey>,
    counters: HashMap<ApplicationParameter, Counter>,
}

pub struct UserFileStorage {
    logger: Logger,
    path: PathBuf,
    security_ids: SecurityIds,
    store: RefCell<Store>,
}

impl UserFileStorage {
    pub fn new(
        path: PathBuf,
        security_ids: SecurityIds,
        logger: Logger,
    ) -> io::Result<UserFileStorage> {
        let store = Self::load_store(&path, security_ids)?;
        Ok(UserFileStorage {
            logger: logger,
            path: path,
            security_ids: security_ids,
            store: RefCell::new(store),
        })
    }

    fn save(&self) -> io::Result<()> {
        let uid = self.security_ids.uid;
        let gid = self.security_ids.gid;
        let _user_switch = switch_user_group(uid, gid).unwrap();
        overwrite_file_atomic(&self.path, &self.logger, |writer| {
            serde_json::to_writer_pretty(writer, &*self.store.borrow()).unwrap();
            Ok(())
        })
    }

    fn load_store(path: &Path, security_ids: SecurityIds) -> io::Result<Store> {
        let uid = security_ids.uid;
        let gid = security_ids.gid;
        let _user_switch = switch_user_group(uid, gid).unwrap();
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

impl SecretStore for UserFileStorage {
    fn add_application_key(
        &self,
        key: &ApplicationKey,
    ) -> Box<Future<Item = (), Error = io::Error>> {
        self.store
            .borrow_mut()
            .application_keys
            .insert(key.application, key.clone());

        Box::new(self.save().into_future())
    }

    fn get_and_increment_counter(
        &self,
        application: &ApplicationParameter,
    ) -> Box<Future<Item = Counter, Error = io::Error>> {
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
                }
                None => unreachable!(),
            }
        };

        Box::new(self.save().into_future().map(move |_| value))
    }

    fn retrieve_application_key(
        &self,
        application: &ApplicationParameter,
        handle: &KeyHandle,
    ) -> Box<Future<Item = Option<ApplicationKey>, Error = io::Error>> {
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

fn overwrite_file_atomic<W>(path: &Path, logger: &Logger, writer_fn: W) -> io::Result<()>
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

    trace!(logger, "overwrite_file_atomic"; "path" => path.to_str().unwrap(), "tmp_path" => tmp_path.as_path().to_str().unwrap());

    {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        writer_fn(Box::new(file.try_clone()?))?;
        file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;
    Ok(())
}
