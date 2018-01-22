use futures::{Future, IntoFuture};
use futures::future;
use serde_json;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use u2f_core::{AppId, ApplicationKey, Counter, KeyHandle, SecretStore};

#[derive(Serialize, Deserialize)]
struct Data {
    application_keys: HashMap<AppId, ApplicationKey>,
    counters: HashMap<AppId, Counter>,
}

pub struct FileStore {
    path: PathBuf,
    data: RefCell<Data>,
}

impl FileStore {
    pub fn new(path: PathBuf) -> io::Result<FileStore> {
        let data = Self::load(&path)?;
        Ok(FileStore {
            path: path,
            data: RefCell::new(data),
        })
    }

    fn save(&self) -> io::Result<()> {
        overwrite_file_atomic(&self.path, |writer| {
            serde_json::to_writer_pretty(writer, &*self.data.borrow()).unwrap();
            Ok(())
        })
    }

    fn load(path: &Path) -> io::Result<Data> {
        match File::open(path) {
            Ok(file) => Ok(serde_json::from_reader(file).unwrap()),
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(Data {
                application_keys: HashMap::new(),
                counters: HashMap::new(),
            }),
            Err(err) => Err(err),
        }
    }
}

impl SecretStore for FileStore {
    fn add_application_key(
        &self,
        key: &ApplicationKey,
    ) -> Box<Future<Item = (), Error = io::Error>> {
        self.data
            .borrow_mut()
            .application_keys
            .insert(key.application, key.clone());

        Box::new(self.save().into_future())
    }

    fn get_and_increment_counter(
        &self,
        application: &AppId,
    ) -> Box<Future<Item = Counter, Error = io::Error>> {
        let value = {
            let mut data = self.data.borrow_mut();

            if !data.counters.contains_key(application) {
                data.counters.insert(*application, 0);
            }

            match data.counters.get_mut(application) {
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
        application: &AppId,
        handle: &KeyHandle,
    ) -> Box<Future<Item = Option<ApplicationKey>, Error = io::Error>> {
        let res = match self.data.borrow().application_keys.get(application) {
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
    W: FnOnce(Box<&mut Write>) -> io::Result<()>,
{
    let directory = path.parent().ok_or(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid file path, does not have a parent directory",
        ))?;
    let tmp_path = make_tmp_path(path)?;

    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        writer_fn(Box::new(&mut tmp_file))?;
        tmp_file.flush()?;
        tmp_file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;
    fsync_dir(directory)?;
    Ok(())
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    let f = File::open(dir)?;
    f.sync_all()
}

fn make_tmp_path(path: &Path) -> io::Result<PathBuf> {
    let mut tmp_path = PathBuf::from(path);
    let mut file_name = tmp_path.file_name().ok_or(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid file path, does not end in a file name",
        ))?.to_owned();
    file_name.push(".tmp");
    tmp_path.set_file_name(file_name);
    Ok(tmp_path)
}

#[cfg(test)]
mod tests {
    extern crate tempdir;

    use self::tempdir::TempDir;
    use super::*;
    use u2f_core::Key;

    fn fake_app_id() -> AppId {
        AppId::from_bytes(&vec![0u8; 32])
    }

    fn fake_key() -> Key {
        Key::from_pem("-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICm1nBaPoI3Q3+RJ143W8eCBAdkxrq5YUoNQ9joO0CdroAoGCCqGSM49
AwEHoUQDQgAE4CiwgIh5tZgW85DKWRajIeTv7Z11C0nmida+m53yVySriU2YK/8O
i2L2wGDHkWWIJJSthmgwkZovXHyMXMpDhw==
-----END EC PRIVATE KEY-----")
    }

    fn fake_key_handle() -> KeyHandle {
        KeyHandle::from(&Vec::new())
    }

    #[test]
    fn get_and_increment_counter() {
        let dir = TempDir::new("file_store_tests").unwrap();
        let path = dir.path().join("store");
        let store = FileStore::new(path).unwrap();
        let app_id = fake_app_id();
        let handle = fake_key_handle();
        let key = fake_key();
        let app_key = ApplicationKey::new(app_id, handle, key);
        store.add_application_key(&app_key).wait().unwrap();

        let counter0 = store.get_and_increment_counter(&app_id).wait().unwrap();
        let counter1 = store.get_and_increment_counter(&app_id).wait().unwrap();

        assert_eq!(counter0+1, counter1);
    }

    #[test]
    fn retrieve_application_key() {
        let dir = TempDir::new("file_store_tests").unwrap();
        let path = dir.path().join("store");
        let store = FileStore::new(path).unwrap();
        let app_id = fake_app_id();
        let handle = fake_key_handle();
        let key = fake_key();
        let app_key = ApplicationKey::new(app_id, handle, key);
        store.add_application_key(&app_key).wait().unwrap();

        let retrieved_app_key = store
            .retrieve_application_key(&app_key.application, &app_key.handle)
            .wait()
            .unwrap()
            .unwrap();

        assert_eq!(retrieved_app_key.application, app_key.application);
        assert_eq!(retrieved_app_key.handle, app_key.handle);
        // Skip key field, it is not easily comparable
    }

    #[test]
    fn retrieve_nonexistent_key_is_none() {
        let dir = TempDir::new("file_store_tests").unwrap();
        let path = dir.path().join("store");
        let store = FileStore::new(path).unwrap();

        let key = store
            .retrieve_application_key(&fake_app_id(), &fake_key_handle())
            .wait()
            .unwrap();

        assert!(key.is_none());
    }
}
