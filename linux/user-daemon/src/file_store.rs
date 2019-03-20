use futures::future;
use futures::{Future, IntoFuture};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

use u2f_core::{AppId, ApplicationKey, Counter, KeyHandle, SecretStore};

macro_rules! tryf {
    ($e:expr) => {
        match $e {
            Ok(t) => t,
            Err(e) => return Box::new(future::err(From::from(e))),
        }
    };
}

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
        Ok(FileStore { path: path })
    }

    fn save(&self, data: &Data) -> io::Result<()> {
        overwrite_file_atomic(&self.path, move |writer| {
            serde_json::to_writer_pretty(writer, &data).map_err(|e| e.into())
        })
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

impl SecretStore for FileStore {
    fn add_application_key(
        &self,
        key: &ApplicationKey,
    ) -> Box<Future<Item = (), Error = io::Error>> {
        let mut data = tryf!(self.load());
        data.application_keys.insert(key.application, key.clone());
        Box::new(self.save(&data).into_future())
    }

    fn get_and_increment_counter(
        &self,
        application: &AppId,
    ) -> Box<Future<Item = Counter, Error = io::Error>> {
        let mut data = tryf!(self.load());

        if !data.counters.contains_key(application) {
            data.counters.insert(*application, 0);
        }

        let value = match data.counters.get_mut(application) {
            Some(counter) => {
                let value = *counter;
                *counter = value + 1;
                value
            }
            None => unreachable!(),
        };

        Box::new(self.save(&data).into_future().map(move |_| value))
    }

    fn retrieve_application_key(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> Box<Future<Item = Option<ApplicationKey>, Error = io::Error>> {
        let data = tryf!(self.load());
        let opt_key = data.application_keys.get(application).and_then(|key| {
            if key.handle.eq_consttime(handle) {
                Some(key.clone())
            } else {
                None
            }
        });
        Box::new(future::ok(opt_key))
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
            .mode(0o600)
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
    let mut file_name = tmp_path
        .file_name()
        .ok_or(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid file path, does not end in a file name",
        ))?
        .to_owned();
    file_name.push(".tmp");
    tmp_path.set_file_name(file_name);
    Ok(tmp_path)
}

#[cfg(test)]
mod tests {
    extern crate tempdir;

    use self::tempdir::TempDir;
    use super::*;
    use u2f_core::PrivateKey;

    fn fake_app_id() -> AppId {
        AppId::from_bytes(&vec![0u8; 32])
    }

    fn fake_key() -> PrivateKey {
        PrivateKey::from_pem(
            "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICm1nBaPoI3Q3+RJ143W8eCBAdkxrq5YUoNQ9joO0CdroAoGCCqGSM49
AwEHoUQDQgAE4CiwgIh5tZgW85DKWRajIeTv7Z11C0nmida+m53yVySriU2YK/8O
i2L2wGDHkWWIJJSthmgwkZovXHyMXMpDhw==
-----END EC PRIVATE KEY-----",
        )
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

        assert_eq!(counter0 + 1, counter1);
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
