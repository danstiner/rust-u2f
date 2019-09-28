use std::fs;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

use directories::ProjectDirs;
use serde_json;
use u2f_core::{AppId, ApplicationKey, Counter, KeyHandle, SecretStore};

use stores::Secret;

#[derive(Serialize, Deserialize)]
struct Data {
    secrets: Vec<Secret>,
}

impl Data {
    fn find_secret(&self, application: &AppId, handle: &KeyHandle) -> Option<&Secret> {
        self.secrets.iter().find(|s| {
            s.application_key.application.eq_consttime(application)
                && s.application_key.handle.eq_consttime(handle)
        })
    }
    fn find_secret_mut(&mut self, application: &AppId, handle: &KeyHandle) -> Option<&mut Secret> {
        self.secrets.iter_mut().find(|s| {
            s.application_key.application.eq_consttime(application)
                && s.application_key.handle.eq_consttime(handle)
        })
    }
    fn push(&mut self, secret: Secret) {
        self.secrets.push(secret)
    }
}

pub struct FileStoreV2 {
    path: PathBuf,
}

impl FileStoreV2 {
    pub fn new(projectDirs: ProjectDirs) -> io::Result<FileStoreV2> {
        let path = projectDirs.data_local_dir().join("secrets.json");
        Ok(FileStoreV2 { path })
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    fn read(&self) -> io::Result<Data> {
        match File::open(&self.path) {
            Ok(file) => serde_json::from_reader(file).map_err(|e| e.into()),
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(Data {
                secrets: Vec::new(),
            }),
            Err(err) => Err(err),
        }
    }

    fn write(&self, data: &Data) -> io::Result<()> {
        overwrite_file_atomic(&self.path, move |writer| {
            serde_json::to_writer_pretty(writer, &data).map_err(|e| e.into())
        })
    }
}

impl SecretStore for FileStoreV2 {
    fn add_application_key(&self, key: &ApplicationKey) -> io::Result<()> {
        let mut data = self.read()?;
        data.push(Secret {
            application_key: key.clone(),
            counter: 0,
        });
        self.write(&data)
    }

    fn get_and_increment_counter(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Counter> {
        let mut data = self.read()?;
        let secret = data
            .find_secret_mut(application, handle)
            .ok_or(io::Error::new(io::ErrorKind::Other, ""))?;
        let new_counter = secret.counter + 1;
        secret.counter = new_counter;
        self.write(&data)?;
        Ok(new_counter)
    }

    fn retrieve_application_key(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Option<ApplicationKey>> {
        Ok(self
            .read()?
            .find_secret(application, handle)
            .map(|secret| secret.application_key.clone()))
    }
}

fn overwrite_file_atomic<W>(path: &Path, writer_fn: W) -> io::Result<()>
where
    W: FnOnce(Box<&mut dyn Write>) -> io::Result<()>,
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

    use u2f_core::PrivateKey;

    use super::*;

    use self::tempdir::TempDir;

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
        let store = FileStoreV2 { path };
        let app_id = fake_app_id();
        let handle = fake_key_handle();
        let key = fake_key();
        let app_key = ApplicationKey::new(app_id, handle, key);
        store.add_application_key(&app_key).unwrap();

        let counter0 = store
            .get_and_increment_counter(&app_id, &app_key.handle)
            .unwrap();
        let counter1 = store
            .get_and_increment_counter(&app_id, &app_key.handle)
            .unwrap();

        assert_eq!(counter0 + 1, counter1);
    }

    #[test]
    fn retrieve_application_key() {
        let dir = TempDir::new("file_store_tests").unwrap();
        let path = dir.path().join("store");
        let store = FileStoreV2 { path };
        let app_id = fake_app_id();
        let handle = fake_key_handle();
        let key = fake_key();
        let app_key = ApplicationKey::new(app_id, handle, key);
        store.add_application_key(&app_key).unwrap();

        let retrieved_app_key = store
            .retrieve_application_key(&app_key.application, &app_key.handle)
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
        let store = FileStoreV2 { path };

        let key = store
            .retrieve_application_key(&fake_app_id(), &fake_key_handle())
            .unwrap();

        assert!(key.is_none());
    }
}
