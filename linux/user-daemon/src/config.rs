use alloc::vec::IntoIter;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{BufReader, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

use directories::ProjectDirs;
use failure::Error;
use serde_json;

#[derive(Serialize, Deserialize)]
struct Config {
    secret_store_type: SecretStoreType,
}

#[derive(Serialize, Deserialize)]
enum SecretStoreType {
    File,
    SecretService,
}

struct ConfigFilePath(PathBuf);

impl ConfigFilePath {
    pub fn from_config_dir(dirs: &ProjectDirs) -> ConfigFilePath {
        ConfigFilePath::from_dir(dirs.config_dir())
    }

    pub fn from_dir(dir: &Path) -> ConfigFilePath {
        ConfigFilePath(dir.join("config.json"))
    }

    fn get(&self) -> &Path {
        &self.0
    }
}

struct ConfigFile {
    config: Config,
    path: ConfigFilePath,
}

impl ConfigFile {
    pub fn new(path: ConfigFilePath, config: Config) -> ConfigFile {
        ConfigFile { config, path }
    }

    pub fn load(path: ConfigFilePath) -> io::Result<Option<ConfigFile>> {
        match File::open(path.get()) {
            Ok(file) => serde_json::from_reader(file)
                .map_err(|e| e.into())
                .map(|config| Some(ConfigFile { config, path })),
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub fn save(&self) -> io::Result<()> {
        overwrite_file_atomic(self.path(), move |writer| {
            serde_json::to_writer_pretty(writer, &self.config).map_err(|e| e.into())
        })
    }

    fn path(&self) -> &Path {
        self.path.get()
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

    use super::*;

    use self::tempdir::TempDir;

    #[test]
    fn load_with_not_existing_file_returns_none() {
        let temp_dir = TempDir::new("config_tests").unwrap();
        let file_path = ConfigFilePath::from_dir(temp_dir.path());

        assert!(ConfigFile::load(file_path).unwrap().is_none());
    }
}
